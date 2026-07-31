// Command gobench measures the Go reference implementation on the same corpus
// the Rust harness uses, so the two sets of timings are actually comparable.
//
// Usage:
//
//	cd tools/gobench
//	go mod tidy && go run . <corpus-dir> [chunk-size] [iterations]
//
// This side never writes the corpus. The Rust harness generates it and Go only
// reads it, which removes any chance of the two measuring subtly different
// bytes.
//
// The DAG root is printed for the same reason the Rust side prints it: timings
// only mean something once both implementations are shown to have built the same
// DAG. A port that looks fast because it skipped work is the failure mode this
// guards against.
//
// Every timed region repeats its workload until it spans at least targetWindow,
// then divides by the repetition count. This is mandatory, not tidy: time.Now()
// on this platform resolves to ~537us, and 199999 of 200000 consecutive reads
// observe no tick at all. Timing a sub-millisecond workload once therefore
// reports 0.000ms -- which reads as "infinitely fast" instead of "below the
// clock's floor". The Rust harness calibrates identically.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"time"

	scionic "github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
)

func main() {
	corpus := "bench-corpus"
	if len(os.Args) > 1 {
		corpus = os.Args[1]
	}
	chunkSize := 256 * 1024
	if len(os.Args) > 2 {
		if parsed, err := strconv.Atoi(os.Args[2]); err == nil {
			chunkSize = parsed
		}
	}
	samples := 5
	if len(os.Args) > 3 {
		if parsed, err := strconv.Atoi(os.Args[3]); err == nil {
			samples = parsed
		}
	}

	if _, err := os.Stat(corpus); err != nil {
		fmt.Fprintf(os.Stderr, "corpus %s not found: generate it with the Rust harness first\n", corpus)
		os.Exit(1)
	}
	corpusBytes := corpusSize(corpus)

	scionic.SetChunkSize(chunkSize)
	scionic.SetDefaultBatchSize()

	built, err := scionic.CreateDag(corpus, false)
	must(err)
	cborBytes, err := built.ToCBOR()
	must(err)
	jsonBytes, err := built.ToJSON()
	must(err)

	fmt.Printf("scionic-bench impl=go root=%s leaves=%d corpus_bytes=%d cbor_bytes=%d json_bytes=%d chunk=%d samples=%d\n",
		built.Root, len(built.Leafs), corpusBytes, len(cborBytes), len(jsonBytes), chunkSize, samples)
	fmt.Printf("%-20s %8s %11s %11s %14s\n", "workload", "reps", "min", "median", "throughput")

	bench("create_sequential", samples, corpusBytes, func() {
		_, err := scionic.CreateDag(corpus, false)
		must(err)
	})
	bench("create_parallel", samples, corpusBytes, func() {
		_, err := scionic.CreateDagWithConfig(corpus, scionic.ParallelConfig())
		must(err)
	})
	bench("verify", samples, corpusBytes, func() {
		must(built.Verify())
	})
	bench("to_cbor", samples, int64(len(cborBytes)), func() {
		_, err := built.ToCBOR()
		must(err)
	})
	bench("from_cbor", samples, int64(len(cborBytes)), func() {
		_, err := scionic.FromCBOR(cborBytes)
		must(err)
	})
	bench("to_json", samples, int64(len(jsonBytes)), func() {
		_, err := built.ToJSON()
		must(err)
	})
	bench("from_json", samples, int64(len(jsonBytes)), func() {
		_, err := scionic.FromJSON(jsonBytes)
		must(err)
	})
	bench("leaf_sequence", samples, corpusBytes, func() {
		if len(built.GetLeafSequence()) == 0 {
			panic("empty leaf sequence")
		}
	})
	bench("batched_sequence", samples, corpusBytes, func() {
		if len(built.GetBatchedLeafSequence()) == 0 {
			panic("empty batched sequence")
		}
	})

	fmt.Printf("os=%s cpus=%d go=%s\n", runtime.GOOS, runtime.NumCPU(), runtime.Version())
}

// targetWindow is how long one timed region must last before its measurement is
// trustworthy. At ~537us clock resolution, 100ms carries roughly 0.5% timing
// quantization error instead of the 100% error a single sub-ms run would carry.
const targetWindow = 100 * time.Millisecond

const maxReps = 1 << 22

// calibrate finds how many repetitions push one timed region past targetWindow.
func calibrate(run func()) int {
	reps := 1
	for {
		start := time.Now()
		for i := 0; i < reps; i++ {
			run()
		}
		elapsed := time.Since(start)
		if elapsed >= targetWindow || reps >= maxReps {
			return reps
		}
		// Project the needed count from what was just observed, but never trust
		// a zero reading (that is the clock failing to tick, not infinite speed)
		// and never let the estimate shrink the loop.
		projected := reps * 16
		if elapsed > 0 {
			projected = int(float64(reps) * (float64(targetWindow) / float64(elapsed)) * 1.2)
		}
		if doubled := reps * 2; projected < doubled {
			projected = doubled
		}
		if projected > maxReps {
			projected = maxReps
		}
		reps = projected
	}
}

// bench warms up, calibrates, then reports min and median across samples.
// Min is the least noisy estimator for CPU-bound work: it is the sample least
// disturbed by the scheduler, and unlike a mean it cannot be dragged by an
// outlier.
func bench(label string, samples int, benchBytes int64, run func()) {
	run()
	reps := calibrate(run)
	timings := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		start := time.Now()
		for j := 0; j < reps; j++ {
			run()
		}
		timings = append(timings, time.Since(start)/time.Duration(reps))
	}
	sort.Slice(timings, func(i, j int) bool { return timings[i] < timings[j] })
	// Not named min/median: min would shadow the builtin, and a shadowed builtin
	// is exactly the kind of thing that reads fine until someone edits nearby.
	fastest := timings[0]
	middle := timings[len(timings)/2]
	fmt.Printf("%-20s %8d %9.4fms %9.4fms %9.1f MiB/s\n",
		label, reps, millis(fastest), millis(middle), throughput(benchBytes, fastest))
}

func millis(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func throughput(bytes int64, d time.Duration) float64 {
	seconds := d.Seconds()
	if seconds <= 0 {
		return 0
	}
	return (float64(bytes) / (1024 * 1024)) / seconds
}

func corpusSize(root string) int64 {
	var total int64
	must(filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	}))
	return total
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

