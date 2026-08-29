//! Performance harness for the Scionic Merkle DAG, paired with `tools/gobench`.
//!
//! Usage:
//!
//! ```text
//! cargo run --release --example bench -- <corpus-dir> [chunk-size] [iterations]
//! cd tools/gobench && go run . <corpus-dir> [chunk-size] [iterations]
//! ```
//!
//! This side generates the corpus when the directory does not exist; the Go side
//! only ever reads it, so the two implementations cannot drift apart by
//! generating subtly different bytes.
//!
//! Both print the resulting DAG root. Timings from two implementations that built
//! different DAGs are meaningless, so compare the roots first -- a port that is
//! fast because it skipped work would otherwise look like a win.
//!
//! Each timed region repeats the workload until it spans at least
//! [`TARGET_WINDOW`], then divides by the repetition count. That is not a
//! refinement, it is required for the numbers to mean anything: Go's
//! `time.Now()` was measured on this platform at ~537us resolution, where
//! 199999 of 200000 consecutive reads observed no tick at all. Single-shot
//! timing of a sub-millisecond workload there reports 0.000ms and a nonsense
//! throughput. Both harnesses use the same calibrated repetition strategy so
//! the two columns are comparable rather than merely adjacent.
//!
//! Results are reported as min and median across N samples. Min is the least
//! noisy estimator for CPU-bound work: it is the sample least disturbed by the
//! scheduler, and unlike a mean it cannot be dragged by an outlier.
//!
//! Throughput divides by the bytes each workload actually processes -- corpus
//! bytes for building and traversal, encoded bytes for the serialization paths.
//! Measuring a decode against the corpus size would flatter whichever
//! implementation happens to encode larger.

use scionic_merkletree::{
    create_dag_parallel, create_dag_with_options, Dag, DagBuildOptions, Result,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// Distinct per-file content. Byte-identical files would collapse into a single
// shared leaf, so a corpus built from one repeated pattern would quietly measure
// deduplication instead of hashing throughput.
const CORPUS: &[(&str, usize, usize)] = &[
    ("large", 4, 4 * 1024 * 1024),
    ("medium", 8, 256 * 1024),
    ("small", 64, 4 * 1024),
];

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let corpus = PathBuf::from(args.first().map_or("bench-corpus", String::as_str));
    let chunk_size: usize = args
        .get(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(256 * 1024);
    let samples: usize = args
        .get(2)
        .and_then(|value| value.parse().ok())
        .unwrap_or(5);

    let corpus_bytes = ensure_corpus(&corpus)?;
    let options = DagBuildOptions::default().with_chunk_size(chunk_size)?;
    let parallel_options = DagBuildOptions::default()
        .with_chunk_size(chunk_size)?
        .with_parallel();

    let dag = create_dag_with_options(&corpus, &options)?;
    let cbor = dag.to_cbor()?;
    let json = dag.to_json()?;
    let cbor_bytes = cbor.len() as u64;
    let json_bytes = json.len() as u64;

    println!(
        "scionic-bench impl=rust root={} leaves={} corpus_bytes={corpus_bytes} cbor_bytes={cbor_bytes} json_bytes={json_bytes} chunk={chunk_size} samples={samples}",
        dag.root(),
        dag.len()
    );
    println!(
        "{:<20} {:>8} {:>11} {:>11} {:>14}",
        "workload", "reps", "min", "median", "throughput"
    );

    bench("create_sequential", samples, corpus_bytes, || {
        create_dag_with_options(&corpus, &options).map(|_| ())
    })?;
    bench("create_parallel", samples, corpus_bytes, || {
        create_dag_parallel(&corpus, &parallel_options).map(|_| ())
    })?;
    bench("verify", samples, corpus_bytes, || dag.verify())?;
    bench("to_cbor", samples, cbor_bytes, || dag.to_cbor().map(|_| ()))?;
    bench("from_cbor", samples, cbor_bytes, || {
        Dag::from_cbor(&cbor).map(|_| ())
    })?;
    bench("to_json", samples, json_bytes, || dag.to_json().map(|_| ()))?;
    bench("from_json", samples, json_bytes, || {
        Dag::from_json(&json).map(|_| ())
    })?;
    bench("leaf_sequence", samples, corpus_bytes, || {
        dag.get_leaf_sequence().map(|_| ())
    })?;
    bench("batched_sequence", samples, corpus_bytes, || {
        dag.batched_leaf_sequence().map(|_| ())
    })?;

    println!(
        "os={} cpus={} rustc_profile=release",
        std::env::consts::OS,
        std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get)
    );
    Ok(())
}

/// A timed region must be far larger than the platform clock's resolution, or
/// the measurement reports the clock rather than the code.
const TARGET_WINDOW: Duration = Duration::from_millis(100);
const MAX_REPS: usize = 1 << 22;

/// Find how many repetitions push one timed region past [`TARGET_WINDOW`].
fn calibrate(run: &mut impl FnMut() -> Result<()>) -> Result<usize> {
    let mut reps = 1;
    loop {
        let start = Instant::now();
        for _ in 0..reps {
            run()?;
        }
        let elapsed = start.elapsed();
        if elapsed >= TARGET_WINDOW || reps >= MAX_REPS {
            return Ok(reps);
        }
        // Project the needed count from what was just observed, but never trust
        // a zero reading (that is the clock failing to tick, not infinite speed)
        // and never let the estimate shrink the loop.
        let projected = if elapsed.is_zero() {
            reps.saturating_mul(16)
        } else {
            let ratio = TARGET_WINDOW.as_secs_f64() / elapsed.as_secs_f64();
            ((reps as f64) * ratio * 1.2).ceil() as usize
        };
        reps = projected.max(reps.saturating_mul(2)).min(MAX_REPS);
    }
}

fn bench(
    label: &str,
    samples: usize,
    bytes: u64,
    mut run: impl FnMut() -> Result<()>,
) -> Result<()> {
    run()?; // warm the file cache and any lazily built state
    let reps = calibrate(&mut run)?;
    let mut timings = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        for _ in 0..reps {
            run()?;
        }
        timings.push(start.elapsed() / reps as u32);
    }
    timings.sort_unstable();
    let fastest = timings[0];
    let middle = timings[timings.len() / 2];
    println!(
        "{label:<20} {reps:>8} {:>9.4}ms {:>9.4}ms {:>9.1} MiB/s",
        millis(fastest),
        millis(middle),
        throughput(bytes, fastest)
    );
    Ok(())
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn throughput(bytes: u64, duration: Duration) -> f64 {
    let seconds = duration.as_secs_f64();
    if seconds <= 0.0 {
        return f64::INFINITY;
    }
    (bytes as f64 / (1024.0 * 1024.0)) / seconds
}

fn ensure_corpus(root: &Path) -> Result<u64> {
    if root.exists() {
        return Ok(corpus_size(root));
    }
    fs::create_dir_all(root).map_err(|error| io(root, error))?;
    let mut seed = 0_usize;
    for (prefix, count, size) in CORPUS {
        for index in 0..*count {
            let data: Vec<u8> = (0..*size)
                .map(|offset| b'A' + ((offset + seed) % 26) as u8)
                .collect();
            let path = root.join(format!("{prefix}_{index}.bin"));
            fs::write(&path, &data).map_err(|error| io(&path, error))?;
            seed += 7;
        }
    }
    Ok(corpus_size(root))
}

fn corpus_size(root: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(entries) = fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_dir() {
                stack.push(entry_path);
            } else if let Ok(metadata) = entry.metadata() {
                total += metadata.len();
            }
        }
    }
    total
}

fn io(path: &Path, error: std::io::Error) -> scionic_merkletree::Error {
    scionic_merkletree::Error::Io {
        operation: "prepare benchmark corpus",
        path: path.to_path_buf(),
        source: error,
    }
}
