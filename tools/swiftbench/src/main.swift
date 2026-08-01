// Command swiftbench measures the Swift port on the same corpus the Rust and Go
// harnesses use, so all three sets of timings are actually comparable.
//
// Usage:
//
//	cd tools/swiftbench
//	swift run -c release swiftbench <corpus-dir> [chunk-size] [iterations]
//
// This side never writes the corpus. The Rust harness generates it; Go and Swift
// only read it, which removes any chance of the three measuring subtly different
// bytes.
//
// The DAG root is printed for the same reason the other two print it: timings only
// mean something once every implementation is shown to have built the same DAG. A
// port that looks fast because it skipped work is the failure mode this guards
// against.
//
// Every timed region repeats its workload until it spans at least targetWindow,
// then divides by the repetition count, identically to the other two harnesses.
// That is mandatory rather than tidy: a single-shot timing of a sub-millisecond
// workload reports the clock's floor instead of the code, which reads as
// "infinitely fast".
//
// The clock is DispatchTime, which is monotonic and available on every platform
// the toolchain targets. ContinuousClock is the modern spelling but requires
// macOS 13, and this package tracks the library's macOS 12 floor.

import Dispatch
import Foundation
import ScionicMerkleTree

// MARK: - Constants
//
// Declared before every function that reads them: top-level code in main.swift is
// executed in statement order, so a global read by a function called earlier than
// its own initializer would not be ready.

/// How long one timed region must last before its measurement is trustworthy.
/// At the ~537us clock resolution measured on this platform, 100ms carries roughly
/// 0.5% timing quantization error instead of the 100% error a single sub-ms run
/// would carry.
let targetWindow: UInt64 = 100_000_000  // nanoseconds

let maxReps = 1 << 22

#if os(Windows)
let osName = "windows"
#elseif os(macOS)
let osName = "macos"
#elseif os(Linux)
let osName = "linux"
#else
let osName = "unknown"
#endif

// MARK: - Failures

enum BenchFailure: Error, CustomStringConvertible {
    case corpusMissing(String)
    case emptySequence(String)

    var description: String {
        switch self {
        case .corpusMissing(let path):
            return "corpus \(path) not found: generate it with the Rust harness first"
        case .emptySequence(let which):
            return "empty \(which)"
        }
    }
}

// MARK: - Timing

func nowNanos() -> UInt64 {
    DispatchTime.now().uptimeNanoseconds
}

/// Finds how many repetitions push one timed region past `targetWindow`.
func calibrate(_ run: () throws -> Void) rethrows -> Int {
    var reps = 1
    while true {
        let start = nowNanos()
        for _ in 0..<reps {
            try run()
        }
        let elapsed = nowNanos() - start
        if elapsed >= targetWindow || reps >= maxReps {
            return reps
        }
        // Project the needed count from what was just observed, but never trust a
        // zero reading (that is the clock failing to tick, not infinite speed) and
        // never let the estimate shrink the loop.
        var projected = reps * 16
        if elapsed > 0 {
            projected = Int(Double(reps) * (Double(targetWindow) / Double(elapsed)) * 1.2)
        }
        projected = max(projected, reps * 2)
        projected = min(projected, maxReps)
        reps = projected
    }
}

/// Warms up, calibrates, then reports min and median across samples.
/// Min is the least noisy estimator for CPU-bound work: it is the sample least
/// disturbed by the scheduler, and unlike a mean it cannot be dragged by an outlier.
func bench(
    _ label: String,
    _ samples: Int,
    _ benchBytes: Int64,
    _ run: () throws -> Void
) rethrows {
    try run()  // warm the file cache and any lazily built state
    let reps = try calibrate(run)
    var timings: [UInt64] = []
    timings.reserveCapacity(samples)
    for _ in 0..<samples {
        let start = nowNanos()
        for _ in 0..<reps {
            try run()
        }
        timings.append((nowNanos() - start) / UInt64(reps))
    }
    timings.sort()
    // Not named min/median: min would shadow the stdlib free function, and a
    // shadowed builtin is exactly the kind of thing that reads fine until someone
    // edits nearby.
    let fastest = timings[0]
    let middle = timings[timings.count / 2]
    // Matches Go's "%-20s %8d %9.4fms %9.4fms %9.1f MiB/s" exactly, so the three
    // outputs can be read side by side without re-aligning columns.
    print(
        padRight(label, 20)
            + " " + padLeft(String(reps), 8)
            + " " + padLeft(String(format: "%.4f", millis(fastest)), 9) + "ms"
            + " " + padLeft(String(format: "%.4f", millis(middle)), 9) + "ms"
            + " " + padLeft(String(format: "%.1f", throughput(benchBytes, fastest)), 9) + " MiB/s"
    )
}

func millis(_ nanos: UInt64) -> Double {
    Double(nanos) / 1_000_000.0
}

func throughput(_ bytes: Int64, _ nanos: UInt64) -> Double {
    let seconds = Double(nanos) / 1_000_000_000.0
    if seconds <= 0 {
        return 0
    }
    return (Double(bytes) / (1024 * 1024)) / seconds
}

// MARK: - Formatting

func padRight(_ text: String, _ width: Int) -> String {
    text.count >= width ? text : text + String(repeating: " ", count: width - text.count)
}

func padLeft(_ text: String, _ width: Int) -> String {
    text.count >= width ? text : String(repeating: " ", count: width - text.count) + text
}

// MARK: - Corpus

/// Sums the corpus's file bytes. Read-only by design; see the header note.
func corpusSize(_ root: String) -> Int64 {
    let manager = FileManager.default
    guard let walker = manager.enumerator(atPath: root) else { return 0 }
    let base = URL(fileURLWithPath: root)
    var total: Int64 = 0
    for case let relative as String in walker {
        // resourceValues rather than attributesOfItem: the latter hands back
        // platform-dependent boxed number types, and unboxing it wrongly would
        // silently report a zero-byte corpus and an infinite throughput.
        let entry = base.appendingPathComponent(relative)
        guard let values = try? entry.resourceValues(forKeys: [.isDirectoryKey, .fileSizeKey]),
            values.isDirectory != true
        else { continue }
        total += Int64(values.fileSize ?? 0)
    }
    return total
}

// MARK: - Entry point

func runBenchmarks() throws {
    let arguments = Array(CommandLine.arguments.dropFirst())
    let corpus = arguments.first ?? "bench-corpus"
    let chunk = arguments.count > 1 ? (Int(arguments[1]) ?? 256 * 1024) : 256 * 1024
    let samples = arguments.count > 2 ? (Int(arguments[2]) ?? 5) : 5

    guard FileManager.default.fileExists(atPath: corpus) else {
        throw BenchFailure.corpusMissing(corpus)
    }
    let corpusBytes = corpusSize(corpus)

    setChunkSize(chunk)
    setDefaultBatchSize()

    let built = try createDag(path: corpus, timestampRoot: false)
    let cborBytes = built.toCBOR()
    let jsonBytes = try built.toJSON()

    print(
        "scionic-bench impl=swift root=\(built.root) leaves=\(built.leafs.count) "
            + "corpus_bytes=\(corpusBytes) cbor_bytes=\(cborBytes.count) "
            + "json_bytes=\(jsonBytes.count) chunk=\(chunk) samples=\(samples)"
    )
    print(
        padRight("workload", 20)
            + " " + padLeft("reps", 8)
            + " " + padLeft("min", 11)
            + " " + padLeft("median", 11)
            + " " + padLeft("throughput", 14)
    )

    try bench("create_sequential", samples, corpusBytes) {
        _ = try createDag(path: corpus, timestampRoot: false)
    }
    try bench("create_parallel", samples, corpusBytes) {
        _ = try createDagWithConfig(path: corpus, config: .parallelConfig())
    }
    try bench("verify", samples, corpusBytes) {
        try built.verify()
    }
    // No `try`: toCBOR is the one non-throwing workload, and bench is rethrows,
    // so this call cannot throw.
    bench("to_cbor", samples, Int64(cborBytes.count)) {
        _ = built.toCBOR()
    }
    try bench("from_cbor", samples, Int64(cborBytes.count)) {
        _ = try Dag.fromCBOR(cborBytes)
    }
    try bench("to_json", samples, Int64(jsonBytes.count)) {
        _ = try built.toJSON()
    }
    try bench("from_json", samples, Int64(jsonBytes.count)) {
        _ = try Dag.fromJSON(jsonBytes)
    }
    try bench("leaf_sequence", samples, corpusBytes) {
        if built.getLeafSequence().isEmpty {
            throw BenchFailure.emptySequence("leaf sequence")
        }
    }
    try bench("batched_sequence", samples, corpusBytes) {
        if built.getBatchedLeafSequence().isEmpty {
            throw BenchFailure.emptySequence("batched sequence")
        }
    }

    print("os=\(osName) cpus=\(ProcessInfo.processInfo.activeProcessorCount) swift_config=release")
}

do {
    try runBenchmarks()
} catch {
    FileHandle.standardError.write(Data("swiftbench failed: \(error)\n".utf8))
    exit(1)
}
