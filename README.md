# Scionic Merkle Tree — Rust

The authoritative Rust implementation of Scionic Merkle Tree: a chunked,
verifiable-as-you-download Merkle DAG for directory trees and large files.
Go is deprecated for this workspace; historical Go and Swift artifacts are
retained only as regression evidence.

A Scionic Merkle DAG combines the folder support of an IPFS-style Merkle DAG with
the small branch proofs of a classic Merkle tree. Each parent commits to its
children through a classic Merkle root, so a receiver can authenticate every leaf
as it arrives — independently, and without holding the whole structure.

## Status

The current Rust format/library version is **v2.4.3** across all five layers
listed below, including the frozen fastcdc-v1 content-defined chunking mode.
Committed historical cross-language vectors provide additional byte evidence,
but Rust source, tests, and release decisions define the active contract.

| Layer | Scope |
|---|---|
| 1 — Primitives | CBOR, base32lower, base58btc, varint, CIDv1 |
| 2 — Classic Merkle tree | construction, proof generation, proof verification |
| 3 — Leaf hashing | CBOR → SHA-256 → CIDv1 → base32lower |
| 4 — DAG creation | filesystem walk, chunking (fastcdc-v1 default, fixed-2m), sequential and parallel |
| 5 — DAG operations | verify, serialize, transmit, diff, partial DAGs, store |

Correctness is not asserted from a round trip against this crate's own encoder.
The Rust suite also checks committed independent JSON/CBOR vectors, including
historical cross-language bytes, so a divergence fails rather than going unnoticed.
[`PARITY.md`](PARITY.md) documents the current Rust wire contract and labels the
historical evidence that supports it.

`#![forbid(unsafe_code)]`, a single dependency (`sha2`), no workspace, no FFI.

## Install

Not published to crates.io. Depend on it by git:

```toml
[dependencies]
scionic-merkletree = { git = "https://github.com/HORNET-Storage/Scionic-MerkleTree-Rust", tag = "v2.4.3" }
```

Requires Rust 1.85 or newer.

## Usage

### Build a DAG from a directory

```rust
use scionic_merkletree::create_dag;

let dag = create_dag("path/to/directory")?;
println!("root: {}", dag.root());
dag.verify()?;
```

Parallel creation builds a byte-identical DAG:

```rust
use scionic_merkletree::{create_dag_parallel, ParallelDagBuildOptions};

let dag = create_dag_parallel("path/to/directory", &ParallelDagBuildOptions::default())?;
```

Build settings live on `DagBuildOptions`, passed through
`create_dag_with_options`.

### Chunking

New trees default to **fastcdc-v1** content-defined chunking — 512 KiB min /
2 MiB target / 8 MiB max, gear-hash boundaries. Boundaries follow content
rather than offsets, so an edit re-cuts only the chunks it touches and
identical runs deduplicate across files and versions. Roots built under it
carry `"chunking": "fastcdc-v1"` in their additional data, stamped by the
library (absent ⇒ fixed-2m).

```rust
use scionic_merkletree::{Chunking, DagBuildOptions};

// fastcdc-v1 is the default. These select the explicit fixed-size modes:
let fixed = DagBuildOptions::default().with_chunk_size(2 * 1024 * 1024)?;
let whole_file = DagBuildOptions::default().with_chunking_disabled();

// Producers holding content in memory cut through the same normative cutter,
// so every producer slices identical content into identical chunks:
let chunks = Chunking::FastCdcV1.cut(&content);
```

The algorithm is frozen by the Rust implementation and the committed
`spec/fastcdc-vectors` corpus: its constants, gear table, boundary loop, boundary
offsets, chunk digests, edit-reuse partitions, rebuilt DAG roots, and root tag are
pinned for 11 cases. Historical Go and Swift results show that identical bytes were
cut into identical chunks across implementations and platforms; they do not control
future Rust changes.

### Serialize

```rust
use scionic_merkletree::Dag;

let cbor = dag.to_cbor()?;
let restored = Dag::from_cbor(&cbor)?;

let json = dag.to_json()?;
let restored = Dag::from_json(&json)?;
```

Branch proofs have one exact CBOR/JSON shape: `{Leaf, Proof:{Siblings, Path}}`.
Flat `{Leaf, Siblings, Path}` input is rejected; the Rust encoder emits only the
nested form, which is also pinned by historical vectors.

### Transmit, verifying each leaf on arrival

```rust
use scionic_merkletree::TransmissionReceiver;

let mut receiver = TransmissionReceiver::new();
for packet in dag.get_leaf_sequence()? {
    receiver.apply_and_verify_transmission_packet(packet)?;
}
let received = receiver.into_dag()?;
```

Each packet carries the Merkle proof binding its leaf to the parent that packet
declares, so the receiver authenticates as it goes rather than trusting the sender
and checking at the end.

For larger transfers, `batched_leaf_sequence()` groups leaves into size-limited
packets:

```rust
use scionic_merkletree::BatchedDagReceiver;

let mut receiver = BatchedDagReceiver::new();
for batch in dag.batched_leaf_sequence()? {
    receiver.apply_and_verify(&batch)?;
}
let received = receiver.finish_verified()?;
```

### Partial DAGs

A partial DAG carries a subset of leaves plus the Merkle proofs needed to verify
them against the original root, so a peer can request specific files without
downloading — or being able to forge — the rest.

## Wire contract

The Rust serialized envelope has one exact CBOR shape and one exact JSON shape.
Historical Go and Swift artifacts matched those bytes and remain independent
regression evidence. Three rules define the current Rust contract:

- **Struct fields ride in declaration order.** This is the frozen canonical shape.
- **Exactly five fields are genuinely dynamic maps**, and only those are
  key-sorted: `Leafs`, `AdditionalData`, `stored_proofs`, `proofs`, and
  `Relationships`. Everything else is struct-shaped and must not sort.
- **Each format sorts those five by its own comparator.** The distinction is
  explicit in the Rust encoder:

| Format | Rule | `m`, `zz-probe`, `aaa-probe` sort to |
|---|---|---|
| CBOR | RFC 8949 core-deterministic — length first, then bytewise | `m`, `zz-probe`, `aaa-probe` |
| JSON | canonical Rust rule — plain bytewise, no length term | `aaa-probe`, `m`, `zz-probe` |

The two comparators agree on every pair of equal-length keys and disagree
otherwise — an overlap that can hide a comparator mix-up completely; see
[The two formats sort map keys by different rules](#the-two-formats-sort-map-keys-by-different-rules).

`stored_proofs` and `proofs` are omitted entirely when empty.

Rust implements and tests all three rules, so the same DAG encodes to the same
bytes on every run in either format. Historical cross-language agreement supports
that result but does not define it. Deterministic bytes make the envelope safe to
digest, cache, deduplicate, and compare byte for byte.

CID computation is a **third** contract and none of the above touches it: the
hashed preimage flattens `AdditionalData` into a sorted *array* before hashing, so
no map iteration order can reach a CID. That third comparator is frozen into every
CID ever minted and must never be unified with the two above, however alike they
look.

## Historical cross-language performance evidence

The table below is a historical same-session comparison against earlier Go and
Swift implementations on one generated corpus and chunk size. Each harness printed
the same DAG root (`bafireifuqx7…lrqrmxi`, 141 leaves), preventing different output
from masquerading as a speed difference. These measurements are not compatibility
or release gates for the current Rust crate.

All three also report an identical `cbor_bytes` **and** an identical `json_bytes`,
and that holds across the chunk sweep, where the DAG itself changes shape:

| Chunk | Leaves | `cbor_bytes` | `json_bytes` |
|---|---:|---:|---:|
| 256 KiB | 141 | 19188357 | 25591601 |
| 1 MiB | 93 | 19170909 | 25565908 |
| 2 MiB | 85 | 19168005 | 25561620 |

Equal sizes are *weak* evidence on their own, because reordering a map preserves
byte length exactly; the byte-for-byte guarantee comes from the shared
spec-vector corpus ([JSON is byte-identical too](#json-is-byte-identical-too)),
not from this table.

18.25 MiB corpus, 256 KiB chunks, min of 15 samples, Windows / 24 CPUs /
Go 1.24.4 / Swift 6.3.1, all three harnesses run back to back in one session.
Lower is better.

| Workload | Rust | Go | Swift | Rust vs Go |
|---|---:|---:|---:|---|
| `verify` | 5.02 ms | 10.93 ms | 17.44 ms | **2.18× faster** |
| `from_json` | 48.29 ms | 70.78 ms | 61.43 ms | **1.47× faster** |
| `create_parallel` | 3.46 ms | 4.80 ms | 9.66 ms | **1.39× faster** |
| `to_json` | 67.09 ms | 79.75 ms | 81.38 ms | **1.19× faster** |
| `from_cbor` | 3.09 ms | 3.16 ms | 3.02 ms | parity |
| `leaf_sequence` | 2.63 ms | 2.79 ms | 0.32 ms | parity |
| `batched_sequence` | 0.102 ms | 0.089 ms | 0.291 ms | parity |
| `create_sequential` | 18.66 ms | 15.80 ms | 53.48 ms | 1.18× slower |
| `to_cbor` | 4.71 ms | 3.57 ms | 9.95 ms | 1.32× slower |

Swift's column, and the caveats around its absolute magnitudes, are covered in
[Where the Swift port sits](#where-the-swift-port-sits).

**Determinism is not what the `to_cbor` row measures.** All three ports encode
deterministically, by the two rules above, and in none of them does that cost
anything visible: ordering a few hundred short keys per DAG does not show up in
any profile. All three encoders also share the same single-pass shape — append
into one pre-sized buffer, no per-nesting-level temporaries — and the output is
byte-identical, not merely by assertion: the shared spec-vector corpus
regenerates bit-for-bit in all three repositories.

Most of this crate's `to_cbor` row is not encoder work at all — it is the
allocator handing back a fresh ~19 MB `Vec`, which is roughly three quarters of
the measurement. Callers encoding many DAGs can skip that with `to_cbor_into`,
which appends into a buffer they own and reuse — 2.00 ms against 4.87 ms in a
dedicated recording, so the reuse figures are not directly comparable to the
table above. Go has the same escape hatch in `AppendCBOR`. Both delegate to the
one encoder, so neither can drift from `to_cbor`/`ToCBOR`.

`from_cbor`, `leaf_sequence` and `batched_sequence` are reported as parity
because the spread between repeated runs of either implementation is wider than
the difference between them.

Leaf payloads and leaf names are shared through `Arc` rather than deep-copied, so
cloning a leaf — which transmission, batching and every store read do constantly
— costs a refcount bump instead of an allocation. This is sound because both are
immutable: a leaf's CID commits to `sha256(content)` and to `ItemName` through the
identity CBOR, so mutating either in place would invalidate the leaf's identity,
and `Arc` hands out no `&mut` while a second owner exists. The invariant is
enforced by the type system rather than by convention.

### Where the Swift port sits

Swift builds a bit-identical DAG, a bit-identical CBOR envelope and a
bit-identical JSON document, so nothing in its column is a correctness gap:

| Workload | Swift | Swift vs Go | Swift vs Rust |
|---|---:|---|---|
| `verify` | 17.44 ms | 1.6× slower | 3.5× slower |
| `create_sequential` | 53.48 ms | 3.4× slower | 2.9× slower |
| `create_parallel` | 9.66 ms | 2.0× slower | 2.8× slower |
| `to_cbor` | 9.95 ms | 2.8× slower | 2.1× slower |
| `leaf_sequence` | 0.32 ms | **8.7× faster** | **8.2× faster** |
| `batched_sequence` | 0.291 ms | 3.3× slower | 2.9× slower |
| `to_json` | 81.38 ms | parity | 1.21× slower |
| `from_json` | 61.43 ms | **1.15× faster** | 1.27× slower |
| `from_cbor` | 3.02 ms | parity | parity |

The design decisions behind Swift's column, in brief — the Swift repository's
README covers them in full:

- **Windows SHA-256 goes through CNG/BCrypt.** swift-crypto's vendored BoringSSL
  ships 123 assembly files, every one guarded `__ELF__`/`__APPLE__`, so on
  Windows they all compile to empty objects and SHA-256 runs as portable C —
  449 MB/s on this machine, against 4,199 MB/s through `BCryptHashData`, with
  BCrypt ahead at every input size down to 64-byte sibling pairs (287 ns
  against 515 ns per hash). The port's default hash path is one internal seam:
  BCrypt on Windows, swift-crypto everywhere else — Apple keeps CryptoKit,
  Linux keeps BoringSSL's ELF assembly — and the digests are identical by
  definition and by test.
- **The CBOR encoder appends into one exactly pre-sized `[UInt8]` buffer** — the
  same single-pass shape this crate and Go use.
- **Sibling-pair hashing streams both halves into one hasher** instead of
  allocating a concatenated temporary per Merkle pair.
- **`getLeafSequence` builds each parent's proof tree once per parent**, not
  once per child. The other two ports rebuild it per child, which is why Swift
  leads that row by ~8× over both.

What separates Swift on the create/verify rows is allocation and ARC traffic in
the builder paths, not hashing.

One caveat on the absolute magnitudes: the Windows Swift 6.3.1 toolchain reports
`Build config: +assertions`, so the shipped standard library carries internal
assertions the Go and Rust toolchains do not, and `-c release` disables
assertions in *this* code, not in the stdlib it links against — some unknown
share of the 2–3.5× gap is toolchain rather than port. The Windows column is
also a declared proxy for the production target: the encoder and allocation
characteristics are relative and expected to transfer to iOS, the BCrypt seam
does not exist on Apple platforms — there swift-crypto is `@_exported import
CryptoKit` and hashing is already hardware-backed — and absolute iOS numbers
are not measured here.

### JSON is byte-identical too

Rust builds one wire tree per DAG and hands it to either the CBOR writer or the
canonical JSON writer, so the formats cannot drift in field names or shape.
The historical Swift implementation shipped no `Codable` conformances on its wire
types; that is retained here only as comparison evidence.

#### The two formats sort map keys by different rules

One wire tree feeding both writers keeps key *names* aligned between formats —
but the writers must not share a map-key comparator, because both rules are
correct and they are different:

| | Rule | `zz-probe` vs `aaa-probe` |
|---|---|---|
| CBOR | RFC 8949 core-deterministic — length first, then bytewise | `zz-probe`, `aaa-probe` |
| JSON | canonical Rust rule — plain bytewise, no length term (historically matched `encoding/json`) | `aaa-probe`, `zz-probe` |

Both writers sort under an explicit `KeyOrder`, applied only at the five
genuinely dynamic maps. Struct-shaped maps stay in declaration order for both
formats, as they must.

The overlap between the two rules is easy to underestimate. They **agree on
every pair of equal-length keys**, and four of the five dynamic maps are keyed
by CIDs — `b` plus base32 of exactly 36 bytes, so exactly 59 characters,
always. Only `AdditionalData` takes arbitrary caller strings, so a corpus in
which that map never holds two keys of differing length cannot tell the two
comparators apart — and matching `json_bytes` is no evidence either, because
reordering a map's keys preserves byte length exactly.

The shared spec-vector corpus is built so that blind spot cannot exist. It
commits a `.json` sibling for every `.cbor` artifact and carries a
`json_metadata_probe` case whose root leaf holds three `AdditionalData` keys of
lengths 1, 8 and 9 — chosen so the two comparators produce completely reversed
orders. All three ports assert, per artifact, that re-encoding reproduces the
committed JSON bytes *and* that the value decoded from JSON re-encodes to the
committed CBOR bytes. The generator refuses to emit a corpus in which the two
orderings agree, and swapping either port's JSON comparator for the CBOR rule
fails the corpus on `json_metadata_probe` — the probe cannot quietly lose its
teeth.

### Historical Rust/Go measurement notes

The recorded Rust result trailed the historical Go result on two rows. `to_cbor` is covered above. `create_sequential` is
the substantive one, and the cause is allocation count rather than anything
algorithmic: it allocates one retained buffer per chunk, and the gap tracks that
count rather than the byte total. Same corpus, same bytes, same hashing — only
the chunk size changes:

| Chunk size | Rust | Go | Swift | Rust vs Go |
|---|---:|---:|---:|---|
| 256 KiB | 18.66 ms | 15.80 ms | 53.48 ms | 1.18× slower |
| 1 MiB | 17.46 ms | 17.53 ms | 60.01 ms | parity |
| 2 MiB (fastcdc target / fixed-mode default) | 17.02 ms | 18.11 ms | 63.24 ms | **1.06× faster** |

So at 2 MiB — the fixed-mode default and the fastcdc-v1 target — Rust is
slightly ahead, and the deficit only appears when a caller chooses small
chunks. Swift's cost rises mildly with
chunk size (53 → 63 ms) — per-byte buffer work in its builder rather than the
per-chunk allocation this table isolates. `create_parallel`, the path
most callers use, is 1.34–1.43× *faster* than Go at every size in the same
sweep, and builds an identical DAG.

## Versioning

`v2.4.3` is the current Rust format/library version. Future versions follow Rust
release decisions and SemVer; they do not wait for, mirror, or claim conformance to
a Go release.

The earlier `v2.4.1` and `v2.4.3` numbering records the historical point at which
the independent byte corpus was adopted. It does not transfer authority over the
Rust format or release history.

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

The Rust tests cover layers 1–5, committed historical wire vectors, and the local
spec-vector corpus under `spec/vectors`, which pins both `.cbor` and `.json`
encodings for every artifact. The fastcdc-v1 corpus under
`spec/fastcdc-vectors` pins 11 cases covering boundary offsets, chunk digests,
edit-reuse partitions, rebuilt DAG roots, and the root `chunking` tag.

`tools/gobench`, `tools/gowirevectors`, and `tools/swiftbench` are optional
historical comparison harnesses. They are not needed to build, test, version, or
release the crate. When their adjacent historical repositories are available, they
can read the Rust-generated corpus for independent byte and benchmark comparison;
only the Rust harness generates the authoritative corpus. Same-session timing is
required for any meaningful historical comparison:

```bash
cargo run --release --example bench -- bench-corpus 262144 15
(cd tools/gobench   && go run . ../../bench-corpus 262144 15)
(cd tools/swiftbench && swift run -c release swiftbench ../../bench-corpus 262144 15)
```

Each prints its DAG root and encoded sizes first. Compare those before comparing
any timing: a port that looks fast because it built a smaller DAG is the failure
mode that ordering guards against.

## Related repositories

| Repository | Role |
|---|---|
| [Scionic-Merkle-Tree](https://github.com/HORNET-Storage/Scionic-Merkle-Tree) | Historical Go implementation and vector provenance |
| [Scionic-MerkleTree-Swift](https://github.com/HORNET-Storage/Scionic-MerkleTree-Swift) | Historical Swift implementation and comparison evidence |

## License

MIT
