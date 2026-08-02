# Cross-Language Parity: Go, Swift, Rust

Three implementations of the Scionic Merkle Tree exist at `v2.4.1`: the
[Go reference](https://github.com/HORNET-Storage/Scionic-Merkle-Tree), the
[Swift port](https://github.com/HORNET-Storage/Scionic-MerkleTree-Swift), and this
Rust crate. They agree on every hashed byte and on every serialized byte.

This document is the contract that makes that true, and the evidence that it holds.

---

## 1. Two contracts, deliberately separate

The most important structural fact about this format is that **hashing and
serialization are different contracts**, and conflating them is the one mistake
that cannot be undone.

| | CID preimage | Wire envelope |
|---|---|---|
| Produced by | leaf identity encoding | `ToCBOR` / `ToJSON` |
| Determines | the CID — permanent identity | bytes on the network and on disk |
| Map ordering | none: maps are flattened to sorted arrays *before* hashing | keys sorted, by a comparator that depends on the output format (§2.2) |
| Field ordering | declaration order | declaration order |
| Changing it | rewrites every CID ever minted | changes the wire format for deployed peers |

`AdditionalData` is flattened into a sorted array of key/value structs before it
reaches the hash, so **no map iteration order can ever reach a CID**. That is why
the wire-ordering rules below are free to exist: they operate strictly above the
layer where identity is decided.

There are therefore **three** comparators in this system, and no two of them may
ever be unified:

| Comparator | Applies to | Rule |
|---|---|---|
| CID preimage | a sorted *array*, before hashing | plain lexicographic over the decoded string |
| CBOR wire map | the five maps in §2.2 | length-first, then bytewise over encoded UTF-8 |
| JSON wire map | the same five maps | plain bytewise over encoded UTF-8, no length term |

All three agree on uniform-length keys — which is exactly how two of them drifted
apart without any test noticing. The preimage comparator is frozen into every CID
ever minted; the other two are frozen into deployed peers.

---

## 2. The wire envelope

Three rules define the serialized form. All three ports implement all three.

### 2.1 Struct fields ride in declaration order

Every serialized type emits its fields in declaration order. This is the shape
deployed peers produce and expect, and it is pinned against golden bytes captured
from a real deployed build.

| Type | Key order |
|---|---|
| `SerializableDag` | `Root`, `Leafs` |
| `SerializableDagLeaf` | `Hash`, `ItemName`, `Type`, `ContentHash`, `Content`, `ClassicMerkleRoot`, `CurrentLinkCount`, `LeafCount`, `ContentSize`, `DagSize`, `Links`, `AdditionalData`, then `stored_proofs` when present |
| `SerializableTransmissionPacket` | `Leaf`, `ParentHash`, then `proofs` when present |
| `SerializableBatchedTransmissionPacket` | `Leaves`, `Relationships`, `PacketIndex`, `TotalPackets` |

### 2.2 Exactly five maps are key-ordered

A map has no inherent order, so each port imposes one. These five fields, and
nothing else, are sorted:

| Map | Lives on |
|---|---|
| `Leafs` | `SerializableDag` |
| `AdditionalData`, `stored_proofs` | `SerializableDagLeaf` |
| `proofs` | `SerializableTransmissionPacket` |
| `Relationships` | `SerializableBatchedTransmissionPacket` |

**The comparator depends on the output format, and the two do not agree.**

*CBOR* sorts **length-first, then bytewise** over the UTF-8 key — RFC 8949's rule
for text keys. For text keys this reduces exactly to sorting by encoded bytes,
because the encoded head grows monotonically with length (`0x60+len` below 24,
`0x78` for 24–255, `0x79` for 256–65535).

*JSON* sorts **plain bytewise, with no length term**. Go reaches JSON through
`encoding/json`, which sorts map keys with a straight string compare, and Go is
the reference — so every port must reproduce that rule and not the CBOR one. The
two agree on every pair of equal-length keys and disagree otherwise:

```text
keys: zz-probe (8), aaa-probe (9)
CBOR: zz-probe, aaa-probe
JSON: aaa-probe, zz-probe
```

Section 2.1 is unaffected by the format: struct fields ride in declaration order
in both. Only these five maps re-sort, and only they switch comparator.

Each language expresses the same scoping differently. Go declares those fields as
a `sortedMap[T]` type that sorts inside its own `MarshalCBOR`; Swift and Rust
cannot distinguish a struct from a map at the CBOR layer — both are just maps — so
they apply `CBOREncoder.sortedWireMap` / `sorted_wire_map`, each taking an
explicit key-order argument, at exactly those five call sites and nowhere else.

### 2.3 Empty proof maps are omitted, not emitted empty

`stored_proofs` and `proofs` are dropped entirely when empty, and present when the
leaf or packet genuinely carries proofs. A full DAG therefore contains no
`stored_proofs` key at all, while transmission packets do.

### 2.4 The axis the corpus could not see, and now can

For four releases, every map key the shared corpus exercised was a CID of uniform
length — always exactly 59 characters, because a CID is `b` plus base32 of exactly
36 bytes — and on uniform-length keys length-first and plain-bytewise ordering
**coincide**. `AdditionalData` is the only wire map with arbitrary, mixed-length
keys, and it was empty in every corpus case. So the corpus could not distinguish
the two comparators, and the ports were free to drift onto different ones while
staying green. Matching output sizes were not evidence either: reordering keys
preserves byte length exactly.

That is not hypothetical. The Rust port emitted the CBOR comparator into JSON, and
the Swift port emitted a different set of key *names* altogether through
`Codable`. Both stayed green throughout, because nothing in any of the three
repositories ever compared a JSON byte across ports.

The axis is now pinned three ways:

| Guard | Lives in | Pins |
|---|---|---|
| 20-byte CBOR ordering vector | `dag/sortedmap_test.go`, `src/encoding.rs`, `WireMapOrderingTests.swift` | the CBOR comparator alone |
| Both comparators, side by side | `src/encoding.rs`, `WireMapOrderingTests.swift` | that the two rules produce *different* orders |
| `json_metadata_probe` corpus case | `spec/vectors`, asserted by all three ports | both comparators, end to end, against committed Go bytes |

The 20-byte vector:

```text
a3626d6d6132627a7a6131666161616161616133
keys mm, zz, aaaaaa — length-first, then bytewise
plain bytewise would emit aaaaaa, mm, zz
```

The corpus case carries three `AdditionalData` keys of lengths 1, 8 and 9 — `m`,
`zz-probe`, `aaa-probe` — chosen so the two rules produce *completely reversed*
orders, so that no subset of them can come out right by luck:

```text
CBOR: m, zz-probe, aaa-probe
JSON: aaa-probe, m, zz-probe
```

Every `.cbor` artifact in the corpus now has a `.json` sibling, and each port
asserts per artifact that re-encoding reproduces the committed JSON bytes *and*
that the value decoded from JSON re-encodes to the committed CBOR bytes. The
generator refuses to emit a corpus in which the two orderings agree, so the probe
cannot silently stop testing anything.

---

## 3. Clone and ownership semantics

Copies are everywhere — every transmission packet, every batch, every store read
clones a leaf — and a leaf's CID commits to `sha256(content)`. Handing out a copy
through which the original can be modified would not merely produce wrong data; it
would silently invalidate identity, surfacing later as a verification failure
somewhere else entirely.

The three languages reach the same guarantee by different means:

| | Go | Swift | Rust |
|---|---|---|---|
| Leaf type | `*DagLeaf` (pointer) | `DagLeaf` (class) | `DagLeaf` (value) |
| Clone cost | free | free (COW) | free (refcount) |
| Payload safety | shared by design, documented | independent | independent |
| Hash-field safety | deep-copied | independent | independent |
| Proof safety | deep-copied | independent (struct) | independent |
| Enforced by | documentation + test | value types | type system |

- **Swift** gets both properties for free: `Data`, `[String]`, `[String: String]`
  and `ClassicTreeBranch` are value types, so a copy is independent *and* copies
  no bytes until written.
- **Rust** reaches the same position through `Arc<Vec<u8>>`: free *and* safe, with
  immutability enforced rather than documented, because `Arc` hands out no `&mut`
  while a second owner exists.
- **Go** has no copy-on-write, so a cheap clone must alias. Sharing `Content` is a
  deliberate performance trade — deep-copying it would cost roughly 1.8 ms on
  `batched_sequence` against the ~6 µs the small hash fields cost. The contract is
  written into the doc comment (*reassign `Content`, never write through it*) and
  pinned by a test that fails if someone makes it independent without updating the
  reasoning.

**Store boundaries carry the same contract.** A store shares no leaf with its
caller in either direction, because the library writes through retrieved leaves on
purpose. Go and Swift clone at both ends and state the contract on the store
interface; Rust gets it from ownership — `store_leaf` takes the leaf by value and
`retrieve_leaf` returns an owned clone, so no reference into the store can outlive
the lock.

---

## 4. Standing invariants

Behavioural rules all three ports obey. Each exists because the alternative is
silently wrong rather than loudly wrong.

| Invariant | Why |
|---|---|
| A shared leaf resolves to the **lowest** parent CID | A content-identical chunk can hang under several parents. Resolving in map order makes proofs depend on hash-map iteration order, so the same DAG yields different proofs on different runs. Every path derives it through one function. |
| Links sort lexicographically **only for directory leaves** | File chunk order is reassembly order and must be preserved. |
| Chunk reassembly orders by **numeric** `ItemName` | Lexical order puts chunk 10 before chunk 2. Legacy path-prefixed names (`file/0`, `file\0`) are accepted with either separator regardless of host, so a Windows-authored DAG reads correctly on Unix. |
| Chunk names are bare indices, never joined paths | The chunk `ItemName` is hashed, so joining a platform path separator into it makes every chunked-file CID depend on the OS that built the DAG. |
| `nil` and empty are distinct | The distinction is hash-visible: a nil `ClassicMerkleRoot` serializes as CBOR `0xf6`, a zero-length one as `0x40`. |
| `ParentHash` is context, never evidence | It is not hashed and not serialized, so a peer can claim anything. Verification checks links and Merkle proofs instead. |
| A separate content store actually separates | The payload belongs in exactly one place; writing it to both stores doubles the footprint and defeats the reason the second store exists. |

---

## 5. Test suites

| Port | Suite | Result | Static analysis |
|---|---|---|---|
| Go | `go test -count=1 ./...` | 128 tests across 4 packages | `go vet ./...` clean |
| Swift | `swift test` | 280 tests, **0 skips** | — |
| Rust | `cargo test` | 119 tests | `cargo clippy --all-targets -- -D warnings` clean |

### 5.1 Shared guards

Each port carries the same guard set, so no single implementation is the only one
watching a given contract:

| Guard | Pins |
|---|---|
| Spec-vector corpus, CBOR | Re-encoding the committed corpus reproduces it **byte for byte** — full DAGs, partials, transmission packets and batched packets alike |
| Spec-vector corpus, JSON | The same, for the `.json` sibling of every artifact — plus that a value decoded from JSON re-encodes to the committed *CBOR* bytes, which is what makes the two decoders provably equivalent rather than merely both self-consistent |
| Negative vectors | Deliberately broken DAGs are rejected in **both** encodings, so a lenient JSON path cannot shelter behind a strict CBOR one |
| Wire shape | Struct fields in declaration order; re-encoding is byte-stable across 200 encodes; empty proof maps omitted but present on the transmission path |
| Wire map ordering | The 20-byte length-first vector from §2.4, and the two comparators asserted against each other |
| Mixed-length map keys | The `json_metadata_probe` corpus case from §2.4 — the only vector able to tell the two comparators apart |
| Batch splitting | At least one corpus case splits across multiple batches, so the splitting path cannot go untested while looking tested |

The corpus is generated by the Go repository's `tools/specvectors` and committed
into all three repositories. A missing corpus fails loudly in each; it never
skips. Regeneration is bit-for-bit reproducible, and the three committed copies
are identical — 226 files each, compared by digesting every relative path and its
contents in sorted order.

### 5.2 Guards are mutation-tested

A test that passes both with and without the behaviour it guards proves nothing.
Every guard above was run against the inverted behaviour and required to fail
**for its own stated reason** — and to stay silent for everything else, so the
suite discriminates rather than alarming on any change:

| Inverted behaviour | Fails |
|---|---|
| Two leaf fields swapped | The declaration-order guard in all three ports, naming the offending key; every committed-byte comparison |
| `stored_proofs` emitted unconditionally | The omitempty guard in all three ports, and nothing else |
| Plain-lexicographic map keys | The 20-byte ordering vector in all three ports |
| CBOR's length-first comparator used to write JSON | The JSON corpus assertion, in Rust and in Swift — and **only** on `json_metadata_probe`; all six fixture cases still pass, which is §2.4's blind spot demonstrating itself |

That last row is worth reading twice: it is the mutation test that would have
caught the original bug, run against the corpus that exists precisely because it
did not.

---

## 6. Byte-parity evidence

| Evidence | Result |
|---|---|
| Go, Swift and Rust DAG root on the same corpus | identical — `bafireifuqx7auvelcittqzbmrvto5m66xp4zj5yddrup3ueo6edlrqrmxi`, 141 leaves |
| CBOR encoding size | identical across all three — `19188357` bytes, and again at 1 MiB and 2 MiB chunks |
| JSON encoding size | identical across all three — `25591601` bytes |
| CBOR comparison method | byte-for-byte — each port re-encodes the committed corpus to identical bytes |
| JSON comparison method | byte-for-byte, both directions — JSON→JSON and JSON→CBOR |
| Committed corpus, three repositories | identical — 226 files each, digested path-and-contents in sorted order |
| Deployed wire shape | unchanged — pinned against golden bytes from a deployed build |

The two size rows are the weakest lines in that table and are there for
orientation only: reordering a map preserves byte length, so equal sizes cannot
distinguish a correct encoder from one using the wrong comparator. The
byte-for-byte rows are what carry the claim.

---

## 7. Performance

Same corpus, same chunk size, all three harnesses run back to back in one session.
Rust is faster on four workloads, at parity on three, and slower on two. The full
table, method, and the two remaining gaps are in [`README.md`](README.md).

Only same-session ratios are meaningful: the machine drifts by roughly the
run-to-run variance (±5%) between sessions.
