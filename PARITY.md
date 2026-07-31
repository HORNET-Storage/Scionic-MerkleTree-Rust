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
| Map ordering | none: maps are flattened to sorted arrays *before* hashing | keys sorted, length-first then bytewise |
| Field ordering | declaration order | declaration order |
| Changing it | rewrites every CID ever minted | changes the wire format for deployed peers |

`AdditionalData` is flattened into a sorted array of key/value structs before it
reaches the hash, so **no map iteration order can ever reach a CID**. That is why
the wire-ordering rules below are free to exist: they operate strictly above the
layer where identity is decided.

The comparator used inside the preimage (plain lexicographic over the decoded
string, applied to an array) and the comparator used for wire map keys
(length-first over encoded UTF-8, applied to a map) are **not the same** and must
not be unified. They agree only on uniform-length keys.

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

Ordering is **length-first, then bytewise** over the UTF-8 key — RFC 8949's rule
for text keys. For text keys this reduces exactly to sorting by encoded bytes,
because the encoded head grows monotonically with length (`0x60+len` below 24,
`0x78` for 24–255, `0x79` for 256–65535).

Each language expresses the same scoping differently. Go declares those fields as
a `sortedMap[T]` type that sorts inside its own `MarshalCBOR`; Swift and Rust
cannot distinguish a struct from a map at the CBOR layer — both are just maps — so
they apply `CBOREncoder.sortedCBORMap` / `sorted_cbor_map` at exactly those five
call sites and nowhere else.

### 2.3 Empty proof maps are omitted, not emitted empty

`stored_proofs` and `proofs` are dropped entirely when empty, and present when the
leaf or packet genuinely carries proofs. A full DAG therefore contains no
`stored_proofs` key at all, while transmission packets do.

### 2.4 The axis the corpus cannot see

Every map key the shared corpus exercises is a CID of uniform length, where
length-first and plain-lexicographic ordering **coincide**. `AdditionalData` is
the only wire map with arbitrary, mixed-length keys, and it is empty in every
corpus case — so the corpus alone cannot distinguish the two comparators, and the
ports could drift onto different ones while staying green.

That axis is pinned separately by one 20-byte vector asserted identically in all
three ports (`dag/sortedmap_test.go`, `src/encoding.rs`, `WireMapOrderingTests.swift`):

```text
a3626d6d6132627a7a6131666161616161616133
keys mm, zz, aaaaaa — length-first, then bytewise
plain lexicographic would emit aaaaaa, mm, zz
```

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
| Go | `go test -count=1 ./...` | 124 tests across 4 packages | `go vet ./...` clean |
| Swift | `swift test` | 269 tests, **0 skips** | — |
| Rust | `cargo test` | 114 tests | `cargo clippy --all-targets -- -D warnings` clean |

### 5.1 Shared guards

Each port carries the same guard set, so no single implementation is the only one
watching a given contract:

| Guard | Pins |
|---|---|
| Spec-vector corpus | Re-encoding the committed corpus reproduces it **byte for byte** — full DAGs, transmission packets and batched packets alike |
| Wire shape | Struct fields in declaration order; re-encoding is byte-stable across 200 encodes; empty proof maps omitted but present on the transmission path |
| Wire map ordering | The 20-byte length-first vector from §2.4 |
| Batch splitting | At least one corpus case splits across multiple batches, so the splitting path cannot go untested while looking tested |

The corpus is generated by the Go repository's `tools/specvectors` and committed
into all three repositories. A missing corpus fails loudly in each; it never
skips.

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

---

## 6. Byte-parity evidence

| Evidence | Result |
|---|---|
| Go and Rust DAG root on the same corpus | identical — `bafireifuqx7auvelcittqzbmrvto5m66xp4zj5yddrup3ueo6edlrqrmxi`, 141 leaves |
| CBOR encoding size | identical — `19188357` bytes |
| JSON encoding size | identical — `25591601` bytes |
| CBOR comparison method | byte-for-byte across all three ports — each re-encodes the committed corpus to identical bytes |
| JSON comparison method | byte-for-byte |
| Deployed wire shape | unchanged — pinned against golden bytes from a deployed build |

---

## 7. Performance

Same corpus, same chunk size, both harnesses run back to back in one session.
Rust is faster on six workloads, at parity on one, and slower on two. The full
table, method, and the two remaining gaps are in [`README.md`](README.md).

Only same-session ratios are meaningful: the machine drifts by roughly the
run-to-run variance (±5%) between sessions.
