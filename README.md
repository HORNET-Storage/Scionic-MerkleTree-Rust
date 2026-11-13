# Scionic Merkle trees, in Rust

A Scionic Merkle tree holds a folder of files, or one file, under one root hash.

- **Identical things are stored once.** A piece of a file is hashed by its bytes alone, a file is the list of its pieces, and a folder is the list of its names. So the same piece, file or folder has the same hash in every tree, and a store keeps it once.
- **Any part can be shown without the rest,** and checked against the root: one name of a folder, a run of its entries, one piece of a file, or a stretch of a file's bytes.
- **Syncing is by file hash and piece number.** A receiver walks down from a root it trusts, asks for what it lacks, and skips what it holds. Nothing is compared between the two sides.
- **Nothing is trusted on arrival.** Every answer is checked against a hash that is already checked, and nothing is kept before it is tied to the root.

`spec/FORMAT.md` says exactly what every hash covers, what a receiver checks, and the bytes of every request and answer. This crate is the reference for it. The Go and Swift libraries are kept in step with this crate, and the three are held to each other by the vectors under `spec/`.

## What is in it

| Module | What it does |
| --- | --- |
| `format` | The bytes of a piece, a file, a folder, an entry and the record, and the runs that show a part of a list. Reading is strict. |
| `tree` | The tree of a list: its forks, showing a run of a list, and checking one. |
| `fastcdc` | Cutting a file into pieces by its content (`fastcdc-v1`), in memory and as a stream. |
| `build` | Building a tree from a folder on disk or from bytes: a piece at a time, several files at once. |
| `intake` | The one set of checks for a tree that comes from a peer, comes in a bundle, or sits in a store. |
| `read` | Finding a path, reading a file or a stretch of one, and writing a tree out to disk. |
| `diff` | What changed between two trees. |
| `wire` | The requests, and the frames that answer them. |
| `sync` | Answering requests from a store, fetching a whole tree, reading parts of one straight from a peer, bundles, and all of it over a connection. |
| `store` | What a store has to do, and a store in memory. |

It depends on `sha2`, and on Unix on `rustix`, which opens a file from the folder it is in. The crate forbids `unsafe`.

## Using it

A store keeps bytes by their hash. `MemoryStore` is one for tests and small trees. A database implements the `Store` trait.

```rust
use scionic_merkletree::{build, verify, write_to_disk, BuildOptions, MemoryStore};

let store = MemoryStore::new();

// Build a tree from a folder. The root is the same wherever the folder is,
// and whatever it is called.
let root = build(&store, "models/my-model", &BuildOptions::new())?;
println!("{root}"); // bafkrei...

// Check everything the store holds of it: every list and every piece.
let summary = verify(&store, &root)?;
println!("{} bytes", summary.record.top().size);

// Write it out again, to a place that does not exist yet.
write_to_disk(&store, &root, "restored")?;
```

Building and checking use every processor core unless they are told otherwise: `BuildOptions::workers`, `Builder::threads` and `VerifyOptions::workers` say how many. Several files are cut at once, and the pieces of one long file are hashed several at once. A file is never held in memory whole. A builder holds up to 16 MiB of it, or up to 64 MiB while other threads help it.

When bytes were harmed in the store, `verify` says which thing it is: `Error::Corrupt` carries its hash. It changes nothing. With `VerifyOptions::new().discard_damaged(true)` it removes what is damaged, and a `fetch` then brings those parts again. A `fetch` on its own replaces a damaged list or record, because it cannot go on with one.

Syncing runs over anything that reads and writes bytes. One side serves, and the other asks.

```rust
use scionic_merkletree::{fetch, serve, Remote, StreamPeer};

// The side that holds the tree answers requests until the connection ends.
serve(&store, &mut from_peer, &mut to_peer)?;

// The other side fetches the whole tree. What it holds already is skipped,
// and a fetch that stops goes on from what the store holds.
let mut peer = StreamPeer::new(from_peer, to_peer);
fetch(&store, &root, &mut peer)?;

// Or it reads a part and keeps nothing: one file's entry, then 4,096 bytes
// from the middle of that file. Only the pieces that hold them are sent.
let mut remote = Remote::open(&mut peer, &root)?;
if let Some(entry) = remote.lookup("weights/model.safetensors")? {
    remote.read(&entry.target(), 1 << 30, 4096, &mut out)?;
}
```

`export` and `import` carry a whole tree as one stream, for a file or a pipe. `diff` lists what changed between two trees. `Intake` is the piece under all of them, for a caller that brings its own transport: give it frames, and it says what to ask for next.

`examples/roundtrip.rs` takes a folder the whole way round with a store on disk: it builds the tree, checks it, fetches it into a second store, reads a stretch from the middle of its largest file, writes it out again, and holds the copy to the same root. It prints how long each step took. Its store keeps each thing as a file named by its hash, and shows what a store has to do.

```sh
cargo run --release --example roundtrip -- <folder> <work-dir>
```

`examples/speed.rs` measures cutting, hashing, building and checking on one file held in memory, so that no disk is in the way:

```sh
cargo run --release --example speed -- <MiB>
```

## What it guards against

The tests under `tests/` hold the library to these, with forged bytes made by a second copy of the format's rules (`tests/support/oracle.rs`):

- A made-up child under a folder or a file, a real child's proof with another child, a file taken for a folder, a list taken for a piece, and a file given another file's pieces are all refused.
- A file never comes back short. If a piece is missing, reading is an error.
- A folder cannot show one name at two places, even if it was put together out of order on purpose.
- A frame that nothing names is refused and not kept. A list that is named and then fails a check is not kept either, and that intake takes nothing more.
- A peer cannot make a receiver set aside more memory than the tree it trusts calls for: every request says how long its answer may be.
- A tree's record says how much the tree holds, and taking it in stops as soon as it holds more.
- A small tree that stands for an endless one, by holding one folder under many names, is counted before it is written out, and refused.
- Bytes that were harmed in a store are found when the tree is checked, and named by their hash. They can be removed and fetched again.
- Nothing a peer sends makes a store remove bytes that are sound. A list that names a held piece with a wrong length is refused, and the piece stays.
- A link is never followed when a tree is built. That holds for a link that is in the folder, and for one that takes a file's or a folder's place while the folder is being read: each folder is held open while it is read, and what is in it is opened from the folder itself, never by a path that is looked up again.
- A tree is written only to a new place, and only with names the system can hold as they are. The new folders are held open while they are filled, so a link that takes the place of one is not written through.
- Malformed input is an error, and never a crash or a loop.

## What it does not do well yet

- One file is cut on one processor core, because where a piece ends decides where the next begins. On the desktop it was measured on, that is about 5 GB a second. Hashing the pieces, which is the greater part of the work, uses every core.
- Fetching a tree and writing a tree out use one core each. On the disks they were tried on, the disk was the slower part.
- Checking or fetching a whole tree keeps about a hundred bytes in memory for every different piece, so that each piece is counted once: about 50 MB for a terabyte.
- A list is taken in whole. A file's list is about 19 MB for each terabyte of the file, and a folder's list has to fit in memory.
- A responder that tells a peer which pieces of a file it holds looks into its store for each of them. `Responder::have(false)` switches that off for one that serves strangers.
- A tree is built from a folder as the folder is while it is read. If another program changes files in it meanwhile, the tree can hold a mix of old and new. It cannot be led outside the folder.
- Opening every file from its folder costs a little for each file on Windows: a folder of 20,000 small files took 0.19 seconds to build where it had taken 0.15. While a folder is being read there, other programs cannot rename or delete it. On systems that are neither Unix nor Windows, a folder is not held open, and a link that is swapped in while a folder is read can be followed.

## Checking a change

```sh
cargo fmt --check
cargo clippy --all-targets --locked --offline -- -D warnings
cargo test --locked --offline
```

`AGENTS.md` holds the rules for contributors.
