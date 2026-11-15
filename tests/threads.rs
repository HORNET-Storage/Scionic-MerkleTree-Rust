//! Several threads build, take in and check what one thread builds, takes in
//! and checks.

mod support;

use scionic_merkletree::{
    build, export, fetch, import, verify_with, Builder, ChunkRef, Chunking, Error, ExtraData, Hash,
    Intake, MemoryStore, Result, Root, Store, Stored, VerifyOptions, BUNDLE_MAGIC, FRAME_CHUNK,
};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use support::{
    bytes, contents, sample_folder, small_chunks, small_options, write, TempDir, TestPeer,
};

#[test]
fn one_file_is_the_same_whatever_number_of_threads_keep_its_chunks() {
    // 6,250 chunks of 16 bytes: more than a builder hands on at a time.
    let data = bytes("threads-one-file", 100_000);
    let mut roots = Vec::new();
    let mut stores = Vec::new();
    for threads in [1, 2, 8, 0] {
        let store = MemoryStore::new();
        let mut builder = Builder::new(&store, small_chunks()).threads(threads);
        let streamed = builder.file(&mut data.as_slice()).unwrap();
        let in_place = builder.file_from_bytes(&data).unwrap();
        assert_eq!(streamed, in_place, "{threads} threads");
        roots.push(builder.finish(streamed, ExtraData::new()).unwrap());
        stores.push(contents(&store));
    }
    assert!(roots.windows(2).all(|pair| pair[0] == pair[1]));
    assert!(stores.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn a_file_chunked_by_content_is_the_same_with_help() {
    let data = bytes("threads-by-content", 9 << 20);
    let mut roots = Vec::new();
    for threads in [1, 4] {
        let store = MemoryStore::new();
        let mut builder = Builder::new(&store, Chunking::FastCdcV1).threads(threads);
        let streamed = builder.file(&mut data.as_slice()).unwrap();
        assert_eq!(streamed, builder.file_from_bytes(&data).unwrap());
        assert!(store.count(Stored::Chunk) > 2, "several chunks");
        let root = builder.finish(streamed, ExtraData::new()).unwrap();
        for workers in [1, 4] {
            let options = VerifyOptions::new().workers(workers).rechunk(true);
            verify_with(&store, &root, options).unwrap();
        }
        roots.push(root);
    }
    assert_eq!(roots[0], roots[1]);
}

#[test]
fn a_folder_is_the_same_when_threads_outnumber_its_files() {
    let temp = TempDir::new("threads-folder").unwrap();
    let folder = sample_folder(temp.path(), "tree").unwrap();
    let mut roots = Vec::new();
    let mut stores = Vec::new();
    for workers in [1, 2, 64] {
        let store = MemoryStore::new();
        let root = build(&store, &folder, &small_options().workers(workers)).unwrap();
        verify_with(&store, &root, VerifyOptions::new().workers(workers)).unwrap();
        roots.push(root);
        stores.push(contents(&store));
    }
    assert!(roots.windows(2).all(|pair| pair[0] == pair[1]));
    assert!(stores.windows(2).all(|pair| pair[0] == pair[1]));
}

/// A store that will not keep one chunk.
struct Refusing {
    inner: MemoryStore,
    refused: Hash,
}

impl Store for Refusing {
    fn put(&self, kind: Stored, hash: &Hash, bytes: &[u8]) -> Result<()> {
        if kind == Stored::Chunk && *hash == self.refused {
            return Err(Error::Invariant {
                detail: "this store will not keep that chunk",
            });
        }
        self.inner.put(kind, hash, bytes)
    }

    fn get(&self, kind: Stored, hash: &Hash) -> Result<Option<Arc<[u8]>>> {
        self.inner.get(kind, hash)
    }

    fn remove(&self, kind: Stored, hash: &Hash) -> Result<()> {
        self.inner.remove(kind, hash)
    }
}

#[test]
fn a_chunk_that_cannot_be_kept_stops_the_file_whoever_was_keeping_it() {
    let data = bytes("threads-refused", 100_000);
    let refused = ChunkRef::of(&data[64_000..64_016]).unwrap().hash;
    for threads in [1, 8] {
        let store = Refusing {
            inner: MemoryStore::new(),
            refused,
        };
        let mut builder = Builder::new(&store, small_chunks()).threads(threads);
        for attempt in [
            builder.file(&mut data.as_slice()),
            builder.file_from_bytes(&data),
        ] {
            assert!(
                matches!(attempt, Err(Error::Invariant { .. })),
                "{threads} threads: {attempt:?}"
            );
        }
        // A file whose chunks are not all kept has no list.
        assert_eq!(store.inner.count(Stored::FileList), 0);
    }
}

#[test]
fn the_failure_that_is_told_is_the_one_that_happened() {
    // A folder of many files, one of which holds a chunk the store refuses.
    // The threads that stop because of it have nothing of their own to tell.
    let temp = TempDir::new("threads-failure").unwrap();
    let folder = temp.path().join("tree");
    for number in 0..64 {
        let data = bytes(&format!("failure-{number}"), 64);
        write(folder.join(format!("file-{number:02}")), &data).unwrap();
    }
    let refused = ChunkRef::of(&bytes("failure-40", 64)[..16]).unwrap().hash;
    for workers in [1, 2, 8] {
        let store = Refusing {
            inner: MemoryStore::new(),
            refused,
        };
        match build(&store, &folder, &small_options().workers(workers)) {
            Err(Error::Invariant { detail }) => {
                assert_eq!(detail, "this store will not keep that chunk");
            }
            other => panic!("{workers} workers: {other:?}"),
        }
    }
}

/// A store that falls over whenever it is handed a chunk, as one would whose
/// own code has a fault.
struct Falling(MemoryStore);

impl Store for Falling {
    fn put(&self, kind: Stored, hash: &Hash, bytes: &[u8]) -> Result<()> {
        assert!(kind != Stored::Chunk, "this store falls over");
        self.0.put(kind, hash, bytes)
    }

    fn get(&self, kind: Stored, hash: &Hash) -> Result<Option<Arc<[u8]>>> {
        self.0.get(kind, hash)
    }

    fn remove(&self, kind: Stored, hash: &Hash) -> Result<()> {
        self.0.remove(kind, hash)
    }
}

#[test]
fn a_store_that_falls_over_does_not_leave_a_build_waiting() {
    // More files than the threads take at once: if every thread that chunks
    // is gone, the one that reads the folder must not wait for them.
    let temp = TempDir::new("threads-falling").unwrap();
    let folder = temp.path().join("tree");
    for number in 0..400 {
        let data = bytes(&format!("falling-{number}"), 16);
        write(
            folder.join(format!("dir-{}/file-{number:03}", number % 40)),
            &data,
        )
        .unwrap();
    }
    for workers in [1, 2, 8] {
        let folder = folder.clone();
        let (tell, hear) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let store = Falling(MemoryStore::new());
            let options = small_options().workers(workers);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                build(&store, &folder, &options).map(|_| ())
            }));
            let _ = tell.send(outcome.is_err());
        });
        // The build ends, and it ends as the store did: by falling over.
        match hear.recv_timeout(std::time::Duration::from_secs(20)) {
            Ok(fell) => assert!(fell, "{workers} workers"),
            Err(_) => panic!("with {workers} workers the build was left waiting"),
        }
    }
}

/// A tree of one file chunked by content, long enough that its chunks are
/// taken in by several threads at once, and the frames of its bundle.
fn long_tree(seed: &str) -> (MemoryStore, Root, Vec<Vec<u8>>) {
    let store = MemoryStore::new();
    let mut builder = Builder::new(&store, Chunking::FastCdcV1);
    let top = builder.file_from_bytes(&bytes(seed, 12 << 20)).unwrap();
    let root = builder.finish(top, ExtraData::new()).unwrap();
    let mut bundle = Vec::new();
    export(&store, &root, &mut bundle).unwrap();
    let mut frames = Vec::new();
    let mut rest = &bundle[BUNDLE_MAGIC.len()..];
    while let Some((length, after)) = rest.split_first_chunk::<4>() {
        let (frame, after) = after.split_at(u32::from_be_bytes(*length) as usize);
        frames.push(frame.to_vec());
        rest = after;
    }
    (store, root, frames)
}

/// A bundle that holds these frames.
fn bundle_of(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut bundle = BUNDLE_MAGIC.to_vec();
    for frame in frames {
        bundle.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        bundle.extend_from_slice(frame);
    }
    bundle
}

/// Where the chunks' frames are among these frames.
fn chunk_places(frames: &[Vec<u8>]) -> Vec<usize> {
    (0..frames.len())
        .filter(|&place| frames[place][0] == FRAME_CHUNK)
        .collect()
}

#[test]
fn chunks_taken_in_by_several_threads_are_taken_in_as_by_one() {
    let (source, root, frames) = long_tree("threads-intake");
    let places = chunk_places(&frames);
    assert!(places.len() > 3, "several chunks");
    let imported = MemoryStore::new();
    import(&imported, &root, &mut bundle_of(&frames).as_slice()).unwrap();
    assert_eq!(contents(&imported), contents(&source));
    let fetched = MemoryStore::new();
    fetch(&fetched, &root, &mut TestPeer::new(&source)).unwrap();
    assert_eq!(contents(&fetched), contents(&source));

    // A chunk that comes twice in a row is kept once.
    let mut twice = frames.clone();
    twice.insert(places[1] + 1, frames[places[1]].clone());
    let store = MemoryStore::new();
    import(&store, &root, &mut bundle_of(&twice).as_slice()).unwrap();
    assert_eq!(contents(&store), contents(&source));
}

#[test]
fn a_chunk_refused_among_others_is_what_is_told_and_nothing_false_is_kept() {
    let (source, root, frames) = long_tree("threads-forged");
    let places = chunk_places(&frames);
    // The third chunk's last byte is changed: no list names what it is now.
    let mut forged = frames.clone();
    let last = forged[places[2]].len() - 1;
    forged[places[2]][last] ^= 1;
    let store = MemoryStore::new();
    let result = import(&store, &root, &mut bundle_of(&forged).as_slice());
    assert!(matches!(result, Err(Error::NotWanted { .. })), "{result:?}");
    // What was kept is the tree's, and so are the chunks that came before.
    for (kind, hash, kept) in contents(&store) {
        let held = source.get(kind, &hash).unwrap();
        assert_eq!(held.as_deref(), Some(kept.as_slice()));
    }
    for &place in &places[..2] {
        let hash = Hash::of(&frames[place][1..]);
        assert!(store.has(Stored::Chunk, &hash).unwrap());
    }
    // The tree is made whole from what is held.
    import(&store, &root, &mut bundle_of(&frames).as_slice()).unwrap();
    assert_eq!(contents(&store), contents(&source));
}

/// A store that will not keep one chunk the first time it is handed it.
struct RefusingOnce {
    inner: MemoryStore,
    refused: Hash,
    asked: AtomicBool,
}

impl RefusingOnce {
    fn new(refused: Hash) -> Self {
        Self {
            inner: MemoryStore::new(),
            refused,
            asked: AtomicBool::new(false),
        }
    }
}

impl Store for RefusingOnce {
    fn put(&self, kind: Stored, hash: &Hash, bytes: &[u8]) -> Result<()> {
        if kind == Stored::Chunk
            && *hash == self.refused
            && !self.asked.swap(true, Ordering::Relaxed)
        {
            return Err(Error::Invariant {
                detail: "this store will not keep that chunk yet",
            });
        }
        self.inner.put(kind, hash, bytes)
    }

    fn get(&self, kind: Stored, hash: &Hash) -> Result<Option<Arc<[u8]>>> {
        self.inner.get(kind, hash)
    }

    fn remove(&self, kind: Stored, hash: &Hash) -> Result<()> {
        self.inner.remove(kind, hash)
    }
}

#[test]
fn a_chunk_that_a_store_cannot_keep_is_wanted_still() {
    let (source, root, frames) = long_tree("threads-refused-once");
    let places = chunk_places(&frames);
    let refused = Hash::of(&frames[places[1]][1..]);
    let not_yet = |result: &Result<_>| {
        matches!(
            result,
            Err(Error::Invariant {
                detail: "this store will not keep that chunk yet"
            })
        )
    };

    // One frame at a time: the chunk is refused, and taken when it comes
    // again.
    let store = RefusingOnce::new(refused);
    let mut intake = Intake::new(&store, root).unwrap();
    for frame in &frames[..places[1]] {
        intake.accept(frame).unwrap();
    }
    assert!(not_yet(&intake.accept(&frames[places[1]]).map(|_| ())));
    assert!(intake.accept(&frames[places[1]]).unwrap().kept);
    for frame in &frames[places[1] + 1..] {
        intake.accept(frame).unwrap();
    }
    intake.finish().unwrap();
    assert_eq!(contents(&store.inner), contents(&source));

    // Many at once, from a bundle and from a peer: the tree is made whole
    // from what is held.
    let store = RefusingOnce::new(refused);
    let bundle = bundle_of(&frames);
    assert!(not_yet(
        &import(&store, &root, &mut bundle.as_slice()).map(|_| ())
    ));
    assert!(!store.inner.has(Stored::Chunk, &refused).unwrap());
    import(&store, &root, &mut bundle.as_slice()).unwrap();
    assert_eq!(contents(&store.inner), contents(&source));
    let store = RefusingOnce::new(refused);
    let fetched = fetch(&store, &root, &mut TestPeer::new(&source));
    assert!(not_yet(&fetched.map(|_| ())));
    fetch(&store, &root, &mut TestPeer::new(&source)).unwrap();
    assert_eq!(contents(&store.inner), contents(&source));
}

#[test]
fn a_store_that_falls_over_while_it_keeps_a_chunk_leaves_the_intake_done() {
    let (_source, root, frames) = long_tree("threads-falling-intake");
    let places = chunk_places(&frames);
    let store = Falling(MemoryStore::new());
    let mut intake = Intake::new(&store, root).unwrap();
    for frame in &frames[..places[0]] {
        intake.accept(frame).unwrap();
    }
    let fell = std::panic::catch_unwind(AssertUnwindSafe(|| intake.accept(&frames[places[0]])));
    assert!(fell.is_err());
    // The intake never holds the chunk as kept: it is done.
    let again = intake.accept(&frames[places[0]]);
    assert!(matches!(again, Err(Error::IntakeFailed)), "{again:?}");
    assert!(matches!(intake.finish(), Err(Error::IntakeFailed)));

    // Many at once: the fall comes through to the caller.
    let bundle = bundle_of(&frames);
    let fell = std::panic::catch_unwind(AssertUnwindSafe(|| {
        import(&Falling(MemoryStore::new()), &root, &mut bundle.as_slice())
    }));
    assert!(fell.is_err());
}

#[test]
fn a_bundle_ends_at_the_first_chunk_that_is_damaged_or_missing() {
    let (source, root, frames) = long_tree("threads-export");
    let places = chunk_places(&frames);
    let copy = || {
        let store = MemoryStore::new();
        for (kind, hash, bytes) in contents(&source) {
            store.put(kind, &hash, &bytes).unwrap();
        }
        store
    };
    // The chunks are read and checked ahead, several at once, and written
    // in order: what comes out is the bundle up to the bad chunk.
    for bad in [places[0], places[2], places[places.len() - 1]] {
        let hash = Hash::of(&frames[bad][1..]);
        let before = bundle_of(&frames[..bad]);

        let damaged = copy();
        damaged.remove(Stored::Chunk, &hash).unwrap();
        let mut bytes = frames[bad][1..].to_vec();
        bytes[0] ^= 1;
        damaged.put(Stored::Chunk, &hash, &bytes).unwrap();
        let mut out = Vec::new();
        let result = export(&damaged, &root, &mut out);
        assert!(matches!(result, Err(Error::Corrupt { .. })), "{result:?}");
        assert!(out == before, "damaged chunk at frame {bad}");

        let missing = copy();
        missing.remove(Stored::Chunk, &hash).unwrap();
        let mut out = Vec::new();
        let result = export(&missing, &root, &mut out);
        assert!(matches!(result, Err(Error::Missing { .. })), "{result:?}");
        assert!(out == before, "missing chunk at frame {bad}");
    }
}
