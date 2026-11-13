//! Several threads build and check what one thread builds and checks.

mod support;

use scionic_merkletree::{
    build, verify_with, Builder, Cutting, Error, ExtraData, Hash, MemoryStore, PieceRef, Result,
    Store, Stored, VerifyOptions,
};
use std::sync::Arc;
use support::{bytes, contents, sample_folder, small_options, small_pieces, write, TempDir};

#[test]
fn one_file_is_the_same_whatever_number_of_threads_keep_its_pieces() {
    // 6,250 pieces of 16 bytes: more than a builder hands on at a time.
    let data = bytes("threads-one-file", 100_000);
    let mut roots = Vec::new();
    let mut stores = Vec::new();
    for threads in [1, 2, 8, 0] {
        let store = MemoryStore::new();
        let mut builder = Builder::new(&store, small_pieces()).threads(threads);
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
fn a_file_cut_by_content_is_the_same_with_help() {
    let data = bytes("threads-by-content", 9 << 20);
    let mut roots = Vec::new();
    for threads in [1, 4] {
        let store = MemoryStore::new();
        let mut builder = Builder::new(&store, Cutting::FastCdcV1).threads(threads);
        let streamed = builder.file(&mut data.as_slice()).unwrap();
        assert_eq!(streamed, builder.file_from_bytes(&data).unwrap());
        assert!(store.count(Stored::Piece) > 2, "several pieces");
        let root = builder.finish(streamed, ExtraData::new()).unwrap();
        for workers in [1, 4] {
            let options = VerifyOptions::new().workers(workers).recut(true);
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

/// A store that will not keep one piece.
struct Refusing {
    inner: MemoryStore,
    refused: Hash,
}

impl Store for Refusing {
    fn put(&self, kind: Stored, hash: &Hash, bytes: &[u8]) -> Result<()> {
        if kind == Stored::Piece && *hash == self.refused {
            return Err(Error::Invariant {
                detail: "this store will not keep that piece",
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
fn a_piece_that_cannot_be_kept_stops_the_file_whoever_was_keeping_it() {
    let data = bytes("threads-refused", 100_000);
    let refused = PieceRef::of(&data[64_000..64_016]).unwrap().hash;
    for threads in [1, 8] {
        let store = Refusing {
            inner: MemoryStore::new(),
            refused,
        };
        let mut builder = Builder::new(&store, small_pieces()).threads(threads);
        for attempt in [
            builder.file(&mut data.as_slice()),
            builder.file_from_bytes(&data),
        ] {
            assert!(
                matches!(attempt, Err(Error::Invariant { .. })),
                "{threads} threads: {attempt:?}"
            );
        }
        // A file whose pieces are not all kept has no list.
        assert_eq!(store.inner.count(Stored::FileList), 0);
    }
}

#[test]
fn the_failure_that_is_told_is_the_one_that_happened() {
    // A folder of many files, one of which holds a piece the store refuses.
    // The threads that stop because of it have nothing of their own to tell.
    let temp = TempDir::new("threads-failure").unwrap();
    let folder = temp.path().join("tree");
    for number in 0..64 {
        let data = bytes(&format!("failure-{number}"), 64);
        write(folder.join(format!("file-{number:02}")), &data).unwrap();
    }
    let refused = PieceRef::of(&bytes("failure-40", 64)[..16]).unwrap().hash;
    for workers in [1, 2, 8] {
        let store = Refusing {
            inner: MemoryStore::new(),
            refused,
        };
        match build(&store, &folder, &small_options().workers(workers)) {
            Err(Error::Invariant { detail }) => {
                assert_eq!(detail, "this store will not keep that piece");
            }
            other => panic!("{workers} workers: {other:?}"),
        }
    }
}

/// A store that falls over whenever it is handed a piece, as one would whose
/// own code has a fault.
struct Falling(MemoryStore);

impl Store for Falling {
    fn put(&self, kind: Stored, hash: &Hash, bytes: &[u8]) -> Result<()> {
        assert!(kind != Stored::Piece, "this store falls over");
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
    // More files than the threads take at once: if every thread that cuts
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
