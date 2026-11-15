//! A responder keeps the lists it was asked about, so that a busy one does
//! not read and hash a long list again for every request.

mod support;

use scionic_merkletree::{
    Builder, ChunkRef, Entry, Error, ExtraData, FileList, FolderList, Frame, Hash, MemoryStore,
    OpenFile, OpenFolder, Refusal, Request, Responder, Result, Store, Stored,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use support::{bytes, small_chunks};

/// A store that counts how often a list is read from it.
struct Counting {
    inner: MemoryStore,
    lists_read: AtomicUsize,
}

impl Store for Counting {
    fn put(&self, kind: Stored, hash: &Hash, bytes: &[u8]) -> Result<()> {
        self.inner.put(kind, hash, bytes)
    }

    fn get(&self, kind: Stored, hash: &Hash) -> Result<Option<Arc<[u8]>>> {
        if matches!(kind, Stored::FileList | Stored::FolderList) {
            self.lists_read.fetch_add(1, Ordering::Relaxed);
        }
        self.inner.get(kind, hash)
    }

    fn has(&self, kind: Stored, hash: &Hash) -> Result<bool> {
        self.inner.has(kind, hash)
    }

    fn size(&self, kind: Stored, hash: &Hash) -> Result<Option<u64>> {
        self.inner.size(kind, hash)
    }

    fn remove(&self, kind: Stored, hash: &Hash) -> Result<()> {
        self.inner.remove(kind, hash)
    }
}

/// Asks about two files in turn, as two peers at once would, and says how
/// often a list was read from the store for it.
fn lists_read_for(store: &Counting, responder: &Responder<'_>, files: [Hash; 2]) -> usize {
    let before = store.lists_read.load(Ordering::Relaxed);
    for round in 0..20_u64 {
        for file in files {
            for request in [
                Request::Chunks {
                    file,
                    start: round,
                    count: 2,
                },
                Request::FileBranch {
                    file,
                    start: round,
                    count: 3,
                },
                Request::FileBytes {
                    file,
                    offset: round * 16,
                    length: 20,
                },
            ] {
                let mut frames = 0;
                responder
                    .answer(&request.encode(), &mut |_| {
                        frames += 1;
                        Ok(())
                    })
                    .unwrap();
                assert!(frames > 0);
            }
        }
    }
    store.lists_read.load(Ordering::Relaxed) - before
}

#[test]
fn lists_that_were_asked_about_are_not_read_again() {
    let store = Counting {
        inner: MemoryStore::new(),
        lists_read: AtomicUsize::new(0),
    };
    let mut builder = Builder::new(&store, small_chunks());
    let first = builder
        .file_from_bytes(&bytes("responder-a", 1_600))
        .unwrap();
    let second = builder
        .file_from_bytes(&bytes("responder-b", 1_600))
        .unwrap();
    let files = [first.hash, second.hash];

    // Each of the two lists is read once, for 120 requests.
    let responder = Responder::new(&store);
    assert_eq!(lists_read_for(&store, &responder, files), 2);
    // A responder that keeps one list only reads again at every change.
    let forgetful = Responder::new(&store).recent(0);
    assert_eq!(lists_read_for(&store, &forgetful, files), 40);

    // A list that was harmed in the store is named, not served.
    store.inner.remove(Stored::FileList, &first.hash).unwrap();
    store
        .inner
        .put(Stored::FileList, &first.hash, &[7; 72])
        .unwrap();
    let request = Request::FileBranch {
        file: first.hash,
        start: 0,
        count: 1,
    };
    let fresh = Responder::new(&store);
    match fresh.answer(&request.encode(), &mut |_| Ok(())) {
        Err(Error::Corrupt { hash, .. }) => assert_eq!(hash, first.hash),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_responder_can_keep_to_itself_which_chunks_it_holds() {
    let store = MemoryStore::new();
    let mut builder = Builder::new(&store, small_chunks());
    let file = builder
        .file_from_bytes(&bytes("responder-have", 160))
        .unwrap();
    let request = Request::Have(file.hash).encode();
    let answer = |responder: &Responder<'_>| {
        let mut frames: Vec<Vec<u8>> = Vec::new();
        responder
            .answer(&request, &mut |frame| {
                frames.push(frame.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(frames.len(), 1);
        frames.remove(0)
    };
    let told = answer(&Responder::new(&store));
    match Frame::decode(&told).unwrap() {
        Frame::Have(map) => assert_eq!((map.count(), map.held()), (10, 10)),
        other => panic!("{other:?}"),
    }
    let kept = answer(&Responder::new(&store).have(false));
    assert_eq!(
        Frame::decode(&kept).unwrap(),
        Frame::Refused(Refusal::NotHeld)
    );
}

/// A responder fills one frame again for every chunk it sends, from one
/// request to the next. What it sends is the chunk that was asked for and
/// nothing of a longer one before it, and a frame that is lent out is never
/// filled again: a request that is answered inside the answer to another is
/// given a frame of its own. Otherwise the frame is filled again in the same
/// memory.
#[test]
fn a_frame_that_is_filled_again_holds_the_chunk_asked_for_alone() {
    let store = MemoryStore::new();
    let long = bytes("frame-long", 4_000);
    let short = bytes("frame-short", 10);
    for chunk in [&long, &short] {
        store.put(Stored::Chunk, &Hash::of(chunk), chunk).unwrap();
    }
    let ask = |chunk: &[u8]| Request::Chunk(Hash::of(chunk)).encode();
    let responder = Responder::new(&store);
    let mut sent = Vec::new();
    for chunk in [&long, &short, &long, &short] {
        responder
            .answer(&ask(chunk), &mut |frame| {
                sent.push(frame.to_vec());
                Ok(())
            })
            .unwrap();
    }
    for (frame, chunk) in sent.iter().zip([&long, &short, &long, &short]) {
        assert_eq!(Frame::decode(frame).unwrap(), Frame::Chunk(chunk));
    }

    let (mut outer, mut inner) = (Vec::new(), Vec::new());
    responder
        .answer(&ask(&long), &mut |frame| {
            responder.answer(&ask(&short), &mut |frame| {
                inner = frame.to_vec();
                Ok(())
            })?;
            // The answer inside left this frame as it was.
            outer = frame.to_vec();
            Ok(())
        })
        .unwrap();
    assert_eq!(Frame::decode(&outer).unwrap(), Frame::Chunk(&long));
    assert_eq!(Frame::decode(&inner).unwrap(), Frame::Chunk(&short));

    // Otherwise the frame is filled again in the same memory.
    let place = |chunk: &[u8]| {
        let mut at = std::ptr::null();
        responder
            .answer(&ask(chunk), &mut |frame| {
                at = frame.as_ptr();
                Ok(())
            })
            .unwrap();
        at
    };
    let first = place(&long);
    assert_eq!(place(&short), first);
    assert_eq!(place(&long), first);
}

#[test]
fn a_list_read_with_its_tree_is_the_list_read_alone() {
    for count in [0_usize, 1, 2, 3, 5, 8, 13, 100] {
        let items: Vec<ChunkRef> = (0..count)
            .map(|number| ChunkRef::of(&bytes(&format!("chunk-{number}"), 16)).unwrap())
            .collect();
        let list = FileList::new(items).unwrap();
        let open = OpenFile::decode(&list.encode()).unwrap();
        assert_eq!(open.list(), &list, "{count} chunks");
        if count > 0 {
            let end = count.min(3) as u64;
            assert_eq!(
                open.open(0, end).unwrap(),
                OpenFile::new(list.clone()).unwrap().open(0, end).unwrap()
            );
        }
    }
    let file = FileList::new(vec![ChunkRef::of(b"some bytes").unwrap()])
        .unwrap()
        .target();
    let entry =
        |number: usize| Entry::new(format!("name-{number:03}"), file, ExtraData::new()).unwrap();
    for count in [0_usize, 1, 2, 3, 7, 50] {
        let list = FolderList::new((0..count).map(entry).collect()).unwrap();
        let open = OpenFolder::decode(&list.encode()).unwrap();
        assert_eq!(open.list(), &list, "{count} entries");
        for name in ["name-000", "name-025", "not-there"] {
            assert_eq!(
                open.open_name(name).unwrap(),
                OpenFolder::new(list.clone())
                    .unwrap()
                    .open_name(name)
                    .unwrap()
            );
        }
    }
    // Entries out of order are no list, read either way.
    // A list's bytes are its entries' bytes, one after another.
    let mut unsorted = Vec::new();
    for number in [2, 1] {
        unsorted.extend(FolderList::new(vec![entry(number)]).unwrap().encode());
    }
    assert!(FolderList::decode(&unsorted).is_err());
    assert!(OpenFolder::decode(&unsorted).is_err());
}
