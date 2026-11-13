//! How much a receiver sets aside for a peer: no more than the tree it
//! trusts calls for. And an intake that has refused a part of its tree does
//! not go on as if nothing had happened.

mod support;

use scionic_merkletree::{
    chunk_frame, fetch, file_list_frame, folder_list_frame, lookup, read_frame, record_of,
    ChunkRef, Entry, Error, ExtraData, FileList, FolderList, Intake, MemoryStore, Record, Remote,
    Request, Root, Store, Stored, Target, Totals, MAX_RECORD_BYTES,
};
use support::{bytes, contents, sample_tree, small_chunks, TestPeer};

fn target_at(store: &MemoryStore, root: &Root, path: &str) -> Target {
    lookup(store, root, path).unwrap().unwrap().target()
}

#[test]
fn every_request_says_how_long_its_answer_may_be() {
    let (_temp, source, root) = sample_tree("limits-fetch");
    let dest = MemoryStore::new();
    let mut peer = TestPeer::new(&source);
    fetch(&dest, &root, &mut peer).unwrap();
    let list_bytes = record_of(&source, &root).unwrap().totals().list_bytes as usize;
    assert_eq!(peer.wire.requests.len(), peer.wire.limits.len());
    for (request, limit) in peer.wire.requests.iter().zip(&peer.wire.limits) {
        match Request::decode(request).unwrap() {
            Request::Record(_) => assert_eq!(*limit, MAX_RECORD_BYTES),
            // A folder's list: no longer than the record leaves room for.
            Request::Folder(_) => assert!(*limit <= list_bytes + 1),
            // A file's list: no longer than the file's size allows. These
            // files are split into chunks of 16 bytes, so it is known exactly.
            Request::File(file) => {
                let list = source.get(Stored::FileList, &file).unwrap().unwrap();
                assert_eq!(*limit, (list.len() + 1).max(2));
            }
            // A chunk: no longer than the tree's way of chunking allows.
            Request::Chunks { .. } => assert_eq!(*limit, 17),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn an_answer_that_is_too_long_is_refused_by_its_length() {
    let (_temp, source, root) = sample_tree("limits-long");
    // The first answer to each kind of request, with bytes added to it. A
    // connection refuses such a frame by the length that comes before it.
    for asked in [0x30_u8, 0x31, 0x34, 0x37] {
        let mut done = false;
        let dest = MemoryStore::new();
        let result = {
            let mut peer = TestPeer::tampering(&source, move |request, mut frames| {
                if request[0] == asked && !done {
                    done = true;
                    frames[0].extend_from_slice(&[0; 40_000]);
                }
                frames
            });
            fetch(&dest, &root, &mut peer)
        };
        assert!(
            matches!(result, Err(Error::LimitExceeded { .. })),
            "{asked:#x}: {result:?}"
        );
        for thing in contents(&dest) {
            assert!(contents(&source).contains(&thing), "{asked:#x}");
        }
    }

    // The same for one who reads parts of a tree and keeps nothing.
    let weights = target_at(&source, &root, "weights");
    let model = target_at(&source, &root, "weights/model.bin");
    for asked in [0x30_u8, 0x32, 0x33, 0x36, 0x37, 0x39] {
        let mut peer = TestPeer::tampering(&source, move |request, mut frames| {
            if request[0] == asked {
                frames[0].extend_from_slice(&[0; 200_000]);
            }
            frames
        });
        let mut out = Vec::new();
        let result = Remote::open(&mut peer, &root).and_then(|mut remote| {
            remote.entries(&weights, 0, 2)?;
            remote.entry(&weights, "model.bin")?;
            remote.read(&model, 100, 300, &mut out)?;
            remote.have(&model).map(|_| ())
        });
        assert!(
            matches!(result, Err(Error::LimitExceeded { .. })),
            "{asked:#x}: {result:?}"
        );
    }
    // What such a reader lets through for a stretch of a file is small: the
    // branch of the list that holds the stretch, and chunks no longer than the
    // branch says they are.
    let mut peer = TestPeer::new(&source);
    let mut remote = Remote::open(&mut peer, &root).unwrap();
    remote.read(&model, 100, 300, &mut Vec::new()).unwrap();
    remote.have(&model).unwrap();
    let limits = &peer.wire.limits;
    // 300 bytes lie in 20 chunks of 16 bytes at the most, the two at the
    // ends counted: 23 bytes, 20 items, and 80 nodes of 40 bytes.
    assert_eq!(limits[1], 23 + 20 * 36 + 80 * 40);
    assert_eq!(limits[2], 17);
    // 63 chunks are 63 bits: 8 bytes, after the frame's first byte and
    // the count.
    assert_eq!(limits[3], 17);
}

#[test]
fn a_long_frame_that_never_comes_costs_little() {
    // A stream that claims a frame of 3 GiB and holds five bytes of it. The
    // frame's bytes are set aside as they come, so this is an error at
    // once, and not three gigabytes of memory first.
    let mut stream = (3_u32 << 30).to_be_bytes().to_vec();
    stream.extend_from_slice(b"short");
    assert!(matches!(
        read_frame(&mut stream.as_slice(), usize::MAX),
        Err(Error::InvalidData { .. })
    ));
    // Under a limit it is refused by its length, with nothing of it read.
    let mut unread = stream.as_slice();
    assert!(matches!(
        read_frame(&mut unread, 1 << 20),
        Err(Error::LimitExceeded { .. })
    ));
    assert_eq!(unread, b"short");

    // A frame that spans several steps of setting aside comes back whole.
    let long = bytes("long", (3 << 20) + 7);
    let mut stream = (long.len() as u32).to_be_bytes().to_vec();
    stream.extend_from_slice(&long);
    let mut input = stream.as_slice();
    assert_eq!(read_frame(&mut input, long.len()).unwrap(), Some(long));
    assert_eq!(read_frame(&mut input, 1).unwrap(), None);
    // A length of zero is no frame.
    assert!(read_frame(&mut [0_u8; 4].as_slice(), 100).is_err());
    // A stream that ends inside the length.
    assert!(read_frame(&mut [0_u8, 0].as_slice(), 100).is_err());
}

fn entry(name: &str, target: Target) -> Entry {
    Entry::new(name, target, ExtraData::new()).unwrap()
}

/// A tree that is wrong in itself: two of its files list the same chunk, the
/// one with 16 bytes and the other with 15. Every list of it is well formed
/// and has the hash its parent gives it.
fn tree_with_a_chunk_of_two_lengths() -> (Record, FolderList, FileList, FileList, Vec<u8>) {
    let whole = bytes("whole", 16);
    let item = ChunkRef::of(&whole).unwrap();
    let right = FileList::new(vec![item]).unwrap();
    let wrong = FileList::new(vec![ChunkRef { length: 15, ..item }]).unwrap();
    let folder =
        FolderList::new(vec![entry("a", right.target()), entry("b", wrong.target())]).unwrap();
    let record = Record::new(
        folder.target(),
        Totals {
            chunks: 1,
            chunk_bytes: 16,
            list_bytes: 72 + folder.encoded_len(),
        },
        small_chunks(),
        ExtraData::new(),
    )
    .unwrap();
    (record, folder, right, wrong, whole)
}

#[test]
fn an_intake_that_refused_a_part_of_its_tree_is_done() {
    let (record, folder, right, wrong, whole) = tree_with_a_chunk_of_two_lengths();
    let root = record.root();
    let dest = MemoryStore::new();
    let mut intake = Intake::new(&dest, root).unwrap();
    intake.accept(&record.encode()).unwrap();

    // A frame that is refused at the door leaves the intake as it was.
    assert!(matches!(
        intake.accept(&chunk_frame(b"nothing names this")),
        Err(Error::NotWanted { .. })
    ));
    assert!(intake.accept(&[0x25]).is_err());
    intake.accept(&folder_list_frame(&folder.encode())).unwrap();
    intake.accept(&file_list_frame(&right.encode())).unwrap();

    // The second list is named, and it is what its hash says. It fails a
    // check all the same, and that shows the tree itself to be wrong.
    assert!(matches!(
        intake.accept(&file_list_frame(&wrong.encode())),
        Err(Error::SizeMismatch { .. })
    ));
    assert!(
        !dest.has(Stored::FileList, wrong.hash()).unwrap(),
        "a list that failed its checks is not kept"
    );
    // From here on the intake takes nothing, asks for nothing, and never
    // says that the tree is whole.
    assert!(matches!(
        intake.accept(&chunk_frame(&whole)),
        Err(Error::IntakeFailed)
    ));
    assert!(matches!(
        intake.accept(&file_list_frame(&right.encode())),
        Err(Error::IntakeFailed)
    ));
    assert!(intake.requests(10).is_empty());
    assert!(matches!(intake.finish(), Err(Error::IntakeFailed)));
    assert!(!dest
        .has(Stored::Chunk, &ChunkRef::of(&whole).unwrap().hash)
        .unwrap());

    // A new intake goes on from what the store holds, and finds the same.
    let mut again = Intake::new(&dest, root).unwrap();
    assert_eq!(again.outstanding(), 2, "one list and one chunk");
    assert!(again.accept(&file_list_frame(&wrong.encode())).is_err());
    assert!(matches!(again.finish(), Err(Error::IntakeFailed)));

    // And so does one that is given the lists the other way round.
    let fresh = MemoryStore::new();
    let mut intake = Intake::new(&fresh, root).unwrap();
    intake.accept(&record.encode()).unwrap();
    intake.accept(&folder_list_frame(&folder.encode())).unwrap();
    intake.accept(&file_list_frame(&wrong.encode())).unwrap();
    assert!(intake.accept(&file_list_frame(&right.encode())).is_err());
    assert!(!fresh.has(Stored::FileList, right.hash()).unwrap());
    assert!(matches!(intake.finish(), Err(Error::IntakeFailed)));
}

#[test]
fn a_tree_never_takes_more_room_than_its_record_says() {
    let (_temp, source, root) = sample_tree("limits-room");
    let record = record_of(&source, &root).unwrap();
    let right = record.totals();
    // Records that say less than the tree holds: of lists, of chunks, and
    // of the chunks' bytes.
    for totals in [
        Totals {
            list_bytes: right.list_bytes - 1,
            ..right
        },
        Totals {
            chunks: right.chunks - 1,
            ..right
        },
        Totals {
            chunk_bytes: right.chunk_bytes - 1,
            ..right
        },
    ] {
        let forged =
            Record::new(record.top(), totals, record.chunking(), ExtraData::new()).unwrap();
        source
            .put(Stored::Record, forged.root().as_hash(), &forged.encode())
            .unwrap();
        let dest = MemoryStore::new();
        assert!(matches!(
            fetch(&dest, &forged.root(), &mut TestPeer::new(&source)),
            Err(Error::TotalsMismatch { .. })
        ));
        // The fetch stopped at the list that went over. That list is not
        // kept, so what is kept fits in what the record said.
        let lists = dest.bytes(Stored::FileList) + dest.bytes(Stored::FolderList);
        assert!(lists <= totals.list_bytes, "{totals:?}");
        assert!(dest.count(Stored::Chunk) as u64 <= totals.chunks);
        assert!(dest.bytes(Stored::Chunk) <= totals.chunk_bytes);
    }
}
