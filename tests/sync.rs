//! Syncing by file hash and piece number: a whole tree into a store, parts
//! of a tree straight from a peer, and a tree as one stream.

mod support;

use scionic_merkletree::{
    build, export, fetch, file_of, folder_of, import, lookup, record_of, verify, Error, Frame,
    Kind, MemoryStore, Refusal, Remote, Request, Responder, Root, Store, Stored, Target,
    BUNDLE_MAGIC, FRAME_FILE_LIST, FRAME_FILE_RUN, FRAME_FOLDER_LIST, FRAME_FOLDER_RUN,
    FRAME_PIECE, FRAME_RECORD,
};
use std::fs;
use support::{
    bytes, contents, sample_folder, sample_tree, small_options, write, TempDir, TestPeer,
};

fn target_at(store: &MemoryStore, root: &Root, path: &str) -> Target {
    lookup(store, root, path).unwrap().unwrap().target()
}

#[test]
fn a_tree_is_fetched_whole_into_an_empty_store() {
    let (_temp, source, root) = sample_tree("sync-whole");
    let dest = MemoryStore::new();
    let mut peer = TestPeer::new(&source);
    let summary = fetch(&dest, &root, &mut peer).unwrap();
    assert_eq!(summary, verify(&dest, &root).unwrap());
    assert_eq!(contents(&dest), contents(&source));

    // Each thing came once: the record, 5 folders, 6 files, 76 pieces.
    assert_eq!(peer.wire.frames_of(FRAME_RECORD), 1);
    assert_eq!(peer.wire.frames_of(FRAME_FOLDER_LIST), 5);
    assert_eq!(peer.wire.frames_of(FRAME_FILE_LIST), 6);
    assert_eq!(peer.wire.frames_of(FRAME_PIECE), 76);
    assert_eq!(peer.wire.frames.len(), 88);

    // From the top down. The record is asked for first, a list only once
    // the list that names it is in, and pieces only by their file's hash and
    // their numbers in it.
    let mut known = vec![*root.as_hash()];
    let mut asked_pieces = 0;
    for request in &peer.wire.requests {
        match Request::decode(request).unwrap() {
            Request::Record(asked) => assert_eq!(asked, root),
            Request::Folder(folder) => {
                assert!(known.contains(&folder));
                let list = dest.get(Stored::FolderList, &folder).unwrap().unwrap();
                let list = scionic_merkletree::FolderList::decode(&list).unwrap();
                known.extend(list.entries().iter().map(|entry| *entry.hash()));
            }
            Request::File(file) => assert!(known.contains(&file)),
            Request::Pieces { file, count, .. } => {
                assert!(known.contains(&file));
                asked_pieces += count;
            }
            other => panic!("a whole tree is not fetched by {other:?}"),
        }
        if known.len() == 1 {
            known.push(record_of(&dest, &root).unwrap().top().hash);
        }
    }
    assert_eq!(asked_pieces, 76);
}

#[test]
fn pieces_are_asked_for_by_their_file_and_their_numbers() {
    let (_temp, source, root) = sample_tree("sync-numbers");
    let dest = MemoryStore::new();
    let mut peer = TestPeer::new(&source);
    fetch(&dest, &root, &mut peer).unwrap();
    let model = target_at(&source, &root, "weights/model.bin");
    // The file has 63 pieces, and two names. All of its pieces are asked
    // for once, in one request of 45 bytes.
    let for_model: Vec<&Vec<u8>> = peer
        .wire
        .requests
        .iter()
        .filter(|request| {
            matches!(
                Request::decode(request).unwrap(),
                Request::Pieces { file, .. } if file == model.hash
            )
        })
        .collect();
    assert_eq!(for_model.len(), 1);
    assert_eq!(for_model[0].len(), 45);
    assert_eq!(
        Request::decode(for_model[0]).unwrap(),
        Request::Pieces {
            file: model.hash,
            start: 0,
            count: 63
        }
    );
}

#[test]
fn what_a_receiver_holds_is_not_asked_for_again() {
    let temp = TempDir::new("sync-held").unwrap();
    let folder = sample_folder(temp.path(), "sample").unwrap();
    let source = MemoryStore::new();
    let first = build(&source, &folder, &small_options()).unwrap();
    let dest = MemoryStore::new();
    fetch(&dest, &first, &mut TestPeer::new(&source)).unwrap();

    // A second tree: one piece of one file changed, a file that is there
    // already under another name, and one new file of two pieces.
    let mut model = bytes("model", 1_000);
    model[320..336].copy_from_slice(&bytes("changed", 16));
    write(folder.join("weights/model.bin"), &model).unwrap();
    write(folder.join("weights/a-again.bin"), &bytes("shard-a", 100)).unwrap();
    write(folder.join("new.txt"), &bytes("new", 20)).unwrap();
    let second = build(&source, &folder, &small_options()).unwrap();

    let mut peer = TestPeer::new(&source);
    fetch(&dest, &second, &mut peer).unwrap();
    // The record, the two folders on the way to the changes, the lists of
    // the changed file and the new one, and three pieces.
    assert_eq!(peer.wire.frames_of(FRAME_RECORD), 1);
    assert_eq!(peer.wire.frames_of(FRAME_FOLDER_LIST), 2);
    assert_eq!(peer.wire.frames_of(FRAME_FILE_LIST), 2);
    assert_eq!(peer.wire.frames_of(FRAME_PIECE), 3);
    // The one changed piece of the file was asked for by its number.
    let changed = target_at(&source, &second, "weights/model.bin");
    assert!(peer.wire.requests.contains(
        &Request::Pieces {
            file: changed.hash,
            start: 20,
            count: 1
        }
        .encode()
    ));
    verify(&dest, &first).unwrap();
    verify(&dest, &second).unwrap();

    // A tree that is held whole is not asked about at all.
    let mut idle = TestPeer::new(&source);
    fetch(&dest, &second, &mut idle).unwrap();
    assert!(idle.wire.requests.is_empty());
}

#[test]
fn pieces_held_from_anywhere_else_are_skipped_by_their_hash() {
    let (_temp, source, root) = sample_tree("sync-elsewhere");
    let model = target_at(&source, &root, "weights/model.bin");
    let dest = MemoryStore::new();
    // The receiver has the file's bytes from somewhere else, as bare pieces.
    for item in file_of(&source, &model).unwrap().items() {
        let piece = source.get(Stored::Piece, &item.hash).unwrap().unwrap();
        dest.put(Stored::Piece, &item.hash, &piece).unwrap();
    }
    let mut peer = TestPeer::new(&source);
    fetch(&dest, &root, &mut peer).unwrap();
    assert_eq!(peer.wire.frames_of(FRAME_PIECE), 76 - 63);
    verify(&dest, &root).unwrap();
}

#[test]
fn a_fetch_that_stops_goes_on_from_what_is_held() {
    let (_temp, source, root) = sample_tree("sync-resume");
    let dest = MemoryStore::new();
    // A peer that goes silent after 30 frames.
    let mut left = 30_usize;
    let mut flaky = TestPeer::tampering(&source, move |_request, frames| {
        let keep = frames.len().min(left);
        left -= keep;
        frames.into_iter().take(keep).collect()
    });
    assert!(matches!(
        fetch(&dest, &root, &mut flaky),
        Err(Error::Peer { .. })
    ));
    assert_eq!(flaky.wire.frames.len(), 30);
    assert!(matches!(verify(&dest, &root), Err(Error::Missing { .. })));

    let mut peer = TestPeer::new(&source);
    fetch(&dest, &root, &mut peer).unwrap();
    assert_eq!(peer.wire.frames.len(), 88 - 30, "nothing came twice");
    assert_eq!(peer.wire.frames_of(FRAME_RECORD), 0);
    verify(&dest, &root).unwrap();
}

#[test]
fn one_name_is_looked_up_without_the_folder() {
    let (_temp, source, root) = sample_tree("sync-name");
    let mut peer = TestPeer::new(&source);
    {
        let mut remote = Remote::open(&mut peer, &root).unwrap();
        assert_eq!(remote.record(), &record_of(&source, &root).unwrap());
        for path in [
            "readme.txt",
            "weights",
            "weights/model.bin",
            "weights/shards/a.bin",
            "nothing-here",
        ] {
            assert_eq!(
                remote.lookup(path).unwrap(),
                lookup(&source, &root, path).unwrap(),
                "{path}"
            );
            assert!(remote.lookup(path).unwrap().is_some(), "{path}");
        }
        for path in [
            "a",
            "zzz",
            "readme.txs",
            "weights/shards/aa.bin",
            "weights/model.bin/x",
            "nothing-here/x",
            "Weights",
        ] {
            assert!(remote.lookup(path).unwrap().is_none(), "{path}");
        }
        assert!(remote.lookup("weights/../readme.txt").is_err());
    }
    // The record, and one small frame for each name on the way: no folder's
    // whole list, no file's list, and no piece.
    assert_eq!(peer.wire.frames_of(FRAME_RECORD), 1);
    assert_eq!(
        peer.wire.frames_of(FRAME_FOLDER_RUN),
        peer.wire.frames.len() - 1
    );
    assert!(peer.wire.frames.iter().all(|frame| frame.len() < 600));
}

#[test]
fn a_stretch_of_a_file_is_read_without_the_rest() {
    let (_temp, source, root) = sample_tree("sync-stretch");
    let model = target_at(&source, &root, "weights/model.bin");
    let content = bytes("model", 1_000);
    let mut peer = TestPeer::new(&source);
    {
        let mut remote = Remote::open(&mut peer, &root).unwrap();
        let mut out = Vec::new();
        remote.read(&model, 100, 333, &mut out).unwrap();
        assert_eq!(out, &content[100..433]);
    }
    // Bytes 100 to 432 lie in pieces 6 to 27. The record, one run of the
    // file's list, and those 22 pieces came, and nothing else.
    assert_eq!(peer.wire.frames_of(FRAME_FILE_RUN), 1);
    assert_eq!(peer.wire.frames_of(FRAME_PIECE), 22);
    assert_eq!(peer.wire.frames.len(), 24);
    assert!(peer.wire.requests.contains(
        &Request::Pieces {
            file: model.hash,
            start: 6,
            count: 22
        }
        .encode()
    ));

    let mut peer = TestPeer::new(&source);
    let mut remote = Remote::open(&mut peer, &root).unwrap();
    for (offset, length) in [
        (0, 1),
        (0, 16),
        (15, 2),
        (16, 16),
        (999, 1),
        (992, 8),
        (0, 1_000),
        (500, 0),
        (1_000, 0),
    ] {
        let mut out = Vec::new();
        remote.read(&model, offset, length, &mut out).unwrap();
        let (from, to) = (offset as usize, (offset + length) as usize);
        assert_eq!(out, &content[from..to], "{offset}+{length}");
    }
    let mut out = Vec::new();
    assert!(remote.read(&model, 0, 1_001, &mut out).is_err());
    assert!(remote.read(&model, 1_001, 0, &mut out).is_err());
    let weights = target_at(&source, &root, "weights");
    assert!(remote.read(&weights, 0, 1, &mut out).is_err());
    assert!(out.is_empty());
}

#[test]
fn every_stretch_of_a_small_file_reads_back_from_a_peer() {
    let (_temp, source, root) = sample_tree("sync-every-stretch");
    let shard = target_at(&source, &root, "weights/shards/a.bin");
    let content = bytes("shard-a", 100);
    let mut peer = TestPeer::new(&source);
    let mut remote = Remote::open(&mut peer, &root).unwrap();
    for offset in 0..100_usize {
        for length in 1..=100 - offset {
            let mut out = Vec::new();
            remote
                .read(&shard, offset as u64, length as u64, &mut out)
                .unwrap();
            assert_eq!(out, &content[offset..offset + length], "{offset}+{length}");
        }
    }
}

#[test]
fn a_run_of_a_folders_entries_is_listed() {
    let (_temp, source, root) = sample_tree("sync-entries");
    let weights = target_at(&source, &root, "weights");
    let nothing = target_at(&source, &root, "nothing-here");
    let model = target_at(&source, &root, "weights/model.bin");
    let all = folder_of(&source, &weights).unwrap();
    assert_eq!(all.count(), 3);
    let mut peer = TestPeer::new(&source);
    let mut remote = Remote::open(&mut peer, &root).unwrap();

    let listed = remote.entries(&weights, 0, 10).unwrap();
    assert_eq!((listed.total, listed.start), (3, 0));
    assert_eq!(listed.entries, all.entries());
    let one = remote.entries(&weights, 1, 1).unwrap();
    assert_eq!((one.total, one.start), (3, 1));
    assert_eq!(one.entries, &all.entries()[1..2]);
    assert_eq!(one.entries[0].name(), "model.bin");
    assert!(matches!(
        remote.entries(&weights, 3, 1),
        Err(Error::Peer { .. })
    ));
    let empty = remote.entries(&nothing, 0, 5).unwrap();
    assert_eq!((empty.total, empty.entries.len()), (0, 0));
    assert!(remote.entries(&model, 0, 1).is_err());
    assert!(remote.entry(&model, "x").is_err());
    assert_eq!(remote.entry(&nothing, "x").unwrap(), None);
}

#[test]
fn a_peer_says_which_pieces_it_holds() {
    let (_temp, source, root) = sample_tree("sync-have");
    let model = target_at(&source, &root, "weights/model.bin");
    let list = file_of(&source, &model).unwrap();
    for gone in [3, 7, 62] {
        source
            .remove(Stored::Piece, &list.items()[gone].hash)
            .unwrap();
    }
    let mut peer = TestPeer::new(&source);
    let mut remote = Remote::open(&mut peer, &root).unwrap();
    let map = remote.have(&model).unwrap();
    assert_eq!((map.count(), map.held()), (63, 60));
    let missing: Vec<u64> = (0..63).filter(|number| !map.get(*number)).collect();
    assert_eq!(missing, [3, 7, 62]);
    // 63 bits take 8 bytes, after the count.
    assert_eq!(map.encode().len(), 16);
}

#[test]
fn a_tree_goes_through_a_bundle_and_back() {
    let (temp, source, root) = sample_tree("sync-bundle");
    let mut bundle = Vec::new();
    export(&source, &root, &mut bundle).unwrap();
    assert_eq!(bundle[..8], BUNDLE_MAGIC);
    // Each thing once: 88 frames, each with four bytes for its length.
    let bytes_kept: u64 = [
        Stored::Piece,
        Stored::FileList,
        Stored::FolderList,
        Stored::Record,
    ]
    .iter()
    .map(|kind| source.bytes(*kind))
    .sum();
    assert_eq!(bundle.len() as u64, 8 + bytes_kept + 88 * 4 + 87);

    let dest = MemoryStore::new();
    let summary = import(&dest, &root, &mut bundle.as_slice()).unwrap();
    assert_eq!(summary, verify(&dest, &root).unwrap());
    assert_eq!(contents(&dest), contents(&source));
    // Into a store that holds it all already: nothing is kept twice.
    import(&dest, &root, &mut bundle.as_slice()).unwrap();
    assert_eq!(contents(&dest), contents(&source));

    // A bundle as a file on disk.
    let path = temp.path().join("tree.bundle");
    export(&source, &root, &mut fs::File::create(&path).unwrap()).unwrap();
    let from_disk = MemoryStore::new();
    import(&from_disk, &root, &mut fs::File::open(&path).unwrap()).unwrap();
    assert_eq!(contents(&from_disk), contents(&source));

    // A bundle that stops early leaves a tree that is not whole, and says so.
    for cut in [0, 7, 8, 9, 200, bundle.len() - 1] {
        let short = MemoryStore::new();
        assert!(
            import(&short, &root, &mut &bundle[..cut]).is_err(),
            "cut at {cut}"
        );
    }
    // A stream that is no bundle.
    let mut other = bundle.clone();
    other[0] ^= 1;
    assert!(import(&MemoryStore::new(), &root, &mut other.as_slice()).is_err());
    // A bundle of one tree is not taken for another.
    let wrong = Root::of_record(b"another tree");
    assert!(matches!(
        import(&MemoryStore::new(), &wrong, &mut bundle.as_slice()),
        Err(Error::HashMismatch { .. })
    ));
}

#[test]
fn a_responder_says_what_it_does_not_hold_and_what_lies_outside() {
    let (_temp, source, root) = sample_tree("sync-refusals");
    let model = target_at(&source, &root, "weights/model.bin");
    let weights = target_at(&source, &root, "weights");
    let unknown = scionic_merkletree::Hash::of(b"nobody holds this");
    let responder = Responder::new(&source);
    let answer = |request: Request| {
        let mut frames = Vec::new();
        responder
            .answer(&request.encode(), &mut |frame| {
                frames.push(frame.to_vec());
                Ok(())
            })
            .unwrap();
        frames
    };
    let refused = |request: Request, why: Refusal| {
        let frames = answer(request.clone());
        assert_eq!(frames.len(), 1, "{request:?}");
        assert_eq!(
            Frame::decode(&frames[0]).unwrap(),
            Frame::Refused(why),
            "{request:?}"
        );
    };
    for request in [
        Request::Record(Root::from_hash(unknown)),
        Request::Folder(unknown),
        Request::File(unknown),
        Request::Piece(unknown),
        Request::Have(unknown),
        Request::FolderRun {
            folder: unknown,
            start: 0,
            count: 1,
        },
        Request::FolderName {
            folder: unknown,
            name: "a".to_owned(),
        },
        Request::FileRun {
            file: unknown,
            start: 0,
            count: 1,
        },
        Request::FileBytes {
            file: unknown,
            offset: 0,
            length: 1,
        },
        Request::Pieces {
            file: unknown,
            start: 0,
            count: 1,
        },
        // A folder is not found as a file, nor a file as a folder.
        Request::File(weights.hash),
        Request::Folder(model.hash),
    ] {
        refused(request, Refusal::NotHeld);
    }
    for request in [
        Request::FolderRun {
            folder: weights.hash,
            start: 3,
            count: 1,
        },
        Request::FileRun {
            file: model.hash,
            start: 63,
            count: 1,
        },
        Request::FileBytes {
            file: model.hash,
            offset: 1_000,
            length: 1,
        },
        Request::Pieces {
            file: model.hash,
            start: 63,
            count: 1,
        },
    ] {
        refused(request, Refusal::OutOfRange);
    }

    // What reaches past the end is cut off at the end.
    let frames = answer(Request::Pieces {
        file: model.hash,
        start: 60,
        count: 10,
    });
    assert_eq!(frames.len(), 3);
    let frames = answer(Request::FileBytes {
        file: model.hash,
        offset: 990,
        length: 10_000,
    });
    let Frame::FileRun(run) = Frame::decode(&frames[0]).unwrap() else {
        panic!("no run");
    };
    assert_eq!((run.start(), run.items().len()), (61, 2));
    assert_eq!(run.check(&model, None).unwrap(), 976);

    // Pieces come in order, up to the first one that is not held.
    let list = file_of(&source, &model).unwrap();
    source
        .remove(Stored::Piece, &list.items()[12].hash)
        .unwrap();
    let frames = answer(Request::Pieces {
        file: model.hash,
        start: 10,
        count: 5,
    });
    assert_eq!(frames.len(), 3);
    assert!(matches!(
        Frame::decode(&frames[0]).unwrap(),
        Frame::Piece(_)
    ));
    assert!(matches!(
        Frame::decode(&frames[1]).unwrap(),
        Frame::Piece(_)
    ));
    assert_eq!(
        Frame::decode(&frames[2]).unwrap(),
        Frame::Refused(Refusal::NotHeld)
    );

    // A request that is malformed is an error, and gets no frame.
    let mut frames = 0;
    for request in [&[][..], &[0x30], &[0x3a; 33], &[0x37; 44]] {
        assert!(responder
            .answer(request, &mut |_| {
                frames += 1;
                Ok(())
            })
            .is_err());
    }
    assert_eq!(frames, 0);
    assert_eq!(weights.kind, Kind::Folder);
}
