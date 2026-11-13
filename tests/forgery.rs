//! What a forger can try, and that each try is refused.
//!
//! The forger here is a peer that answers a receiver, a bundle that a
//! receiver reads, or whoever wrote into a receiver's store. Each test makes
//! the forgery out of bytes, as a forger would, and holds the receiver to
//! two things: it says no, and it has kept nothing that is not a true part
//! of the tree it asked for.

mod support;

use scionic_merkletree::{
    export, fetch, file_of, folder_of, import, lookup, read_file, verify, Builder, Entry, Error,
    ExtraData, FileList, FileRun, FolderList, FolderRun, Frame, Hash, Intake, Kind, MemoryStore,
    Record, Remote, Request, Responder, Result, Root, Store, Stored, Summary, Target, Totals,
    FRAME_FILE_LIST, FRAME_FILE_RUN, FRAME_FOLDER_LIST, FRAME_FOLDER_RUN, FRAME_PIECE,
    FRAME_RECORD,
};
use std::cell::Cell;
use support::oracle;
use support::{bytes, contents, sample_tree, small_pieces, ScriptedPeer, TestPeer};

fn target_at(store: &MemoryStore, root: &Root, path: &str) -> Target {
    lookup(store, root, path).unwrap().unwrap().target()
}

fn kept(store: &MemoryStore, kind: Stored, hash: &Hash) -> Vec<u8> {
    store.get(kind, hash).unwrap().unwrap().to_vec()
}

fn entry(name: &str, target: Target) -> Entry {
    Entry::new(name, target, ExtraData::new()).unwrap()
}

/// Everything a store holds has to be what its hash says it is.
fn assert_clean(store: &MemoryStore) {
    for (kind, hash, bytes) in contents(store) {
        match kind {
            Stored::Piece => assert_eq!(Hash::of(&bytes), hash),
            Stored::FileList => assert_eq!(*FileList::decode(&bytes).unwrap().hash(), hash),
            Stored::FolderList => assert_eq!(*FolderList::decode(&bytes).unwrap().hash(), hash),
            Stored::Record => {
                assert_eq!(*Root::of_record(&bytes).as_hash(), hash);
                Record::decode(&bytes).unwrap();
            }
        }
    }
}

/// Everything `dest` holds has to be a part of what `source` holds.
fn assert_only_from(dest: &MemoryStore, source: &MemoryStore) {
    assert_clean(dest);
    let honest = contents(source);
    for thing in contents(dest) {
        assert!(
            honest.contains(&thing),
            "{:?} {} was kept",
            thing.0,
            thing.1
        );
    }
}

/// Fetches a tree from a peer that changes its answers on the way.
fn fetch_tampered<'s>(
    source: &'s MemoryStore,
    root: &Root,
    tamper: impl FnMut(&[u8], Vec<Vec<u8>>) -> Vec<Vec<u8>> + 's,
) -> (Result<Summary>, MemoryStore) {
    let dest = MemoryStore::new();
    let result = {
        let mut peer = TestPeer::tampering(source, tamper);
        fetch(&dest, root, &mut peer)
    };
    assert_only_from(&dest, source);
    (result, dest)
}

fn frame_with(tag: u8, body: &[u8]) -> Vec<u8> {
    oracle::frame(tag, body)
}

#[test]
fn any_changed_byte_of_any_frame_is_refused() {
    let (_temp, source, root) = sample_tree("forge-any-byte");
    for target in 0..88_usize {
        for place in 0..3 {
            let mut seen = 0_usize;
            let (result, dest) = fetch_tampered(&source, &root, move |_, mut frames| {
                for frame in &mut frames {
                    if seen == target {
                        let at = [0, frame.len() / 2, frame.len() - 1][place];
                        frame[at] ^= 1;
                    }
                    seen += 1;
                }
                frames
            });
            assert!(result.is_err(), "frame {target}, place {place}");
            assert!(verify(&dest, &root).is_err());
        }
    }
}

#[test]
fn a_made_up_child_under_a_folder_or_a_file_is_refused() {
    let (_temp, source, root) = sample_tree("forge-child");
    let weights = target_at(&source, &root, "weights");
    let model = target_at(&source, &root, "weights/model.bin");
    let made_up = oracle::Entry::file("zz-made-up", oracle::sha(&[b"made up"]), 7);
    let made_up_item = oracle::Item::of(b"a made-up piece");

    // One more entry at the end of a folder's list, one more item at the
    // end of a file's list, and one less of each.
    type Forge = Box<dyn Fn(&[u8]) -> Option<Vec<u8>>>;
    let more_entries = made_up.bytes();
    let more_items = made_up_item.bytes();
    let forges: Vec<(&str, Forge)> = vec![
        (
            "an entry more",
            Box::new(move |frame| {
                (frame[0] == FRAME_FOLDER_LIST).then(|| [frame, &more_entries[..]].concat())
            }),
        ),
        (
            "an item more",
            Box::new(move |frame| {
                (frame[0] == FRAME_FILE_LIST && frame.len() > 1)
                    .then(|| [frame, &more_items[..]].concat())
            }),
        ),
        (
            "an entry less",
            Box::new(|frame| {
                let list = FolderList::decode(&frame[1..]).ok()?;
                let (_, rest) = list.entries().split_last()?;
                let shorter = FolderList::new(rest.to_vec()).unwrap().encode();
                (frame[0] == FRAME_FOLDER_LIST).then(|| frame_with(FRAME_FOLDER_LIST, &shorter))
            }),
        ),
        (
            "an item less",
            Box::new(|frame| {
                (frame[0] == FRAME_FILE_LIST && frame.len() > 37)
                    .then(|| frame[..frame.len() - 36].to_vec())
            }),
        ),
    ];
    for (what, forge) in forges {
        let mut done = false;
        let (result, _dest) = fetch_tampered(&source, &root, move |_, frames| {
            frames
                .into_iter()
                .map(|frame| match forge(&frame) {
                    Some(forged) if !done => {
                        done = true;
                        forged
                    }
                    _ => frame,
                })
                .collect()
        });
        // It is refused as something nothing names, or sooner, by its
        // length: a file's list may be no longer than the file's size allows.
        assert!(
            matches!(
                result,
                Err(Error::NotWanted { .. } | Error::LimitExceeded { .. })
            ),
            "{what}: {result:?}"
        );
    }

    // A part of the folder, from a peer that has made up a folder of four
    // entries which holds the three real ones. It is whole and well formed.
    // It is another folder, and the receiver asked about this one.
    let real = folder_of(&source, &weights).unwrap();
    let mut four: Vec<oracle::Entry> = real
        .entries()
        .iter()
        .map(|entry| oracle::Entry {
            kind: if entry.kind() == Kind::File { 1 } else { 2 },
            size: entry.size(),
            hash: *entry.hash().as_bytes(),
            name: entry.name().as_bytes().to_vec(),
            extra: Vec::new(),
        })
        .collect();
    four.push(made_up.clone());
    for (start, end) in [(0, 4), (3, 4), (0, 1)] {
        let forged = oracle::folder_run_frame(&four, start, end);
        let Frame::FolderRun(run) = Frame::decode(&forged).unwrap() else {
            panic!("no run");
        };
        assert!(run.check(&weights).is_err(), "{start}..{end}");
        assert!(run.check_name(&weights, "zz-made-up").is_err());
    }
    let mut peer = TestPeer::tampering(&source, move |request, frames| {
        if request[0] == 0x33 {
            vec![oracle::folder_run_frame(&four, 3, 4)]
        } else {
            frames
        }
    });
    let mut remote = Remote::open(&mut peer, &root).unwrap();
    assert!(remote.entry(&weights, "zz-made-up").is_err());
    assert!(remote.lookup("weights/zz-made-up").is_err());

    // The same for a file: a made-up list of 64 pieces that holds the real
    // 63 is another file.
    let real = file_of(&source, &model).unwrap();
    let mut longer: Vec<oracle::Item> = real
        .items()
        .iter()
        .map(|item| oracle::Item {
            hash: *item.hash.as_bytes(),
            length: item.length,
        })
        .collect();
    longer.push(made_up_item);
    for (start, end) in [(0, 64), (63, 64), (5, 6)] {
        let forged = oracle::file_run_frame(&longer, start, end);
        let run = FileRun::decode(&forged[1..]).unwrap();
        assert!(run.check(&model, None).is_err(), "{start}..{end}");
    }
}

#[test]
fn a_real_childs_opening_does_not_carry_another_child() {
    let (_temp, source, root) = sample_tree("forge-opening");
    let weights = target_at(&source, &root, "weights");
    let model = target_at(&source, &root, "weights/model.bin");
    let list = folder_of(&source, &weights).unwrap();
    let model_place = list.place_of("model.bin").unwrap();
    let honest = list.open_name("model.bin").unwrap();
    assert_eq!(
        honest
            .check_name(&weights, "model.bin")
            .unwrap()
            .unwrap()
            .name(),
        "model.bin"
    );
    let honest = honest.encode();

    // The entry that is shown starts 20 bytes into the run: its kind, its
    // size, its hash, and then its name.
    let with = |at: usize, value: u8| {
        let mut forged = honest.clone();
        forged[at] = value;
        FolderRun::decode(&forged).and_then(|run| run.check_name(&weights, "model.bin").map(|_| ()))
    };
    assert!(with(20, 2).is_err(), "the file shown as a folder");
    assert!(with(28, honest[28] ^ 1).is_err(), "another size");
    assert!(with(29, honest[29] ^ 1).is_err(), "another hash");
    assert!(with(60, honest[60] ^ 1).is_err(), "another hash");
    assert!(with(63, b'n').is_err(), "another name");
    assert!(with(15, honest[15] ^ 1).is_err(), "another place");
    assert!(with(7, honest[7] + 1).is_err(), "another count");

    // The neighbour's opening, with the neighbour passed off under the name
    // that was asked for, and the opening of the wrong place as proof that
    // the name is not there.
    let asked = Cell::new("");
    let entries: Vec<oracle::Entry> = list
        .entries()
        .iter()
        .map(|entry| oracle::Entry {
            kind: if entry.kind() == Kind::File { 1 } else { 2 },
            size: entry.size(),
            hash: *entry.hash().as_bytes(),
            name: entry.name().as_bytes().to_vec(),
            extra: Vec::new(),
        })
        .collect();
    let leaves = oracle::folder_leaves(&entries);
    for place in 0..3_usize {
        for name in [
            "model.bin",
            "copy-of-model.bin",
            "shards",
            "absent",
            "a",
            "zz",
        ] {
            asked.set(name);
            // As the place really is: right only when it is the name's place.
            let plain = oracle::folder_run_frame(&entries, place, place + 1);
            // With the entry renamed to what was asked for.
            let mut renamed = entries[place].clone();
            renamed.name = name.as_bytes().to_vec();
            let passed_off = oracle::folder_run_frame_as(
                3,
                place as u64,
                &[renamed],
                &leaves.carried(place, place + 1),
            );
            let truth = list.get(name).cloned();
            for (forged, is_plain) in [(plain, true), (passed_off, false)] {
                let mut peer = ScriptedPeer {
                    script: |request: &[u8]| {
                        if request[0] == 0x30 {
                            vec![kept(&source, Stored::Record, root.as_hash())]
                        } else {
                            vec![forged.clone()]
                        }
                    },
                };
                let mut remote = Remote::open(&mut peer, &root).unwrap();
                let answer = remote.entry(&weights, name);
                let honest_answer = is_plain && list.place_of(name) == Some(place as u64);
                let unchanged = !is_plain && entries[place].name == name.as_bytes();
                if honest_answer || (unchanged && list.place_of(name) == Some(place as u64)) {
                    assert_eq!(answer.unwrap(), truth, "{name} at {place}");
                } else {
                    assert!(answer.is_err(), "{name} at {place}, plain: {is_plain}");
                }
            }
        }
    }
    assert_eq!(model_place, 1);

    // A file's run with one item changed, and the run of other pieces than
    // those that hold the bytes asked for.
    let file_list = file_of(&source, &model).unwrap();
    let run = file_list.open(6, 9).unwrap().encode();
    assert_eq!(
        FileRun::decode(&run).unwrap().check(&model, None).unwrap(),
        96
    );
    for at in [20, 51, 52, 55] {
        let mut forged = run.clone();
        forged[at] ^= 1;
        let checked = FileRun::decode(&forged).and_then(|run| run.check(&model, None));
        assert!(checked.is_err(), "byte {at}");
    }
    let elsewhere = frame_with(FRAME_FILE_RUN, &file_list.open(0, 3).unwrap().encode());
    let mut peer = TestPeer::tampering(&source, move |request, frames| {
        if request[0] == 0x36 {
            vec![elsewhere.clone()]
        } else {
            frames
        }
    });
    let mut remote = Remote::open(&mut peer, &root).unwrap();
    let mut out = Vec::new();
    assert!(matches!(
        remote.read(&model, 100, 40, &mut out),
        Err(Error::NotWanted { .. })
    ));
    assert!(out.is_empty());
}

#[test]
fn a_file_is_never_taken_for_a_folder_nor_a_list_for_a_piece() {
    let (_temp, source, root) = sample_tree("forge-kinds");
    let weights = target_at(&source, &root, "weights");
    let model = target_at(&source, &root, "weights/model.bin");
    let file_frame = frame_with(
        FRAME_FILE_LIST,
        &kept(&source, Stored::FileList, &model.hash),
    );
    let folder_frame = frame_with(
        FRAME_FOLDER_LIST,
        &kept(&source, Stored::FolderList, &weights.hash),
    );
    let piece_frame = frame_with(FRAME_PIECE, &bytes("model", 16));

    // Each kind of question, answered with a true part of the tree that is
    // of another kind.
    for (asked, answers) in [
        (0x31, [&file_frame, &piece_frame]),
        (0x34, [&folder_frame, &piece_frame]),
        (0x37, [&file_frame, &folder_frame]),
    ] {
        for answer in answers {
            let answer = answer.clone();
            let mut done = false;
            let (result, _dest) = fetch_tampered(&source, &root, move |request, frames| {
                if request[0] == asked && !done {
                    done = true;
                    vec![answer.clone()]
                } else {
                    frames
                }
            });
            assert!(result.is_err(), "{asked:#x}");
        }
    }

    // A file's entry, shown as a folder's: the kind is part of the entry.
    let top = scionic_merkletree::record_of(&source, &root).unwrap().top();
    let mut flipped = kept(&source, Stored::FolderList, &top.hash);
    let list = folder_of(&source, &top).unwrap();
    let before: usize = list.entries()[..1].iter().map(Entry::encoded_len).sum();
    assert_eq!(list.entries()[1].name(), "empty.bin");
    assert_eq!(flipped[before], 1);
    flipped[before] = 2;
    assert!(FolderList::decode(&flipped).is_ok());
    let flipped = frame_with(FRAME_FOLDER_LIST, &flipped);
    let (result, _dest) = fetch_tampered(&source, &root, move |request, frames| {
        if request[0] == 0x31 {
            vec![flipped.clone()]
        } else {
            frames
        }
    });
    assert!(matches!(result, Err(Error::NotWanted { .. })));

    // A file whose bytes are another file's list, to the letter. It is kept
    // as a piece, under the plain hash of its bytes, and never as a list.
    let list_bytes = kept(&source, Stored::FileList, &model.hash);
    let store = MemoryStore::new();
    let mut builder = Builder::new(&store, scionic_merkletree::Cutting::fixed(4096).unwrap());
    let odd = builder.file_from_bytes(&list_bytes).unwrap();
    let odd_root = builder.finish(odd, ExtraData::new()).unwrap();
    let dest = MemoryStore::new();
    fetch(&dest, &odd_root, &mut TestPeer::new(&store)).unwrap();
    let plain = Hash::of(&list_bytes);
    assert!(dest.has(Stored::Piece, &plain).unwrap());
    assert!(!dest.has(Stored::FileList, &plain).unwrap());
    assert!(!dest.has(Stored::FileList, &model.hash).unwrap());
    assert_ne!(plain, model.hash);
}

#[test]
fn a_file_is_not_given_another_files_pieces() {
    let (_temp, source, root) = sample_tree("forge-pieces");
    let model = target_at(&source, &root, "weights/model.bin");
    let shard = target_at(&source, &root, "weights/shards/a.bin");
    let shard_pieces: Vec<Vec<u8>> = file_of(&source, &shard)
        .unwrap()
        .items()
        .iter()
        .map(|item| frame_with(FRAME_PIECE, &kept(&source, Stored::Piece, &item.hash)))
        .collect();

    // A whole fetch: the pieces of one file, sent when another file's were
    // asked for. They are true pieces of the tree, and they are not what
    // was asked for.
    let pieces = shard_pieces.clone();
    let (result, _dest) =
        fetch_tampered(
            &source,
            &root,
            move |request, frames| match Request::decode(request).unwrap() {
                Request::Pieces { file, .. } if file == model.hash => pieces.clone(),
                _ => frames,
            },
        );
    assert!(matches!(result, Err(Error::NotWanted { .. })));

    // A stretch of one file, answered with another file's pieces, and with
    // the file's own pieces in another order.
    for swap in [false, true] {
        let pieces = shard_pieces.clone();
        let mut peer = TestPeer::tampering(&source, move |request, mut frames| {
            if request[0] != 0x37 {
                return frames;
            }
            if swap {
                frames.swap(0, 1);
                frames
            } else {
                pieces.clone()
            }
        });
        let mut remote = Remote::open(&mut peer, &root).unwrap();
        let mut out = Vec::new();
        assert!(
            remote.read(&model, 0, 64, &mut out).is_err(),
            "swap: {swap}"
        );
        assert!(out.is_empty(), "no byte of another piece is handed out");
    }

    // A stretch of one file, answered with the run of another file's list.
    let other_run = frame_with(
        FRAME_FILE_RUN,
        &file_of(&source, &shard)
            .unwrap()
            .open(0, 4)
            .unwrap()
            .encode(),
    );
    let mut peer = TestPeer::tampering(&source, move |request, frames| {
        if request[0] == 0x36 {
            vec![other_run.clone()]
        } else {
            frames
        }
    });
    let mut remote = Remote::open(&mut peer, &root).unwrap();
    let mut out = Vec::new();
    assert!(remote.read(&model, 0, 64, &mut out).is_err());
    assert!(out.is_empty());
}

#[test]
fn a_record_for_another_root_is_refused() {
    let (_temp, source, root) = sample_tree("forge-record");
    let mut builder = Builder::new(&source, small_pieces());
    let other_file = builder.file_from_bytes(b"another tree").unwrap();
    let other = builder.finish(other_file, ExtraData::new()).unwrap();
    let other_record = kept(&source, Stored::Record, other.as_hash());

    let forged = other_record.clone();
    let (result, dest) = fetch_tampered(&source, &root, move |request, frames| {
        if request[0] == 0x30 {
            vec![forged.clone()]
        } else {
            frames
        }
    });
    assert!(matches!(result, Err(Error::HashMismatch { .. })));
    assert_eq!(contents(&dest), Vec::new(), "nothing is kept");

    let forged = other_record.clone();
    let mut peer = TestPeer::tampering(&source, move |_, _| vec![forged.clone()]);
    assert!(matches!(
        Remote::open(&mut peer, &root),
        Err(Error::HashMismatch { .. })
    ));
    // The record that was asked for, with one of its totals changed.
    let mut changed = kept(&source, Stored::Record, root.as_hash());
    changed[45] ^= 1;
    let mut peer = TestPeer::tampering(&source, move |_, _| vec![changed.clone()]);
    assert!(Remote::open(&mut peer, &root).is_err());
}

#[test]
fn nothing_is_kept_before_it_is_tied_to_the_root() {
    let (_temp, source, root) = sample_tree("forge-order");
    let top = scionic_merkletree::record_of(&source, &root).unwrap().top();
    let readme = target_at(&source, &root, "readme.txt");
    let shard = target_at(&source, &root, "weights/shards/a.bin");
    let record = kept(&source, Stored::Record, root.as_hash());
    let top_list = frame_with(
        FRAME_FOLDER_LIST,
        &kept(&source, Stored::FolderList, &top.hash),
    );
    let readme_list = frame_with(
        FRAME_FILE_LIST,
        &kept(&source, Stored::FileList, &readme.hash),
    );
    let readme_piece = frame_with(FRAME_PIECE, b"a small file");
    let deep_list = frame_with(
        FRAME_FILE_LIST,
        &kept(&source, Stored::FileList, &shard.hash),
    );
    let made_up_piece = frame_with(FRAME_PIECE, b"no part of this tree");

    let dest = MemoryStore::new();
    let refused = |frame: &[u8], what: &str| {
        let before = contents(&dest);
        let mut intake = Intake::new(&dest, root).unwrap();
        let verdict = intake.accept(frame);
        assert!(
            matches!(verdict, Err(Error::NotWanted { .. })),
            "{what}: {verdict:?}"
        );
        assert_eq!(contents(&dest), before, "{what}: something was kept");
    };
    let taken = |frame: &[u8], what: &str| {
        let mut intake = Intake::new(&dest, root).unwrap();
        assert!(intake.accept(frame).unwrap().kept, "{what}");
        // The same thing again is passed over, and not kept twice.
        let before = contents(&dest);
        assert!(!intake.accept(frame).unwrap().kept, "{what}, again");
        assert_eq!(contents(&dest), before);
    };

    // Before the record, nothing is tied to anything.
    for (frame, what) in [
        (&top_list, "the top folder"),
        (&readme_list, "a file's list"),
        (&readme_piece, "a piece"),
    ] {
        refused(frame, what);
    }
    assert!(Intake::new(&dest, root).unwrap().record().is_none());
    taken(&record, "the record");
    // The record's totals are there to be looked at before anything more is
    // taken.
    let intake = Intake::new(&dest, root).unwrap();
    assert_eq!(intake.record().unwrap().totals().pieces, 76);
    assert_eq!(intake.outstanding(), 1, "the top folder");

    // After the record, only the top folder is named.
    refused(&readme_list, "a file's list before its folder");
    refused(&readme_piece, "a piece before its file's list");
    refused(&deep_list, "a list from further down");
    taken(&top_list, "the top folder");
    // Now the top folder's files are named, and their pieces are not yet.
    refused(&readme_piece, "a piece before its file's list");
    refused(&deep_list, "a list from further down");
    refused(&made_up_piece, "a made-up piece");
    taken(&readme_list, "a file's list");
    refused(&made_up_piece, "a made-up piece");
    taken(&readme_piece, "a piece");

    assert_only_from(&dest, &source);
    assert!(matches!(
        Intake::new(&dest, root).unwrap().finish(),
        Err(Error::Missing { .. })
    ));

    // A bundle with a made-up piece in it is refused where the piece comes,
    // be the piece as long as a piece of this tree or longer.
    let mut bundle = Vec::new();
    export(&source, &root, &mut bundle).unwrap();
    let short_piece = frame_with(FRAME_PIECE, b"not of this tree");
    for piece in [&short_piece, &made_up_piece] {
        let mut extra = bundle.clone();
        extra.extend_from_slice(&(piece.len() as u32).to_be_bytes());
        extra.extend_from_slice(piece);
        let fresh = MemoryStore::new();
        assert!(matches!(
            import(&fresh, &root, &mut extra.as_slice()),
            Err(Error::NotWanted { .. })
        ));
        assert_only_from(&fresh, &source);
    }
    // And one whose first list comes before its record.
    let mut early = bundle[..8].to_vec();
    early.extend_from_slice(&(top_list.len() as u32).to_be_bytes());
    early.extend_from_slice(&top_list);
    early.extend_from_slice(&bundle[8..]);
    let fresh = MemoryStore::new();
    assert!(import(&fresh, &root, &mut early.as_slice()).is_err());
    assert_eq!(contents(&fresh), Vec::new());
}

#[test]
fn a_peer_whose_own_store_is_wrong_is_found_out() {
    let (_temp, source, root) = sample_tree("forge-store");
    let model = target_at(&source, &root, "weights/model.bin");
    let shard = target_at(&source, &root, "weights/shards/a.bin");
    let weights = target_at(&source, &root, "weights");
    let data = target_at(&source, &root, "data");
    let piece = file_of(&source, &model).unwrap().items()[9];
    let cases = [
        (Stored::Piece, piece.hash, bytes("wrong", 16)),
        (
            Stored::FileList,
            model.hash,
            kept(&source, Stored::FileList, &shard.hash),
        ),
        (
            Stored::FolderList,
            weights.hash,
            kept(&source, Stored::FolderList, &data.hash),
        ),
    ];
    for (kind, hash, wrong) in cases {
        let honest = kept(&source, kind, &hash);
        source.remove(kind, &hash).unwrap();
        source.put(kind, &hash, &wrong).unwrap();
        // One set of checks: the same forgery is refused in the store that
        // holds it, and by whoever fetches from that store.
        assert!(verify(&source, &root).is_err(), "{kind:?}");
        let dest = MemoryStore::new();
        assert!(
            fetch(&dest, &root, &mut TestPeer::new(&source)).is_err(),
            "{kind:?}"
        );
        assert_clean(&dest);
        assert!(
            !dest.has(kind, &hash).unwrap(),
            "{kind:?}: the forged part was kept"
        );
        source.remove(kind, &hash).unwrap();
        source.put(kind, &hash, &honest).unwrap();
    }
    verify(&source, &root).unwrap();
}

#[test]
fn a_file_never_comes_back_short() {
    let (_temp, source, root) = sample_tree("forge-short");
    let model = target_at(&source, &root, "weights/model.bin");
    let list = file_of(&source, &model).unwrap();
    let last = *list.items().last().unwrap();

    // A peer that never sends the file's last piece.
    let (result, dest) = fetch_tampered(&source, &root, move |_, frames| {
        frames
            .into_iter()
            .filter(|frame| frame[0] != FRAME_PIECE || Hash::of(&frame[1..]) != last.hash)
            .collect()
    });
    assert!(matches!(result, Err(Error::Peer { .. })));
    let mut out = Vec::new();
    assert!(matches!(
        read_file(&dest, &model, &mut out),
        Err(Error::Missing { .. })
    ));
    assert!(out.is_empty(), "an error, and never a shorter file");
    assert!(verify(&dest, &root).is_err());

    // The last piece, one byte short.
    let (result, _dest) = fetch_tampered(&source, &root, move |_, frames| {
        frames
            .into_iter()
            .map(|mut frame| {
                if frame[0] == FRAME_PIECE && Hash::of(&frame[1..]) == last.hash {
                    frame.pop();
                }
                frame
            })
            .collect()
    });
    assert!(result.is_err());

    // A made-up file that is the real one without its last piece. It is
    // whole and well formed, it is shorter, and it is another file.
    let shorter: Vec<oracle::Item> = list.items()[..62]
        .iter()
        .map(|item| oracle::Item {
            hash: *item.hash.as_bytes(),
            length: item.length,
        })
        .collect();
    let shorter_list = frame_with(FRAME_FILE_LIST, &oracle::file_list_bytes(&shorter));
    let (result, _dest) =
        fetch_tampered(
            &source,
            &root,
            move |request, frames| match Request::decode(request).unwrap() {
                Request::File(file) if file == model.hash => vec![shorter_list.clone()],
                _ => frames,
            },
        );
    assert!(matches!(result, Err(Error::NotWanted { .. })));
    let shorter_run = oracle::file_run_frame(&shorter, 0, 62);
    let mut peer = TestPeer::tampering(&source, move |request, frames| {
        if request[0] == 0x36 {
            vec![shorter_run.clone()]
        } else {
            frames
        }
    });
    let mut remote = Remote::open(&mut peer, &root).unwrap();
    let mut out = Vec::new();
    assert!(remote.read(&model, 0, 1_000, &mut out).is_err());
    assert!(out.is_empty());

    // A peer that sends fewer pieces than a stretch needs, and then none.
    let mut sent = 0;
    let mut peer = TestPeer::tampering(&source, move |request, frames| {
        if request[0] != 0x37 {
            return frames;
        }
        let keep = frames.len().min(3 - sent);
        sent += keep;
        frames.into_iter().take(keep).collect()
    });
    let mut remote = Remote::open(&mut peer, &root).unwrap();
    let mut out = Vec::new();
    assert!(matches!(
        remote.read(&model, 0, 1_000, &mut out),
        Err(Error::Peer { .. })
    ));
}

#[test]
fn one_name_has_one_place_in_a_folder() {
    // A folder made by an author who put its entries out of order on
    // purpose, with one name twice. The library makes no such folder, so it
    // is hashed here by hand, to the letter of the format.
    let hash = |seed: &str| oracle::sha(&[seed.as_bytes()]);
    for names in [
        vec!["b", "a", "b", "c"],
        vec!["a", "b", "b", "c"],
        vec!["c", "b", "a"],
        vec!["b", "b"],
        vec!["a", "c", "b", "d", "a", "e", "b"],
    ] {
        let entries: Vec<oracle::Entry> = names
            .iter()
            .enumerate()
            .map(|(place, name)| oracle::Entry::file(name, hash(&format!("{name}{place}")), 1))
            .collect();
        let (folder_hash, size) = oracle::folder_hash(&entries);
        let folder = Target {
            kind: Kind::Folder,
            hash: Hash::from_bytes(folder_hash),
            size,
        };
        let record = oracle::record_bytes(
            2,
            size,
            &folder_hash,
            (0, 0, oracle::folder_list_bytes(&entries).len() as u64),
            &oracle::cut_tag("fixed-16"),
        );
        let root = Root::of_record(&record);

        // Whole, the list is refused as soon as it is read.
        let whole = frame_with(FRAME_FOLDER_LIST, &oracle::folder_list_bytes(&entries));
        let dest = MemoryStore::new();
        let mut intake = Intake::new(&dest, root).unwrap();
        intake.accept(&record).unwrap();
        assert!(matches!(
            intake.accept(&whole),
            Err(Error::InvalidData { .. })
        ));
        assert_eq!(dest.count(Stored::FolderList), 0);

        // In part, the author shows whichever place suits him. For each
        // name at most one place is ever accepted, so two entries under one
        // name are never both shown.
        let place = Cell::new(0_usize);
        for name in ["a", "b", "c", "d", "e", "f"] {
            let mut accepted = Vec::new();
            for shown in 0..entries.len() {
                place.set(shown);
                let mut peer = ScriptedPeer {
                    script: |request: &[u8]| {
                        if request[0] == 0x30 {
                            vec![record.clone()]
                        } else {
                            vec![oracle::folder_run_frame(
                                &entries,
                                place.get(),
                                place.get() + 1,
                            )]
                        }
                    },
                };
                let mut remote = Remote::open(&mut peer, &root).unwrap();
                if let Ok(answer) = remote.entry(&folder, name) {
                    accepted.push((shown, answer.map(|entry| *entry.hash())));
                }
            }
            assert!(
                accepted.len() <= 1,
                "{names:?}: {name} answered at {accepted:?}"
            );
        }

        // A run of several entries is accepted only where each of them is
        // at its name's one place: never a run that shows a name twice.
        for start in 0..entries.len() {
            for end in start + 1..=entries.len() {
                let frame = oracle::folder_run_frame(&entries, start, end);
                let Ok(Frame::FolderRun(run)) = Frame::decode(&frame) else {
                    continue;
                };
                if run.check(&folder).is_ok() {
                    let shown: Vec<&str> = run.entries().iter().map(Entry::name).collect();
                    let mut unique = shown.clone();
                    unique.dedup();
                    assert_eq!(shown, unique);
                    assert!(shown.windows(2).all(|pair| pair[0] < pair[1]));
                }
            }
        }
    }
}

#[test]
fn no_place_exists_beyond_the_count_and_a_fork_is_no_leaf() {
    let pieces: Vec<Vec<u8>> = (0..5)
        .map(|index| bytes(&format!("p{index}"), 16))
        .collect();
    let items: Vec<oracle::Item> = pieces.iter().map(|piece| oracle::Item::of(piece)).collect();
    let (hash, size) = oracle::file_hash(&items);
    let file = Target {
        kind: Kind::File,
        hash: Hash::from_bytes(hash),
        size,
    };
    let check = |frame: &[u8]| FileRun::decode(&frame[1..]).and_then(|run| run.check(&file, None));
    assert_eq!(check(&oracle::file_run_frame(&items, 4, 5)).unwrap(), 64);

    // The last piece, shown again at the place after the last. A tree that
    // fills up a level by repeating its last leaf would take this.
    let carried = oracle::file_leaves(&items).carried(4, 5);
    for (count, start) in [(5, 5), (6, 5), (6, 4), (4, 4), (8, 7)] {
        let forged = oracle::file_run_frame_as(count, start, &items[4..], &carried);
        assert!(check(&forged).is_err(), "as {count} pieces, at {start}");
    }
    // A file of six pieces whose sixth is the fifth again is another file.
    let mut six = items.clone();
    six.push(items[4].clone());
    assert_ne!(oracle::file_hash(&six).0, hash);
    assert_ne!(
        oracle::file_leaves(&six).top().0,
        oracle::file_leaves(&items).top().0
    );
    for (start, end) in [(0, 6), (5, 6), (4, 5)] {
        assert!(check(&oracle::file_run_frame(&six, start, end)).is_err());
    }

    // A fork passed off as a piece: a file of two "pieces" that are the
    // two forks under the top of a file of four.
    let four = &items[..4];
    let leaves = oracle::file_leaves(four);
    let (four_hash, four_size) = oracle::file_hash(four);
    let four_file = Target {
        kind: Kind::File,
        hash: Hash::from_bytes(four_hash),
        size: four_size,
    };
    let forks: Vec<oracle::Item> = [leaves.node(0, 2), leaves.node(2, 2)]
        .iter()
        .map(|(hash, size)| oracle::Item {
            hash: *hash,
            length: *size as u32,
        })
        .collect();
    let as_two = oracle::file_run_frame(&forks, 0, 2);
    let run = FileRun::decode(&as_two[1..]).unwrap();
    assert!(run.check(&four_file, None).is_err());
    assert_ne!(oracle::file_hash(&forks).0, four_hash);
    // And a leaf passed off as a fork: the top of a file of one piece is
    // never the top of a file of two.
    let one = &items[..1];
    assert_ne!(
        oracle::file_leaves(one).top().0,
        oracle::file_leaves(&items[..2]).top().0
    );
}

#[test]
fn a_tree_that_holds_more_than_its_record_says_is_stopped() {
    let (_temp, source, root) = sample_tree("forge-totals");
    let record = scionic_merkletree::record_of(&source, &root).unwrap();
    let right = record.totals();
    for (field, totals) in [
        (
            "pieces",
            Totals {
                pieces: right.pieces - 1,
                ..right
            },
        ),
        (
            "piece bytes",
            Totals {
                piece_bytes: right.piece_bytes - 16,
                ..right
            },
        ),
        (
            "list bytes",
            Totals {
                list_bytes: right.list_bytes - 1,
                ..right
            },
        ),
    ] {
        let forged = Record::new(record.top(), totals, record.cutting(), ExtraData::new()).unwrap();
        let forged_root = forged.root();
        source
            .put(Stored::Record, forged_root.as_hash(), &forged.encode())
            .unwrap();
        let dest = MemoryStore::new();
        match fetch(&dest, &forged_root, &mut TestPeer::new(&source)) {
            Err(Error::TotalsMismatch { field: named, .. }) => assert_eq!(named, field),
            other => panic!("{totals:?}: {other:?}"),
        }
        assert_clean(&dest);
    }
}

#[test]
fn a_tree_that_is_too_deep_is_refused_however_it_arrives() {
    let source = MemoryStore::new();
    let mut builder = Builder::new(&source, small_pieces());
    let file = builder.file_from_bytes(b"at the bottom").unwrap();
    let mut inner = builder.folder(vec![entry("file", file)]).unwrap();
    for _ in 1..128 {
        inner = builder.folder(vec![entry("d", inner)]).unwrap();
    }
    let deepest_allowed = builder.finish(inner, ExtraData::new()).unwrap();
    let totals = verify(&source, &deepest_allowed).unwrap().record.totals();

    // One folder more, and a record for it written without the builder.
    let over = FolderList::new(vec![entry("d", inner)]).unwrap();
    source
        .put(Stored::FolderList, over.hash(), &over.encode())
        .unwrap();
    let forged = Record::new(
        over.target(),
        Totals {
            list_bytes: totals.list_bytes + over.encoded_len(),
            ..totals
        },
        small_pieces(),
        ExtraData::new(),
    )
    .unwrap();
    let forged_root = forged.root();
    source
        .put(Stored::Record, forged_root.as_hash(), &forged.encode())
        .unwrap();

    assert!(matches!(
        verify(&source, &forged_root),
        Err(Error::TooDeep { limit: 128 })
    ));
    let dest = MemoryStore::new();
    assert!(matches!(
        fetch(&dest, &forged_root, &mut TestPeer::new(&source)),
        Err(Error::TooDeep { limit: 128 })
    ));
    let mut bundle = Vec::new();
    assert!(matches!(export(&source, &forged_root, &mut bundle), Ok(())));
    let dest = MemoryStore::new();
    assert!(matches!(
        import(&dest, &forged_root, &mut bundle.as_slice()),
        Err(Error::TooDeep { limit: 128 })
    ));
    assert!(scionic_merkletree::write_to_disk(
        &source,
        &forged_root,
        std::env::temp_dir().join("scionic-never-written")
    )
    .is_err());
    assert!(lookup(&source, &forged_root, &["d"; 130].join("/")).is_err());
}

#[test]
fn malformed_input_is_an_error_and_never_a_crash() {
    let (_temp, source, root) = sample_tree("forge-malformed");
    let top = scionic_merkletree::record_of(&source, &root).unwrap().top();
    let model = target_at(&source, &root, "weights/model.bin");
    let weights = target_at(&source, &root, "weights");
    let record = kept(&source, Stored::Record, root.as_hash());
    let honest: Vec<Vec<u8>> = vec![
        record.clone(),
        frame_with(
            FRAME_FOLDER_LIST,
            &kept(&source, Stored::FolderList, &top.hash),
        ),
        frame_with(
            FRAME_FILE_LIST,
            &kept(&source, Stored::FileList, &model.hash),
        ),
        frame_with(FRAME_PIECE, b"a small file"),
        frame_with(
            FRAME_FILE_RUN,
            &file_of(&source, &model)
                .unwrap()
                .open(3, 9)
                .unwrap()
                .encode(),
        ),
        frame_with(
            FRAME_FOLDER_RUN,
            &folder_of(&source, &weights)
                .unwrap()
                .open(1, 2)
                .unwrap()
                .encode(),
        ),
        frame_with(0x26, &[0, 0, 0, 0, 0, 0, 0, 9, 0xff, 0x80]),
        vec![0x27, 1],
    ];
    assert_eq!(honest[0][0], FRAME_RECORD);

    // Every way of cutting a frame short, and every single byte of it
    // changed in three ways.
    let mut forged: Vec<Vec<u8>> = Vec::new();
    for frame in &honest {
        let step = (frame.len() / 400).max(1);
        for cut in (0..frame.len()).step_by(step) {
            forged.push(frame[..cut].to_vec());
        }
        for at in (0..frame.len()).step_by(step) {
            for change in [1_u8, 0x80, 0xff] {
                let mut changed = frame.clone();
                changed[at] ^= change;
                forged.push(changed);
            }
        }
        forged.push([frame.clone(), vec![0]].concat());
    }
    // And bytes that are nothing at all.
    for length in [1, 2, 20, 36, 37, 45, 66, 100, 500] {
        for seed in 0..8 {
            for tag in [
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x30, 0x33, 0x36, 0xff,
            ] {
                let mut noise = bytes(&format!("noise-{seed}"), length);
                noise[0] = tag;
                forged.push(noise);
            }
        }
    }

    let responder = Responder::new(&source);
    let dest = MemoryStore::new();
    Intake::new(&dest, root).unwrap().accept(&record).unwrap();
    for frame in &forged {
        let _ = Frame::decode(frame);
        let _ = Request::decode(frame);
        let _ = Record::decode(frame);
        let _ = FileList::decode(frame);
        let _ = FolderList::decode(frame);
        let _ = FileRun::decode(frame).map(|run| run.check(&model, None));
        let _ = FolderRun::decode(frame).map(|run| {
            let _ = run.check(&weights);
            run.check_name(&weights, "model.bin").map(|_| ())
        });
        let _ = Root::parse(&String::from_utf8_lossy(frame));
        let _ = responder.answer(frame, &mut |_| Ok(()));
        let _ = Intake::new(&dest, root).unwrap().accept(frame);
        let mut bundle = scionic_merkletree::BUNDLE_MAGIC.to_vec();
        bundle.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        bundle.extend_from_slice(frame);
        let _ = import(&MemoryStore::new(), &root, &mut bundle.as_slice());
        let _ = import(&MemoryStore::new(), &root, &mut frame.as_slice());
    }
    assert!(forged.len() > 5_000);
    // Whatever got through was a true part of the tree.
    assert_only_from(&dest, &source);
    let _ = (
        kept(&source, Stored::Record, root.as_hash()),
        verify(&source, &root).unwrap(),
    );
}
