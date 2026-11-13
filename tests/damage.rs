//! A tree whose bytes were harmed where they are kept: the harm is found and
//! named, it can be removed and fetched again, and nothing that a peer sends
//! can make a store give up what is sound.

mod support;

use scionic_merkletree::{
    fetch, file_of, lookup, verify, verify_with, Error, ExtraData, FileList, Hash, Intake,
    MemoryStore, PieceRef, Record, Root, Store, Stored, Totals, VerifyOptions,
};
use support::{bytes, sample_tree, small_pieces, TestPeer};

/// Puts other bytes under a hash that the store holds already.
fn swap(store: &MemoryStore, kind: Stored, hash: &Hash, bytes: &[u8]) {
    store.remove(kind, hash).unwrap();
    store.put(kind, hash, bytes).unwrap();
}

#[test]
fn a_damaged_piece_is_named_and_the_store_is_left_as_it_is() {
    let (_temp, store, root) = sample_tree("damage-named");
    let model = lookup(&store, &root, "weights/model.bin")
        .unwrap()
        .unwrap()
        .target();
    let piece = file_of(&store, &model).unwrap().items()[3];
    let rot = bytes("rot", piece.length as usize);
    swap(&store, Stored::Piece, &piece.hash, &rot);
    for workers in [0, 1, 4] {
        match verify_with(&store, &root, VerifyOptions::new().workers(workers)) {
            Err(Error::Corrupt { what, hash }) => {
                assert_eq!(what, "a stored piece");
                assert_eq!(hash, piece.hash);
            }
            other => panic!("{workers} workers: {other:?}"),
        }
    }
    // Checking changes nothing unless it is told to.
    assert_eq!(
        store.get(Stored::Piece, &piece.hash).unwrap().as_deref(),
        Some(rot.as_slice())
    );
}

#[test]
fn damage_is_removed_when_asked_and_a_fetch_makes_the_tree_whole() {
    let (_temp, source, root) = sample_tree("damage-mended");
    let dest = MemoryStore::new();
    fetch(&dest, &root, &mut TestPeer::new(&source)).unwrap();
    verify(&dest, &root).unwrap();
    let model = lookup(&dest, &root, "weights/model.bin")
        .unwrap()
        .unwrap()
        .target();
    let weights = lookup(&dest, &root, "weights").unwrap().unwrap().target();
    let list = file_of(&dest, &model).unwrap();

    // Two pieces: one harmed at its own length, one at another length.
    let (same, other) = (list.items()[1], list.items()[4]);
    swap(
        &dest,
        Stored::Piece,
        &same.hash,
        &bytes("rot-1", same.length as usize),
    );
    swap(&dest, Stored::Piece, &other.hash, &bytes("rot-2", 7));
    let discard = VerifyOptions::new().discard_damaged(true);
    assert!(matches!(
        verify_with(&dest, &root, discard),
        Err(Error::Missing {
            what: "the piece",
            ..
        })
    ));
    assert!(!dest.has(Stored::Piece, &same.hash).unwrap());
    assert!(!dest.has(Stored::Piece, &other.hash).unwrap());
    let mut peer = TestPeer::new(&source);
    fetch(&dest, &root, &mut peer).unwrap();
    verify(&dest, &root).unwrap();

    // A list and the record: checking names them, and a fetch replaces them
    // without being told to, because it cannot go on with them.
    for (kind, hash, harmed, what) in [
        (
            Stored::FolderList,
            weights.hash,
            vec![9_u8; 50],
            "a stored folder's list",
        ),
        (
            Stored::FileList,
            model.hash,
            vec![7_u8; 72],
            "a stored file's list",
        ),
        (
            Stored::Record,
            *root.as_hash(),
            vec![0x20_u8; 80],
            "a stored record",
        ),
    ] {
        swap(&dest, kind, &hash, &harmed);
        match verify(&dest, &root) {
            Err(Error::Corrupt {
                what: named,
                hash: damaged,
            }) => {
                assert_eq!(named, what);
                assert_eq!(damaged, hash);
            }
            other => panic!("{what}: {other:?}"),
        }
        fetch(&dest, &root, &mut TestPeer::new(&source)).unwrap();
        verify(&dest, &root).unwrap();
    }
}

#[test]
fn a_list_that_lies_about_a_piece_cannot_cost_a_store_the_piece() {
    // A sound piece of 16 bytes, and a file's list that gives it 15.
    let whole = bytes("sound", 16);
    let item = PieceRef::of(&whole).unwrap();
    let lying = FileList::new(vec![PieceRef { length: 15, ..item }]).unwrap();
    let totals = Totals {
        pieces: 1,
        piece_bytes: 15,
        list_bytes: 36,
    };
    let record = Record::new(lying.target(), totals, small_pieces(), ExtraData::new()).unwrap();
    let root = Root::of_record(&record.encode());
    let forger = MemoryStore::new();
    forger
        .put(Stored::Record, root.as_hash(), &record.encode())
        .unwrap();
    forger
        .put(Stored::FileList, lying.hash(), &lying.encode())
        .unwrap();

    // A holder of the piece is sent the tree. The tree is refused, and the
    // piece stays: bytes that hash to what they are kept under are sound,
    // whatever a list says of them.
    let holder = MemoryStore::new();
    holder.put(Stored::Piece, &item.hash, &whole).unwrap();
    assert!(matches!(
        fetch(&holder, &root, &mut TestPeer::new(&forger)),
        Err(Error::SizeMismatch { .. })
    ));
    assert_eq!(
        holder.get(Stored::Piece, &item.hash).unwrap().as_deref(),
        Some(whole.as_slice())
    );
    // The same when the list is in the store already.
    forger.put(Stored::Piece, &item.hash, &whole).unwrap();
    assert!(matches!(
        Intake::new(&forger, root).map(|_| ()),
        Err(Error::SizeMismatch { .. })
    ));
    assert!(matches!(
        verify_with(&forger, &root, VerifyOptions::new().discard_damaged(true)),
        Err(Error::SizeMismatch { .. })
    ));
    assert!(forger.has(Stored::Piece, &item.hash).unwrap());
}
