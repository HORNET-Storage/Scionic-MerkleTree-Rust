//! Checking a whole tree that a store holds.

mod support;

use scionic_merkletree::{
    file_of, folder_of, lookup, record_of, verify, verify_with, Builder, ChunkRef, Chunking, Entry,
    Error, ExtraData, FileList, Hash, MemoryStore, Record, Root, Store, Stored, Target, Totals,
    VerifyOptions,
};
use support::{bytes, sample_tree, small_chunks};

/// Puts other bytes under a hash that the store holds already.
fn swap(store: &MemoryStore, kind: Stored, hash: &Hash, bytes: &[u8]) {
    store.remove(kind, hash).unwrap();
    store.put(kind, hash, bytes).unwrap();
}

fn kept(store: &MemoryStore, kind: Stored, hash: &Hash) -> Vec<u8> {
    store.get(kind, hash).unwrap().unwrap().to_vec()
}

fn entry(name: &str, target: Target) -> Entry {
    Entry::new(name, target, ExtraData::new()).unwrap()
}

#[test]
fn a_whole_tree_checks_and_a_missing_part_is_named() {
    let (_temp, store, root) = sample_tree("verify-missing");
    verify(&store, &root).unwrap();
    verify_with(&store, &root, VerifyOptions::new().rechunk(true)).unwrap();

    let model = lookup(&store, &root, "weights/model.bin")
        .unwrap()
        .unwrap()
        .target();
    let weights = lookup(&store, &root, "weights").unwrap().unwrap().target();
    let chunk = file_of(&store, &model).unwrap().items()[5];
    for (kind, hash, what) in [
        (Stored::Chunk, chunk.hash, "the chunk"),
        (Stored::FileList, model.hash, "the list of the file"),
        (Stored::FolderList, weights.hash, "the list of the folder"),
        (Stored::Record, *root.as_hash(), "the record of"),
    ] {
        let bytes = kept(&store, kind, &hash);
        store.remove(kind, &hash).unwrap();
        match verify(&store, &root) {
            Err(Error::Missing {
                what: named,
                hash: missing,
            }) => {
                assert_eq!(named, what);
                assert_eq!(missing, hash);
            }
            other => panic!("{what} was not missed: {other:?}"),
        }
        store.put(kind, &hash, &bytes).unwrap();
        verify(&store, &root).unwrap();
    }
}

#[test]
fn bytes_that_changed_in_the_store_are_found() {
    let (_temp, store, root) = sample_tree("verify-changed");
    let model = lookup(&store, &root, "weights/model.bin")
        .unwrap()
        .unwrap()
        .target();
    let shard = lookup(&store, &root, "weights/shards/a.bin")
        .unwrap()
        .unwrap()
        .target();
    let weights = lookup(&store, &root, "weights").unwrap().unwrap().target();
    let data = lookup(&store, &root, "data").unwrap().unwrap().target();
    let chunk = file_of(&store, &model).unwrap().items()[5];

    let cases: Vec<(Stored, Hash, Vec<u8>, &str)> = vec![
        (
            Stored::Chunk,
            chunk.hash,
            bytes("other", 16),
            "a chunk's bytes",
        ),
        (
            Stored::Chunk,
            chunk.hash,
            bytes("other", 15),
            "a chunk cut short",
        ),
        (
            Stored::Chunk,
            chunk.hash,
            bytes("other", 17),
            "a chunk made longer",
        ),
        (
            Stored::FileList,
            model.hash,
            kept(&store, Stored::FileList, &shard.hash),
            "another file's list",
        ),
        (Stored::FileList, model.hash, vec![7; 35], "no list at all"),
        (
            Stored::FolderList,
            weights.hash,
            kept(&store, Stored::FolderList, &data.hash),
            "another folder's list",
        ),
        (
            Stored::FolderList,
            weights.hash,
            vec![9; 50],
            "no list at all",
        ),
        (
            Stored::Record,
            *root.as_hash(),
            vec![0x20; 80],
            "another record",
        ),
    ];
    for (kind, hash, forged, what) in cases {
        let honest = kept(&store, kind, &hash);
        swap(&store, kind, &hash, &forged);
        let verdict = verify(&store, &root);
        assert!(
            matches!(
                verdict,
                Err(Error::Corrupt { .. } | Error::SizeMismatch { .. } | Error::InvalidData { .. })
            ),
            "{what}: {verdict:?}"
        );
        swap(&store, kind, &hash, &honest);
        verify(&store, &root).unwrap();
    }
}

#[test]
fn a_record_with_wrong_totals_is_refused() {
    let (_temp, store, root) = sample_tree("verify-totals");
    let record = record_of(&store, &root).unwrap();
    let right = record.totals();
    let wrong = [
        (
            "chunks",
            Totals {
                chunks: right.chunks - 1,
                ..right
            },
        ),
        (
            "chunks",
            Totals {
                chunks: right.chunks + 1,
                ..right
            },
        ),
        (
            "chunk bytes",
            Totals {
                chunk_bytes: right.chunk_bytes - 1,
                ..right
            },
        ),
        (
            "chunk bytes",
            Totals {
                chunk_bytes: right.chunk_bytes + 1,
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
        (
            "list bytes",
            Totals {
                list_bytes: right.list_bytes + 1,
                ..right
            },
        ),
    ];
    for (field, totals) in wrong {
        let forged =
            Record::new(record.top(), totals, record.chunking(), ExtraData::new()).unwrap();
        let forged_root = forged.root();
        assert_ne!(forged_root, root);
        store
            .put(Stored::Record, forged_root.as_hash(), &forged.encode())
            .unwrap();
        match verify(&store, &forged_root) {
            Err(Error::TotalsMismatch { field: named, .. }) => assert_eq!(named, field),
            other => panic!("{totals:?} passed: {other:?}"),
        }
    }
}

#[test]
fn an_entry_cannot_give_what_is_under_it_another_size() {
    let store = MemoryStore::new();
    let mut builder = Builder::new(&store, small_chunks());
    let file = builder.file_from_bytes(&bytes("sized", 70)).unwrap();
    let folder = builder.folder(vec![entry("f", file)]).unwrap();
    let grown = |target: Target| Target {
        size: target.size + 1,
        ..target
    };

    let cases = [
        vec![entry("f", grown(file))],
        vec![entry("d", grown(folder))],
        // The same file under two names, once with its size and once not.
        vec![entry("a", file), entry("b", grown(file))],
        vec![entry("a", grown(file)), entry("b", file)],
    ];
    for entries in cases {
        let mut builder = Builder::new(&store, small_chunks());
        let top = builder.folder(entries.clone()).unwrap();
        let verdict = builder.finish(top, ExtraData::new());
        assert!(
            matches!(verdict, Err(Error::SizeMismatch { .. })),
            "{entries:?}: {verdict:?}"
        );
    }
    let mut builder = Builder::new(&store, small_chunks());
    let top = builder
        .folder(vec![entry("d", folder), entry("f", file)])
        .unwrap();
    let root = builder.finish(top, ExtraData::new()).unwrap();
    assert_eq!(verify(&store, &root).unwrap().record.top().size, 140);
}

/// Puts a file into a store by hand, with whatever chunks it is given.
fn file_by_hand(store: &MemoryStore, chunks: &[&[u8]]) -> Target {
    let mut items = Vec::new();
    for chunk in chunks {
        let item = ChunkRef::of(chunk).unwrap();
        store.put(Stored::Chunk, &item.hash, chunk).unwrap();
        items.push(item);
    }
    let list = FileList::new(items).unwrap();
    store
        .put(Stored::FileList, list.hash(), &list.encode())
        .unwrap();
    list.target()
}

#[test]
fn every_file_is_held_to_the_way_its_tree_was_chunked() {
    let store = MemoryStore::new();
    let (first, short, last) = (bytes("p0", 16), bytes("p1", 9), bytes("p2", 16));
    // A chunk in the middle that is shorter than the tree's chunks.
    let uneven = file_by_hand(&store, &[&first, &short, &last]);
    // A last chunk that is longer than the tree's chunks.
    let long_tail = file_by_hand(&store, &[&first, &bytes("tail", 17)]);
    for file in [uneven, long_tail] {
        let mut builder = Builder::new(&store, small_chunks());
        let top = builder.folder(vec![entry("f", file)]).unwrap();
        assert!(matches!(
            builder.finish(top, ExtraData::new()),
            Err(Error::InvalidData { .. })
        ));
        // A tree of the file alone is refused as well.
        let builder = Builder::new(&store, small_chunks());
        assert!(builder.finish(file, ExtraData::new()).is_err());
    }

    // Small chunks are no chunks of a tree that is chunked by content.
    let even = file_by_hand(&store, &[&first, &last, &short]);
    Builder::new(&store, small_chunks())
        .finish(even, ExtraData::new())
        .unwrap();
    assert!(Builder::new(&store, Chunking::FastCdcV1)
        .finish(even, ExtraData::new())
        .is_err());
    // A file of one small chunk fits either way.
    let single = file_by_hand(&store, &[&short]);
    for chunking in [small_chunks(), Chunking::FastCdcV1] {
        let root = Builder::new(&store, chunking)
            .finish(single, ExtraData::new())
            .unwrap();
        verify(&store, &root).unwrap();
    }
}

#[test]
fn chunking_again_finds_a_file_that_was_chunked_another_way() {
    let data = bytes("scionic-fastcdc-v1:corpus:random_3mib", 3 << 20);
    let store = MemoryStore::new();
    let mut builder = Builder::new(&store, Chunking::FastCdcV1);
    let honest = builder.file_from_bytes(&data).unwrap();
    let root = builder.finish(honest, ExtraData::new()).unwrap();
    let rechunk = VerifyOptions::new().rechunk(true);
    verify_with(&store, &root, rechunk).unwrap();

    // The same bytes, cut in the middle. Each half is long enough to pass
    // for a chunk that the chunker made, so its lengths alone give nothing
    // away. It is another file: the same bytes under another hash.
    let forged = file_by_hand(&store, &[&data[..3 << 19], &data[3 << 19..]]);
    assert_eq!(forged.size, honest.size);
    assert_ne!(forged.hash, honest.hash);
    let forged_root = Builder::new(&store, Chunking::FastCdcV1)
        .finish(forged, ExtraData::new())
        .unwrap();
    verify(&store, &forged_root).unwrap();
    assert!(matches!(
        verify_with(&store, &forged_root, rechunk),
        Err(Error::InvalidData { .. })
    ));
}

#[test]
fn a_chunk_cannot_be_listed_with_two_lengths() {
    let store = MemoryStore::new();
    let whole = bytes("whole", 16);
    let right = file_by_hand(&store, &[&whole]);
    let item = ChunkRef::of(&whole).unwrap();
    let shorter = FileList::new(vec![ChunkRef { length: 15, ..item }]).unwrap();
    store
        .put(Stored::FileList, shorter.hash(), &shorter.encode())
        .unwrap();

    // The chunk is held with 16 bytes, so a list that gives it 15 is wrong
    // on its own, and wrong beside a list that gives it 16.
    for entries in [
        vec![entry("wrong", shorter.target())],
        vec![entry("a-right", right), entry("b-wrong", shorter.target())],
        vec![entry("a-wrong", shorter.target()), entry("b-right", right)],
    ] {
        let mut builder = Builder::new(&store, small_chunks());
        let top = builder.folder(entries).unwrap();
        assert!(matches!(
            builder.finish(top, ExtraData::new()),
            Err(Error::SizeMismatch { .. })
        ));
    }

    // Without the chunk's bytes, two lists that disagree are still refused.
    let bare = MemoryStore::new();
    for list in [&shorter, &FileList::new(vec![item]).unwrap()] {
        bare.put(Stored::FileList, list.hash(), &list.encode())
            .unwrap();
    }
    let mut builder = Builder::new(&bare, small_chunks());
    let top = builder
        .folder(vec![entry("a", right), entry("b", shorter.target())])
        .unwrap();
    assert!(matches!(
        builder.finish(top, ExtraData::new()),
        Err(Error::SizeMismatch { .. })
    ));
}

#[test]
fn a_tree_is_checked_by_its_root_and_by_nothing_else() {
    let (_temp, store, root) = sample_tree("verify-root");
    // A root that the store has no record for.
    let unknown = Root::of_record(b"nothing is kept under this");
    assert!(matches!(
        verify(&store, &unknown),
        Err(Error::Missing {
            what: "the record of",
            ..
        })
    ));
    // The record of one tree, kept under the root of another.
    let record = kept(&store, Stored::Record, root.as_hash());
    store
        .put(Stored::Record, unknown.as_hash(), &record)
        .unwrap();
    assert!(matches!(
        verify(&store, &unknown),
        Err(Error::Corrupt { .. })
    ));
    // A folder is checked once, however many names it has.
    let weights = lookup(&store, &root, "weights").unwrap().unwrap().target();
    let mut builder = Builder::new(&store, small_chunks());
    let top = builder
        .folder(vec![entry("one", weights), entry("two", weights)])
        .unwrap();
    let twice = builder.finish(top, ExtraData::new()).unwrap();
    let summary = verify(&store, &twice).unwrap();
    assert_eq!(summary.folders, 3, "the top, `weights` and `shards`");
    assert_eq!(summary.record.top().size, 2 * weights.size);
    assert_eq!(folder_of(&store, &top).unwrap().count(), 2);
}
