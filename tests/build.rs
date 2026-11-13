//! Building a tree, and what the format promises about it: the same things
//! have the same hashes wherever they are, and are stored once.

mod support;

use scionic_merkletree::{
    build, build_with, file_of, folder_of, lookup, read_file_to_vec, record_of, verify,
    BuildOptions, Builder, Cutting, Entry, Error, ExtraData, Kind, Links, MemoryStore, Store,
    Stored, CUTTING_KEY, TIMESTAMP_KEY,
};
use std::fs;
use support::oracle;
use support::{
    bytes, contents, sample_folder, sample_tree, small_options, small_pieces, write, TempDir,
};

#[test]
fn a_folder_has_the_same_root_wherever_it_is_and_whatever_it_is_called() {
    let temp = TempDir::new("same-root").unwrap();
    let first = sample_folder(temp.path(), "one").unwrap();
    let second = sample_folder(&temp.path().join("deeper/still"), "another-name").unwrap();
    let (store_a, store_b) = (MemoryStore::new(), MemoryStore::new());
    let root_a = build(&store_a, &first, &small_options()).unwrap();
    let root_b = build(&store_b, &second, &small_options()).unwrap();
    assert_eq!(root_a, root_b);
    assert_eq!(contents(&store_a), contents(&store_b));

    // The same folder, named by another path to it.
    let roundabout = first.join("weights").join("..");
    let store_c = MemoryStore::new();
    assert_eq!(
        build(&store_c, &roundabout, &small_options()).unwrap(),
        root_a
    );
    assert!(root_a.to_text().starts_with("bafkrei"));
}

#[test]
fn the_root_is_what_the_format_says_it_is() {
    let temp = TempDir::new("oracle").unwrap();
    let top = temp.path().join("tree");
    let a = b"hello".to_vec();
    let b = bytes("b", 40);
    write(top.join("a.txt"), &a).unwrap();
    write(top.join("sub/b.bin"), &b).unwrap();
    write(top.join("sub/empty"), b"").unwrap();
    let store = MemoryStore::new();
    let root = build(&store, &top, &small_options()).unwrap();

    // The same tree by the rules, written out by hand.
    let a_items = vec![oracle::Item::of(&a)];
    let b_items: Vec<oracle::Item> = b.chunks(16).map(oracle::Item::of).collect();
    assert_eq!(b_items.len(), 3);
    let (a_hash, a_size) = oracle::file_hash(&a_items);
    let (b_hash, b_size) = oracle::file_hash(&b_items);
    let (empty_hash, _) = oracle::file_hash(&[]);
    let sub = vec![
        oracle::Entry::file("b.bin", b_hash, b_size),
        oracle::Entry::file("empty", empty_hash, 0),
    ];
    let (sub_hash, sub_size) = oracle::folder_hash(&sub);
    let tree = vec![
        oracle::Entry::file("a.txt", a_hash, a_size),
        oracle::Entry::folder("sub", sub_hash, sub_size),
    ];
    let (top_hash, top_size) = oracle::folder_hash(&tree);
    assert_eq!((a_size, b_size, sub_size, top_size), (5, 40, 40, 45));
    let list_bytes = 36
        + 3 * 36
        + oracle::folder_list_bytes(&sub).len() as u64
        + oracle::folder_list_bytes(&tree).len() as u64;
    let record = oracle::record_bytes(
        2,
        45,
        &top_hash,
        (4, 45, list_bytes),
        &oracle::cut_tag("fixed-16"),
    );

    assert_eq!(*root.as_hash().as_bytes(), oracle::sha(&[&record]));
    let kept = |kind, hash: &oracle::H| {
        store
            .get(kind, &scionic_merkletree::Hash::from_bytes(*hash))
            .unwrap()
            .map(|bytes| bytes.to_vec())
    };
    assert_eq!(
        kept(Stored::Record, root.as_hash().as_bytes()),
        Some(record)
    );
    assert_eq!(
        kept(Stored::FolderList, &top_hash),
        Some(oracle::folder_list_bytes(&tree))
    );
    assert_eq!(
        kept(Stored::FolderList, &sub_hash),
        Some(oracle::folder_list_bytes(&sub))
    );
    assert_eq!(
        kept(Stored::FileList, &b_hash),
        Some(oracle::file_list_bytes(&b_items))
    );
    assert_eq!(kept(Stored::FileList, &empty_hash), Some(Vec::new()));
    assert_eq!(
        kept(Stored::Piece, &b_items[2].hash),
        Some(b[32..].to_vec())
    );
    // A piece's hash is the plain SHA-256 of its bytes.
    assert_eq!(
        scionic_merkletree::Hash::of(&a).to_hex(),
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    assert_eq!(kept(Stored::Piece, &a_items[0].hash), Some(a));
}

#[test]
fn identical_things_are_stored_once() {
    let (_temp, store, root) = sample_tree("stored-once");
    // Two names, one file: the same hash, one list, and its pieces once.
    let model = lookup(&store, &root, "weights/model.bin").unwrap().unwrap();
    let copy = lookup(&store, &root, "weights/copy-of-model.bin")
        .unwrap()
        .unwrap();
    assert_eq!(model.hash(), copy.hash());
    assert_eq!(model.target(), copy.target());

    let summary = verify(&store, &root).unwrap();
    let totals = summary.record.totals();
    assert_eq!((summary.files, summary.folders), (6, 5));
    assert_eq!(store.count(Stored::FileList), 6);
    assert_eq!(store.count(Stored::FolderList), 5);
    assert_eq!(store.count(Stored::Record), 1);
    // 12, 1,000, 100, 33 and 32 bytes in pieces of 16.
    assert_eq!(totals.pieces, 1 + 63 + 7 + 3 + 2);
    assert_eq!(totals.piece_bytes, 12 + 1_000 + 100 + 33 + 32);
    assert_eq!(store.count(Stored::Piece) as u64, totals.pieces);
    assert_eq!(store.bytes(Stored::Piece), totals.piece_bytes);
    assert_eq!(
        store.bytes(Stored::FileList) + store.bytes(Stored::FolderList),
        totals.list_bytes
    );
    // The tree's size counts the file under both of its names.
    assert_eq!(summary.record.top().size, totals.piece_bytes + 1_000);
    assert_eq!(summary.record.top().kind, Kind::Folder);
}

#[test]
fn a_second_tree_adds_only_what_is_new() {
    let temp = TempDir::new("second-tree").unwrap();
    let folder = sample_folder(temp.path(), "sample").unwrap();
    let store = MemoryStore::new();
    let first = build(&store, &folder, &small_options()).unwrap();
    let before = (
        store.count(Stored::Piece),
        store.count(Stored::FileList),
        store.count(Stored::FolderList),
    );

    // One piece of one file changes, and another file gets a new name.
    let mut model = bytes("model", 1_000);
    model[320..336].copy_from_slice(&bytes("changed", 16));
    write(folder.join("weights/model.bin"), &model).unwrap();
    fs::rename(folder.join("readme.txt"), folder.join("notes.txt")).unwrap();
    let second = build(&store, &folder, &small_options()).unwrap();
    assert_ne!(first, second);

    let after = (
        store.count(Stored::Piece),
        store.count(Stored::FileList),
        store.count(Stored::FolderList),
    );
    // One new piece. One new list for the changed file: the renamed file is
    // the same file. Two new folders: the one that holds the change, and the
    // top, which holds both.
    assert_eq!(after, (before.0 + 1, before.1 + 1, before.2 + 2));
    verify(&store, &first).unwrap();
    verify(&store, &second).unwrap();
    let renamed = lookup(&store, &second, "notes.txt").unwrap().unwrap();
    let original = lookup(&store, &first, "readme.txt").unwrap().unwrap();
    assert_eq!(renamed.hash(), original.hash());
    assert!(lookup(&store, &second, "readme.txt").unwrap().is_none());
    // What did not change has the same hash in both trees.
    for path in [
        "weights/shards",
        "data",
        "weights/copy-of-model.bin",
        "nothing-here",
    ] {
        assert_eq!(
            lookup(&store, &first, path).unwrap().unwrap(),
            lookup(&store, &second, path).unwrap().unwrap(),
            "{path}"
        );
    }
}

#[test]
fn a_file_that_repeats_a_piece_reads_back_whole() {
    let store = MemoryStore::new();
    let mut builder = Builder::new(&store, small_pieces());
    let (x, y) = (bytes("x", 16), bytes("y", 16));
    let content = [x.clone(), y, x].concat();
    let file = builder.file_from_bytes(&content).unwrap();
    assert_eq!(store.count(Stored::Piece), 2);

    let list = file_of(&store, &file).unwrap();
    assert_eq!(list.count(), 3);
    assert_eq!(list.items()[0], list.items()[2]);
    assert_eq!(read_file_to_vec(&store, &file).unwrap(), content);
    // Each of the three places is shown on its own, at its own byte.
    for place in 0..3 {
        let run = list.open(place, place + 1).unwrap();
        assert_eq!(run.check(&file, Some(small_pieces())).unwrap(), place * 16);
    }

    let root = builder.finish(file, ExtraData::new()).unwrap();
    let summary = verify(&store, &root).unwrap();
    let totals = summary.record.totals();
    assert_eq!(summary.record.top().size, 48);
    assert_eq!(
        (totals.pieces, totals.piece_bytes, totals.list_bytes),
        (2, 32, 108)
    );
}

#[test]
fn the_same_piece_in_two_files_is_one_piece() {
    let store = MemoryStore::new();
    let mut builder = Builder::new(&store, small_pieces());
    let shared = bytes("shared", 16);
    let first = builder
        .file_from_bytes(&[shared.clone(), bytes("first", 10)].concat())
        .unwrap();
    let second = builder
        .file_from_bytes(&[bytes("second", 16), shared].concat())
        .unwrap();
    assert_ne!(first.hash, second.hash);
    assert_eq!(store.count(Stored::Piece), 3);
    let top = builder
        .folder(vec![
            Entry::new("second", second, ExtraData::new()).unwrap(),
            Entry::new("first", first, ExtraData::new()).unwrap(),
        ])
        .unwrap();
    let root = builder.finish(top, ExtraData::new()).unwrap();
    let totals = verify(&store, &root).unwrap().record.totals();
    assert_eq!((totals.pieces, totals.piece_bytes), (3, 42));
    // The builder sorted the entries by name.
    let names: Vec<String> = folder_of(&store, &top)
        .unwrap()
        .entries()
        .iter()
        .map(|entry| entry.name().to_owned())
        .collect();
    assert_eq!(names, ["first", "second"]);
}

#[test]
fn building_with_several_workers_gives_the_same_tree() {
    let temp = TempDir::new("workers").unwrap();
    let top = temp.path().join("many");
    for index in 0..40_usize {
        let path = top.join(format!("d{}/f{index:02}.bin", index % 5));
        write(path, &bytes(&format!("file-{}", index % 30), index * 37)).unwrap();
    }
    let mut stores = Vec::new();
    let mut roots = Vec::new();
    for workers in [1, 2, 7, 0] {
        let store = MemoryStore::new();
        roots.push(build(&store, &top, &small_options().workers(workers)).unwrap());
        stores.push(store);
    }
    for (store, root) in stores.iter().zip(&roots) {
        assert_eq!(root, &roots[0]);
        assert_eq!(contents(store), contents(&stores[0]));
        verify(store, root).unwrap();
    }
}

#[test]
fn files_are_cut_by_content_unless_a_test_says_otherwise() {
    // A case of the committed cutting vectors: 3 MiB, cut after 2,118,489.
    let data = bytes("scionic-fastcdc-v1:corpus:random_3mib", 3 << 20);
    let temp = TempDir::new("by-content").unwrap();
    let path = temp.path().join("random.bin");
    write(&path, &data).unwrap();
    let store = MemoryStore::new();
    let root = build(&store, &path, &BuildOptions::new()).unwrap();
    let record = record_of(&store, &root).unwrap();
    assert_eq!(record.cutting(), Cutting::FastCdcV1);
    assert_eq!(record.extra().text(CUTTING_KEY), Some("fastcdc-v1"));
    assert_eq!(record.extra().len(), 1);
    assert_eq!(record.top().kind, Kind::File);
    let lengths: Vec<u32> = file_of(&store, &record.top())
        .unwrap()
        .items()
        .iter()
        .map(|item| item.length)
        .collect();
    assert_eq!(lengths, [2_118_489, (3 << 20) - 2_118_489]);
    verify(&store, &root).unwrap();

    // The same bytes, by the builder that is given bytes: the same file.
    let other = MemoryStore::new();
    let file = Builder::new(&other, Cutting::FastCdcV1)
        .file_from_bytes(&data)
        .unwrap();
    assert_eq!(file, record.top());
}

#[test]
fn the_record_carries_what_the_builder_was_told() {
    let (temp, plain_store, plain) = sample_tree("record-extra");
    let folder = temp.path().join("sample");
    let store = MemoryStore::new();
    let extra = ExtraData::new()
        .with("name", "my model")
        .unwrap()
        .with(CUTTING_KEY, "not for a caller to say")
        .unwrap();
    let options = small_options().extra(extra).timestamp(true);
    let root = build(&store, &folder, &options).unwrap();
    assert_ne!(root, plain);
    let record = record_of(&store, &root).unwrap();
    assert_eq!(record.extra().text("name"), Some("my model"));
    assert_eq!(record.extra().text(CUTTING_KEY), Some("fixed-16"));
    let stamp = record.extra().text(TIMESTAMP_KEY).unwrap();
    assert_eq!(stamp.len(), 20, "{stamp}");
    assert!(stamp.starts_with("20") && stamp.ends_with('Z'), "{stamp}");
    // The folder on top is the same folder: only the record differs.
    assert_eq!(record.top(), record_of(&plain_store, &plain).unwrap().top());
}

#[test]
fn every_entry_can_be_given_extra_data() {
    let (temp, plain_store, plain) = sample_tree("entry-extra");
    let folder = temp.path().join("sample");
    let store = MemoryStore::new();
    let seen = std::sync::Mutex::new(Vec::new());
    let root = build_with(&store, &folder, &small_options(), &|path, name, kind| {
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), name);
        assert_eq!(path.is_dir(), kind == Kind::Folder);
        seen.lock().unwrap().push(name.to_owned());
        ExtraData::new().with("kind", if kind == Kind::Folder { "d" } else { "f" })
    })
    .unwrap();
    assert_ne!(root, plain);
    let mut seen = seen.into_inner().unwrap();
    seen.sort();
    assert_eq!(
        seen,
        [
            "a.bin",
            "b.bin",
            "copy-of-model.bin",
            "data",
            "empty.bin",
            "exactly-two-pieces.bin",
            "model.bin",
            "nothing-here",
            "readme.txt",
            "shards",
            "weights"
        ]
    );
    let shards = lookup(&store, &root, "weights/shards").unwrap().unwrap();
    assert_eq!(shards.extra().text("kind"), Some("d"));
    let model = lookup(&store, &root, "weights/model.bin").unwrap().unwrap();
    assert_eq!(model.extra().text("kind"), Some("f"));
    // Extra data sits beside the name: the file itself is the same file.
    let plain_model = lookup(&plain_store, &plain, "weights/model.bin")
        .unwrap()
        .unwrap();
    assert_eq!(model.hash(), plain_model.hash());
    verify(&store, &root).unwrap();
}

#[test]
fn a_file_on_its_own_is_a_tree() {
    let temp = TempDir::new("top-file").unwrap();
    let data = bytes("alone", 70);
    let path = temp.path().join("whatever-it-is-called.bin");
    write(&path, &data).unwrap();
    let store = MemoryStore::new();
    let root = build(&store, &path, &small_options()).unwrap();
    let summary = verify(&store, &root).unwrap();
    assert_eq!(summary.record.top().kind, Kind::File);
    assert_eq!((summary.files, summary.folders), (1, 0));
    assert_eq!(
        read_file_to_vec(&store, &summary.record.top()).unwrap(),
        data
    );
    // The same bytes under another name are the same tree.
    let other_path = temp.path().join("other-name");
    write(&other_path, &data).unwrap();
    assert_eq!(build(&store, &other_path, &small_options()).unwrap(), root);
    // An empty file is a tree too.
    let empty_path = temp.path().join("empty");
    write(&empty_path, b"").unwrap();
    let empty = build(&store, &empty_path, &small_options()).unwrap();
    let totals = verify(&store, &empty).unwrap().record.totals();
    assert_eq!(
        (totals.pieces, totals.piece_bytes, totals.list_bytes),
        (0, 0, 0)
    );
}

#[test]
fn a_link_is_never_followed() {
    let temp = TempDir::new("links").unwrap();
    let outside = temp.path().join("outside-secret.txt");
    write(&outside, b"not part of the folder").unwrap();
    let folder = temp.path().join("folder");
    write(folder.join("inside.txt"), b"part of the folder").unwrap();
    let link = folder.join("link.txt");
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(&outside, &link);
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_file(&outside, &link);
    if let Err(error) = made {
        // Windows lets only some accounts make links.
        eprintln!("skipped: this account cannot make a link ({error})");
        return;
    }

    let store = MemoryStore::new();
    match build(&store, &folder, &small_options()) {
        Err(Error::UnsupportedEntry { path, what }) => {
            assert_eq!(path, link);
            assert_eq!(what, "a link");
        }
        other => panic!("a link was not refused: {other:?}"),
    }
    let root = build(&store, &folder, &small_options().links(Links::Skip)).unwrap();
    assert!(lookup(&store, &root, "link.txt").unwrap().is_none());
    assert!(lookup(&store, &root, "inside.txt").unwrap().is_some());
    let secret = scionic_merkletree::Hash::of(b"not part of the folder");
    assert!(!store.has(Stored::Piece, &secret).unwrap());
}

#[test]
fn a_folder_inside_128_others_is_too_deep() {
    // Made by hand: a path that long does not fit on every system.
    let store = MemoryStore::new();
    let mut builder = Builder::new(&store, small_pieces());
    let file = builder.file_from_bytes(b"at the bottom").unwrap();
    let mut inner = builder
        .folder(vec![Entry::new("file", file, ExtraData::new()).unwrap()])
        .unwrap();
    for _ in 1..128 {
        inner = builder
            .folder(vec![Entry::new("d", inner, ExtraData::new()).unwrap()])
            .unwrap();
    }
    // 128 folders, one inside the other, is the most there can be.
    let root = builder.finish(inner, ExtraData::new()).unwrap();
    assert_eq!(verify(&store, &root).unwrap().folders, 128);

    let mut builder = Builder::new(&store, small_pieces());
    let one_more = builder
        .folder(vec![Entry::new("d", inner, ExtraData::new()).unwrap()])
        .unwrap();
    let records_before = store.count(Stored::Record);
    assert!(matches!(
        builder.finish(one_more, ExtraData::new()),
        Err(Error::TooDeep { limit: 128 })
    ));
    assert_eq!(
        store.count(Stored::Record),
        records_before,
        "no record is kept"
    );

    // A folder that is reached twice is measured by its deepest place. Here
    // 100 folders sit one inside the other. The top reaches them directly,
    // under `near`, and again under `far`, with more folders on the way.
    let hundred_deep = |wrapped: usize| {
        let mut builder = Builder::new(&store, small_pieces());
        let mut hundred = builder
            .folder(vec![Entry::new("file", file, ExtraData::new()).unwrap()])
            .unwrap();
        for _ in 1..100 {
            hundred = builder
                .folder(vec![Entry::new("d", hundred, ExtraData::new()).unwrap()])
                .unwrap();
        }
        let mut far = hundred;
        for _ in 0..wrapped {
            far = builder
                .folder(vec![Entry::new("d", far, ExtraData::new()).unwrap()])
                .unwrap();
        }
        let top = builder
            .folder(vec![
                Entry::new("far", far, ExtraData::new()).unwrap(),
                Entry::new("near", hundred, ExtraData::new()).unwrap(),
            ])
            .unwrap();
        builder.finish(top, ExtraData::new())
    };
    // The top, 27 folders, and the hundred: 128 on the longest way down.
    let root = hundred_deep(27).unwrap();
    verify(&store, &root).unwrap();
    // One more on the way, and the hundred sit too deep under `far`, though
    // they are well within the limit under `near`.
    assert!(matches!(
        hundred_deep(28),
        Err(Error::TooDeep { limit: 128 })
    ));
}
