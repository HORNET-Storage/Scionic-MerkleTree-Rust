//! What changed between two trees.

mod support;

use scionic_merkletree::{
    build, build_with, diff, lookup, Builder, Change, Error, ExtraData, Kind, MemoryStore, Store,
    Stored,
};
use std::fs;
use support::{bytes, sample_folder, small_options, small_pieces, write, TempDir};

#[test]
fn each_change_is_listed_once_by_its_path() {
    let temp = TempDir::new("diff").unwrap();
    let folder = sample_folder(temp.path(), "sample").unwrap();
    let store = MemoryStore::new();
    let old = build(&store, &folder, &small_options()).unwrap();
    assert_eq!(diff(&store, &old, &old).unwrap(), Vec::new());

    // One piece of a file changes.
    let mut model = bytes("model", 1_000);
    model[320..336].copy_from_slice(&bytes("changed", 16));
    write(folder.join("weights/model.bin"), &model).unwrap();
    // A file gets another name.
    fs::rename(folder.join("readme.txt"), folder.join("notes.txt")).unwrap();
    // A folder comes, with two files in it, and a folder goes.
    write(folder.join("more/one.bin"), &bytes("one", 40)).unwrap();
    write(folder.join("more/two.bin"), &bytes("two", 40)).unwrap();
    fs::remove_dir_all(folder.join("data")).unwrap();
    // A file becomes a folder of the same name.
    fs::remove_file(folder.join("empty.bin")).unwrap();
    write(folder.join("empty.bin/inside"), b"no longer empty").unwrap();
    let new = build(&store, &folder, &small_options()).unwrap();

    let changes = diff(&store, &old, &new).unwrap();
    let listed: Vec<(&str, &str)> = changes
        .iter()
        .map(|change| {
            let what = match change {
                Change::Added { .. } => "added",
                Change::Removed { .. } => "removed",
                Change::Changed { .. } => "changed",
            };
            (change.path(), what)
        })
        .collect();
    assert_eq!(
        listed,
        [
            ("data", "removed"),
            ("empty.bin", "removed"),
            ("empty.bin", "added"),
            ("more", "added"),
            ("notes.txt", "added"),
            ("readme.txt", "removed"),
            ("weights/model.bin", "changed"),
        ]
    );
    for change in &changes {
        match change {
            Change::Added { path, entry } => {
                assert_eq!(lookup(&store, &new, path).unwrap().as_ref(), Some(entry));
            }
            Change::Removed { path, entry } => {
                assert_eq!(lookup(&store, &old, path).unwrap().as_ref(), Some(entry));
            }
            Change::Changed {
                path,
                old: was,
                new: is,
            } => {
                assert_eq!(lookup(&store, &old, path).unwrap().as_ref(), Some(was));
                assert_eq!(lookup(&store, &new, path).unwrap().as_ref(), Some(is));
                assert_ne!(was.hash(), is.hash());
                assert_eq!(
                    (was.kind(), was.size(), is.size()),
                    (Kind::File, 1_000, 1_000)
                );
            }
        }
    }
    // The file that got another name is the same file.
    let (Change::Added { entry: notes, .. }, Change::Removed { entry: readme, .. }) =
        (&changes[4], &changes[5])
    else {
        panic!("not the rename");
    };
    assert_eq!(notes.target(), readme.target());

    // The other way round, what was added is removed.
    let back = diff(&store, &new, &old).unwrap();
    assert_eq!(back.len(), changes.len());
    assert!(matches!(&back[3], Change::Removed { path, .. } if path == "more"));

    // What is the same in both trees is not read: the comparison works
    // without the folder that did not change, and without any file.
    let shards = lookup(&store, &new, "weights/shards").unwrap().unwrap();
    store.remove(Stored::FolderList, shards.hash()).unwrap();
    for hash in store.hashes(Stored::FileList) {
        store.remove(Stored::FileList, &hash).unwrap();
    }
    for hash in store.hashes(Stored::Piece) {
        store.remove(Stored::Piece, &hash).unwrap();
    }
    assert_eq!(diff(&store, &old, &new).unwrap(), changes);
    // A folder that did change is needed.
    let weights = lookup(&store, &new, "weights").unwrap().unwrap();
    store.remove(Stored::FolderList, weights.hash()).unwrap();
    assert!(matches!(
        diff(&store, &old, &new),
        Err(Error::Missing { .. })
    ));
}

#[test]
fn extra_data_that_changed_is_a_change() {
    let temp = TempDir::new("diff-extra").unwrap();
    let folder = sample_folder(temp.path(), "sample").unwrap();
    let store = MemoryStore::new();
    let tagged = |tag: &'static str| {
        build_with(&store, &folder, &small_options(), &move |_, name, _| {
            if name == "weights" || name == "readme.txt" {
                ExtraData::new().with("tag", tag)
            } else {
                Ok(ExtraData::new())
            }
        })
        .unwrap()
    };
    let (old, new) = (tagged("one"), tagged("two"));
    assert_ne!(old, new);
    let changes = diff(&store, &old, &new).unwrap();
    let paths: Vec<&str> = changes.iter().map(Change::path).collect();
    assert_eq!(paths, ["readme.txt", "weights"]);
    for change in &changes {
        let Change::Changed {
            old: was, new: is, ..
        } = change
        else {
            panic!("{change:?}");
        };
        // The thing itself is the same. What is said about it differs.
        assert_eq!(was.target(), is.target());
        assert_eq!(was.extra().text("tag"), Some("one"));
        assert_eq!(is.extra().text("tag"), Some("two"));
    }
}

#[test]
fn trees_with_a_file_on_top_have_no_entries_to_compare() {
    let store = MemoryStore::new();
    let mut builder = Builder::new(&store, small_pieces());
    let one = builder.file_from_bytes(b"one").unwrap();
    let two = builder.file_from_bytes(b"two").unwrap();
    let folder = builder.folder(Vec::new()).unwrap();
    let finish = |top, extra| {
        Builder::new(&store, small_pieces())
            .finish(top, extra)
            .unwrap()
    };
    let first = finish(one, ExtraData::new());
    let second = finish(two, ExtraData::new());
    let empty = finish(folder, ExtraData::new());
    // The same file under two records is the same tree to compare.
    let named = ExtraData::new().with("name", "again").unwrap();
    let first_again = finish(one, named);
    assert_ne!(first, first_again);
    assert_eq!(diff(&store, &first, &first_again).unwrap(), Vec::new());
    assert!(diff(&store, &first, &second).is_err());
    assert!(diff(&store, &first, &empty).is_err());
    assert!(diff(&store, &empty, &second).is_err());
    assert_eq!(diff(&store, &empty, &empty).unwrap(), Vec::new());
}
