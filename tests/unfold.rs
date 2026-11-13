//! A tree keeps a folder once, however many places the folder has in it. So
//! a small tree can stand for a very large one, and whatever goes through a
//! tree place by place has to know when to stop.
//!
//! Checking a tree, taking it in and sending it go through each folder once,
//! and need no such care. Writing a tree out is in `tests/read.rs`. Listing
//! what changed between two trees is here.

mod support;

use scionic_merkletree::{
    build, diff, diff_within, Builder, Entry, Error, ExtraData, MemoryStore, Stored, Target,
    DEFAULT_MAX_CHANGES,
};
use std::fs;
use support::{sample_folder, small_options, small_pieces, write, TempDir};

fn entry(name: &str, target: Target) -> Entry {
    Entry::new(name, target, ExtraData::new()).unwrap()
}

/// A folder with one file, under `levels` folders that each hold the one
/// below under two names.
fn doubled(builder: &mut Builder<'_>, content: &[u8], levels: usize) -> Target {
    let file = builder.file_from_bytes(content).unwrap();
    let mut folder = builder.folder(vec![entry("x", file)]).unwrap();
    for _ in 0..levels {
        folder = builder
            .folder(vec![entry("a", folder), entry("b", folder)])
            .unwrap();
    }
    folder
}

#[test]
fn two_small_trees_that_differ_at_more_places_than_a_list_holds_are_refused() {
    let store = MemoryStore::new();
    let mut builder = Builder::new(&store, small_pieces());
    // Two trees of 41 small folders each. They differ in one file, and that
    // file has 2^40 places.
    let old_top = doubled(&mut builder, b"old", 40);
    let new_top = doubled(&mut builder, b"new", 40);
    assert_eq!(store.count(Stored::FolderList), 82);
    let finish = |top| {
        Builder::new(&store, small_pieces())
            .finish(top, ExtraData::new())
            .unwrap()
    };
    let (old, new) = (finish(old_top), finish(new_top));
    // The search stops soon after it has found more than it may list.
    match diff_within(&store, &old, &new, 10_000) {
        Err(Error::LimitExceeded {
            limit, requested, ..
        }) => {
            assert_eq!(limit, 10_000);
            assert!(requested > limit && requested < limit + 1_000);
        }
        other => panic!("{:?}", other.map(|changes| changes.len())),
    }
    // Left to itself, it lists a million changes and no more.
    assert_eq!(DEFAULT_MAX_CHANGES, 1_000_000);
    assert_eq!(diff(&store, &old, &old).unwrap(), Vec::new());

    // Ten levels of it are 1,024 places, and are listed.
    let mut builder = Builder::new(&store, small_pieces());
    let old_top = doubled(&mut builder, b"old", 10);
    let new_top = doubled(&mut builder, b"new", 10);
    let (old, new) = (finish(old_top), finish(new_top));
    let changes = diff(&store, &old, &new).unwrap();
    assert_eq!(changes.len(), 1_024);
    assert_eq!(changes[0].path(), "a/a/a/a/a/a/a/a/a/a/x");
    assert_eq!(changes[1_023].path(), "b/b/b/b/b/b/b/b/b/b/x");
    assert_eq!(diff_within(&store, &old, &new, 1_024).unwrap(), changes);
    assert!(matches!(
        diff_within(&store, &old, &new, 1_023),
        Err(Error::LimitExceeded { .. })
    ));
}

#[test]
fn a_limit_on_changes_is_held_exactly() {
    let temp = TempDir::new("unfold-exact").unwrap();
    let folder = sample_folder(temp.path(), "sample").unwrap();
    let store = MemoryStore::new();
    let old = build(&store, &folder, &small_options()).unwrap();
    fs::remove_file(folder.join("readme.txt")).unwrap();
    write(folder.join("weights/new.bin"), b"new").unwrap();
    write(folder.join("data/new.bin"), b"new").unwrap();
    let new = build(&store, &folder, &small_options()).unwrap();
    assert_eq!(diff(&store, &old, &new).unwrap().len(), 3);
    assert_eq!(diff_within(&store, &old, &new, 3).unwrap().len(), 3);
    for most in 0..3 {
        assert!(matches!(
            diff_within(&store, &old, &new, most),
            Err(Error::LimitExceeded { .. })
        ));
    }
}
