//! Reading a tree that a store holds, and writing it out to disk.

mod support;

use scionic_merkletree::{
    build, file_of, lookup, read_file, read_file_to_vec, read_range, unwritable_on_windows,
    write_to_disk, Builder, Entry, Error, ExtraData, Kind, MemoryStore, Root, Store, Stored,
    Target,
};
use std::fs;
use std::path::Path;
use support::{bytes, sample_tree, small_options, small_pieces, write, TempDir};

fn entry(name: &str, target: Target) -> Entry {
    Entry::new(name, target, ExtraData::new()).unwrap()
}

#[test]
fn every_stretch_of_a_file_reads_back() {
    let store = MemoryStore::new();
    let data = bytes("stretch", 100);
    let file = Builder::new(&store, small_pieces())
        .file_from_bytes(&data)
        .unwrap();
    for offset in 0..=100_usize {
        for length in 0..=100 - offset {
            let mut out = Vec::new();
            read_range(&store, &file, offset as u64, length as u64, &mut out).unwrap();
            assert_eq!(out, &data[offset..offset + length], "{offset}+{length}");
        }
    }
    assert_eq!(read_file_to_vec(&store, &file).unwrap(), data);
    let mut out = Vec::new();
    assert!(read_range(&store, &file, 0, 101, &mut out).is_err());
    assert!(read_range(&store, &file, 101, 0, &mut out).is_err());
    assert!(read_range(&store, &file, u64::MAX, 2, &mut out).is_err());
    assert!(out.is_empty());
}

#[test]
fn a_file_with_a_piece_missing_gives_an_error_and_no_bytes() {
    let store = MemoryStore::new();
    let data = bytes("holed", 100);
    let file = Builder::new(&store, small_pieces())
        .file_from_bytes(&data)
        .unwrap();
    // Piece 3 holds bytes 48 to 63.
    let piece = file_of(&store, &file).unwrap().items()[3];
    let honest = store.get(Stored::Piece, &piece.hash).unwrap().unwrap();
    store.remove(Stored::Piece, &piece.hash).unwrap();

    let mut out = Vec::new();
    assert!(matches!(
        read_file(&store, &file, &mut out),
        Err(Error::Missing { .. })
    ));
    assert!(out.is_empty(), "never a shorter file");
    assert!(read_file_to_vec(&store, &file).is_err());
    for (offset, length) in [(40, 10), (48, 1), (63, 1), (0, 100), (60, 40)] {
        assert!(read_range(&store, &file, offset, length, &mut out).is_err());
        assert!(out.is_empty(), "{offset}+{length}");
    }
    // What does not need the piece is still read.
    read_range(&store, &file, 0, 48, &mut out).unwrap();
    read_range(&store, &file, 64, 36, &mut out).unwrap();
    assert_eq!(out, [&data[..48], &data[64..]].concat());

    // Other bytes under the piece's hash are no piece of the file.
    store
        .put(Stored::Piece, &piece.hash, &bytes("other", 16))
        .unwrap();
    assert!(matches!(
        read_file_to_vec(&store, &file),
        Err(Error::HashMismatch { .. })
    ));
    store.remove(Stored::Piece, &piece.hash).unwrap();
    store
        .put(Stored::Piece, &piece.hash, &bytes("other", 5))
        .unwrap();
    let mut out = Vec::new();
    assert!(matches!(
        read_file(&store, &file, &mut out),
        Err(Error::SizeMismatch { .. })
    ));
    assert!(out.is_empty());
    store.remove(Stored::Piece, &piece.hash).unwrap();
    store.put(Stored::Piece, &piece.hash, &honest).unwrap();
    assert_eq!(read_file_to_vec(&store, &file).unwrap(), data);
}

#[test]
fn a_path_is_found_or_it_is_not() {
    let (_temp, store, root) = sample_tree("read-path");
    let found = |path: &str| lookup(&store, &root, path).unwrap();
    assert_eq!(found("readme.txt").unwrap().kind(), Kind::File);
    assert_eq!(found("weights").unwrap().kind(), Kind::Folder);
    assert_eq!(found("weights/shards/b.bin").unwrap().size(), 33);
    assert_eq!(found("nothing-here").unwrap().size(), 0);
    for path in [
        "missing",
        "weights/missing",
        "weights/shards/b.bin/deeper",
        "readme.txt/x",
        "Readme.txt",
        "weights/shards/c.bin",
    ] {
        assert!(found(path).is_none(), "{path}");
    }
    for path in [
        "",
        "/",
        "weights/",
        "/weights",
        "weights//shards",
        "weights/../readme.txt",
        ".",
    ] {
        assert!(lookup(&store, &root, path).is_err(), "{path:?}");
    }
    let unknown = Root::of_record(b"no such tree");
    assert!(lookup(&store, &unknown, "readme.txt").is_err());
}

/// Every file under `folder`, by its path from there, with its bytes.
fn files_under(folder: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    let mut pending = vec![(folder.to_path_buf(), String::new())];
    while let Some((path, prefix)) = pending.pop() {
        for entry in fs::read_dir(&path).unwrap() {
            let entry = entry.unwrap();
            let name = format!("{prefix}{}", entry.file_name().to_str().unwrap());
            if entry.file_type().unwrap().is_dir() {
                pending.push((entry.path(), format!("{name}/")));
                files.push((format!("{name}/"), Vec::new()));
            } else {
                files.push((name, fs::read(entry.path()).unwrap()));
            }
        }
    }
    files.sort();
    files
}

#[test]
fn a_tree_written_to_disk_builds_to_the_same_root() {
    let (temp, store, root) = sample_tree("read-write");
    let dest = temp.path().join("written");
    write_to_disk(&store, &root, &dest).unwrap();
    assert_eq!(files_under(&dest), files_under(&temp.path().join("sample")));
    assert!(dest.join("nothing-here").is_dir());
    let again = MemoryStore::new();
    assert_eq!(build(&again, &dest, &small_options()).unwrap(), root);

    // A place that is there already is never written into.
    let before = files_under(&dest);
    assert!(write_to_disk(&store, &root, &dest).is_err());
    assert_eq!(files_under(&dest), before);

    // A tree with a file on top is written as that file.
    let file = lookup(&store, &root, "weights/model.bin")
        .unwrap()
        .unwrap()
        .target();
    let alone = Builder::new(&store, small_pieces())
        .finish(file, ExtraData::new())
        .unwrap();
    let dest_file = temp.path().join("written.bin");
    write_to_disk(&store, &alone, &dest_file).unwrap();
    assert_eq!(fs::read(&dest_file).unwrap(), bytes("model", 1_000));
    assert!(write_to_disk(&store, &alone, &dest_file).is_err());
}

#[test]
fn nothing_is_written_when_a_part_is_missing() {
    let (temp, store, root) = sample_tree("read-missing");
    let shard = lookup(&store, &root, "weights/shards/b.bin")
        .unwrap()
        .unwrap()
        .target();
    let piece = file_of(&store, &shard).unwrap().items()[2];
    store.remove(Stored::Piece, &piece.hash).unwrap();
    let dest = temp.path().join("written");
    assert!(matches!(
        write_to_disk(&store, &root, &dest),
        Err(Error::Missing { .. })
    ));
    assert!(
        !dest.exists(),
        "the lack is found before anything is written"
    );
}

/// Whether this system takes `Probe` and `probe` for one name.
fn folds_case(folder: &Path) -> bool {
    write(folder.join("Probe"), b"x").unwrap();
    folder.join("probe").exists()
}

#[test]
fn two_names_that_one_system_takes_for_one_are_refused_there() {
    let temp = TempDir::new("read-fold").unwrap();
    let folds = folds_case(temp.path());
    let store = MemoryStore::new();
    let mut builder = Builder::new(&store, small_pieces());
    let upper = builder.file_from_bytes(b"under the capital").unwrap();
    let lower = builder.file_from_bytes(b"under the small letter").unwrap();
    let inner = builder.folder(vec![entry("x", upper)]).unwrap();
    let cases = [
        (
            "two-files",
            vec![entry("File", upper), entry("file", lower)],
        ),
        (
            "file-and-folder",
            vec![entry("Name", inner), entry("name", lower)],
        ),
        (
            "two-folders",
            vec![entry("Dir", inner), entry("dir", inner)],
        ),
    ];
    for (case, entries) in cases {
        let mut builder = Builder::new(&store, small_pieces());
        let top = builder.folder(entries.clone()).unwrap();
        // Held in a tree, the two names are two names.
        let root = builder.finish(top, ExtraData::new()).unwrap();
        let dest = temp.path().join(case);
        let written = write_to_disk(&store, &root, &dest);
        if folds {
            match written {
                Err(Error::UnwritableName { name, .. }) => {
                    assert!(entries.iter().any(|entry| entry.name() == name), "{name}");
                }
                other => panic!("{case}: both names were written: {other:?}"),
            }
        } else {
            written.unwrap();
            let again = MemoryStore::new();
            assert_eq!(build(&again, &dest, &small_options()).unwrap(), root);
        }
    }
}

#[test]
fn names_that_windows_cannot_hold_are_found() {
    for name in [
        "a",
        "a.b",
        ".git",
        "a b",
        "com",
        "com10",
        "nul1",
        "console",
        "aux2",
        "lpt",
        "\u{e9}t\u{e9}",
        "model.safetensors",
        "a.b.c",
        "con1.txt",
        "$con",
    ] {
        assert_eq!(unwritable_on_windows(name), None, "{name:?}");
    }
    for name in [
        "a:b",
        "a\\b",
        "a/b",
        "a?",
        "a*",
        "a<b",
        "a>b",
        "a|b",
        "a\"b",
        "a\tb",
        "a\u{1}",
        "a.",
        "a ",
        "...",
        "CON",
        "con",
        "Nul",
        "nul.txt",
        "NUL.tar.gz",
        "NUL .txt",
        "COM1",
        "com9.txt",
        "COM0",
        "LPT1",
        "lpt3.x",
        "COM\u{b9}",
        "lpt\u{b3}",
        "AUX",
        "PRN",
        "CONIN$",
        "conout$",
    ] {
        assert!(unwritable_on_windows(name).is_some(), "{name:?}");
    }
}

#[test]
fn a_name_this_system_cannot_hold_is_refused_before_anything_is_written() {
    let temp = TempDir::new("read-names").unwrap();
    let store = MemoryStore::new();
    let mut builder = Builder::new(&store, small_pieces());
    let file = builder.file_from_bytes(b"content").unwrap();
    let inner = builder
        .folder(vec![entry("fine", file), entry("nul.txt", file)])
        .unwrap();
    let top = builder
        .folder(vec![entry("a-fine-name", file), entry("sub", inner)])
        .unwrap();
    let root = builder.finish(top, ExtraData::new()).unwrap();
    let dest = temp.path().join("written");
    let written = write_to_disk(&store, &root, &dest);
    if cfg!(windows) {
        match written {
            Err(Error::UnwritableName { name, .. }) => assert_eq!(name, "nul.txt"),
            other => panic!("a device name was written: {other:?}"),
        }
        assert!(
            !dest.exists(),
            "the name is found before anything is written"
        );
    } else {
        written.unwrap();
        assert_eq!(fs::read(dest.join("sub/nul.txt")).unwrap(), b"content");
    }
}
