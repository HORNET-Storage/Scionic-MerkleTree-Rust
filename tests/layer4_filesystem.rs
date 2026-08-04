mod support;

use scionic_merkletree::{
    create_dag, create_dag_custom, create_dag_with_options, Dag, DagBuildOptions, Error,
    LeafType, Metadata, DEFAULT_CHUNK_SIZE, MAX_IN_MEMORY_LEAF_BYTES,
};
use std::collections::BTreeMap;
use std::fs;
use support::{alpha_data, create_fixture, options_4096, write, TempDir, FIXTURES};

fn leaf_by_name<'a>(
    dag: &'a Dag,
    name: &str,
    leaf_type: LeafType,
) -> &'a scionic_merkletree::DagLeaf {
    dag.leaves()
        .values()
        .find(|leaf| leaf.item_name() == name && leaf.leaf_type() == leaf_type)
        .unwrap_or_else(|| panic!("missing {leaf_type} leaf {name}"))
}

#[test]
fn simple_directory_matches_every_layer_4_1_cid() {
    let temp = TempDir::new("simple-directory").unwrap();
    let input = temp.path().join("input");
    fs::create_dir_all(input.join("subdir")).unwrap();
    write(input.join("file1.txt"), b"Hello from file one").unwrap();
    write(input.join("file2.txt"), b"Hello from file two").unwrap();
    write(input.join("subdir").join("nested.txt"), b"I am nested").unwrap();
    let dag = create_dag_with_options(&input, &options_4096()).unwrap();
    let expected = BTreeMap::from([
        (
            "bafireiaptl7ndqt7ngu5ctnpghwvwyxekrt66cpzxyzst2nyso7ppq76v4",
            ("file1.txt", LeafType::File),
        ),
        (
            "bafireicmmr4urltkiwzp7cx3w2lmpza4zvkpf4gj2llt42f2cyxlwyfd6e",
            ("file2.txt", LeafType::File),
        ),
        (
            "bafireidzdh6wxep5jg3gbkrm5gxns7syv6igqmmqngeioidfc2ljadkjzu",
            ("nested.txt", LeafType::File),
        ),
        (
            "bafireihanc6pjpcfhhnljfss6227fpjy7ftqi52ubxqomjosv32d2ovehm",
            ("subdir", LeafType::Directory),
        ),
        (
            "bafireibf7zhg6orisvqjl6mqskfokize6haalmt2bgthnxrlruauufqg4u",
            ("input", LeafType::Directory),
        ),
    ]);
    assert_eq!(
        dag.root().as_str(),
        "bafireibf7zhg6orisvqjl6mqskfokize6haalmt2bgthnxrlruauufqg4u"
    );
    assert_eq!(dag.len(), 5);
    for (cid, (name, leaf_type)) in expected {
        let leaf = dag
            .leaves()
            .values()
            .find(|leaf| leaf.cid().as_str() == cid)
            .unwrap_or_else(|| panic!("missing reference leaf {cid}"));
        assert_eq!(leaf.item_name(), name);
        assert_eq!(leaf.leaf_type(), leaf_type);
        leaf.verify_identity().unwrap();
    }
}

#[test]
fn deep_directory_matches_every_layer_4_2_cid() {
    let temp = TempDir::new("deep-directory").unwrap();
    let root = temp.path().join("testdir");
    fs::create_dir_all(root.join("docs")).unwrap();
    fs::create_dir_all(root.join("src").join("lib")).unwrap();
    fs::create_dir_all(root.join("data")).unwrap();
    for (path, content) in [
        ("readme.txt", "This is the README file for the project"),
        ("docs/guide.txt", "Getting started guide content here"),
        ("docs/api.txt", "API documentation for developers"),
        ("src/main.txt", "Main source file with entry point"),
        ("src/lib/utils.txt", "Utility functions and helpers"),
        ("src/lib/helpers.txt", "Additional helper functions"),
        ("data/config.txt", "configuration=value\nkey=data"),
    ] {
        write(root.join(path), content.as_bytes()).unwrap();
    }
    let dag = create_dag_with_options(&root, &options_4096()).unwrap();
    let expected = [
        (
            "bafireialntcwjpmas6p776q3blz6vvnkyes7twkchtv6mo4zvjpgeo3rqy",
            "readme.txt",
            LeafType::File,
            0,
        ),
        (
            "bafireihl66nsr2gqh5owxxpyl43ofuqimpe5vdotoae6wqzjl23imgncae",
            "config.txt",
            LeafType::File,
            0,
        ),
        (
            "bafireiexdg54x7eetnk2ckbouiu66w6j75iochjbmoegpy5vy7kp72ky6a",
            "api.txt",
            LeafType::File,
            0,
        ),
        (
            "bafireiagwomu24byawpabi6ybaml2pyeeim6mfur62lgm42mbmc3a5p224",
            "guide.txt",
            LeafType::File,
            0,
        ),
        (
            "bafireiflxvbmm3iiut6e5m7hvk2synwlofnumydozqgugt4iksm2zyamby",
            "main.txt",
            LeafType::File,
            0,
        ),
        (
            "bafireiaspsfljwfeixrz36s23dfxi467sjq2ur4wbrok637whwyjezlxqu",
            "helpers.txt",
            LeafType::File,
            0,
        ),
        (
            "bafireie6v4qq6im4gbqoy5losadzrmeuiqiwelu3xequ33hv76dg5b4wau",
            "utils.txt",
            LeafType::File,
            0,
        ),
        (
            "bafireichjrezseonnh4utrjpfg55pc2fpm5pzy3d5pe3ukzho5j244hoga",
            "data",
            LeafType::Directory,
            1,
        ),
        (
            "bafireihs3y5ciehbhyr5oua62vdl4kak4zzbzikd5tt2gzgoxbhno7e2hm",
            "docs",
            LeafType::Directory,
            2,
        ),
        (
            "bafireieuupf6vtz4raiewiwh7uecfl3vvo47avxg3tsnxa5r3vjhv5a7fa",
            "lib",
            LeafType::Directory,
            2,
        ),
        (
            "bafireieg5oh5pff7tt2fkau6jfcesdqtubbjzikr2pkc5mozvheoccmqxq",
            "src",
            LeafType::Directory,
            2,
        ),
        (
            "bafireidb74bnd3jalcdjrog3sgnfdkxblqlphtkvbycksk3qpvrzbwzntu",
            "testdir",
            LeafType::Directory,
            4,
        ),
    ];
    assert_eq!(
        dag.root().as_str(),
        "bafireidb74bnd3jalcdjrog3sgnfdkxblqlphtkvbycksk3qpvrzbwzntu"
    );
    assert_eq!(dag.len(), 12);
    for (cid, name, leaf_type, links) in expected {
        let leaf = dag
            .leaves()
            .values()
            .find(|leaf| leaf.cid().as_str() == cid)
            .unwrap_or_else(|| panic!("missing reference leaf {cid}"));
        assert_eq!(leaf.item_name(), name);
        assert_eq!(leaf.leaf_type(), leaf_type);
        assert_eq!(leaf.links().len(), links);
        leaf.verify_identity().unwrap();
    }
}

#[test]
fn all_six_fixture_roots_and_statistics_match_go() {
    let temp = TempDir::new("fixture-matrix").unwrap();
    for expected in FIXTURES {
        let path = create_fixture(temp.path(), expected.name).unwrap();
        let dag = create_dag_with_options(&path, &options_4096()).unwrap();
        let chunk_count = dag
            .leaves()
            .values()
            .filter(|leaf| leaf.leaf_type() == LeafType::Chunk)
            .count();
        assert_eq!(dag.root().as_str(), expected.root, "{} root", expected.name);
        assert_eq!(dag.len(), expected.leaves, "{} leaves", expected.name);
        assert_eq!(chunk_count, expected.chunks, "{} chunks", expected.name);
        assert_eq!(
            dag.root_leaf().leaf_count(),
            expected.leaves as u64,
            "{} root leaf count",
            expected.name
        );
        assert_eq!(
            dag.root_leaf().content_size(),
            expected.content_size,
            "{} content size",
            expected.name
        );
        assert_eq!(
            dag.root_leaf().dag_size(),
            expected.dag_size,
            "{} DAG size",
            expected.name
        );
        for leaf in dag.leaves().values() {
            leaf.verify_identity().unwrap();
        }
    }
}

#[test]
fn nested_chunked_file_matches_go_and_uses_bare_indices() {
    let temp = TempDir::new("nested-chunked").unwrap();
    let input = temp.path().join("input");
    let file = input.join("nested").join("inner").join("large.bin");
    let data: Vec<u8> = (0..10_000).map(|index| (index % 251) as u8).collect();
    write(&file, &data).unwrap();
    let dag = create_dag_with_options(&input, &options_4096()).unwrap();
    assert_eq!(
        dag.root().as_str(),
        "bafireicgewyfpgq5ywxpx7wddgo56ghfeq6a5sszivzwt4h32xufds4s3u"
    );
    assert_eq!(dag.len(), 7);
    assert_eq!(dag.root_leaf().leaf_count(), 7);
    assert_eq!(dag.root_leaf().content_size(), 10_000);
    assert_eq!(dag.root_leaf().dag_size(), 11_996);
    let mut chunk_names: Vec<&str> = dag
        .leaves()
        .values()
        .filter(|leaf| leaf.leaf_type() == LeafType::Chunk)
        .map(|leaf| leaf.item_name())
        .collect();
    chunk_names.sort();
    assert_eq!(chunk_names, ["0", "1", "2"]);
    assert!(chunk_names
        .iter()
        .all(|name| !name.contains('/') && !name.contains('\\')));
}

#[test]
fn empty_exact_and_plus_one_chunk_boundaries_match_go() {
    let temp = TempDir::new("chunk-boundaries").unwrap();
    let root = temp.path().join("boundaries");
    fs::create_dir(&root).unwrap();
    write(root.join("empty.bin"), &[]).unwrap();
    write(root.join("one.bin"), &[1]).unwrap();
    write(root.join("minus.bin"), &alpha_data(4095)).unwrap();
    write(root.join("exact.bin"), &alpha_data(4096)).unwrap();
    write(root.join("plus.bin"), &alpha_data(4097)).unwrap();
    let dag = create_dag_with_options(&root, &options_4096()).unwrap();
    let empty = leaf_by_name(&dag, "empty.bin", LeafType::File);
    assert!(empty.content().is_none());
    assert!(empty.content_hash().is_none());
    for name in ["one.bin", "minus.bin", "exact.bin"] {
        let leaf = leaf_by_name(&dag, name, LeafType::File);
        assert!(leaf.content().is_some(), "{name}");
        assert!(leaf.links().is_empty(), "{name}");
    }
    let plus = leaf_by_name(&dag, "plus.bin", LeafType::File);
    assert!(plus.content().is_none());
    assert_eq!(plus.links().len(), 2);
    let names: Vec<&str> = plus
        .links()
        .iter()
        .map(|cid| dag.get(cid).unwrap().item_name())
        .collect();
    assert_eq!(names, ["0", "1"]);
}

#[test]
fn disabled_chunking_hashes_an_explicit_empty_buffer() {
    let temp = TempDir::new("disabled-chunking").unwrap();
    let file = temp.path().join("empty.bin");
    write(&file, &[]).unwrap();
    let options = DagBuildOptions::default().with_chunking_disabled();
    let dag = create_dag_with_options(&file, &options).unwrap();
    let root = dag.root_leaf();
    assert_eq!(root.leaf_type(), LeafType::File);
    assert_eq!(root.content(), Some([].as_slice()));
    assert!(root.content_hash().is_some());
    assert_eq!(root.content_size(), 0);
}

#[test]
fn legacy_fixed_default_chunk_size_is_two_mib_and_streams_a_plus_one_file() {
    // Pinned to the legacy fixed mode: the DEFAULT chunking is fastcdc-v1
    // now, and this test's link-count assertion is a fixed-mode contract.
    assert_eq!(DEFAULT_CHUNK_SIZE, 2 * 1024 * 1024);
    let temp = TempDir::new("default-chunk-size").unwrap();
    let file = temp.path().join("default.bin");
    write(&file, &alpha_data(DEFAULT_CHUNK_SIZE + 1)).unwrap();
    let options = DagBuildOptions::default()
        .with_chunk_size(DEFAULT_CHUNK_SIZE)
        .unwrap();
    let dag = create_dag_with_options(&file, &options).unwrap();
    assert_eq!(dag.root_leaf().leaf_type(), LeafType::File);
    assert_eq!(dag.root_leaf().links().len(), 2);
    assert!(dag.root_leaf().content().is_none());
}

#[test]
fn timestamp_root_replaces_caller_metadata_once_and_only_on_the_root() {
    let temp = TempDir::new("timestamp-root").unwrap();
    let root = temp.path().join("timestamped");
    fs::create_dir(&root).unwrap();
    write(root.join("child.txt"), b"timestamp child").unwrap();
    let caller = Metadata::from([
        ("timestamp".to_owned(), "caller".to_owned()),
        ("keep".to_owned(), "x".to_owned()),
    ]);
    // Pinned to the legacy fixed mode so the exact-metadata assertions
    // below stay byte-precise: the fastcdc-v1 default additionally stamps
    // the "chunking" root tag (covered by tests/fastcdc_vectors.rs).
    let enabled_options = DagBuildOptions::default()
        .with_chunk_size(DEFAULT_CHUNK_SIZE)
        .unwrap()
        .with_root_metadata(caller.clone())
        .with_timestamp_root(true);
    let timestamped = create_dag_with_options(&root, &enabled_options).unwrap();
    let generated = timestamped.root_leaf().additional_data();
    assert_eq!(generated.len(), 1);
    let timestamp = generated.get("timestamp").unwrap();
    assert_eq!(timestamp.len(), 20);
    assert_eq!(&timestamp[4..5], "-");
    assert_eq!(&timestamp[7..8], "-");
    assert_eq!(&timestamp[10..11], "T");
    assert_eq!(&timestamp[13..14], ":");
    assert_eq!(&timestamp[16..17], ":");
    assert!(timestamp.ends_with('Z'));
    assert!(timestamp
        .chars()
        .enumerate()
        .all(|(index, character)| matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || character.is_ascii_digit()));
    assert!(timestamped
        .leaves()
        .values()
        .filter(|leaf| leaf.cid() != timestamped.root())
        .all(|leaf| leaf.additional_data().is_empty()));

    let explicit_options = DagBuildOptions::default()
        .with_chunk_size(DEFAULT_CHUNK_SIZE)
        .unwrap()
        .with_root_metadata(generated.clone());
    let explicit = create_dag_with_options(&root, &explicit_options).unwrap();
    assert_eq!(timestamped.root(), explicit.root());
    let disabled_options = DagBuildOptions::default()
        .with_chunk_size(DEFAULT_CHUNK_SIZE)
        .unwrap()
        .with_root_metadata(caller.clone());
    let disabled = create_dag_with_options(&root, &disabled_options).unwrap();
    assert_eq!(disabled.root_leaf().additional_data(), &caller);
}

#[test]
fn leaf_processor_runs_once_per_non_root_filesystem_entry_and_never_for_chunks() {
    use std::path::Path;
    use std::cell::RefCell;
    use std::rc::Rc;

    let temp = TempDir::new("leaf-processor").unwrap();
    let root = temp.path().join("input");
    fs::create_dir_all(root.join("nested")).unwrap();
    write(root.join("a.txt"), b"a").unwrap();
    write(root.join("big.bin"), &alpha_data(150)).unwrap();
    write(root.join("nested").join("inside.txt"), b"inside").unwrap();
    let calls = Rc::new(RefCell::new(
        Vec::<(String, bool, LeafType, bool, u64)>::new(),
    ));
    let processor_calls = Rc::clone(&calls);
    let processor = move |path: &Path,
                     relative_path: &str,
                     entry: &fs::DirEntry,
                     is_root: bool,
                     leaf_type: LeafType|
     -> Option<Metadata> {
        let metadata = entry.metadata().unwrap();
        assert_eq!(entry.file_name().to_str(), Some(relative_path));
        assert_eq!(path.file_name().and_then(|name| name.to_str()), Some(relative_path));
        processor_calls.borrow_mut().push((
            relative_path.to_owned(),
            is_root,
            leaf_type,
            entry.file_type().unwrap().is_dir(),
            metadata.len(),
        ));
        Some(Metadata::from([(
            "processed".to_owned(),
            format!("{}:{relative_path}", leaf_type.as_str()),
        )]))
    };
    let options = DagBuildOptions::default()
        .with_chunk_size(64)
        .unwrap()
        .with_root_metadata(Metadata::from([(
            "root-only".to_owned(),
            "yes".to_owned(),
        )]));
    let dag = create_dag_custom(&root, &options, Some(&processor)).unwrap();
    let recorded = calls.borrow();
    assert_eq!(recorded.len(), 4);
    assert_eq!(
        recorded
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        ["a.txt", "big.bin", "nested", "inside.txt"]
    );
    assert!(recorded.iter().all(|call| !call.1));
    assert!(recorded.iter().all(|call| call.2 != LeafType::Chunk));
    assert!(recorded
        .iter()
        .all(|call| call.3 == (call.2 == LeafType::Directory)));
    drop(recorded);
    assert_eq!(
        dag.root_leaf().additional_data(),
        &Metadata::from([("root-only".to_owned(), "yes".to_owned())])
    );
    for leaf in dag.leaves().values() {
        match leaf.leaf_type() {
            LeafType::Chunk => assert!(leaf.additional_data().is_empty()),
            LeafType::File | LeafType::Directory if leaf.cid() != dag.root() => {
                assert!(leaf.additional_data().contains_key("processed"));
            }
            _ => {}
        }
    }

    calls.borrow_mut().clear();
    let single_file = create_dag_custom(root.join("a.txt"), &options, Some(&processor)).unwrap();
    assert!(calls.borrow().is_empty());
    assert_eq!(
        single_file.root_leaf().additional_data(),
        &Metadata::from([("root-only".to_owned(), "yes".to_owned())])
    );

    let no_processor = create_dag_with_options(&root, &options).unwrap();
    let explicit_none = create_dag_custom(&root, &options, None).unwrap();
    let returns_none = |_path: &Path,
                        _relative_path: &str,
                        _entry: &fs::DirEntry,
                        _is_root: bool,
                        _leaf_type: LeafType|
     -> Option<Metadata> { None };
    let returns_empty = |_path: &Path,
                         _relative_path: &str,
                         _entry: &fs::DirEntry,
                         _is_root: bool,
                         _leaf_type: LeafType|
     -> Option<Metadata> { Some(Metadata::new()) };
    assert_eq!(no_processor, explicit_none);
    assert_eq!(
        no_processor,
        create_dag_custom(&root, &options, Some(&returns_none)).unwrap()
    );
    assert_eq!(
        no_processor,
        create_dag_custom(&root, &options, Some(&returns_empty)).unwrap()
    );
}

#[test]
fn trailing_separator_uses_dot_root_name_without_changing_child_names() {
    let temp = TempDir::new("trailing-root-separator").unwrap();
    let root = temp.path().join("input");
    fs::create_dir(&root).unwrap();
    write(root.join("child.txt"), b"child").unwrap();
    let ordinary = create_dag(&root).unwrap();
    let with_separator = format!(
        "{}{}",
        root.to_str().unwrap(),
        std::path::MAIN_SEPARATOR
    );
    let trailing = create_dag(&with_separator).unwrap();
    assert_eq!(ordinary.root_leaf().item_name(), "input");
    assert_eq!(trailing.root_leaf().item_name(), ".");
    assert_ne!(ordinary.root(), trailing.root());
    assert!(trailing
        .leaves()
        .values()
        .any(|leaf| leaf.item_name() == "child.txt"));
}

#[test]
fn allocation_limits_reject_oversized_chunk_requests_and_sparse_disabled_files() {
    assert!(DagBuildOptions::default()
        .with_chunk_size(MAX_IN_MEMORY_LEAF_BYTES)
        .is_ok());
    assert!(matches!(
        DagBuildOptions::default().with_chunk_size(MAX_IN_MEMORY_LEAF_BYTES + 1),
        Err(Error::InMemoryLimitExceeded {
            resource: "chunk buffer",
            requested,
            limit,
        }) if requested == MAX_IN_MEMORY_LEAF_BYTES as u64 + 1
            && limit == MAX_IN_MEMORY_LEAF_BYTES as u64
    ));
    let temp = TempDir::new("sparse-over-limit").unwrap();
    let file = temp.path().join("oversized.bin");
    let handle = fs::File::create(&file).unwrap();
    handle
        .set_len(MAX_IN_MEMORY_LEAF_BYTES as u64 + 1)
        .unwrap();
    drop(handle);
    let error = create_dag_with_options(
        &file,
        &DagBuildOptions::default().with_chunking_disabled(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        Error::InMemoryLimitExceeded {
            resource: "file content",
            requested,
            limit,
        } if requested == MAX_IN_MEMORY_LEAF_BYTES as u64 + 1
            && limit == MAX_IN_MEMORY_LEAF_BYTES as u64
    ));
}
