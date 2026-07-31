use scionic_merkletree::{DagBuilder, DagStats, LeafBuilder, LeafType, Metadata};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn position(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("expected encoded field name")
}

#[test]
fn simple_leaf_preimage_and_cid_are_exact() {
    let leaf = LeafBuilder::new("test.txt", LeafType::File)
        .build(None)
        .unwrap();
    assert_eq!(
        hex(&leaf.identity_cbor()),
        "a6684974656d4e616d6568746573742e74787464547970656466696c656a4d65726b6c65526f6f74407043757272656e744c696e6b436f756e74006b436f6e74656e7448617368f66e4164646974696f6e616c4461746180"
    );
    assert_eq!(
        leaf.cid().as_str(),
        "bafireibuicwfb4ui2mth5zis4sgurvaoc4ksl2c74ezmjvuzqxdzkdeazq"
    );
    assert_eq!(&leaf.cid().as_bytes()[..4], &[0x01, 0x51, 0x12, 0x20]);
    leaf.verify_identity().unwrap();
}

#[test]
fn all_standalone_reference_leaf_cids_match() {
    let content = LeafBuilder::new("hello.txt", LeafType::File)
        .with_data(b"Hello, World!".to_vec())
        .build(None)
        .unwrap();
    assert_eq!(
        content.cid().as_str(),
        "bafireiflmfq3vajjy5swuz2ayvewhgm2g3nurum6hrizwo4ypic33ke3yu"
    );
    let chunk = LeafBuilder::new("0", LeafType::Chunk)
        .with_data(b"chunk data here".to_vec())
        .build(None)
        .unwrap();
    assert_eq!(
        chunk.cid().as_str(),
        "bafireiankzjounqke5zgzgybia53orcs4xudtpg7ab7cgcobgbvemovv5m"
    );
    let mut metadata = Metadata::new();
    metadata.insert("version".to_owned(), "1.0".to_owned());
    metadata.insert("author".to_owned(), "test".to_owned());
    let metadata_leaf = LeafBuilder::new("meta.txt", LeafType::File)
        .with_data(b"content".to_vec())
        .build(Some(&metadata))
        .unwrap();
    assert_eq!(
        metadata_leaf.cid().as_str(),
        "bafireic7msahojyf4q3xpjtrnrveqkvy7w4y24gx66m7h5xjqgmekapmsy"
    );
    assert_eq!(
        metadata_leaf
            .additional_data()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["author", "version"]
    );
    content.verify_identity().unwrap();
    chunk.verify_identity().unwrap();
    metadata_leaf.verify_identity().unwrap();
}

#[test]
fn manual_two_child_root_matches_all_go_values() {
    let child1 = LeafBuilder::new("file1.txt", LeafType::File)
        .with_data(b"file one content".to_vec())
        .build(None)
        .unwrap();
    let child2 = LeafBuilder::new("file2.txt", LeafType::File)
        .with_data(b"file two content".to_vec())
        .build(None)
        .unwrap();
    assert_eq!(
        child1.cid().as_str(),
        "bafireiglie6hokrajhseihtblq24ckpxverf6owidzeey63oqadljd2xfy"
    );
    assert_eq!(
        child2.cid().as_str(),
        "bafireiahteebcm75zwg7pzo2pvtjejrepxhtogx6p32yr35me3wnieqdra"
    );
    assert_eq!(child1.storage_size().unwrap(), 260);
    assert_eq!(child2.storage_size().unwrap(), 260);
    let mut dag = DagBuilder::new();
    assert!(dag.add_leaf(child1.clone()).unwrap());
    assert!(dag.add_leaf(child2.clone()).unwrap());
    assert_eq!(dag.stats().leaf_count(), 2);
    assert_eq!(dag.stats().content_size(), 32);
    assert_eq!(dag.stats().dag_size(), 520);
    let mut root_builder = LeafBuilder::new("mydir", LeafType::Directory);
    root_builder.add_link(child1.cid().clone());
    root_builder.add_link(child2.cid().clone());
    let root = root_builder
        .build_root_with_stats(dag.stats(), None)
        .unwrap();
    assert_eq!(root.leaf_count(), 3);
    assert_eq!(root.content_size(), 32);
    assert_eq!(root.dag_size(), 677);
    assert_eq!(
        root.cid().as_str(),
        "bafireiglw5me5qi2vhuvkc3f6tygpqvcjvsgmj6zgppdrz7hwvxbopq2iy"
    );
    root.verify_identity().unwrap();
}

#[test]
fn identity_field_order_is_explicit() {
    let leaf = LeafBuilder::new("shape.txt", LeafType::File)
        .build(None)
        .unwrap();
    let identity = leaf.identity_cbor();
    let ordered = [
        b"\x68ItemName".as_slice(),
        b"\x64Type".as_slice(),
        b"\x6aMerkleRoot".as_slice(),
        b"\x70CurrentLinkCount".as_slice(),
        b"\x6bContentHash".as_slice(),
        b"\x6eAdditionalData".as_slice(),
    ];
    let positions: Vec<usize> = ordered.iter().map(|key| position(&identity, key)).collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn absent_and_present_empty_content_remain_distinct() {
    let absent = LeafBuilder::new("empty.txt", LeafType::File)
        .build(None)
        .unwrap();
    let present = LeafBuilder::new("empty.txt", LeafType::File)
        .with_data(Vec::new())
        .build(None)
        .unwrap();
    assert!(absent.content().is_none());
    assert!(absent.content_hash().is_none());
    assert_eq!(present.content(), Some([].as_slice()));
    assert!(present.content_hash().is_some());
    assert_ne!(absent.cid(), present.cid());
    assert_ne!(absent.identity_cbor(), present.identity_cbor());
}

#[test]
fn link_root_semantics_and_stored_order_match_go() {
    let child1 = LeafBuilder::new("a", LeafType::File)
        .with_data(b"a".to_vec())
        .build(None)
        .unwrap();
    let child2 = LeafBuilder::new("b", LeafType::File)
        .with_data(b"b".to_vec())
        .build(None)
        .unwrap();
    let one = LeafBuilder::new("one", LeafType::Directory)
        .with_link(child1.cid().clone())
        .build(None)
        .unwrap();
    assert_eq!(one.classic_merkle_root(), child1.cid().as_str().as_bytes());
    let mut directory_builder = LeafBuilder::new("dir", LeafType::Directory);
    directory_builder.add_link(child1.cid().clone());
    directory_builder.add_link(child2.cid().clone());
    let directory = directory_builder.build(None).unwrap();
    let mut directory_reversed_builder = LeafBuilder::new("dir", LeafType::Directory);
    directory_reversed_builder.add_link(child2.cid().clone());
    directory_reversed_builder.add_link(child1.cid().clone());
    let directory_reversed = directory_reversed_builder.build(None).unwrap();
    assert_eq!(directory.cid(), directory_reversed.cid());
    assert!(directory.links().windows(2).all(|pair| pair[0] <= pair[1]));
    let mut file_forward_builder = LeafBuilder::new("large", LeafType::File);
    file_forward_builder.add_link(child1.cid().clone());
    file_forward_builder.add_link(child2.cid().clone());
    let file_forward = file_forward_builder.build(None).unwrap();
    let mut file_reversed_builder = LeafBuilder::new("large", LeafType::File);
    file_reversed_builder.add_link(child2.cid().clone());
    file_reversed_builder.add_link(child1.cid().clone());
    let file_reversed = file_reversed_builder.build(None).unwrap();
    assert_eq!(file_forward.cid(), file_reversed.cid());
    assert_eq!(
        file_reversed.links(),
        &[child2.cid().clone(), child1.cid().clone()]
    );
    assert_eq!(
        file_forward.classic_merkle_root(),
        directory.classic_merkle_root()
    );
    let file_forward_storage_size = file_forward.storage_size().unwrap();
    let file_reversed_storage_size = file_reversed.storage_size().unwrap();
    assert_eq!(file_forward_storage_size, file_reversed_storage_size);
    assert_eq!(
        directory.storage_size().unwrap(),
        directory_reversed.storage_size().unwrap()
    );

    let mut forward_dag = DagBuilder::new();
    forward_dag.add_leaf(file_forward.clone()).unwrap();
    let mut reversed_dag = DagBuilder::new();
    reversed_dag.add_leaf(file_reversed.clone()).unwrap();
    assert_eq!(forward_dag.stats(), reversed_dag.stats());
    assert_eq!(
        forward_dag.stats().dag_size(),
        file_forward_storage_size
    );

    let stats = DagStats::new(2, 0, 0);
    let file_forward_root = file_forward_builder
        .build_root_with_stats(stats, None)
        .unwrap();
    let file_reversed_root = file_reversed_builder
        .build_root_with_stats(stats, None)
        .unwrap();
    assert_eq!(file_forward_root.cid(), file_reversed_root.cid());
    assert_eq!(
        file_forward_root.storage_size().unwrap(),
        file_reversed_root.storage_size().unwrap()
    );
    let directory_root = directory_builder
        .build_root_with_stats(stats, None)
        .unwrap();
    let directory_reversed_root = directory_reversed_builder
        .build_root_with_stats(stats, None)
        .unwrap();
    assert_eq!(directory_root.cid(), directory_reversed_root.cid());
    assert_eq!(
        directory_root.storage_size().unwrap(),
        directory_reversed_root.storage_size().unwrap()
    );
}

#[test]
fn deduplicated_builder_stats_charge_identical_leaf_once() {
    let leaf = LeafBuilder::new("same", LeafType::Chunk)
        .with_data(b"same bytes".to_vec())
        .build(None)
        .unwrap();
    let mut builder = DagBuilder::new();
    assert!(builder.add_leaf(leaf.clone()).unwrap());
    let once = builder.stats();
    assert!(!builder.add_leaf(leaf).unwrap());
    assert_eq!(builder.stats(), once);
    assert_eq!(builder.len(), 1);
}
