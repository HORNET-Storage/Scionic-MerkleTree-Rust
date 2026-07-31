mod support;

use scionic_merkletree::{
    create_dag_with_options, Cid, Dag, Error, LeafType,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use support::{create_fixture, options_4096, write, TempDir, FIXTURES};

#[test]
fn all_go_fixtures_verify_and_recreate_byte_for_byte() {
    let temp = TempDir::new("layer5-recreate").unwrap();
    for fixture in FIXTURES {
        let input = create_fixture(temp.path(), fixture.name).unwrap();
        let dag = create_dag_with_options(&input, &options_4096()).unwrap();
        dag.verify().unwrap();
        let output = temp.path().join(format!("{}-restored", fixture.name));
        dag.create_directory(&output).unwrap();
        assert_same_tree(&input, &output);
    }
}

#[test]
fn verification_rejects_content_and_root_aggregate_tampering_in_precedence_order() {
    let temp = TempDir::new("layer5-tamper").unwrap();
    let input = create_fixture(temp.path(), "single_small_file").unwrap();
    let dag = create_dag_with_options(&input, &options_4096()).unwrap();
    let json = dag.to_json().unwrap();

    let mut content_tampered = json.clone();
    let marker = b"\"Content\": \"";
    let start = content_tampered
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap()
        + marker.len();
    content_tampered[start] = if content_tampered[start] == b'A' { b'B' } else { b'A' };
    let content_dag = Dag::from_json(&content_tampered).unwrap();
    assert!(matches!(
        content_dag.verify(),
        Err(Error::ContentHashMismatch { .. })
    ));

    let content_size_tampered = replace_once(
        &json,
        b"\"ContentSize\": 1024",
        b"\"ContentSize\": 1025",
    );
    let content_size_dag = Dag::from_json(&content_size_tampered).unwrap();
    assert!(matches!(
        content_size_dag.verify(),
        Err(Error::ContentSizeMismatch {
            stored: 1025,
            calculated: 1024
        })
    ));

    let dag_size_tampered = replace_once(
        &json,
        b"\"DagSize\": 1467",
        b"\"DagSize\": 1468",
    );
    let dag_size_dag = Dag::from_json(&dag_size_tampered).unwrap();
    assert!(matches!(
        dag_size_dag.verify(),
        Err(Error::DagSizeMismatch {
            stored: 1468,
            calculated: 1467
        })
    ));
}

#[test]
fn labels_pin_go_unique_dfs_order_and_root_zero_semantics() {
    let temp = TempDir::new("layer5-labels").unwrap();
    let input = temp.path().join("input");
    fs::create_dir_all(input.join("subdir")).unwrap();
    write(input.join("file1.txt"), b"Hello from file one").unwrap();
    write(input.join("file2.txt"), b"Hello from file two").unwrap();
    write(input.join("subdir").join("nested.txt"), b"I am nested").unwrap();
    let mut dag = create_dag_with_options(&input, &options_4096()).unwrap();
    dag.calculate_labels().unwrap();

    let expected = [
        "bafireiaptl7ndqt7ngu5ctnpghwvwyxekrt66cpzxyzst2nyso7ppq76v4",
        "bafireicmmr4urltkiwzp7cx3w2lmpza4zvkpf4gj2llt42f2cyxlwyfd6e",
        "bafireihanc6pjpcfhhnljfss6227fpjy7ftqi52ubxqomjosv32d2ovehm",
        "bafireidzdh6wxep5jg3gbkrm5gxns7syv6igqmmqngeioidfc2ljadkjzu",
    ];
    assert_eq!(dag.get_label(dag.root()).unwrap(), "0");
    assert_eq!(dag.labels().len(), expected.len());
    for (index, cid) in expected.iter().enumerate() {
        let cid: Cid = cid.parse().unwrap();
        assert_eq!(dag.get_label(&cid).unwrap(), (index + 1).to_string());
    }
    assert_eq!(
        dag.get_hashes_by_label_range(1, 4)
            .unwrap()
            .iter()
            .map(Cid::as_str)
            .collect::<Vec<_>>(),
        expected
    );
    dag.clear_labels();
    assert_eq!(dag.get_label(dag.root()).unwrap(), "0");
    assert!(matches!(
        dag.get_hashes_by_label_range(1, 1),
        Err(Error::LabelsNotCalculated)
    ));
}

#[test]
fn pruned_root_only_and_proof_bearing_partials_verify() {
    let temp = TempDir::new("layer5-partial-verify").unwrap();
    let input = create_fixture(temp.path(), "flat_directory").unwrap();
    let dag = create_dag_with_options(&input, &options_4096()).unwrap();

    let root_only = dag
        .get_partial(std::slice::from_ref(dag.root()), true)
        .unwrap();
    assert_eq!(root_only.len(), 1);
    assert!(root_only.is_partial());
    root_only.verify().unwrap();

    let selected = dag
        .leaves()
        .values()
        .find(|leaf| leaf.item_name() == "file1.txt" && leaf.leaf_type() == LeafType::File)
        .unwrap()
        .cid()
        .clone();
    let partial = dag
        .get_partial(std::slice::from_ref(&selected), true)
        .unwrap();
    assert_eq!(partial.len(), 2);
    assert!(partial.is_partial());
    assert_eq!(
        partial.root_leaf().links(),
        std::slice::from_ref(&selected)
    );
    assert!(partial.root_leaf().proof_for(&selected).is_some());
    partial.verify().unwrap();
}

fn replace_once(input: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    assert_eq!(from.len(), to.len());
    let offset = input
        .windows(from.len())
        .position(|window| window == from)
        .unwrap();
    let mut output = input.to_vec();
    output[offset..offset + from.len()].copy_from_slice(to);
    output
}

fn assert_same_tree(left: &Path, right: &Path) {
    let left_metadata = fs::metadata(left).unwrap();
    let right_metadata = fs::metadata(right).unwrap();
    assert_eq!(left_metadata.is_dir(), right_metadata.is_dir());
    if left_metadata.is_file() {
        assert_eq!(fs::read(left).unwrap(), fs::read(right).unwrap());
        return;
    }
    let left_entries = directory_entries(left);
    let right_entries = directory_entries(right);
    assert_eq!(left_entries.keys().collect::<Vec<_>>(), right_entries.keys().collect::<Vec<_>>());
    for (name, left_path) in left_entries {
        assert_same_tree(&left_path, right_entries.get(&name).unwrap());
    }
}

fn directory_entries(path: &Path) -> BTreeMap<String, std::path::PathBuf> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name().into_string().unwrap(), entry.path())
        })
        .collect()
}
