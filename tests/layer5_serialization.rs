mod support;

use scionic_merkletree::{create_dag_with_options, Dag, LeafType};
use support::{create_fixture, options_4096, TempDir, FIXTURES};

#[test]
fn all_go_fixtures_round_trip_canonical_json_and_cbor() {
    let temp = TempDir::new("layer5-wire").unwrap();
    for fixture in FIXTURES {
        let input = create_fixture(temp.path(), fixture.name).unwrap();
        let dag = create_dag_with_options(&input, &options_4096()).unwrap();

        let json = dag.to_json().unwrap();
        assert!(json.starts_with(b"{\n  \"Root\": \""));
        let json_restored = Dag::from_json(&json).unwrap();
        assert_eq!(json_restored.root().as_str(), fixture.root);
        assert_eq!(json_restored, dag);
        json_restored.verify().unwrap();
        assert_eq!(json_restored.to_json().unwrap(), json);

        let cbor = dag.to_cbor().unwrap();
        let cbor_restored = Dag::from_cbor(&cbor).unwrap();
        assert_eq!(cbor_restored.root().as_str(), fixture.root);
        assert_eq!(cbor_restored, dag);
        cbor_restored.verify().unwrap();
        assert_eq!(cbor_restored.to_cbor().unwrap(), cbor);
    }
}

#[test]
fn lower_camel_json_aliases_are_rejected() {
    let temp = TempDir::new("layer5-lower-camel-json").unwrap();
    let input = create_fixture(temp.path(), "single_small_file").unwrap();
    let dag = create_dag_with_options(&input, &options_4096()).unwrap();
    let mut lower_camel = String::from_utf8(dag.to_json().unwrap()).unwrap();
    for (canonical, alias) in [
        ("Root", "root"),
        ("Leafs", "leafs"),
        ("Hash", "hash"),
        ("ItemName", "itemName"),
        ("Type", "type"),
        ("ContentHash", "contentHash"),
        ("Content", "content"),
        ("ClassicMerkleRoot", "classicMerkleRoot"),
        ("CurrentLinkCount", "currentLinkCount"),
        ("LeafCount", "leafCount"),
        ("ContentSize", "contentSize"),
        ("DagSize", "dagSize"),
        ("Links", "links"),
        ("AdditionalData", "additionalData"),
    ] {
        lower_camel = lower_camel.replace(&format!("\"{canonical}\""), &format!("\"{alias}\""));
    }
    assert!(Dag::from_json(lower_camel.as_bytes()).is_err());
}

#[test]
fn non_root_wire_counters_must_be_zero() {
    let temp = TempDir::new("layer5-non-root-counters").unwrap();
    let input = create_fixture(temp.path(), "single_small_file").unwrap();
    let dag = create_dag_with_options(&input, &options_4096()).unwrap();
    let non_root = dag
        .leaves()
        .values()
        .find(|leaf| leaf.cid() != dag.root())
        .expect("fixture has a non-root leaf");
    let json = String::from_utf8(dag.to_json().unwrap()).unwrap();
    let marker = format!("\"{}\": {{", non_root.cid());
    let leaf_start = json.find(&marker).expect("serialized non-root leaf");

    for field in ["LeafCount", "ContentSize", "DagSize"] {
        let mut changed = json.clone();
        let needle = format!("\"{field}\": 0");
        let relative = changed[leaf_start..]
            .find(&needle)
            .unwrap_or_else(|| panic!("serialized non-root {field}"));
        let start = leaf_start + relative;
        changed.replace_range(start..start + needle.len(), &format!("\"{field}\": 1"));
        assert!(Dag::from_json(changed.as_bytes()).is_err(), "{field}");
    }
}

#[test]
fn partial_round_trips_preserve_bound_proof_keys_children_siblings_and_paths() {
    let temp = TempDir::new("layer5-proof-wire").unwrap();
    let input = create_fixture(temp.path(), "flat_directory").unwrap();
    let dag = create_dag_with_options(&input, &options_4096()).unwrap();
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
    let branch = partial.root_leaf().proof_for(&selected).unwrap();
    assert_eq!(branch.child(), &selected);
    assert!(!branch.proof().siblings().is_empty());

    let json = partial.to_json().unwrap();
    assert!(json
        .windows(b"\"stored_proofs\"".len())
        .any(|window| window == b"\"stored_proofs\""));
    let from_json = Dag::from_json(&json).unwrap();
    assert_eq!(from_json, partial);
    assert_eq!(from_json.root_leaf().proof_for(&selected).unwrap(), branch);
    from_json.verify().unwrap();

    let cbor = partial.to_cbor().unwrap();
    let from_cbor = Dag::from_cbor(&cbor).unwrap();
    assert_eq!(from_cbor, partial);
    assert_eq!(from_cbor.root_leaf().proof_for(&selected).unwrap(), branch);
    from_cbor.verify().unwrap();
}
