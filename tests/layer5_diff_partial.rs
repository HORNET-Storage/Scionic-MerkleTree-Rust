mod support;

use scionic_merkletree::{
    create_dag_with_options, diff, diff_from_new_leaves, LeafType,
};
use support::{create_fixture, options_4096, write, TempDir};

#[test]
fn directional_diff_pins_go_set_counts_and_applies_to_the_new_dag() {
    let temp = TempDir::new("layer5-diff").unwrap();
    let input = create_fixture(temp.path(), "flat_directory").unwrap();
    let old_dag = create_dag_with_options(&input, &options_4096()).unwrap();
    write(input.join("file1.txt"), b"changed in the target DAG").unwrap();
    let new_dag = create_dag_with_options(&input, &options_4096()).unwrap();

    let changes = diff(&old_dag, &new_dag).unwrap();
    assert_eq!(changes.summary().added(), 2);
    assert_eq!(changes.summary().removed(), 2);
    assert_eq!(changes.summary().total(), 4);
    assert_eq!(changes.get_added_leaves().len(), 2);
    assert_eq!(changes.get_removed_leaves().len(), 2);
    let applied = changes.apply_to_dag(&old_dag).unwrap();
    assert_eq!(applied, new_dag);
    applied.verify().unwrap();

    let transport_subset = changes.create_partial_dag(&new_dag).unwrap();
    assert!(transport_subset.is_partial());
    transport_subset.verify().unwrap();
    let from_subset = diff_from_new_leaves(&old_dag, transport_subset.leaves()).unwrap();
    assert_eq!(from_subset.summary(), changes.summary());
    let subset_applied = from_subset.apply_to_dag(&old_dag).unwrap();
    assert_eq!(subset_applied.root(), new_dag.root());
    assert_eq!(subset_applied.len(), new_dag.len());
    for (cid, expected) in new_dag.leaves() {
        let actual = subset_applied.get(cid).unwrap();
        assert_eq!(actual.identity_cbor(), expected.identity_cbor());
        assert_eq!(actual.content(), expected.content());
        assert_eq!(actual.links(), expected.links());
    }
    subset_applied.verify().unwrap();
}

#[test]
fn single_selected_leaf_partial_is_smaller_and_uses_a_bound_root_proof() {
    let temp = TempDir::new("layer5-selected-partial").unwrap();
    let input = create_fixture(temp.path(), "flat_directory").unwrap();
    let dag = create_dag_with_options(&input, &options_4096()).unwrap();
    let selected = dag
        .leaves()
        .values()
        .find(|leaf| leaf.item_name() == "file3.txt" && leaf.leaf_type() == LeafType::File)
        .unwrap()
        .cid()
        .clone();
    let partial = dag
        .get_partial(std::slice::from_ref(&selected), true)
        .unwrap();
    assert!(partial.len() < dag.len());
    assert!(partial.is_partial());
    let branch = partial.root_leaf().proof_for(&selected).unwrap();
    assert_eq!(branch.child(), &selected);
    partial.verify().unwrap();
}
