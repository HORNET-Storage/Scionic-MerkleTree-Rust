use scionic_merkletree::{ClassicMerkleTree, Digest};

type RootCase = (Vec<(String, Vec<u8>)>, &'static str, usize);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn strings(entries: &[(&str, &str)]) -> Vec<(String, Vec<u8>)> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.as_bytes().to_vec()))
        .collect()
}

#[test]
fn all_reference_roots_and_depths_match() {
    let cases: Vec<RootCase> = vec![
        (
            strings(&[("a", "a"), ("b", "b")]),
            "e5a01fee14e0ed5c48714f22180f25ad8365b53f9779f79dc4a3d7e93963f94a",
            1,
        ),
        (
            strings(&[("x", "x"), ("y", "y"), ("z", "z")]),
            "94ee69041d6a31c76688b1da2c00896986f218040c9b41f7118de0b4ee80db98",
            2,
        ),
        (
            strings(&[
                ("bafy2bzacecwv", "bafy2bzacecwv"),
                ("bafy2bzacedxyz", "bafy2bzacedxyz"),
                ("bafy2bzaceaaaa", "bafy2bzaceaaaa"),
            ]),
            "95343f2d4bfe65b2b65f1f3f7a80b5687ff4fbceb27c18a48706e10d2b5cf76a",
            2,
        ),
        (
            strings(&[
                ("key1", "value1"),
                ("key2", "value2"),
                ("key3", "value3"),
                ("key4", "value4"),
                ("key5", "value5"),
            ]),
            "35710a651ac18658280658bd93b0d0cdd27ca6adcebba2083c694018204c4384",
            3,
        ),
    ];
    for (blocks, expected_root, expected_depth) in cases {
        let tree = ClassicMerkleTree::build(blocks).unwrap();
        assert_eq!(hex(tree.root()), expected_root);
        assert_eq!(tree.depth(), expected_depth);
        assert_eq!(tree.proofs().len(), tree.keys().len());
    }
}

#[test]
fn two_leaf_reference_proofs_are_exact() {
    let tree = ClassicMerkleTree::build(strings(&[("a", "a"), ("b", "b")])).unwrap();
    let proof_a = tree.proof_for_key("a").unwrap();
    assert_eq!(proof_a.path(), 1);
    assert_eq!(proof_a.siblings().len(), 1);
    assert_eq!(
        hex(&proof_a.siblings()[0]),
        "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"
    );
    let proof_b = tree.proof_for_key("b").unwrap();
    assert_eq!(proof_b.path(), 0);
    assert_eq!(proof_b.siblings().len(), 1);
    assert_eq!(
        hex(&proof_b.siblings()[0]),
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    );
    tree.verify(b"a", proof_a).unwrap();
    tree.verify(b"b", proof_b).unwrap();
}

#[test]
fn odd_width_proofs_duplicate_the_tail_and_use_go_path_bits() {
    let tree = ClassicMerkleTree::build(strings(&[("x", "x"), ("y", "y"), ("z", "z")])).unwrap();
    let proof_x = tree.proof_for_key("x").unwrap();
    let proof_y = tree.proof_for_key("y").unwrap();
    let proof_z = tree.proof_for_key("z").unwrap();
    assert_eq!(proof_x.path(), 3);
    assert_eq!(proof_y.path(), 2);
    assert_eq!(proof_z.path(), 1);
    assert_eq!(proof_z.siblings()[0], tree.leaf_hashes()[2]);
    for (key, value) in [
        ("x", b"x".as_slice()),
        ("y", b"y".as_slice()),
        ("z", b"z".as_slice()),
    ] {
        tree.verify(value, tree.proof_for_key(key).unwrap())
            .unwrap();
    }
}

#[test]
fn five_leaf_tree_verifies_every_precomputed_proof() {
    let blocks = strings(&[
        ("key1", "value1"),
        ("key2", "value2"),
        ("key3", "value3"),
        ("key4", "value4"),
        ("key5", "value5"),
    ]);
    let tree = ClassicMerkleTree::build(blocks.clone()).unwrap();
    for (key, value) in blocks {
        tree.verify(&value, tree.proof_for_key(&key).unwrap())
            .unwrap();
    }
}

#[test]
fn key_sorting_makes_insertion_order_irrelevant() {
    let forward = strings(&[("a", "a"), ("b", "b"), ("c", "c"), ("d", "d"), ("e", "e")]);
    let mut reverse = forward.clone();
    reverse.reverse();
    let first = ClassicMerkleTree::build(forward).unwrap();
    let second = ClassicMerkleTree::build(reverse).unwrap();
    assert_eq!(first.root(), second.root());
    assert_eq!(first.keys(), second.keys());
    assert_eq!(first.proofs(), second.proofs());
    assert_eq!(first.leaf_hashes(), second.leaf_hashes());
}

#[test]
fn invalid_counts_missing_keys_and_tampering_fail() {
    assert!(ClassicMerkleTree::build(Vec::<(String, Vec<u8>)>::new()).is_err());
    assert!(ClassicMerkleTree::build(strings(&[("only", "value")])).is_err());
    let tree = ClassicMerkleTree::build(strings(&[("a", "a"), ("b", "b")])).unwrap();
    assert!(tree.proof_for_key("missing").is_err());
    assert!(tree
        .verify(b"tampered", tree.proof_for_key("a").unwrap())
        .is_err());
    let wrong_root: Digest = [0_u8; 32];
    assert!(
        ClassicMerkleTree::verify_against(b"a", tree.proof_for_key("a").unwrap(), &wrong_root,)
            .is_err()
    );
}
