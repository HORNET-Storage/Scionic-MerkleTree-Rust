mod support;

use scionic_merkletree::{
    create_dag_with_options, ClassicMerkleTree, Dag, DagBuildOptions, Digest, LeafType,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use support::{alpha_data, create_fixture, options_4096, write, TempDir};

fn file<'a>(dag: &'a Dag, name: &str) -> &'a scionic_merkletree::DagLeaf {
    dag.leaves()
        .values()
        .find(|leaf| leaf.leaf_type() == LeafType::File && leaf.item_name() == name)
        .unwrap_or_else(|| panic!("missing file leaf {name}"))
}

fn verify_parent_proof(parent: &scionic_merkletree::DagLeaf, child: &scionic_merkletree::Cid) {
    let proof = parent.proof_for_child(child).unwrap();
    let root: &Digest = parent.classic_merkle_root().try_into().unwrap();
    ClassicMerkleTree::verify_against(child.as_str().as_bytes(), &proof, root).unwrap();
}

#[test]
fn mixed_sizes_is_byte_identical_for_sixty_four_builds() {
    let temp = TempDir::new("mixed-determinism").unwrap();
    let path = create_fixture(temp.path(), "mixed_sizes").unwrap();
    let baseline = create_dag_with_options(&path, &options_4096()).unwrap();
    assert_eq!(
        baseline.root().as_str(),
        "bafireibrvfd6b3unpr27mq72pdsksj26y6hq32ahjmy6i7omfresfleloq"
    );
    for iteration in 0..64 {
        let rebuilt = create_dag_with_options(&path, &options_4096()).unwrap();
        assert_eq!(
            rebuilt, baseline,
            "build {iteration} changed DAG bytes or order"
        );
    }
}

#[test]
fn shared_chunk_keeps_both_parent_edges_and_both_proofs() {
    let temp = TempDir::new("shared-parent-proofs").unwrap();
    let path = create_fixture(temp.path(), "mixed_sizes").unwrap();
    let dag = create_dag_with_options(&path, &options_4096()).unwrap();
    let medium = file(&dag, "medium.txt");
    let large = file(&dag, "large.txt");
    assert_eq!(medium.links().len(), 2);
    assert_eq!(large.links().len(), 4);
    let shared = &medium.links()[0];
    assert_eq!(shared, &large.links()[0]);
    assert_eq!(dag.get(shared).unwrap().item_name(), "0");
    let parents: Vec<_> = dag
        .leaves()
        .values()
        .filter(|leaf| leaf.links().contains(shared))
        .collect();
    assert_eq!(parents.len(), 2);
    assert!(parents.iter().any(|leaf| leaf.cid() == medium.cid()));
    assert!(parents.iter().any(|leaf| leaf.cid() == large.cid()));
    verify_parent_proof(medium, shared);
    verify_parent_proof(large, shared);
    let chunk_count = dag
        .leaves()
        .values()
        .filter(|leaf| leaf.leaf_type() == LeafType::Chunk)
        .count();
    assert_eq!(chunk_count, 5);
    assert_eq!(dag.root_leaf().leaf_count(), 11);
    assert_eq!(dag.root_leaf().content_size(), 22_656);
    assert_eq!(dag.root_leaf().dag_size(), 25_612);
}

#[test]
fn unique_traversal_visits_shared_leaf_once_for_sixty_four_runs() {
    let temp = TempDir::new("visited-determinism").unwrap();
    let path = create_fixture(temp.path(), "mixed_sizes").unwrap();
    let dag = create_dag_with_options(&path, &options_4096()).unwrap();
    let medium = file(&dag, "medium.txt");
    let large = file(&dag, "large.txt");
    let shared = medium.links()[0].clone();
    assert!(large.links().contains(&shared));
    let parents: Vec<_> = dag
        .leaves()
        .values()
        .filter(|leaf| leaf.links().contains(&shared))
        .map(|leaf| leaf.cid().clone())
        .collect();
    assert_eq!(parents.len(), 2);
    let minimum_parent = parents
        .iter()
        .min_by(|left, right| left.as_str().cmp(right.as_str()))
        .unwrap()
        .clone();
    for iteration in 0..64 {
        let mut counts = BTreeMap::new();
        let mut shared_parent = None;
        dag.visit_unique(|leaf, parent| {
            *counts.entry(leaf.cid().clone()).or_insert(0_usize) += 1;
            if leaf.cid() == &shared {
                shared_parent = parent.map(|parent| parent.cid().clone());
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(counts.len(), dag.len());
        assert_eq!(
            counts.keys().cloned().collect::<BTreeSet<_>>(),
            dag.leaves().keys().cloned().collect(),
            "iteration {iteration} changed the visited CID set"
        );
        assert!(
            counts.values().all(|count| *count == 1),
            "iteration {iteration} visited at least one leaf more than once"
        );
        assert_eq!(counts.get(&shared), Some(&1));
        assert_eq!(shared_parent, Some(minimum_parent.clone()));
    }
}

#[test]
fn reverse_creation_order_cannot_change_flat_directory() {
    let first_temp = TempDir::new("flat-forward").unwrap();
    let first_path = create_fixture(first_temp.path(), "flat_directory").unwrap();
    let first = create_dag_with_options(&first_path, &options_4096()).unwrap();
    let second_temp = TempDir::new("flat-reverse").unwrap();
    let second_path = second_temp.path().join("flat_directory");
    fs::create_dir(&second_path).unwrap();
    for (name, size) in [
        ("file5.txt", 256),
        ("file4.txt", 2048),
        ("file3.txt", 768),
        ("file2.txt", 1024),
        ("file1.txt", 512),
    ] {
        write(second_path.join(name), &alpha_data(size)).unwrap();
    }
    let second = create_dag_with_options(&second_path, &options_4096()).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        second.root().as_str(),
        "bafireigd6awocke3nmagbspbkv2rfiqqai455eimle27u36ljeytyqdb4u"
    );
}

#[test]
fn chunk_order_test() {
    const CHUNK_SIZE: usize = 64;
    const CHUNKS: usize = 12;
    const PERMUTATION: [usize; CHUNKS] = [10, 2, 11, 0, 9, 1, 8, 3, 7, 4, 6, 5];
    let temp = TempDir::new("chunk-order-test").unwrap();
    let file_path = temp.path().join("twelve-chunks.bin");
    let mut expected = Vec::with_capacity(CHUNK_SIZE * CHUNKS);
    for index in 0..CHUNKS {
        expected.extend(std::iter::repeat_n(index as u8, CHUNK_SIZE));
    }
    write(&file_path, &expected).unwrap();
    let options = DagBuildOptions::default()
        .with_chunk_size(CHUNK_SIZE)
        .unwrap();
    let dag = create_dag_with_options(&file_path, &options).unwrap();
    let root = dag.root_leaf();
    assert_eq!(root.leaf_type(), LeafType::File);
    assert_eq!(root.links().len(), CHUNKS);
    let mut permuted: Vec<_> = PERMUTATION
        .iter()
        .map(|index| dag.get(&root.links()[*index]).unwrap())
        .collect();
    assert_eq!(
        permuted
            .iter()
            .map(|chunk| chunk.item_name())
            .collect::<Vec<_>>(),
        ["10", "2", "11", "0", "9", "1", "8", "3", "7", "4", "6", "5"]
    );
    let mut lexical = permuted.clone();
    lexical.sort_by(|left, right| left.item_name().cmp(right.item_name()));
    let lexical_bytes: Vec<u8> = lexical
        .iter()
        .flat_map(|chunk| chunk.content().unwrap().iter().copied())
        .collect();
    assert_ne!(lexical_bytes, expected);
    permuted.sort_by_key(|chunk| chunk.item_name().parse::<usize>().unwrap());
    let reconstructed: Vec<u8> = permuted
        .iter()
        .flat_map(|chunk| chunk.content().unwrap().iter().copied())
        .collect();
    assert_eq!(reconstructed, expected);
}

/// PORT-PLAN determinism case 3: the same bytes must reconstruct the same parent
/// hashes twice.
///
/// A DAG assembled from parts derives each leaf's parent, and a content-identical
/// chunk can hang under several parents at once. Go resolved that by lowest
/// parent CID only after the local copy it replaced kept whichever parent map
/// iteration happened to yield first -- a shared chunk's parent then changed from
/// one deserialization of the same bytes to the next, and verification failed
/// roughly one run in thirty. That reads as flakiness rather than as the
/// correctness bug it is, so it is pinned here over many iterations.
#[test]
fn deserializing_the_same_bytes_reassigns_identical_parent_hashes() {
    let temp = TempDir::new("parent-hash-determinism").unwrap();
    let path = create_fixture(temp.path(), "mixed_sizes").unwrap();
    let dag = create_dag_with_options(&path, &options_4096()).unwrap();

    // mixed_sizes is the only fixture with a chunk under two parents, which is
    // the only shape that can expose parent resolution order at all.
    let shared = file(&dag, "medium.txt").links()[0].clone();
    let parents: Vec<_> = dag
        .leaves()
        .values()
        .filter(|leaf| leaf.links().contains(&shared))
        .map(|leaf| leaf.cid().clone())
        .collect();
    assert_eq!(parents.len(), 2, "the chosen chunk really is shared");
    let lowest = parents
        .iter()
        .min_by(|left, right| left.as_str().cmp(right.as_str()))
        .unwrap()
        .clone();

    let json = dag.to_json().unwrap();
    let cbor = dag.to_cbor().unwrap();
    let mut baseline: Option<BTreeMap<String, Option<String>>> = None;
    for iteration in 0..64 {
        for restored in [Dag::from_json(&json).unwrap(), Dag::from_cbor(&cbor).unwrap()] {
            restored.verify().unwrap();
            assert_eq!(
                restored.root_leaf().parent_hash(),
                None,
                "iteration {iteration}: the root has no parent"
            );
            let observed: BTreeMap<String, Option<String>> = restored
                .leaves()
                .values()
                .map(|leaf| {
                    (
                        leaf.cid().to_string(),
                        leaf.parent_hash().map(ToString::to_string),
                    )
                })
                .collect();
            assert_eq!(
                observed.get(shared.as_str()).unwrap().as_deref(),
                Some(lowest.as_str()),
                "iteration {iteration}: the shared chunk must resolve to its lowest parent"
            );
            match &baseline {
                None => baseline = Some(observed),
                Some(first) => assert_eq!(
                    &observed, first,
                    "iteration {iteration} reconstructed a different parent for at least one leaf"
                ),
            }
        }
    }
}
