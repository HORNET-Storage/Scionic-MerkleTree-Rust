mod support;

use scionic_merkletree::{create_dag_with_options, Dag, Error};
use support::{create_fixture, options_4096, TempDir};

/// An unpruned root-only partial keeps the root's complete link list.
///
/// Root identity commits `ClassicMerkleRoot` and `CurrentLinkCount`, but not the
/// link CIDs themselves, and `verify_partial`'s parent walk skips the root
/// because the root has no parent. Before `verify_partial` recomputed the
/// classic root for complete link lists, that combination accepted a wholesale
/// link substitution: identity still matched, the count still matched, and no
/// non-root leaf existed to trigger parent verification.
///
/// The pre-existing partial test only exercised `prune_links = true`, which
/// takes the proof-verified path, so this branch had no coverage at all.
#[test]
fn unpruned_root_only_partial_rejects_a_same_length_link_substitution() {
    let temp = TempDir::new("partial-integrity").unwrap();
    let input = create_fixture(temp.path(), "flat_directory").unwrap();
    let dag = create_dag_with_options(&input, &options_4096()).unwrap();

    let partial = dag
        .get_partial(std::slice::from_ref(dag.root()), false)
        .unwrap();
    assert_eq!(partial.len(), 1, "a root-only partial retains just the root");
    assert!(partial.is_partial());
    assert_eq!(
        partial.root_leaf().links().len(),
        dag.root_leaf().links().len(),
        "prune_links = false keeps the complete link list"
    );
    partial.verify().unwrap();

    // Swap one link for a syntactically valid CID taken from a different
    // fixture, leaving the link count and the stored ClassicMerkleRoot
    // untouched. Substitution rather than permutation is the point: the classic
    // tree sorts its keys, so reordering the same set is genuinely harmless and
    // correctly still verifies.
    let victim = dag.root_leaf().links()[0].to_string();
    let impostor = "bafireiabahlly4rktdhsvhzgd2prjurwuupjo5shdsefkpayhfqefhcvpe";
    assert_ne!(victim, impostor);

    let json = String::from_utf8(partial.to_json().unwrap()).unwrap();
    assert_eq!(
        json.matches(&victim).count(),
        1,
        "in a root-only partial a child CID appears only inside the root's Links"
    );
    let tampered = json.replace(&victim, impostor);

    let tampered_dag = Dag::from_json(tampered.as_bytes()).unwrap();
    assert_eq!(
        tampered_dag.root_leaf().links().len(),
        dag.root_leaf().links().len(),
        "the tamper preserves the declared link count"
    );
    assert!(
        matches!(
            tampered_dag.verify(),
            Err(Error::ClassicRootMismatch { .. })
        ),
        "a substituted link must be caught by recomputing the classic root, got {:?}",
        tampered_dag.verify()
    );
}

/// Reordering a complete link list is not tampering: the classic Merkle tree
/// sorts its keys, so the recomputed root is identical. This pins that the new
/// check rejects substitution without over-rejecting a harmless permutation.
#[test]
fn unpruned_partial_still_accepts_a_permuted_link_list() {
    let temp = TempDir::new("partial-permute").unwrap();
    let input = create_fixture(temp.path(), "flat_directory").unwrap();
    let dag = create_dag_with_options(&input, &options_4096()).unwrap();

    let partial = dag
        .get_partial(std::slice::from_ref(dag.root()), false)
        .unwrap();

    let links = dag.root_leaf().links();
    assert!(links.len() >= 2, "flat_directory root has several children");
    let first = links[0].to_string();
    let second = links[1].to_string();

    // Swap the first two entries through a placeholder so the two replacements
    // cannot chase each other.
    let json = String::from_utf8(partial.to_json().unwrap()).unwrap();
    let swapped = json
        .replace(&first, "@@PLACEHOLDER@@")
        .replace(&second, &first)
        .replace("@@PLACEHOLDER@@", &second);

    let permuted = Dag::from_json(swapped.as_bytes()).unwrap();
    assert_ne!(
        permuted.root_leaf().links(),
        dag.root_leaf().links(),
        "the link order really did change"
    );
    permuted
        .verify()
        .expect("a permuted complete link list still verifies");
}

