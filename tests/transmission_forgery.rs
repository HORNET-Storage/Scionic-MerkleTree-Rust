//! Adversarial coverage for packet relationship and proof authentication.
//!
//! Every other transmission test feeds the receiver packets this crate just
//! produced, so they only ever exercise the honest path. These construct packets
//! a hostile peer could send and require rejection.
//!
//! Both attacks were live before the fixes these tests guard:
//!
//! * batched verification never checked that the declared parent actually links
//!   the child, and `apply_batched_packet_to` pushes the relationship child onto
//!   the parent's links unconditionally.
//! * an outer proof was looked up by map key but verified against the branch's
//!   own declared child, so a branch filed under key C proving D was accepted.
//!
//! Neither tightening costs parity: Go builds relationships from real parent
//! links, and files each proof under the child it proves.

mod support;

use scionic_merkletree::{
    create_dag_with_options, BatchedDagReceiver, BatchedTransmissionPacket, Batching, Error,
    TransmissionPacket,
};
use support::{create_fixture, options_4096, TempDir};

#[test]
fn batched_receiver_rejects_a_foreign_child_claiming_a_single_link_parent() {
    let temp = TempDir::new("packet-forgery-batched").unwrap();

    // single_large_file's root links exactly one child, so this drives the
    // CurrentLinkCount <= 1 early return -- the path that skipped straight past
    // authentication to the unconditional link push.
    let victim_input = create_fixture(temp.path(), "single_large_file").unwrap();
    let victim = create_dag_with_options(&victim_input, &options_4096()).unwrap();
    assert_eq!(
        victim.root_leaf().current_link_count(),
        1,
        "this fixture is chosen for its single-link root"
    );

    // Any valid leaf from an unrelated DAG serves as the foreign child.
    let foreign_input = create_fixture(temp.path(), "nested_directory").unwrap();
    let foreign = create_dag_with_options(&foreign_input, &options_4096()).unwrap();

    // One leaf per packet keeps the forgery to a single relationship edit.
    let foreign_packets = foreign.batched_leaf_sequence_with(Batching::Disabled).unwrap();
    let foreign_packet = foreign_packets
        .iter()
        .find(|packet| {
            packet
                .leaves()
                .first()
                .and_then(|leaf| packet.parent_for(leaf.cid()))
                .flatten()
                .is_some()
        })
        .expect("a non-root foreign packet");

    let foreign_leaf = foreign_packet.leaves()[0].cid().clone();
    let foreign_parent = foreign_packet
        .parent_for(&foreign_leaf)
        .flatten()
        .expect("a declared parent")
        .clone();

    let json = String::from_utf8(foreign_packet.to_json().unwrap()).unwrap();
    assert_eq!(
        json.matches(foreign_parent.as_str()).count(),
        1,
        "the parent CID should appear only inside Relationships"
    );
    let forged_json = json.replace(foreign_parent.as_str(), victim.root().as_str());
    let forged = BatchedTransmissionPacket::from_json(forged_json.as_bytes())
        .expect("the forgery is structurally valid, which is the point");

    // Seed the receiver with the victim's honest batches.
    let mut receiver = BatchedDagReceiver::new();
    for packet in victim.batched_leaf_sequence().unwrap() {
        receiver.apply_and_verify(&packet).unwrap();
    }
    let before = receiver.leaves().clone();

    let result = receiver.apply_and_verify(&forged);
    assert!(
        matches!(result, Err(Error::ParentMissingLink { .. })),
        "a parent that never linked the child must be rejected, got {result:?}"
    );
    assert_eq!(
        receiver.leaves(),
        &before,
        "a rejected packet must leave receiver state untouched"
    );
    assert!(
        !receiver
            .leaves()
            .get(victim.root())
            .expect("victim root is present")
            .links()
            .contains(&foreign_leaf),
        "the foreign CID must never be installed in the victim root's links"
    );
}

#[test]
fn single_packet_decode_rejects_a_proof_filed_under_another_child() {
    let temp = TempDir::new("packet-forgery-single").unwrap();
    let input = create_fixture(temp.path(), "flat_directory").unwrap();
    let dag = create_dag_with_options(&input, &options_4096()).unwrap();

    let packets = dag.get_leaf_sequence().unwrap();
    let packet = packets
        .iter()
        .find(|packet| !packet.proofs().is_empty())
        .expect("a proof-bearing packet");
    let child = packet.leaf().cid().clone();

    // Pick any other CID in the DAG as the impostor the branch will declare.
    let impostor = dag
        .leaves()
        .keys()
        .find(|cid| *cid != &child && *cid != dag.root())
        .expect("another leaf")
        .clone();

    // In the packet JSON the outer packet leaf is an object ("Leaf": {), while a
    // proof branch declares a CID string ("Leaf": "..."), so this rewrites only
    // the branch's declared child and leaves the proof map key alone.
    let json = String::from_utf8(packet.to_json().unwrap()).unwrap();
    let declared = format!("\"Leaf\": \"{}\"", child.as_str());
    assert_eq!(
        json.matches(declared.as_str()).count(),
        1,
        "exactly one branch declares this child"
    );
    let forged_json = json.replace(
        declared.as_str(),
        &format!("\"Leaf\": \"{}\"", impostor.as_str()),
    );

    let result = TransmissionPacket::from_json(forged_json.as_bytes());
    assert!(
        result.is_err(),
        "a proof whose declared child differs from its map key must be rejected at decode, got {result:?}"
    );
}

