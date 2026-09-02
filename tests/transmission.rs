mod support;

use scionic_merkletree::{
    create_dag_with_options, BatchedDagReceiver, BatchedTransmissionPacket, Batching, Dag, DagLeaf,
    LeafType, TransmissionPacket, TransmissionReceiver,
};
use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use support::{alpha_data, create_fixture, options_4096, write, TempDir, FIXTURES};

fn assert_leaf_core_eq(expected: &DagLeaf, actual: &DagLeaf) {
    assert_eq!(actual.cid(), expected.cid());
    assert_eq!(actual.item_name(), expected.item_name());
    assert_eq!(actual.leaf_type(), expected.leaf_type());
    assert_eq!(actual.content_hash(), expected.content_hash());
    assert_eq!(actual.content(), expected.content());
    assert_eq!(actual.classic_merkle_root(), expected.classic_merkle_root());
    assert_eq!(actual.current_link_count(), expected.current_link_count());
    assert_eq!(actual.leaf_count(), expected.leaf_count());
    assert_eq!(actual.content_size(), expected.content_size());
    assert_eq!(actual.dag_size(), expected.dag_size());
    assert_eq!(actual.links(), expected.links());
    assert_eq!(actual.additional_data(), expected.additional_data());
}

fn assert_reconstructed_core(expected: &Dag, actual: &Dag) {
    assert_eq!(actual.root(), expected.root());
    assert_eq!(actual.len(), expected.len());
    for (cid, expected_leaf) in expected.leaves() {
        assert_leaf_core_eq(expected_leaf, actual.get(cid).unwrap());
    }
}

fn replay_single(packets: &[TransmissionPacket]) -> Dag {
    let mut receiver = TransmissionReceiver::new();
    for packet in packets {
        let json = packet.to_json().unwrap();
        let from_json = TransmissionPacket::from_json(&json).unwrap();
        assert_eq!(from_json, *packet);
        assert_eq!(from_json.to_json().unwrap(), json);

        let cbor = packet.to_cbor().unwrap();
        let from_cbor = TransmissionPacket::from_cbor(&cbor).unwrap();
        assert_eq!(from_cbor, *packet);
        receiver
            .apply_and_verify_transmission_packet(from_cbor)
            .unwrap();
    }
    receiver.into_dag().unwrap()
}

fn replay_batched(packets: &[BatchedTransmissionPacket]) -> Dag {
    let mut receiver = BatchedDagReceiver::new();
    for packet in packets {
        let json = packet.to_json().unwrap();
        let from_json = BatchedTransmissionPacket::from_json(&json).unwrap();
        assert_eq!(from_json, *packet);
        assert_eq!(from_json.to_json().unwrap(), json);

        let cbor = packet.to_cbor().unwrap();
        let from_cbor = BatchedTransmissionPacket::from_cbor(&cbor).unwrap();
        assert_eq!(from_cbor, *packet);
        receiver.apply_and_verify(&from_cbor).unwrap();
    }
    receiver.finish_verified().unwrap()
}

#[test]
fn single_packets_are_sorted_bfs_wire_round_trip_and_reconstruct_all_fixtures() {
    let temp = TempDir::new("single-transmission-all-fixtures").unwrap();
    for fixture in FIXTURES {
        let input = create_fixture(temp.path(), fixture.name).unwrap();
        let source = create_dag_with_options(&input, &options_4096()).unwrap();
        let packets = source.get_leaf_sequence().unwrap();
        assert_eq!(packets.len(), fixture.leaves);
        assert!(packets.first().unwrap().is_root());
        assert!(packets.first().unwrap().proofs().is_empty());

        let mut seen = BTreeSet::new();
        for packet in &packets {
            if let Some(parent) = packet.parent_hash() {
                assert!(seen.contains(parent), "child packet preceded parent");
            }
            assert!(seen.insert(packet.leaf().cid().clone()));
            if let Some(parent) = packet.parent_hash().and_then(|cid| source.get(cid)) {
                let expected_proofs = usize::from(parent.links().len() > 1);
                assert_eq!(packet.proofs().len(), expected_proofs);
                if expected_proofs == 1 {
                    assert!(packet.proof_for(packet.leaf().cid()).is_some());
                }
            }
        }

        let reconstructed = replay_single(&packets);
        reconstructed.verify().unwrap();
        assert_reconstructed_core(&source, &reconstructed);
    }
}

#[test]
fn default_disabled_and_size_one_batches_pin_grouping_counters_and_replay() {
    let temp = TempDir::new("batched-transmission-modes").unwrap();
    for fixture in FIXTURES {
        let input = create_fixture(temp.path(), fixture.name).unwrap();
        let source = create_dag_with_options(&input, &options_4096()).unwrap();
        let single = source.get_leaf_sequence().unwrap();

        let default_batches = source.batched_leaf_sequence().unwrap();
        assert_eq!(default_batches.len(), 1);
        let default_order = default_batches
            .iter()
            .flat_map(|packet| packet.leaves().iter().map(|leaf| leaf.cid().clone()))
            .collect::<Vec<_>>();
        assert_eq!(
            default_order,
            single
                .iter()
                .map(|packet| packet.leaf().cid().clone())
                .collect::<Vec<_>>()
        );
        let default_reconstructed = replay_batched(&default_batches);
        assert_reconstructed_core(&source, &default_reconstructed);

        let disabled = source
            .batched_leaf_sequence_with(Batching::Disabled)
            .unwrap();
        assert_eq!(disabled.len(), source.len());
        for (index, packet) in disabled.iter().enumerate() {
            assert_eq!(packet.leaves().len(), 1);
            assert_eq!(packet.relationships().len(), 1);
            assert_eq!(packet.packet_index(), index as u64);
            assert_eq!(packet.total_packets(), disabled.len() as u64);
        }
        let disabled_reconstructed = replay_batched(&disabled);
        assert_reconstructed_core(&source, &disabled_reconstructed);
    }

    let single_small = TempDir::new("batched-size-one").unwrap();
    let input = create_fixture(single_small.path(), "single_small_file").unwrap();
    let source = create_dag_with_options(&input, &options_4096()).unwrap();
    let size_one = source
        .batched_leaf_sequence_with(Batching::ApproximateBytes(NonZeroUsize::new(1).unwrap()))
        .unwrap();
    assert_eq!(size_one.len(), 2);
    assert_eq!(
        size_one
            .iter()
            .map(|packet| (packet.packet_index(), packet.total_packets()))
            .collect::<Vec<_>>(),
        vec![(0, 2), (1, 2)]
    );
    assert_reconstructed_core(&source, &replay_batched(&size_one));
}

#[test]
fn partial_packets_relay_edge_proofs_and_batches_preserve_parent_proofs() {
    let temp = TempDir::new("partial-transmission").unwrap();
    let input = create_fixture(temp.path(), "flat_directory").unwrap();
    let full = create_dag_with_options(&input, &options_4096()).unwrap();
    let requested = full
        .leaves()
        .values()
        .filter(|leaf| {
            leaf.leaf_type() == LeafType::File
                && matches!(leaf.item_name(), "file1.txt" | "file3.txt")
        })
        .map(|leaf| leaf.cid().clone())
        .collect::<Vec<_>>();
    assert_eq!(requested.len(), 2);
    let partial = full.get_partial(&requested, true).unwrap();
    partial.verify().unwrap();
    assert!(partial.is_partial());

    let packets = partial.get_leaf_sequence().unwrap();
    assert_eq!(packets.len(), 3);
    assert_eq!(packets[0].leaf().proofs().len(), 2);
    assert!(packets[0].proofs().is_empty());
    for packet in packets.iter().skip(1) {
        assert_eq!(packet.proofs().len(), 1);
        let parent = partial.get(packet.parent_hash().unwrap()).unwrap();
        assert_eq!(
            packet.proof_for(packet.leaf().cid()),
            parent.proof_for(packet.leaf().cid())
        );
    }
    let single_reconstructed = replay_single(&packets);
    assert_eq!(single_reconstructed, partial);
    single_reconstructed.verify().unwrap();

    let batches = partial.batched_leaf_sequence().unwrap();
    assert_eq!(batches.len(), 1);
    let batched_root = batches[0].root_leaf().unwrap();
    assert_eq!(
        batched_root.proofs(),
        partial.root_leaf().proofs(),
        "partial finalization must copy every source parent proof"
    );
    let batched_reconstructed = replay_batched(&batches);
    assert_eq!(batched_reconstructed, partial);
}

#[test]
fn chunk_content_order_survives_batched_packet_replay() {
    let temp = TempDir::new("transmission-chunk-order").unwrap();
    let input = temp.path().join("ten-chunks");
    std::fs::create_dir(&input).unwrap();
    let data = alpha_data(10 * 64 + 1);
    write(input.join("payload.bin"), &data).unwrap();
    let options = scionic_merkletree::DagBuildOptions::default()
        .with_chunk_size(64)
        .unwrap();
    let source = create_dag_with_options(&input, &options).unwrap();
    let batches = source
        .batched_leaf_sequence_with(Batching::ApproximateBytes(NonZeroUsize::new(128).unwrap()))
        .unwrap();
    assert!(batches.len() > 1);
    let reconstructed = replay_batched(&batches);
    let file = reconstructed
        .leaves()
        .values()
        .find(|leaf| leaf.item_name() == "payload.bin")
        .unwrap();
    assert_eq!(reconstructed.get_content_from_leaf(file).unwrap(), data);
}

#[test]
fn batched_cbor_without_counters_is_rejected() {
    let temp = TempDir::new("missing-batched-counters").unwrap();
    let input = create_fixture(temp.path(), "single_small_file").unwrap();
    let source = create_dag_with_options(&input, &options_4096()).unwrap();
    let current = source
        .batched_leaf_sequence_with(Batching::Disabled)
        .unwrap()
        .remove(1);
    assert_eq!((current.packet_index(), current.total_packets()), (1, 2));

    let decoded = scionic_merkletree::encoding::cbor_decode(&current.to_cbor().unwrap()).unwrap();
    let scionic_merkletree::encoding::CborValue::Map(mut pairs) = decoded else {
        panic!("current batch is not a map");
    };
    pairs.retain(|(key, _)| matches!(key.as_str(), "Leaves" | "Relationships"));
    let missing_counters = scionic_merkletree::encoding::cbor_encode(
        &scionic_merkletree::encoding::CborValue::Map(pairs),
    );
    assert!(matches!(
        BatchedTransmissionPacket::from_cbor(&missing_counters),
        Err(scionic_merkletree::Error::InvalidData { detail })
            if detail == "batched transmission packet is missing PacketIndex"
    ));
}

#[test]
fn transmission_decoders_reject_noncanonical_outer_aliases() {
    let temp = TempDir::new("transmission-aliases").unwrap();
    let input = create_fixture(temp.path(), "single_small_file").unwrap();
    let source = create_dag_with_options(&input, &options_4096()).unwrap();
    let packet = source.get_leaf_sequence().unwrap().remove(0);
    let json = String::from_utf8(packet.to_json().unwrap()).unwrap();
    let ambiguous = json.replacen("\"Leaf\":", "\"leaf\": null,\n  \"Leaf\":", 1);
    assert!(matches!(
        TransmissionPacket::from_json(ambiguous.as_bytes()),
        Err(scionic_merkletree::Error::InvalidJson { detail })
            if detail == "transmission packet contains unknown field leaf"
    ));
}

#[test]
fn receivers_pin_root_conflicts_missing_parents_and_single_unknown_parent_behavior() {
    let temp = TempDir::new("transmission-receiver-errors").unwrap();
    let first_input = create_fixture(temp.path(), "single_small_file").unwrap();
    let second_input = create_fixture(temp.path(), "flat_directory").unwrap();
    let first = create_dag_with_options(&first_input, &options_4096()).unwrap();
    let second = create_dag_with_options(&second_input, &options_4096()).unwrap();

    let first_packets = first.get_leaf_sequence().unwrap();
    let second_packets = second.get_leaf_sequence().unwrap();
    let mut receiver = TransmissionReceiver::new();
    receiver
        .apply_and_verify_transmission_packet(first_packets[0].clone())
        .unwrap();
    let before_conflict = receiver.clone();
    assert!(matches!(
        receiver.apply_and_verify_transmission_packet(second_packets[0].clone()),
        Err(scionic_merkletree::Error::ConflictingTransmissionRoot { .. })
    ));
    assert_eq!(receiver, before_conflict);

    let mut orphan_receiver = TransmissionReceiver::new();
    orphan_receiver
        .apply_and_verify_transmission_packet(first_packets[1].clone())
        .unwrap();
    assert!(orphan_receiver.root().is_none());
    assert_eq!(orphan_receiver.leaves().len(), 1);

    let child_batch = first
        .batched_leaf_sequence_with(Batching::Disabled)
        .unwrap()
        .remove(1);
    let child_json = String::from_utf8(child_batch.to_json().unwrap()).unwrap();
    let positioned_json = child_json.replace(
        &format!("\"PacketIndex\": {}", child_batch.packet_index()),
        "\"PacketIndex\": 0",
    );
    let child_batch = BatchedTransmissionPacket::from_json(positioned_json.as_bytes())
        .expect("position-adjusted child batch remains structurally valid");
    let mut batched_receiver = BatchedDagReceiver::new();
    let before_missing_parent = batched_receiver.clone();
    assert!(matches!(
        batched_receiver.apply_and_verify(&child_batch),
        Err(scionic_merkletree::Error::UnavailableTransmissionParent { .. })
    ));
    assert_eq!(batched_receiver, before_missing_parent);
}
