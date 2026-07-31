//! Pins the deployed Go v2.2.6 wire shape.
//!
//! This file is the guard whose ABSENCE let a wire-format regression ship. The
//! blanket `sort_map_keys` pass made encoding reproducible, but Rust cannot tell a
//! struct from a map at the CBOR layer -- both are `CborValue::Map` -- so it also
//! reordered every struct-shaped envelope. This suite passed 109/109 through all
//! of it. The only thing that caught it was the Swift port's
//! `CrossCompatWireTests`, pinning these names against golden bytes captured from
//! a real deployed build.
//!
//! Swift should not be carrying that guard alone for three ports, so the same
//! contract is asserted here and in Go (`dag/wireshape_test.go`).

mod support;

use scionic_merkletree::{create_dag_with_options, Dag};
use support::{create_fixture, options_4096, TempDir};

const DEPLOYED_LEAF_KEY_ORDER: [&str; 12] = [
    "Hash",
    "ItemName",
    "Type",
    "ContentHash",
    "Content",
    "ClassicMerkleRoot",
    "CurrentLinkCount",
    "LeafCount",
    "ContentSize",
    "DagSize",
    "Links",
    "AdditionalData",
];

const DEPLOYED_BATCH_KEY_ORDER: [&str; 4] =
    ["Leaves", "Relationships", "PacketIndex", "TotalPackets"];

const DEPLOYED_DAG_KEY_ORDER: [&str; 2] = ["Root", "Leafs"];

/// Renders a map key exactly as CBOR encodes it, so searching for it in the raw
/// bytes cannot collide with a value or with a longer key sharing the same prefix
/// ("Content" vs "ContentHash").
fn cbor_text_key(key: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() + 2);
    if key.len() < 24 {
        out.push(0x60 | key.len() as u8);
    } else {
        out.push(0x78);
        out.push(key.len() as u8);
    }
    out.extend_from_slice(key.as_bytes());
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Requires the first occurrence of each key to appear in the given order. Every
/// leaf carries all twelve keys, so the first occurrence of each lands in the
/// first-encoded leaf, and monotonically increasing offsets mean that leaf emitted
/// them in declaration order.
fn assert_declaration_order(label: &str, encoded: &[u8], keys: &[&str]) {
    let mut prev_offset: isize = -1;
    let mut prev_key = "(start)";
    for key in keys {
        let at = find(encoded, &cbor_text_key(key))
            .unwrap_or_else(|| panic!("{label}: key {key:?} is not on the wire at all"))
            as isize;
        assert!(
            at > prev_offset,
            "{label}: {key:?} at offset {at} is not after {prev_key:?} at offset \
             {prev_offset} -- fields are NOT in declaration order"
        );
        prev_offset = at;
        prev_key = key;
    }
}

/// flat_directory has five files under one directory, so the root carries five
/// links and the transmission path really does generate Merkle proofs -- which the
/// omitempty test below needs in order to prove the key is not over-omitted.
fn build_wire_shape_fixture() -> (TempDir, Dag) {
    let temp = TempDir::new("wire-shape").unwrap();
    let path = create_fixture(temp.path(), "flat_directory").unwrap();
    let dag = create_dag_with_options(&path, &options_4096()).unwrap();
    (temp, dag)
}

#[test]
fn wire_struct_fields_ride_in_declaration_order() {
    let (_temp, dag) = build_wire_shape_fixture();

    let encoded = dag.to_cbor().unwrap();
    assert_declaration_order("dag envelope", &encoded, &DEPLOYED_DAG_KEY_ORDER);
    assert_declaration_order("dag leaf", &encoded, &DEPLOYED_LEAF_KEY_ORDER);

    let batches = dag.batched_leaf_sequence().unwrap();
    assert!(!batches.is_empty(), "fixture produced no batched packets");
    let batch_encoded = batches[0].to_cbor().unwrap();
    assert_declaration_order("batched packet", &batch_encoded, &DEPLOYED_BATCH_KEY_ORDER);
    assert_declaration_order("packet leaf", &batch_encoded, &DEPLOYED_LEAF_KEY_ORDER);
}

/// Encoding must be reproducible, and repeatedly so -- a single agreeing pair of
/// encodes is weak evidence for a property that only fails under hash-map
/// iteration randomness.
#[test]
fn wire_encoding_is_reproducible() {
    let (_temp, dag) = build_wire_shape_fixture();

    let first = dag.to_cbor().unwrap();
    for iteration in 1..=200 {
        assert_eq!(
            dag.to_cbor().unwrap(),
            first,
            "encode #{iteration} differs from encode #0"
        );
    }
}

/// `stored_proofs` and `proofs` are omitted entirely when empty. Go tags them
/// `omitempty`; emitting an empty map instead adds a key to every leaf in every
/// full DAG, which is exactly the regression that shipped on the Go side once
/// those map fields became `cbor.Marshaler` implementations.
#[test]
fn empty_proof_maps_are_omitted_not_emitted_empty() {
    let (_temp, dag) = build_wire_shape_fixture();

    let encoded = dag.to_cbor().unwrap();
    assert!(
        find(&encoded, &cbor_text_key("stored_proofs")).is_none(),
        "a full DAG carries stored_proofs, but no leaf in it has proofs"
    );

    // ...and it must not over-fire: the transmission path really does attach
    // proofs, so the key has to survive there.
    let carried = dag.get_leaf_sequence().unwrap().iter().any(|packet| {
        let encoded_packet = packet.to_cbor().unwrap();
        find(&encoded_packet, &cbor_text_key("proofs")).is_some()
    });
    assert!(
        carried,
        "no packet carried a proofs key, so the omission is over-firing \
         (or the fixture is too shallow to prove it)"
    );
}
