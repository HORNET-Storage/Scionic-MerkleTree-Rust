mod support;

use scionic_merkletree::encoding::CborValue;
use scionic_merkletree::{
    create_dag_with_options, BatchedDagReceiver, BatchedTransmissionPacket, Batching, Dag,
    LeafType, TransmissionPacket,
};
use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use support::{create_fixture, options_4096, TempDir, FIXTURES};

fn vector_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("go")
        .join("packets")
}

fn read_vector(path: impl AsRef<Path>) -> Vec<u8> {
    fs::read(vector_root().join(path)).unwrap()
}

fn proof_bearing_partial(full: &Dag) -> Dag {
    let mut requested = full
        .leaves()
        .values()
        .filter(|leaf| {
            leaf.leaf_type() == LeafType::File
                && matches!(leaf.item_name(), "file1.txt" | "file3.txt")
        })
        .map(|leaf| leaf.cid().clone())
        .collect::<Vec<_>>();
    requested.sort();
    assert_eq!(requested.len(), 2);
    full.get_partial(&requested, true).unwrap()
}

fn assert_single_case(case_name: &str, source: &Dag) {
    let packets = source.get_leaf_sequence().unwrap();
    for (index, packet) in packets.iter().enumerate() {
        let base = format!("transmission/{case_name}/{index:03}");
        let go_json = read_vector(format!("{base}.json"));
        assert_eq!(
            packet.to_json().unwrap(),
            go_json,
            "Go JSON mismatch for {base}"
        );
        let go_cbor = read_vector(format!("{base}.cbor"));
        assert_eq!(
            TransmissionPacket::from_cbor(&go_cbor).unwrap(),
            *packet,
            "Go CBOR semantic mismatch for {base}"
        );
    }
}

fn assert_default_batch_case(case_name: &str, source: &Dag) {
    let batches = source.batched_leaf_sequence().unwrap();
    assert_eq!(batches.len(), 1);
    let base = format!("batched/default/{case_name}/000");
    let go_json = read_vector(format!("{base}.json"));
    assert_eq!(
        batches[0].to_json().unwrap(),
        go_json,
        "Go JSON mismatch for {base}"
    );
    let go_cbor = read_vector(format!("{base}.cbor"));
    assert_eq!(
        BatchedTransmissionPacket::from_cbor(&go_cbor).unwrap(),
        batches[0],
        "Go CBOR semantic mismatch for {base}"
    );
}

#[test]
fn all_45_single_packets_match_go_json_bytes_and_go_cbor_semantics() {
    let temp = TempDir::new("go-single-packet-vectors").unwrap();
    let mut flat = None;
    let mut count = 0;
    for fixture in FIXTURES {
        let input = create_fixture(temp.path(), fixture.name).unwrap();
        let source = create_dag_with_options(&input, &options_4096()).unwrap();
        assert_single_case(fixture.name, &source);
        count += source.len();
        if fixture.name == "flat_directory" {
            flat = Some(source);
        }
    }
    let partial = proof_bearing_partial(flat.as_ref().unwrap());
    assert_single_case("flat_directory_partial_file1_file3", &partial);
    count += partial.len();
    assert_eq!(count, 45);

    let go_json = read_vector("partial/flat_directory_file1_file3.dag.json");
    assert_eq!(partial.to_json().unwrap(), go_json);
    let go_cbor = read_vector("partial/flat_directory_file1_file3.dag.cbor");
    assert_eq!(Dag::from_cbor(&go_cbor).unwrap(), partial);
}

#[test]
fn seven_default_batches_and_size_one_compatibility_match_go_vectors() {
    let temp = TempDir::new("go-batched-packet-vectors").unwrap();
    let mut flat = None;
    let mut single_small = None;
    let mut default_count = 0;
    for fixture in FIXTURES {
        let input = create_fixture(temp.path(), fixture.name).unwrap();
        let source = create_dag_with_options(&input, &options_4096()).unwrap();
        assert_default_batch_case(fixture.name, &source);
        default_count += 1;
        if fixture.name == "flat_directory" {
            flat = Some(source.clone());
        }
        if fixture.name == "single_small_file" {
            single_small = Some(source);
        }
    }
    let partial = proof_bearing_partial(flat.as_ref().unwrap());
    assert_default_batch_case("flat_directory_partial_file1_file3", &partial);
    default_count += 1;
    assert_eq!(default_count, 7);

    let source = single_small.unwrap();
    let size_one = source
        .batched_leaf_sequence_with(Batching::ApproximateBytes(NonZeroUsize::new(1).unwrap()))
        .unwrap();
    assert_eq!(size_one.len(), 2);
    for (index, packet) in size_one.iter().enumerate() {
        let base = format!("batched/size-1/single_small_file/{index:03}");
        assert_eq!(
            packet.to_json().unwrap(),
            read_vector(format!("{base}.json"))
        );
        assert_eq!(
            BatchedTransmissionPacket::from_cbor(&read_vector(format!("{base}.cbor"))).unwrap(),
            *packet
        );
    }

    let legacy_json = read_vector("batched/compat/legacy-no-counters.json");
    let legacy_cbor = read_vector("batched/compat/legacy-no-counters.cbor");
    let legacy_from_json = BatchedTransmissionPacket::from_json(&legacy_json).unwrap();
    let legacy_from_cbor = BatchedTransmissionPacket::from_cbor(&legacy_cbor).unwrap();
    assert_eq!(legacy_from_json, legacy_from_cbor);
    assert_eq!(
        (
            legacy_from_json.packet_index(),
            legacy_from_json.total_packets()
        ),
        (0, 0)
    );

    let first = BatchedTransmissionPacket::from_cbor(&read_vector(
        "batched/size-1/single_small_file/000.cbor",
    ))
    .unwrap();
    let mut receiver = BatchedDagReceiver::new();
    receiver.apply_and_verify(&first).unwrap();
    receiver.apply_and_verify(&legacy_from_cbor).unwrap();
    let reconstructed = receiver.finish_verified().unwrap();
    assert_eq!(reconstructed.root(), source.root());
    assert_eq!(reconstructed.len(), source.len());
}

fn map<'a>(value: &'a CborValue, name: &str) -> &'a [(String, CborValue)] {
    match value {
        CborValue::Map(pairs) => pairs,
        _ => panic!("{name} is not a map"),
    }
}

fn field<'a>(pairs: &'a [(String, CborValue)], name: &str) -> Option<&'a CborValue> {
    pairs
        .iter()
        .find_map(|(key, value)| (key == name).then_some(value))
}

#[test]
fn go_packet_probes_pin_wire_null_empty_omission_and_manifest_policy() {
    let nil_json = String::from_utf8(read_vector("probes/transmission-nil.json")).unwrap();
    assert!(nil_json.contains("\"ContentHash\": null"));
    assert!(nil_json.contains("\"Content\": null"));
    assert!(nil_json.contains("\"ClassicMerkleRoot\": \"\""));
    assert!(nil_json.contains("\"Links\": []"));
    assert!(nil_json.contains("\"AdditionalData\": {}"));
    assert!(!nil_json.contains("stored_proofs"));
    assert!(!nil_json.contains("\"proofs\""));

    let empty_json =
        String::from_utf8(read_vector("probes/transmission-empty-content.json")).unwrap();
    assert!(empty_json.contains("\"Content\": \"\""));

    let nil_cbor =
        scionic_merkletree::encoding::cbor_decode(&read_vector("probes/transmission-nil.cbor"))
            .unwrap();
    let packet = map(&nil_cbor, "packet");
    let leaf = map(field(packet, "Leaf").unwrap(), "leaf");
    assert_eq!(field(leaf, "ContentHash"), Some(&CborValue::Null));
    assert_eq!(field(leaf, "Content"), Some(&CborValue::Null));
    assert_eq!(
        field(leaf, "ClassicMerkleRoot"),
        Some(&CborValue::Bytes(Vec::new()))
    );
    assert_eq!(field(leaf, "Links"), Some(&CborValue::Array(Vec::new())));
    assert!(field(leaf, "stored_proofs").is_none());
    assert!(field(packet, "proofs").is_none());

    let empty_batch_json = read_vector("probes/batched-empty.json");
    let empty_batch_cbor = read_vector("probes/batched-empty.cbor");
    let empty_batch = BatchedTransmissionPacket::from_cbor(&empty_batch_cbor).unwrap();
    assert!(empty_batch.leaves().is_empty());
    assert!(empty_batch.relationships().is_empty());
    assert_eq!(empty_batch.to_json().unwrap(), empty_batch_json);

    let manifest = String::from_utf8(read_vector("manifest.json")).unwrap();
    assert!(manifest.contains("\"transmission_packets\": 45"));
    assert!(manifest.contains("\"default_batches\": 7"));
    assert_eq!(manifest.matches("\"base_path\"").count(), 59);
    assert_eq!(manifest.matches("\"json_compare\": \"bytes\"").count(), 59);
    assert_eq!(
        manifest.matches("\"cbor_compare\": \"decoded\"").count(),
        59
    );
}
