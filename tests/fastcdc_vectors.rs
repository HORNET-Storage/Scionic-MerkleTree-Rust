//! The fastcdc-v1 conformance-vector assertions.
//!
//! The corpus lives in the Go repo as `spec/fastcdc-vectors` and is COMMITTED
//! into this repository at the same relative path: corpus INPUTS are
//! regenerated from the seeded deterministic generators described by the
//! manifest (16..40 MiB binaries have no business in a repository, and
//! implementing the tiny generator is itself a conformance check), while the
//! manifest of expectations — chunk end offsets, chunk SHA-256s, the
//! reused-vs-new partition for edit cases, and the root CID of the
//! single-file DAG built from each input — is the committed truth.
//!
//! The manifest is read as CBOR for the same reason `spec_vectors.rs` reads
//! its manifest as CBOR: the manifest decides WHICH vectors get checked, so
//! reading it with a parser under test would let one bug hide another.

mod support;

use scionic_merkletree::encoding::{cbor_decode, sha256, CborValue};
use scionic_merkletree::{
    create_dag_with_options, Chunking, DagBuildOptions, LeafType, Metadata, CHUNKING_FASTCDC_V1,
    CHUNKING_TAG_KEY, DEFAULT_CHUNK_SIZE,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use support::{write, TempDir};

fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("spec")
        .join("fastcdc-vectors")
}

fn manifest() -> CborValue {
    let path = vectors_root().join("manifest.cbor");
    let bytes = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "fastcdc vector manifest missing at {}: {error}\n\
             Regenerate the corpus from the Go repo with:\n  \
             go run ./tools/fastcdcvectors -out spec/fastcdc-vectors\n\
             then copy manifest.json and manifest.cbor into this repository.",
            path.display()
        )
    });
    let decoded = cbor_decode(&bytes).expect("manifest.cbor does not decode");
    assert_eq!(
        text(field(&decoded, "spec")),
        CHUNKING_FASTCDC_V1,
        "the corpus describes a different chunking spec than this port implements"
    );
    decoded
}

fn cases(manifest: &CborValue) -> &[CborValue] {
    let cases = items(field(manifest, "cases"));
    assert!(
        !cases.is_empty(),
        "the manifest lists no cases; every assertion below would pass vacuously"
    );
    cases
}

fn field<'a>(value: &'a CborValue, key: &str) -> &'a CborValue {
    optional_field(value, key).unwrap_or_else(|| panic!("manifest map has no `{key}` field"))
}

/// Absent fields are meaningful here: the Go generator marshals with
/// `omitempty`, so a zero offset or an empty seed is simply omitted.
fn optional_field<'a>(value: &'a CborValue, key: &str) -> Option<&'a CborValue> {
    match value {
        CborValue::Map(pairs) => pairs
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, entry)| entry),
        _ => panic!("expected a CBOR map when reading `{key}`"),
    }
}

fn text(value: &CborValue) -> &str {
    match value {
        CborValue::Text(text) => text,
        _ => panic!("expected CBOR text"),
    }
}

fn number(value: &CborValue) -> usize {
    match value {
        CborValue::Unsigned(number) => *number as usize,
        _ => panic!("expected a CBOR unsigned integer"),
    }
}

fn boolean(value: &CborValue) -> bool {
    match value {
        CborValue::Bool(flag) => *flag,
        _ => panic!("expected a CBOR bool"),
    }
}

fn items(value: &CborValue) -> &[CborValue] {
    match value {
        CborValue::Array(values) => values,
        _ => panic!("expected a CBOR array"),
    }
}

fn optional_number(case: &CborValue, key: &str) -> usize {
    optional_field(case, key).map_or(0, number)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The normative corpus generator (the Go repo's `docs/fastcdc-v1.md`):
/// block `k` is `SHA-256(seed ++ u64be(k))`, concatenated and truncated.
fn corpus_bytes(seed: &str, length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 32);
    let mut block: u64 = 0;
    while out.len() < length {
        let mut message = Vec::with_capacity(seed.len() + 8);
        message.extend_from_slice(seed.as_bytes());
        message.extend_from_slice(&block.to_be_bytes());
        out.extend_from_slice(&sha256(&message));
        block += 1;
    }
    out.truncate(length);
    out
}

fn case_by_name<'a>(all: &'a [CborValue], name: &str) -> &'a CborValue {
    all.iter()
        .find(|case| text(field(case, "name")) == name)
        .unwrap_or_else(|| panic!("manifest has no case named {name}"))
}

fn materialize(case: &CborValue, all: &[CborValue]) -> Vec<u8> {
    let name = text(field(case, "name"));
    match text(field(case, "kind")) {
        "corpus" => corpus_bytes(text(field(case, "seed")), number(field(case, "length"))),
        "zeros" => vec![0_u8; number(field(case, "length"))],
        "edit" => {
            let base = materialize(case_by_name(all, text(field(case, "base"))), all);
            let offset = optional_number(case, "offset");
            let edit_length = optional_number(case, "edit_length");
            match text(field(case, "op")) {
                "insert" => {
                    let payload = corpus_bytes(text(field(case, "payload_seed")), edit_length);
                    let mut edited = Vec::with_capacity(base.len() + payload.len());
                    edited.extend_from_slice(&base[..offset]);
                    edited.extend_from_slice(&payload);
                    edited.extend_from_slice(&base[offset..]);
                    edited
                }
                "delete" => {
                    let mut edited = Vec::with_capacity(base.len() - edit_length);
                    edited.extend_from_slice(&base[..offset]);
                    edited.extend_from_slice(&base[offset + edit_length..]);
                    edited
                }
                op => panic!("case {name} has unknown op {op:?}"),
            }
        }
        kind => panic!("case {name} has unknown kind {kind:?}"),
    }
}

/// Every case's chunk boundaries and chunk hashes must match the committed
/// manifest exactly — one wrong gear constant, mask, or off-by-one produces
/// valid-looking trees that never dedup, detectable only here.
#[test]
fn fastcdc_vector_chunks_match() {
    let manifest = manifest();
    let all = cases(&manifest);
    for case in all {
        let name = text(field(case, "name"));
        let data = materialize(case, all);
        assert_eq!(
            data.len(),
            number(field(case, "length")),
            "{name}: input length"
        );
        let chunks = Chunking::FastCdcV1.cut(&data);
        let expected_boundaries: Vec<usize> = items(field(case, "boundaries"))
            .iter()
            .map(number)
            .collect();
        let expected_hashes: Vec<&str> = items(field(case, "chunk_sha256"))
            .iter()
            .map(text)
            .collect();
        let mut end = 0_usize;
        let mut boundaries = Vec::with_capacity(chunks.len());
        let mut hashes = Vec::with_capacity(chunks.len());
        for chunk in &chunks {
            end += chunk.len();
            boundaries.push(end);
            hashes.push(hex_encode(&sha256(chunk)));
        }
        assert_eq!(boundaries, expected_boundaries, "{name}: chunk end offsets");
        assert_eq!(hashes, expected_hashes, "{name}: chunk hashes");
    }
}

/// Edit cases must reuse exactly the chunks the manifest says they reuse.
/// The base partition is recomputed from a fresh cut of the base input, so
/// this checks the delta property itself rather than trusting the manifest's
/// bookkeeping.
#[test]
fn fastcdc_vector_edit_reuse_partitions() {
    let manifest = manifest();
    let all = cases(&manifest);
    let mut saw_edit_case = false;
    for case in all {
        if text(field(case, "kind")) != "edit" {
            continue;
        }
        saw_edit_case = true;
        let name = text(field(case, "name"));
        let base_data = materialize(case_by_name(all, text(field(case, "base"))), all);
        let base_hashes: BTreeSet<String> = Chunking::FastCdcV1
            .cut(&base_data)
            .iter()
            .map(|chunk| hex_encode(&sha256(chunk)))
            .collect();
        let expected_reused: Vec<bool> = items(field(case, "reused")).iter().map(boolean).collect();
        let edited = materialize(case, all);
        let reused: Vec<bool> = Chunking::FastCdcV1
            .cut(&edited)
            .iter()
            .map(|chunk| base_hashes.contains(&hex_encode(&sha256(chunk))))
            .collect();
        assert_eq!(reused, expected_reused, "{name}: reused-vs-new partition");
        let fresh = reused.iter().filter(|flag| !**flag).count();
        assert!(
            fresh >= 1,
            "{name}: an edit must produce at least one new chunk"
        );
        assert!(
            fresh <= 4,
            "{name}: {fresh} unseen chunks; the delta property regressed"
        );
    }
    assert!(saw_edit_case, "the manifest lists no edit cases");
}

/// Building a real single-file DAG from each input must reproduce the Go
/// builder's root CID exactly — this pins the streaming cutter, chunk-leaf
/// naming, the root chunking tag, and stats, all the way through leaf
/// hashing, in one assertion per case.
#[test]
fn fastcdc_vector_dag_roots_rebuild() {
    let manifest = manifest();
    let all = cases(&manifest);
    let temp = TempDir::new("fastcdc-vectors").unwrap();
    for case in all {
        let name = text(field(case, "name"));
        let data = materialize(case, all);
        let input = temp.path().join(format!("{name}.bin"));
        write(&input, &data).unwrap();
        let dag = create_dag_with_options(&input, &DagBuildOptions::default())
            .unwrap_or_else(|error| panic!("{name}: build failed: {error}"));
        dag.verify()
            .unwrap_or_else(|error| panic!("{name}: built DAG does not verify: {error}"));
        assert_eq!(
            dag.root().as_str(),
            text(field(case, "root_hash")),
            "{name}: root CID"
        );
        assert_eq!(
            dag.len(),
            number(field(case, "leaf_count")),
            "{name}: leaf count"
        );
        let chunk_leaves = dag
            .leaves()
            .values()
            .filter(|leaf| leaf.leaf_type() == LeafType::Chunk)
            .count();
        assert_eq!(
            chunk_leaves,
            number(field(case, "chunk_leaves")),
            "{name}: chunk leaves"
        );
        assert_eq!(
            dag.root_leaf()
                .additional_data()
                .get(CHUNKING_TAG_KEY)
                .map(String::as_str),
            Some(CHUNKING_FASTCDC_V1),
            "{name}: root chunking tag"
        );
        let cut_count = Chunking::FastCdcV1.cut(&data).len();
        if cut_count <= 1 {
            assert_eq!(
                chunk_leaves, 0,
                "{name}: single-chunk files store data on the file leaf"
            );
        }
    }
}

/// The root tag contract, mirrored from the Go library: fastcdc roots carry
/// the tag, the library owns the key (a caller-supplied value is
/// overwritten), fixed and disabled modes stamp nothing, and the tag
/// survives — and coexists with — timestamp_root's metadata replacement.
#[test]
fn fastcdc_root_tag_semantics() {
    let temp = TempDir::new("fastcdc-tag").unwrap();
    let input = temp.path().join("tag.bin");
    write(&input, &[7_u8; 100]).unwrap();

    let default_dag = create_dag_with_options(&input, &DagBuildOptions::default()).unwrap();
    assert_eq!(
        default_dag.root_leaf().additional_data(),
        &Metadata::from([(CHUNKING_TAG_KEY.to_owned(), CHUNKING_FASTCDC_V1.to_owned())])
    );

    let spoofed = DagBuildOptions::default().with_root_metadata(Metadata::from([
        (CHUNKING_TAG_KEY.to_owned(), "spoofed".to_owned()),
        ("keep".to_owned(), "x".to_owned()),
    ]));
    let overwritten = create_dag_with_options(&input, &spoofed).unwrap();
    assert_eq!(
        overwritten.root_leaf().additional_data(),
        &Metadata::from([
            (CHUNKING_TAG_KEY.to_owned(), CHUNKING_FASTCDC_V1.to_owned()),
            ("keep".to_owned(), "x".to_owned()),
        ])
    );

    let fixed = DagBuildOptions::default()
        .with_chunk_size(DEFAULT_CHUNK_SIZE)
        .unwrap()
        .with_root_metadata(Metadata::from([("keep".to_owned(), "x".to_owned())]));
    let fixed_dag = create_dag_with_options(&input, &fixed).unwrap();
    assert_eq!(
        fixed_dag.root_leaf().additional_data(),
        &Metadata::from([("keep".to_owned(), "x".to_owned())]),
        "fixed mode must stamp nothing"
    );

    let disabled_dag =
        create_dag_with_options(&input, &DagBuildOptions::default().with_chunking_disabled())
            .unwrap();
    assert!(!disabled_dag
        .root_leaf()
        .additional_data()
        .contains_key(CHUNKING_TAG_KEY));

    let timestamped = create_dag_with_options(
        &input,
        &DagBuildOptions::default().with_timestamp_root(true),
    )
    .unwrap();
    let generated = timestamped.root_leaf().additional_data();
    assert_eq!(
        generated.len(),
        2,
        "timestamped fastcdc roots carry exactly timestamp + tag"
    );
    assert!(generated.contains_key("timestamp"));
    assert_eq!(
        generated.get(CHUNKING_TAG_KEY).map(String::as_str),
        Some(CHUNKING_FASTCDC_V1)
    );
}
