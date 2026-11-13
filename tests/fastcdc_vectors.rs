//! The fastcdc-v1 vectors: where files are cut.
//!
//! `spec/fastcdc-vectors/manifest.json` says, for inputs of several kinds,
//! where each piece ends and what each piece hashes to. The inputs are not
//! in the repository: they are made again from the seeds the manifest gives,
//! by a generator that is small enough to be written out in each library.
//!
//! Two builders give the same file the same hash only when both cut at the
//! same bytes, so one wrong gear entry, mask or off-by-one would make trees
//! that look valid and never share a piece with anyone. These vectors are
//! where that shows.
//!
//! The manifest is read with a JSON reader of the tests' own, and not with
//! code of the library that is under test.

mod support;

use scionic_merkletree::{file_of, Builder, Cutting, Hash, MemoryStore};
use std::collections::BTreeSet;
use std::path::Path;
use support::bytes as corpus_bytes;
use support::json::Json;

fn manifest() -> Json {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("spec")
        .join("fastcdc-vectors")
        .join("manifest.json");
    let manifest = Json::parse(&std::fs::read(&path).unwrap());
    assert_eq!(manifest.get("spec").text(), "fastcdc-v1");
    assert!(
        manifest.get("cases").items().len() >= 11,
        "the manifest lists too few cases"
    );
    manifest
}

fn number(value: &Json) -> usize {
    match value {
        Json::Number(text) => text.parse().unwrap(),
        other => panic!("not a number: {other:?}"),
    }
}

/// A number that the manifest leaves out when it is zero.
fn number_or_zero(case: &Json, key: &str) -> usize {
    if case.has(key) {
        number(case.get(key))
    } else {
        0
    }
}

fn case_named<'a>(cases: &'a [Json], name: &str) -> &'a Json {
    cases
        .iter()
        .find(|case| case.get("name").text() == name)
        .unwrap_or_else(|| panic!("the manifest has no case named {name}"))
}

/// The input of a case, made from what the manifest says about it.
fn input_of(case: &Json, cases: &[Json]) -> Vec<u8> {
    let name = case.get("name").text();
    match case.get("kind").text() {
        "corpus" => corpus_bytes(case.get("seed").text(), number(case.get("length"))),
        "zeros" => vec![0_u8; number(case.get("length"))],
        "edit" => {
            let base = input_of(case_named(cases, case.get("base").text()), cases);
            let offset = number_or_zero(case, "offset");
            let edit_length = number_or_zero(case, "edit_length");
            match case.get("op").text() {
                "insert" => {
                    let payload = corpus_bytes(case.get("payload_seed").text(), edit_length);
                    [&base[..offset], &payload, &base[offset..]].concat()
                }
                "delete" => [&base[..offset], &base[offset + edit_length..]].concat(),
                op => panic!("case {name} has the unknown op {op:?}"),
            }
        }
        kind => panic!("case {name} has the unknown kind {kind:?}"),
    }
}

#[test]
fn every_case_is_cut_where_the_manifest_says() {
    let manifest = manifest();
    let cases = manifest.get("cases").items();
    for case in cases {
        let name = case.get("name").text();
        let data = input_of(case, cases);
        assert_eq!(
            data.len(),
            number(case.get("length")),
            "{name}: input length"
        );
        let expected_ends: Vec<usize> = case.get("boundaries").items().iter().map(number).collect();
        let expected_hashes: Vec<&str> = case
            .get("chunk_sha256")
            .items()
            .iter()
            .map(Json::text)
            .collect();

        // Cut in memory.
        let mut end = 0;
        let mut ends = Vec::new();
        let mut hashes = Vec::new();
        for piece in Cutting::FastCdcV1.cut(&data) {
            end += piece.len();
            ends.push(end);
            hashes.push(Hash::of(piece).to_hex());
        }
        assert_eq!(ends, expected_ends, "{name}: where the pieces end");
        assert_eq!(hashes, expected_hashes, "{name}: the pieces' hashes");

        // Cut as a stream, by the builder: the file's list names the same
        // pieces, in the same order, with the same lengths.
        let store = MemoryStore::new();
        let file = Builder::new(&store, Cutting::FastCdcV1)
            .file_from_bytes(&data)
            .unwrap();
        let list = file_of(&store, &file).unwrap();
        let listed: Vec<String> = list.items().iter().map(|item| item.hash.to_hex()).collect();
        assert_eq!(listed, expected_hashes, "{name}: the file's list");
        let mut end = 0;
        let listed_ends: Vec<usize> = list
            .items()
            .iter()
            .map(|item| {
                end += item.length as usize;
                end
            })
            .collect();
        assert_eq!(
            listed_ends, expected_ends,
            "{name}: the lengths in the file's list"
        );
        list.check_cutting(Cutting::FastCdcV1).unwrap();
    }
}

/// A case that edits another one must share with it exactly the pieces the
/// manifest says it shares. What the base has is worked out here by cutting
/// the base again, and not taken from the manifest.
#[test]
fn an_edit_changes_only_the_pieces_around_it() {
    let manifest = manifest();
    let cases = manifest.get("cases").items();
    let mut edits = 0;
    for case in cases {
        if case.get("kind").text() != "edit" {
            continue;
        }
        edits += 1;
        let name = case.get("name").text();
        let base = input_of(case_named(cases, case.get("base").text()), cases);
        let in_base: BTreeSet<Hash> = Cutting::FastCdcV1
            .cut(&base)
            .iter()
            .map(|piece| Hash::of(piece))
            .collect();
        let expected: Vec<bool> = case
            .get("reused")
            .items()
            .iter()
            .map(|flag| *flag == Json::Bool(true))
            .collect();
        let edited = input_of(case, cases);
        let shared: Vec<bool> = Cutting::FastCdcV1
            .cut(&edited)
            .iter()
            .map(|piece| in_base.contains(&Hash::of(piece)))
            .collect();
        assert_eq!(
            shared, expected,
            "{name}: which pieces are shared with the base"
        );
        let new = shared.iter().filter(|shared| !**shared).count();
        assert!((1..=4).contains(&new), "{name}: {new} new pieces");
    }
    assert!(edits >= 4, "the manifest lists too few edits");
}
