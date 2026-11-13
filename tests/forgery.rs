//! Forgeries: input that no honest sender could have produced for the root in
//! question, and that a verifier therefore has to refuse.
//!
//! Each one is built the way a hostile peer builds it. Honest wire bytes are
//! read as plain JSON, edited, and handed back to the public decoders; nothing
//! here reaches inside the crate. Every test first checks that the honest form
//! of the same input is accepted, so a refusal cannot come from an unrelated
//! fault in the setup, and every test reports each forged input that got
//! through, not only the first.

mod support;

use scionic_merkletree::{
    create_dag, create_dag_with_options, BatchedDagReceiver, BatchedTransmissionPacket, Cid, Dag,
    DagBuildOptions, DagLeaf, DagStore, Error, TransmissionPacket, TransmissionReceiver,
};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use support::json::Json;
use support::{write, TempDir};

/// Every forged input that a test saw accepted.
#[derive(Default)]
struct Accepted(Vec<String>);

impl Accepted {
    fn unless_refused<T>(&mut self, outcome: Result<T, Error>, what: &str) {
        self.when(outcome.is_ok(), what);
    }

    fn when(&mut self, accepted: bool, what: &str) {
        if accepted {
            self.0.push(what.to_owned());
        }
    }

    fn finish(self) {
        assert!(
            self.0.is_empty(),
            "accepted:\n  - {}",
            self.0.join("\n  - ")
        );
    }
}

/// A directory of `count` one-byte files as a DAG: a root with `count` children.
fn flat_dag(temp: &TempDir, name: &str, count: usize) -> Dag {
    let dir = temp.path().join(name);
    for index in 0..count {
        write(dir.join(format!("f{index}.txt")), &[b'a' + index as u8]).unwrap();
    }
    create_dag(&dir).unwrap()
}

/// A directory of files cut into 16-byte chunks, as a DAG.
fn chunked_dag(temp: &TempDir, name: &str, files: &[(&str, &[u8])]) -> Dag {
    let dir = temp.path().join(name);
    for (file, body) in files {
        write(dir.join(file), body).unwrap();
    }
    let options = DagBuildOptions::default().with_chunk_size(16).unwrap();
    create_dag_with_options(&dir, &options).unwrap()
}

/// Three 16-byte chunks, each one letter repeated.
fn three_chunks(letters: [u8; 3]) -> Vec<u8> {
    letters.iter().flat_map(|letter| [*letter; 16]).collect()
}

fn wire_of(dag: &Dag) -> Json {
    Json::parse(&dag.to_json().unwrap())
}

fn text(value: &str) -> Json {
    Json::Text(value.to_owned())
}

fn links(cids: &[&str]) -> Json {
    Json::Array(cids.iter().copied().map(text).collect())
}

fn readable(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// One leaf of a DAG on the wire.
fn leaf_mut<'a>(dag: &'a mut Json, cid: &str) -> &'a mut Json {
    dag.get_mut("Leafs").get_mut(cid)
}

/// The leaf named `name` in a DAG: its CID, and its wire form.
fn leaf_named(dag: &Dag, name: &str) -> (String, Json) {
    wire_of(dag)
        .get("Leafs")
        .members()
        .iter()
        .find(|(_, leaf)| leaf.get("ItemName").text() == name)
        .unwrap_or_else(|| panic!("no leaf named {name}"))
        .clone()
}

/// A self-consistent leaf that belongs to no victim DAG: the file leaf of an
/// unrelated one-file directory. A leaf's hash covers only the leaf's own
/// fields, so the leaf is valid wherever it is placed.
fn forged_leaf(temp: &TempDir, name: &str) -> (String, Json) {
    let dir = temp.path().join(format!("attacker-{name}"));
    write(dir.join(name), b"echo forged").unwrap();
    leaf_named(&create_dag(&dir).unwrap(), name)
}

/// What a receiver does with DAG bytes: decode them, then verify. `Ok` means
/// that the bytes were taken as a valid DAG. CBOR carries the same structure,
/// and has to get the same verdict.
fn decode_and_verify(wire: &Json) -> Result<Dag, Error> {
    let dag = Dag::from_json(&wire.to_bytes())?;
    let verdict = dag.verify();
    let through_cbor = Dag::from_cbor(&dag.to_cbor().unwrap()).and_then(|dag| dag.verify());
    assert_eq!(
        verdict.is_ok(),
        through_cbor.is_ok(),
        "JSON and CBOR disagree: {verdict:?} against {through_cbor:?}"
    );
    verdict.map(|()| dag)
}

/// A store filled from DAG bytes that were decoded and not yet verified.
fn store_of(wire: &Json) -> DagStore {
    let dag = Dag::from_json(&wire.to_bytes())
        .expect("decoding checks the shape of the bytes, not what they claim");
    DagStore::from_dag(&dag).unwrap()
}

/// A single-leaf packet that hands `leaf` to a receiver as a child of
/// `parent`, with no proof.
fn packet_for(leaf: &Json, parent: &str) -> TransmissionPacket {
    let wire = Json::Object(vec![
        ("Leaf".to_owned(), leaf.clone()),
        ("ParentHash".to_owned(), text(parent)),
    ]);
    TransmissionPacket::from_json(&wire.to_bytes())
        .expect("the forged packet is well formed, which is the point")
}

/// The one batch a small DAG travels in, on the wire.
fn batch_of(dag: &Dag) -> Json {
    let batches = dag.batched_leaf_sequence().unwrap();
    assert_eq!(batches.len(), 1, "a small DAG travels in one batch");
    Json::parse(&batches[0].to_json().unwrap())
}

/// One batch that carries the given leaves, each beside its parent. The root's
/// parent is the empty string.
fn batch_from(leaves: &[(&Json, &str)]) -> Json {
    Json::Object(vec![
        (
            "Leaves".to_owned(),
            Json::Array(leaves.iter().map(|(leaf, _)| (*leaf).clone()).collect()),
        ),
        (
            "Relationships".to_owned(),
            Json::Object(
                leaves
                    .iter()
                    .map(|(leaf, parent)| (leaf.get("Hash").text().to_owned(), text(parent)))
                    .collect(),
            ),
        ),
        ("PacketIndex".to_owned(), Json::Number("0".to_owned())),
        ("TotalPackets".to_owned(), Json::Number("1".to_owned())),
    ])
}

fn batch_leaf_mut<'a>(batch: &'a mut Json, cid: &str) -> &'a mut Json {
    batch
        .get_mut("Leaves")
        .items_mut()
        .iter_mut()
        .find(|leaf| leaf.get("Hash").text() == cid)
        .unwrap_or_else(|| panic!("no leaf {cid} in the batch"))
}

/// Adds a leaf to a batch, as a child of `parent`.
fn add_to_batch(batch: &mut Json, cid: &str, leaf: &Json, parent: &str) {
    batch.get_mut("Leaves").push(leaf.clone());
    batch.get_mut("Relationships").set(cid, text(parent));
}

fn decode_batch(wire: &Json) -> Result<BatchedTransmissionPacket, Error> {
    BatchedTransmissionPacket::from_json(&wire.to_bytes())
}

/// What a fresh receiver makes of a batch: decode it, then verify it.
fn verify_batch(wire: &Json) -> Result<(), Error> {
    BatchedDagReceiver::new().verify_packet(&decode_batch(wire)?)
}

/// Whether a fresh streaming receiver hands the forged leaf's bytes to its sink.
fn streams_forged_bytes(packet: &BatchedTransmissionPacket, forged: &Cid) -> bool {
    let mut delivered = false;
    let _ = BatchedDagReceiver::new().apply_and_verify_streaming::<Error>(
        packet,
        &mut |leaf: &DagLeaf, _bytes: &[u8]| {
            delivered |= leaf.cid() == forged;
            Ok(())
        },
    );
    delivered
}

/// Records a forged batch that a fresh receiver accepts, and whether a
/// streaming receiver passes the forged leaf's bytes on.
fn judge_batch(accepted: &mut Accepted, what: &str, wire: &Json, forged: &Cid) {
    let Ok(packet) = decode_batch(wire) else {
        return; // refused while decoding
    };
    if BatchedDagReceiver::new().verify_packet(&packet).is_ok() {
        let sink = if streams_forged_bytes(&packet, forged) {
            ", and a streaming receiver hands its bytes to the sink"
        } else {
            ""
        };
        accepted.0.push(format!("{what}{sink}"));
    }
}

/// An extra child appended to a parent of a full DAG has no proof at all.
#[test]
fn full_dag_refuses_an_extra_child() {
    let temp = TempDir::new("forgery-full-extra-child").unwrap();
    let dag = flat_dag(&temp, "victim", 3);
    let mut forged = wire_of(&dag);
    decode_and_verify(&forged).expect("the honest DAG verifies");

    let (cid, leaf) = forged_leaf(&temp, "install.sh");
    forged.get_mut("Leafs").set(&cid, leaf);
    leaf_mut(&mut forged, dag.root().as_str())
        .get_mut("Links")
        .push(text(&cid));

    let mut accepted = Accepted::default();
    accepted.unless_refused(
        decode_and_verify(&forged),
        "a full DAG with an extra child under its root",
    );
    accepted.finish();
}

/// A forged child of a pruned parent: with no proof, with a real sibling's
/// proof filed under its hash, and with that proof renamed to it.
#[test]
fn partial_refuses_a_forged_child_carrying_a_siblings_proof() {
    let temp = TempDir::new("forgery-partial-sibling-proof").unwrap();
    let dag = flat_dag(&temp, "victim", 3);
    let root = dag.root().as_str();
    let real = dag.root_leaf().links()[0].clone();
    let partial = dag.get_partial(std::slice::from_ref(&real), true).unwrap();
    let honest = wire_of(&partial);
    decode_and_verify(&honest).expect("the honest partial verifies");
    let real_branch = honest
        .get("Leafs")
        .get(root)
        .get("stored_proofs")
        .get(real.as_str())
        .clone();

    let (cid, leaf) = forged_leaf(&temp, "install.sh");
    let mut unproven = honest.clone();
    unproven.get_mut("Leafs").set(&cid, leaf);
    leaf_mut(&mut unproven, root)
        .get_mut("Links")
        .push(text(&cid));

    let mut filed = unproven.clone();
    leaf_mut(&mut filed, root)
        .get_mut("stored_proofs")
        .set(&cid, real_branch.clone());

    let mut renamed = unproven.clone();
    let mut branch = real_branch;
    branch.set("Leaf", text(&cid));
    leaf_mut(&mut renamed, root)
        .get_mut("stored_proofs")
        .set(&cid, branch);

    let mut accepted = Accepted::default();
    accepted.unless_refused(
        decode_and_verify(&unproven),
        "a forged child of a pruned parent, with no proof",
    );
    accepted.unless_refused(
        decode_and_verify(&filed),
        "the same child, with a real sibling's proof filed under its hash",
    );
    accepted.unless_refused(
        decode_and_verify(&renamed),
        "the same child, with that proof renamed to it",
    );
    accepted.finish();
}

/// A leaf sent on its own as the child of a parent that never committed to it.
#[test]
fn transmission_refuses_a_child_its_parent_never_committed_to() {
    let temp = TempDir::new("forgery-transmission-child").unwrap();
    let (_, forged) = forged_leaf(&temp, "install.sh");
    let mut accepted = Accepted::default();

    // A pruned parent that commits to three children.
    let dag = flat_dag(&temp, "three", 3);
    let real = dag.root_leaf().links()[0].clone();
    let partial = dag.get_partial(std::slice::from_ref(&real), true).unwrap();
    let packets = partial.get_leaf_sequence().unwrap();
    let mut receiver = TransmissionReceiver::new();
    receiver
        .apply_and_verify_transmission_packet(packets[0].clone())
        .expect("the root packet verifies");
    receiver
        .verify_transmission_packet(&packets[1])
        .expect("the real child's packet verifies");
    let bad = packet_for(&forged, dag.root().as_str());
    accepted.unless_refused(
        receiver.verify_transmission_packet(&bad),
        "receiver: an unproven child of a pruned parent that commits to three children",
    );
    accepted.unless_refused(
        partial.verify_transmission_packet(&bad),
        "DAG: an unproven child of a pruned parent that commits to three children",
    );

    // A parent that commits to one child, and has it.
    let dag = flat_dag(&temp, "one", 1);
    let mut receiver = TransmissionReceiver::new();
    for packet in dag.get_leaf_sequence().unwrap() {
        receiver
            .apply_and_verify_transmission_packet(packet)
            .expect("an honest packet verifies");
    }
    let bad = packet_for(&forged, dag.root().as_str());
    accepted.unless_refused(
        receiver.verify_transmission_packet(&bad),
        "receiver: a second child of a parent that commits to one child",
    );
    accepted.unless_refused(
        dag.verify_transmission_packet(&bad),
        "DAG: a second child of a parent that commits to one child",
    );

    // A file that commits to no children.
    let dag = flat_dag(&temp, "none", 3);
    let file = dag.root_leaf().links()[0].as_str();
    let mut receiver = TransmissionReceiver::new();
    for packet in dag.get_leaf_sequence().unwrap() {
        receiver
            .apply_and_verify_transmission_packet(packet)
            .expect("an honest packet verifies");
    }
    let bad = packet_for(&forged, file);
    accepted.unless_refused(
        receiver.verify_transmission_packet(&bad),
        "receiver: a child of a file that commits to no children",
    );
    accepted.unless_refused(
        dag.verify_transmission_packet(&bad),
        "DAG: a child of a file that commits to no children",
    );

    accepted.finish();
}

/// A leaf sent in a batch as the child of a parent that never committed to it.
#[test]
fn batch_refuses_a_child_its_parent_never_committed_to() {
    let temp = TempDir::new("forgery-batch-child").unwrap();
    let (cid, forged) = forged_leaf(&temp, "install.sh");
    let forged_cid: Cid = cid.parse().unwrap();
    let mut accepted = Accepted::default();

    // A complete parent that commits to three children.
    let dag = flat_dag(&temp, "three", 3);
    let root = dag.root().as_str();
    let honest = batch_of(&dag);
    verify_batch(&honest).expect("the honest batch verifies");
    let mut named = honest.clone();
    add_to_batch(&mut named, &cid, &forged, root);
    judge_batch(
        &mut accepted,
        "a forged leaf that names a three-child root as its parent",
        &named,
        &forged_cid,
    );
    let mut listed = named.clone();
    batch_leaf_mut(&mut listed, root)
        .get_mut("Links")
        .push(text(&cid));
    judge_batch(
        &mut accepted,
        "the same leaf, added to that root's links as well",
        &listed,
        &forged_cid,
    );

    // A parent that commits to one child.
    let dag = flat_dag(&temp, "one", 1);
    let root = dag.root().as_str();
    let mut second = batch_of(&dag);
    verify_batch(&second).expect("the honest batch verifies");
    add_to_batch(&mut second, &cid, &forged, root);
    batch_leaf_mut(&mut second, root)
        .get_mut("Links")
        .push(text(&cid));
    judge_batch(
        &mut accepted,
        "a second child of a root that commits to one child",
        &second,
        &forged_cid,
    );

    // A file that commits to no children.
    let dag = flat_dag(&temp, "none", 3);
    let file = dag.root_leaf().links()[0].as_str();
    let mut under_file = batch_of(&dag);
    add_to_batch(&mut under_file, &cid, &forged, file);
    batch_leaf_mut(&mut under_file, file).set("Links", links(&[cid.as_str()]));
    judge_batch(
        &mut accepted,
        "a child of a file that commits to no children",
        &under_file,
        &forged_cid,
    );

    // A pruned parent that carries a proof for another child.
    let dag = flat_dag(&temp, "pruned", 3);
    let root = dag.root().as_str();
    let real = dag.root_leaf().links()[0].clone();
    let partial = wire_of(&dag.get_partial(std::slice::from_ref(&real), true).unwrap());
    let mut root_leaf = partial.get("Leafs").get(root).clone();
    let real_leaf = partial.get("Leafs").get(real.as_str()).clone();
    verify_batch(&batch_from(&[(&root_leaf, ""), (&real_leaf, root)]))
        .expect("the honest batch of a partial verifies");
    root_leaf.get_mut("Links").push(text(&cid));
    judge_batch(
        &mut accepted,
        "an unproven child of a pruned root that carries a proof for another child",
        &batch_from(&[(&root_leaf, ""), (&real_leaf, root), (&forged, root)]),
        &forged_cid,
    );

    accepted.finish();
}

/// A forged leaf under a file that commits to no children.
#[test]
fn decoded_dag_refuses_a_child_under_a_file() {
    let temp = TempDir::new("forgery-child-under-file").unwrap();
    let dag = flat_dag(&temp, "victim", 3);
    let file = dag.root_leaf().links()[0].as_str();
    let mut forged = wire_of(&dag);
    decode_and_verify(&forged).expect("the honest DAG verifies");

    let (cid, leaf) = forged_leaf(&temp, "install.sh");
    forged.get_mut("Leafs").set(&cid, leaf);
    leaf_mut(&mut forged, file).set("Links", links(&[cid.as_str()]));

    let mut accepted = Accepted::default();
    accepted.unless_refused(
        decode_and_verify(&forged),
        "a forged leaf under a file that commits to no children",
    );
    accepted.finish();
}

/// No forged leaf, and the leaf count is unchanged: a real file that commits
/// to no children is given a link to another real file.
#[test]
fn full_dag_refuses_a_link_under_a_leaf_with_no_children() {
    let temp = TempDir::new("forgery-full-childless-link").unwrap();
    let mut accepted = Accepted::default();
    // The root's children are walked in order, so one of the two files is
    // reached first: both directions are tried.
    for (from, to) in [(1, 0), (0, 1)] {
        let dag = flat_dag(&temp, &format!("victim-{from}-{to}"), 3);
        let children = dag.root_leaf().links();
        let mut forged = wire_of(&dag);
        // A leaf may travel without its content, which turns the size checks off.
        leaf_mut(&mut forged, children[2].as_str()).set("Content", Json::Null);
        decode_and_verify(&forged).expect("an honest DAG with one content-less leaf verifies");

        leaf_mut(&mut forged, children[from].as_str())
            .set("Links", links(&[children[to].as_str()]));
        accepted.unless_refused(
            decode_and_verify(&forged),
            &format!("a link from child {from} of the root to child {to}, in a full DAG"),
        );
    }
    accepted.finish();
}

/// The same edit in a partial DAG. Eight leaves are edited in turn, so the
/// edit lands on leaves whose hash is above and below the root's.
#[test]
fn partial_refuses_a_link_under_a_leaf_with_no_children() {
    let temp = TempDir::new("forgery-partial-childless-link").unwrap();
    let dag = flat_dag(&temp, "victim", 9);
    let kept = dag.root_leaf().links()[..8].to_vec();
    let honest = wire_of(&dag.get_partial(&kept, true).unwrap());
    decode_and_verify(&honest).expect("the honest partial verifies");

    let mut accepted = Accepted::default();
    for (index, leaf) in kept.iter().enumerate() {
        let target = &kept[(index + 1) % kept.len()];
        let mut forged = honest.clone();
        leaf_mut(&mut forged, leaf.as_str()).set("Links", links(&[target.as_str()]));
        accepted.unless_refused(
            decode_and_verify(&forged),
            &format!("a link from {leaf}, which commits to no children, in a partial DAG"),
        );
    }
    accepted.finish();
}

/// A forged leaf filed under a real child's hash, while saying that it is the
/// root.
#[test]
fn decoded_dag_refuses_a_leaf_filed_under_another_hash() {
    let temp = TempDir::new("forgery-filed-under-another-hash").unwrap();
    let dag = flat_dag(&temp, "victim", 3);
    let real = dag.root_leaf().links()[0].clone();
    let partial = dag.get_partial(std::slice::from_ref(&real), true).unwrap();
    let mut forged = wire_of(&partial);
    decode_and_verify(&forged).expect("the honest partial verifies");

    let leaf = leaf_mut(&mut forged, real.as_str());
    leaf.set("Hash", text(dag.root().as_str()));
    leaf.set("Content", text("Zm9yZ2Vk")); // "forged"

    let mut accepted = Accepted::default();
    accepted.unless_refused(
        decode_and_verify(&forged),
        "a leaf whose hash differs from the key it is filed under",
    );
    accepted.finish();
}

/// A later packet that claims to be the root.
#[test]
fn transmission_refuses_a_root_packet_for_another_root() {
    let temp = TempDir::new("forgery-foreign-root").unwrap();
    let dag = flat_dag(&temp, "victim", 3);
    let packets = dag.get_leaf_sequence().unwrap();
    // The root packet of a different, valid DAG.
    let foreign = flat_dag(&temp, "foreign", 2)
        .get_leaf_sequence()
        .unwrap()
        .remove(0);
    let mut accepted = Accepted::default();

    let mut receiver = TransmissionReceiver::new();
    receiver
        .apply_and_verify_transmission_packet(packets[0].clone())
        .expect("the root packet verifies");
    accepted.unless_refused(
        receiver.verify_transmission_packet(&foreign),
        "receiver that holds a root: a root packet for another root",
    );

    let pinned = TransmissionReceiver::with_root(dag.root().clone());
    accepted.unless_refused(
        pinned.verify_transmission_packet(&foreign),
        "receiver pinned to a root: a root packet for another root",
    );

    accepted.unless_refused(
        dag.verify_transmission_packet(&foreign),
        "DAG: a root packet for a root other than its own",
    );

    let mut store = DagStore::in_memory();
    store
        .add_transmission_packet(&packets[0])
        .expect("the root packet is stored");
    accepted.unless_refused(
        store.add_transmission_packet(&foreign),
        "store that holds a root: a root packet for another root",
    );
    accepted.when(
        store.root() != Some(dag.root()),
        "store: a later root packet replaced its root",
    );

    accepted.finish();
}

/// A store's own verification, given what DAG verification refuses.
#[test]
fn store_verification_refuses_forged_children() {
    let temp = TempDir::new("forgery-store-verify").unwrap();
    let mut accepted = Accepted::default();

    // An extra child under the root.
    let dag = flat_dag(&temp, "extra", 3);
    DagStore::from_dag(&dag)
        .unwrap()
        .verify_streaming()
        .expect("the honest store verifies");
    let (cid, leaf) = forged_leaf(&temp, "install.sh");
    let mut forged = wire_of(&dag);
    forged.get_mut("Leafs").set(&cid, leaf);
    leaf_mut(&mut forged, dag.root().as_str())
        .get_mut("Links")
        .push(text(&cid));
    let store = store_of(&forged);
    accepted.unless_refused(
        store.verify_streaming(),
        "streaming verification: an extra child under the root",
    );
    accepted.unless_refused(
        store.verify(),
        "materializing verification: an extra child under the root",
    );

    // A link under a file that commits to no children.
    let dag = flat_dag(&temp, "link", 3);
    let from = dag.root_leaf().links()[0].clone();
    let to = dag.root_leaf().links()[1].clone();
    let mut forged = wire_of(&dag);
    leaf_mut(&mut forged, from.as_str()).set("Links", links(&[to.as_str()]));
    let store = store_of(&forged);
    if store.verify_streaming().is_ok() {
        accepted.0.push(format!(
            "streaming verification: a link under a file that commits to no children; \
             the store then returns {:?} for a file that holds {:?}",
            store
                .get_content_from_leaf_streaming(&from)
                .map(|bytes| readable(&bytes)),
            readable(dag.get(&from).unwrap().content().unwrap()),
        ));
    }
    accepted.unless_refused(
        store.verify(),
        "materializing verification: a link under a file that commits to no children",
    );

    accepted.finish();
}

/// A store taking in a leaf that its parent never committed to.
#[test]
fn store_intake_refuses_a_leaf_its_parent_never_committed_to() {
    let temp = TempDir::new("forgery-store-intake").unwrap();
    let (cid, forged) = forged_leaf(&temp, "install.sh");
    let forged_cid: Cid = cid.parse().unwrap();
    let dag = flat_dag(&temp, "victim", 3);
    let root = dag.root().as_str();
    let file = dag.root_leaf().links()[0].as_str();
    let packets = dag.get_leaf_sequence().unwrap();
    let mut accepted = Accepted::default();

    // In a batch.
    let honest = batch_of(&dag);
    DagStore::in_memory()
        .add_batched_transmission_packet(&decode_batch(&honest).unwrap())
        .expect("the honest batch is stored");
    let mut named = honest.clone();
    add_to_batch(&mut named, &cid, &forged, root);
    let mut listed = named.clone();
    batch_leaf_mut(&mut listed, root)
        .get_mut("Links")
        .push(text(&cid));
    for (what, wire) in [
        (
            "batch: a forged leaf that names the root as its parent",
            &named,
        ),
        (
            "batch: the same leaf, added to the root's links as well",
            &listed,
        ),
    ] {
        let mut store = DagStore::in_memory();
        if let Ok(packet) = decode_batch(wire) {
            let _ = store.add_batched_transmission_packet(&packet);
        }
        accepted.when(store.has_leaf(&forged_cid).unwrap(), what);
    }

    // Leaf by leaf: a parent the store has never seen.
    let mut store = DagStore::in_memory();
    store
        .add_transmission_packet(&packets[0])
        .expect("the root packet is stored");
    let stranger = flat_dag(&temp, "stranger", 2);
    let _ = store.add_transmission_packet(&packet_for(&forged, stranger.root().as_str()));
    accepted.when(
        store.has_leaf(&forged_cid).unwrap(),
        "leaf by leaf: a leaf that names a parent the store has never seen",
    );

    // Leaf by leaf: a stored file that commits to no children.
    let mut store = DagStore::in_memory();
    for packet in &packets {
        store
            .add_transmission_packet(packet)
            .expect("an honest packet is stored");
    }
    let _ = store.add_transmission_packet(&packet_for(&forged, file));
    accepted.when(
        store.has_leaf(&forged_cid).unwrap(),
        "leaf by leaf: a child of a stored file that commits to no children",
    );

    // Leaf by leaf: the same file, whose own packet arrived listing the forged leaf.
    let mut store = DagStore::in_memory();
    for packet in &packets {
        let mut wire = Json::parse(&packet.to_json().unwrap());
        if wire.get("Leaf").get("Hash").text() == file {
            wire.get_mut("Leaf").set("Links", links(&[cid.as_str()]));
        }
        if let Ok(packet) = TransmissionPacket::from_json(&wire.to_bytes()) {
            let _ = store.add_transmission_packet(&packet);
        }
    }
    let _ = store.add_transmission_packet(&packet_for(&forged, file));
    accepted.when(
        store.has_leaf(&forged_cid).unwrap(),
        "leaf by leaf: a child of a file whose own packet arrived listing it",
    );

    accepted.finish();
}

/// A file must not come back short with no error.
#[test]
fn content_refuses_an_incomplete_file() {
    let temp = TempDir::new("forgery-incomplete-file").unwrap();
    let body = three_chunks(*b"ABC");
    let dag = chunked_dag(
        &temp,
        "victim",
        &[("big.bin", &body[..]), ("other.txt", &b"x"[..])],
    );
    let file = dag
        .leaves()
        .values()
        .find(|leaf| leaf.item_name() == "big.bin")
        .expect("the chunked file");
    assert_eq!(file.links().len(), 3, "big.bin is cut into three chunks");
    let chunk = |name: &str| {
        file.links()
            .iter()
            .find(|cid| dag.get(cid).unwrap().item_name() == name)
            .unwrap()
            .clone()
    };
    let (first, middle, last) = (chunk("0"), chunk("1"), chunk("2"));
    let partial = dag.get_partial(file.links(), true).unwrap();
    let honest = wire_of(&partial);
    let whole = decode_and_verify(&honest).expect("the honest partial verifies");
    let content_of = |dag: &Dag| dag.get_content_from_leaf(dag.get(file.cid()).unwrap());
    assert_eq!(
        content_of(&whole).unwrap(),
        body,
        "a complete file comes back whole"
    );

    // The middle chunk dropped the way a sender can drop it: its leaf, its link
    // and its proof.
    let mut shortened = honest.clone();
    shortened.get_mut("Leafs").remove(middle.as_str());
    let leaf = leaf_mut(&mut shortened, file.cid().as_str());
    leaf.set("Links", links(&[first.as_str(), last.as_str()]));
    leaf.get_mut("stored_proofs").remove(middle.as_str());
    let shortened = decode_and_verify(&shortened)
        .expect("a partial with two of three chunks is still a valid partial");

    // The middle chunk present, without its content.
    let mut hollow = honest.clone();
    leaf_mut(&mut hollow, middle.as_str()).set("Content", Json::Null);
    let hollow = decode_and_verify(&hollow).expect("a leaf may travel without its content");

    let mut accepted = Accepted::default();
    for (how, forged) in [
        ("its middle chunk absent", &shortened),
        ("its middle chunk without content", &hollow),
    ] {
        if let Ok(bytes) = content_of(forged) {
            accepted.0.push(format!(
                "DAG: {} bytes returned, with no error, for a {}-byte file with {how}",
                bytes.len(),
                body.len()
            ));
        }
        let store = DagStore::from_dag(forged).unwrap();
        if let Ok(bytes) = store.get_content_from_leaf_streaming(file.cid()) {
            accepted.0.push(format!(
                "store: {} bytes returned, with no error, for a {}-byte file with {how}",
                bytes.len(),
                body.len()
            ));
        }
    }
    accepted.finish();
}

/// Runs `attempt` on a thread of its own and says what went wrong, if anything
/// did: the input was accepted, the call panicked, or it never came back.
fn fault_of(attempt: impl FnOnce() -> Result<(), Error> + Send + 'static) -> Option<&'static str> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(attempt().is_ok());
    });
    match receiver.recv_timeout(Duration::from_secs(10)) {
        Ok(false) => None,
        Ok(true) => Some("was accepted"),
        Err(mpsc::RecvTimeoutError::Disconnected) => Some("made the library panic"),
        Err(mpsc::RecvTimeoutError::Timeout) => Some("never returned"),
    }
}

/// Malformed input must come back as an error: no panic, and no hang.
#[test]
fn malformed_input_returns_an_error() {
    let temp = TempDir::new("forgery-malformed").unwrap();
    let dag = flat_dag(&temp, "victim", 5);
    let root = dag.root().as_str();
    let real = dag.root_leaf().links()[0].clone();
    let partial = wire_of(&dag.get_partial(std::slice::from_ref(&real), true).unwrap());
    let mut cases = Vec::new();

    let mut no_root = partial.clone();
    no_root.get_mut("Leafs").remove(root);
    cases.push(("a DAG without its root leaf", no_root));

    let mut null_leaf = partial.clone();
    null_leaf.get_mut("Leafs").set(real.as_str(), Json::Null);
    cases.push(("a null leaf", null_leaf));

    let mut null_proof = partial.clone();
    leaf_mut(&mut null_proof, root)
        .get_mut("stored_proofs")
        .set(real.as_str(), Json::Null);
    cases.push(("a null proof", null_proof));

    // Two leaves that commit to no children, and list each other.
    let (x, mut x_leaf) = forged_leaf(&temp, "x");
    let (y, mut y_leaf) = forged_leaf(&temp, "y");
    x_leaf.set("Links", links(&[y.as_str()]));
    y_leaf.set("Links", links(&[x.as_str()]));
    let mut ring = partial.clone();
    ring.get_mut("Leafs").set(&x, x_leaf);
    ring.get_mut("Leafs").set(&y, y_leaf);
    cases.push(("two childless leaves that list each other", ring));

    // Two leaves that commit to three children each, so that a list of one
    // reads as pruned, and that list each other.
    let attacker = chunked_dag(
        &temp,
        "attacker-ring",
        &[
            ("x.bin", &three_chunks(*b"XYZ")[..]),
            ("y.bin", &three_chunks(*b"UVW")[..]),
        ],
    );
    let (x, mut x_leaf) = leaf_named(&attacker, "x.bin");
    let (y, mut y_leaf) = leaf_named(&attacker, "y.bin");
    x_leaf.set("Links", links(&[y.as_str()]));
    y_leaf.set("Links", links(&[x.as_str()]));
    let mut pruned_ring = partial.clone();
    pruned_ring.get_mut("Leafs").set(&x, x_leaf);
    pruned_ring.get_mut("Leafs").set(&y, y_leaf);
    cases.push((
        "two pruned-looking leaves that list each other",
        pruned_ring,
    ));

    let mut accepted = Accepted::default();
    for (what, wire) in cases {
        let bytes = wire.to_bytes();
        let attempt = move || Dag::from_json(&bytes).and_then(|dag| dag.verify());
        if let Some(fault) = fault_of(attempt) {
            accepted.0.push(format!("{what} {fault}"));
        }
    }
    accepted.finish();
}

/// In a partial DAG a chunk is walked up to the root through one parent only.
/// A second file that lists the same chunk among its own is never asked for a
/// proof.
#[test]
fn partial_refuses_a_link_through_a_second_parent() {
    let temp = TempDir::new("forgery-second-parent").unwrap();
    let dag = chunked_dag(
        &temp,
        "victim",
        &[
            ("a.bin", &three_chunks(*b"abc")[..]),
            ("b.bin", &three_chunks(*b"xyz")[..]),
        ],
    );
    let file = |name: &str| {
        dag.leaves()
            .values()
            .find(|leaf| leaf.item_name() == name)
            .unwrap()
    };
    let chunk = |file: &DagLeaf, name: &str| {
        file.links()
            .iter()
            .find(|cid| dag.get(cid).unwrap().item_name() == name)
            .unwrap()
            .clone()
    };
    let (a, b) = (file("a.bin"), file("b.bin"));
    let (a0, b1) = (chunk(a, "0"), chunk(b, "1"));
    let partial = dag.get_partial(&[a0.clone(), b1.clone()], true).unwrap();
    let honest = wire_of(&partial);
    decode_and_verify(&honest).expect("the honest partial verifies");

    // The walk takes a chunk's lowest parent. So the forged link goes into
    // whichever file has the higher hash: the chunk's real parent, the lower
    // one, then vouches for it, and the forged link is never looked at.
    let (host, guest, home) = if a.cid() > b.cid() {
        (a, &b1, b)
    } else {
        (b, &a0, a)
    };
    let mut forged = honest.clone();
    leaf_mut(&mut forged, host.cid().as_str())
        .get_mut("Links")
        .push(text(guest.as_str()));

    let mut accepted = Accepted::default();
    if let Ok(taken) = decode_and_verify(&forged) {
        accepted.0.push(format!(
            "DAG: {} lists a chunk of {} among its own, and returns {:?}",
            host.item_name(),
            home.item_name(),
            taken
                .get_content_from_leaf(taken.get(host.cid()).unwrap())
                .map(|bytes| readable(&bytes)),
        ));
    }
    if let Ok(taken) = Dag::from_json(&forged.to_bytes()) {
        let store = DagStore::from_dag(&taken).unwrap();
        accepted.unless_refused(
            store.verify_streaming(),
            "store, streaming verification: the same partial",
        );
        accepted.unless_refused(
            store.verify(),
            "store, materializing verification: the same partial",
        );
    }
    accepted.finish();
}

/// From a hostile sender to a wrong file: a store takes the transfer in, its
/// streaming verification passes, and a real file reads back as forged bytes.
#[test]
fn a_verified_store_never_serves_forged_bytes_for_a_real_file() {
    let temp = TempDir::new("forgery-store-forged-bytes").unwrap();
    let dag = flat_dag(&temp, "victim", 3);
    let file = dag.root_leaf().links()[0].clone();
    let honest_bytes = dag.get(&file).unwrap().content().unwrap().to_vec();
    let (cid, forged) = forged_leaf(&temp, "install.sh");

    let mut honest = DagStore::in_memory();
    for packet in dag.get_leaf_sequence().unwrap() {
        honest
            .add_transmission_packet(&packet)
            .expect("an honest packet is stored");
    }
    honest
        .verify_streaming()
        .expect("the honest store verifies");
    assert_eq!(
        honest.get_content_from_leaf_streaming(&file).unwrap(),
        honest_bytes,
        "the honest store returns the file"
    );

    let mut accepted = Accepted::default();
    let mut judge = |how: &str, store: &DagStore| {
        let verified = store.verify_streaming().is_ok();
        if let (true, Ok(bytes)) = (verified, store.get_content_from_leaf_streaming(&file)) {
            if bytes != honest_bytes {
                accepted.0.push(format!(
                    "{how}: the store verifies, and returns {:?} for a file that holds {:?}",
                    readable(&bytes),
                    readable(&honest_bytes)
                ));
            }
        }
    };

    // Leaf by leaf: the file's own packet lists the forged leaf as its child,
    // and the forged leaf follows.
    let mut store = DagStore::in_memory();
    for packet in dag.get_leaf_sequence().unwrap() {
        let mut wire = Json::parse(&packet.to_json().unwrap());
        if wire.get("Leaf").get("Hash").text() == file.as_str() {
            wire.get_mut("Leaf").set("Links", links(&[cid.as_str()]));
        }
        if let Ok(packet) = TransmissionPacket::from_json(&wire.to_bytes()) {
            let _ = store.add_transmission_packet(&packet);
        }
    }
    let _ = store.add_transmission_packet(&packet_for(&forged, file.as_str()));
    judge("leaf by leaf", &store);

    // One batch that does the same.
    let mut wire = batch_of(&dag);
    add_to_batch(&mut wire, &cid, &forged, file.as_str());
    batch_leaf_mut(&mut wire, file.as_str()).set("Links", links(&[cid.as_str()]));
    let mut store = DagStore::in_memory();
    if let Ok(packet) = decode_batch(&wire) {
        let _ = store.add_batched_transmission_packet(&packet);
    }
    judge("in one batch", &store);

    accepted.finish();
}
