//! PARITY_SPEC 5.8, plus the store-backed bullets of 5.1 and 5.4.
//!
//! Several of the spec's claims are about what the code does *not* do -- streaming
//! verification must not materialize the DAG, parent-hash updates must not erase
//! content, batches must stay bounded. Those cannot be checked by asserting on a
//! return value, so the stores here are instrumented: they count metadata reads,
//! count content reads, and record the size of every batch write.

mod support;

use scionic_merkletree::{
    create_dag_with_options, BatchedTransmissionPacket, Batching, Cid, ContentStore, Dag, DagLeaf,
    DagStore, Error, LeafStore, LeafType, MemoryContentStore, MemoryLeafStore, Result,
    TransmissionPacket,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use support::{create_fixture, options_4096, TempDir, FIXTURES};

// ---- instrumented backends ----

#[derive(Clone, Default)]
struct Probe {
    leaves: Arc<MemoryLeafStore>,
    contents: Arc<MemoryContentStore>,
    leaf_reads: Arc<AtomicUsize>,
    content_reads: Arc<AtomicUsize>,
    batch_sizes: Arc<Mutex<Vec<usize>>>,
}

impl Probe {
    fn leaf_reads(&self) -> usize {
        self.leaf_reads.load(Ordering::Relaxed)
    }

    fn content_reads(&self) -> usize {
        self.content_reads.load(Ordering::Relaxed)
    }

    fn batch_sizes(&self) -> Vec<usize> {
        self.batch_sizes.lock().unwrap().clone()
    }

    fn reset(&self) {
        self.leaf_reads.store(0, Ordering::Relaxed);
        self.content_reads.store(0, Ordering::Relaxed);
        self.batch_sizes.lock().unwrap().clear();
    }

    fn leaf_store(&self) -> Box<dyn LeafStore> {
        Box::new(ProbeLeafStore(self.clone()))
    }

    fn content_store(&self) -> Box<dyn ContentStore> {
        Box::new(ProbeContentStore(self.clone()))
    }
}

struct ProbeLeafStore(Probe);

impl LeafStore for ProbeLeafStore {
    fn store_leaf(&self, leaf: DagLeaf) -> Result<()> {
        self.0.leaves.store_leaf(leaf)
    }

    fn retrieve_leaf(&self, cid: &Cid) -> Result<Option<DagLeaf>> {
        self.0.leaf_reads.fetch_add(1, Ordering::Relaxed);
        self.0.leaves.retrieve_leaf(cid)
    }

    fn has_leaf(&self, cid: &Cid) -> Result<bool> {
        self.0.leaves.has_leaf(cid)
    }

    fn delete_leaf(&self, cid: &Cid) -> Result<()> {
        self.0.leaves.delete_leaf(cid)
    }

    fn store_leaves(&self, leaves: Vec<DagLeaf>) -> Result<()> {
        self.0.batch_sizes.lock().unwrap().push(leaves.len());
        self.0.leaves.store_leaves(leaves)
    }

    fn count(&self) -> Option<usize> {
        self.0.leaves.count()
    }

    fn all_leaf_hashes(&self) -> Option<Vec<Cid>> {
        self.0.leaves.all_leaf_hashes()
    }
}

struct ProbeContentStore(Probe);

impl ContentStore for ProbeContentStore {
    fn store_content(&self, cid: &Cid, content: &[u8]) -> Result<()> {
        self.0.contents.store_content(cid, content)
    }

    fn retrieve_content(&self, cid: &Cid) -> Result<Option<Vec<u8>>> {
        self.0.content_reads.fetch_add(1, Ordering::Relaxed);
        self.0.contents.retrieve_content(cid)
    }

    fn has_content(&self, cid: &Cid) -> Result<bool> {
        self.0.contents.has_content(cid)
    }

    fn delete_content(&self, cid: &Cid) -> Result<()> {
        self.0.contents.delete_content(cid)
    }
}

/// A leaf store that already knows its child-to-parent edges, so `build_index`
/// takes the cached path instead of traversing.
struct CachedRelationshipStore {
    inner: MemoryLeafStore,
    relationships: BTreeMap<Cid, Option<Cid>>,
}

impl LeafStore for CachedRelationshipStore {
    fn store_leaf(&self, leaf: DagLeaf) -> Result<()> {
        self.inner.store_leaf(leaf)
    }

    fn retrieve_leaf(&self, cid: &Cid) -> Result<Option<DagLeaf>> {
        self.inner.retrieve_leaf(cid)
    }

    fn has_leaf(&self, cid: &Cid) -> Result<bool> {
        self.inner.has_leaf(cid)
    }

    fn delete_leaf(&self, cid: &Cid) -> Result<()> {
        self.inner.delete_leaf(cid)
    }

    fn count(&self) -> Option<usize> {
        self.inner.count()
    }

    fn all_leaf_hashes(&self) -> Option<Vec<Cid>> {
        self.inner.all_leaf_hashes()
    }

    fn cached_relationships(&self) -> Option<BTreeMap<Cid, Option<Cid>>> {
        Some(self.relationships.clone())
    }
}

fn build(temp: &TempDir, fixture: &str) -> Dag {
    let input = create_fixture(temp.path(), fixture).unwrap();
    create_dag_with_options(&input, &options_4096()).unwrap()
}

// ---- 5.1: store verification ----

#[test]
fn every_fixture_verifies_through_the_store_both_ways() {
    let temp = TempDir::new("store-verify-all").unwrap();
    for fixture in FIXTURES {
        let dag = build(&temp, fixture.name);
        let store = DagStore::from_dag(&dag).unwrap();
        assert_eq!(store.root(), Some(dag.root()));
        assert_eq!(store.leaf_count(), fixture.leaves as u64);
        assert!(!store.is_partial().unwrap(), "{} is a full DAG", fixture.name);
        store.verify().unwrap();
        store.verify_streaming().unwrap();
        assert_eq!(store.to_dag().unwrap(), dag, "{}", fixture.name);
        assert_eq!(store.count_leaves_streaming().unwrap(), fixture.leaves);
    }
}

/// The spec requires streaming verification to work through metadata-first access
/// rather than materializing the DAG. With content held in a separate store that
/// is directly measurable: verifying must never read a payload, while the
/// materializing path must.
#[test]
fn verify_streaming_never_reads_the_content_store() {
    let temp = TempDir::new("store-metadata-first").unwrap();
    let dag = build(&temp, "mixed_sizes");
    let probe = Probe::default();
    let store =
        DagStore::from_dag_with(&dag, probe.leaf_store(), Some(probe.content_store())).unwrap();

    probe.reset();
    store.verify_streaming().unwrap();
    assert_eq!(
        probe.content_reads(),
        0,
        "streaming verification must not load any leaf payload"
    );
    assert!(
        probe.leaf_reads() > 0,
        "streaming verification does read leaf metadata"
    );

    // The contrast that gives the assertion above its meaning: the materializing
    // path reads content for every leaf that has any.
    probe.reset();
    store.verify().unwrap();
    assert!(
        probe.content_reads() > 0,
        "to_dag-based verification does load payloads, so the zero above is real"
    );
}

#[test]
fn verify_streaming_accepts_a_partial_dag_through_stored_proofs() {
    let temp = TempDir::new("store-partial").unwrap();
    let dag = build(&temp, "flat_directory");
    let selected = dag
        .leaves()
        .values()
        .find(|leaf| leaf.leaf_type() == LeafType::File && leaf.item_name() == "file1.txt")
        .unwrap()
        .cid()
        .clone();
    let partial = dag
        .get_partial(std::slice::from_ref(&selected), true)
        .unwrap();
    assert!(partial.is_partial());

    let store = DagStore::from_dag(&partial).unwrap();
    assert!(store.is_partial().unwrap());
    // The root declares five children but only one is stored, so this can only
    // pass by checking the retained edge against the root's stored Merkle proof.
    let stored_root = store
        .retrieve_leaf_without_content(store.root().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(stored_root.links().len(), 1);
    assert_eq!(stored_root.current_link_count(), dag.root_leaf().links().len());
    store.verify_streaming().unwrap();
}

#[test]
fn verify_streaming_rejects_a_leaf_whose_identity_was_tampered_with() {
    let temp = TempDir::new("store-tamper").unwrap();
    let dag = build(&temp, "flat_directory");
    let store = DagStore::from_dag(&dag).unwrap();
    store.verify_streaming().unwrap();

    // Rename one leaf inside the serialized DAG, keeping the byte length
    // identical so nothing else shifts. ItemName is hashed into the leaf CID, so
    // the decoded leaf now sits under a key its own identity no longer produces --
    // exactly the substitution a hostile store would attempt. Decoding still
    // succeeds because the embedded Hash field and the map key still agree; only
    // re-deriving identity from the leaf's own fields can catch it.
    let json = String::from_utf8(dag.to_json().unwrap()).unwrap();
    assert_eq!(
        json.matches("\"file1.txt\"").count(),
        1,
        "the name to tamper with appears exactly once"
    );
    let tampered = Dag::from_json(json.replace("\"file1.txt\"", "\"file9.txt\"").as_bytes())
        .expect("the tamper is structurally valid, which is the point");
    let store = DagStore::from_dag(&tampered).unwrap();

    let result = store.verify_streaming();
    assert!(
        matches!(result, Err(Error::LeafCidMismatch { .. })),
        "a renamed leaf must fail streaming verification, got {result:?}"
    );
}

#[test]
fn streaming_content_load_rejects_bytes_that_do_not_match_the_content_hash() {
    let temp = TempDir::new("store-content-tamper").unwrap();
    let dag = build(&temp, "single_large_file");
    let probe = Probe::default();
    let store =
        DagStore::from_dag_with(&dag, probe.leaf_store(), Some(probe.content_store())).unwrap();

    let file = dag
        .leaves()
        .values()
        .find(|leaf| leaf.leaf_type() == LeafType::File && !leaf.links().is_empty())
        .unwrap();
    let expected = dag.get_content_from_leaf(file).unwrap();
    assert_eq!(
        store.get_content_from_leaf_streaming(file.cid()).unwrap(),
        expected
    );

    // Corrupt one chunk's payload behind the store's back. Metadata still
    // verifies perfectly, so only the content-hash re-check can catch this.
    let chunk = &file.links()[0];
    probe
        .contents
        .store_content(chunk, b"not the original chunk bytes")
        .unwrap();
    let result = store.get_content_from_leaf_streaming(file.cid());
    assert!(
        matches!(result, Err(Error::ContentHashMismatch { .. })),
        "corrupted chunk bytes must be rejected on load, got {result:?}"
    );
}

// ---- 5.8: index ----

#[test]
fn index_orders_parents_before_children_and_survives_the_lifecycle() {
    let temp = TempDir::new("store-index").unwrap();
    for fixture in FIXTURES {
        let dag = build(&temp, fixture.name);
        let mut store = DagStore::from_dag(&dag).unwrap();
        assert!(!store.has_index());
        assert!(store.index().is_none());

        store.build_index().unwrap();
        assert!(store.has_index());
        let index = store.index().unwrap();
        assert_eq!(index.len(), fixture.leaves, "{}", fixture.name);

        let mut seen = Vec::new();
        for cid in index.leaf_hashes() {
            if let Some(parent) = index.parent_of(cid) {
                assert!(
                    seen.iter().any(|earlier| earlier == parent),
                    "{}: child {cid} precedes its parent {parent} in the index",
                    fixture.name
                );
            } else {
                assert_eq!(cid, dag.root(), "{}: only the root has no parent", fixture.name);
            }
            seen.push(cid.clone());
        }

        store.clear_index();
        assert!(!store.has_index());
        assert!(store.index().is_none());
    }
}

#[test]
fn incrementally_added_index_entries_are_ignored_once_present() {
    let temp = TempDir::new("store-index-incremental").unwrap();
    let dag = build(&temp, "flat_directory");
    let mut store = DagStore::from_dag(&dag).unwrap();

    let root = dag.root().clone();
    let children = dag.root_leaf().links().to_vec();
    store.add_to_index(root.clone(), None, children.clone());
    assert!(
        !store.has_index(),
        "an index under construction is not built until it is marked built"
    );
    for child in &children {
        store.add_to_index(child.clone(), Some(root.clone()), Vec::new());
    }
    // A shared chunk gets announced by each of its parents; re-adding must not
    // duplicate the entry or flip the recorded parent.
    store.add_to_index(children[0].clone(), Some(children[1].clone()), Vec::new());
    store.mark_index_built();

    assert!(store.has_index());
    let index = store.index().unwrap();
    assert_eq!(index.len(), 1 + children.len());
    assert_eq!(index.parent_of(&children[0]), Some(&root));
    assert_eq!(index.parent_of(&root), None);
    assert_eq!(index.children_of(&root), children.as_slice());
}

#[test]
fn cached_relationships_and_traversal_agree_on_the_index() {
    let temp = TempDir::new("store-index-cache").unwrap();
    for fixture in FIXTURES {
        let dag = build(&temp, fixture.name);

        let mut traversed = DagStore::from_dag(&dag).unwrap();
        traversed.build_index().unwrap();
        let expected = traversed.index().unwrap().clone();

        // The cache stands in for a backend that already tracks its edges, so it
        // is populated exactly the way such a backend would see them.
        let mut relationships: BTreeMap<Cid, Option<Cid>> = BTreeMap::new();
        dag.visit_unique(|leaf, parent| {
            relationships.insert(leaf.cid().clone(), parent.map(|parent| parent.cid().clone()));
            Ok(())
        })
        .unwrap();
        let backend = CachedRelationshipStore {
            inner: MemoryLeafStore::new(),
            relationships,
        };
        for leaf in dag.leaves().values() {
            backend.store_leaf(leaf.clone()).unwrap();
        }
        let mut cached = DagStore::empty(Box::new(backend), None);
        cached.set_root(dag.root().clone()).unwrap();
        cached.build_index().unwrap();
        let actual = cached.index().unwrap();

        assert_eq!(actual.len(), expected.len(), "{}", fixture.name);
        let mut seen: Vec<Cid> = Vec::new();
        for cid in actual.leaf_hashes() {
            if let Some(parent) = actual.parent_of(cid) {
                assert!(
                    seen.iter().any(|earlier| earlier == parent),
                    "{}: cached index puts {cid} before its parent",
                    fixture.name
                );
            }
            seen.push(cid.clone());
        }
    }
}

#[test]
fn iterate_with_index_yields_every_leaf_without_loading_content() {
    let temp = TempDir::new("store-iterate-index").unwrap();
    let dag = build(&temp, "mixed_sizes");
    let probe = Probe::default();
    let mut store =
        DagStore::from_dag_with(&dag, probe.leaf_store(), Some(probe.content_store())).unwrap();
    store.build_index().unwrap();

    probe.reset();
    let mut visited = Vec::new();
    store
        .iterate_dag_with_index(|leaf, parent| {
            visited.push((leaf.clone(), parent.cloned()));
            Ok(())
        })
        .unwrap();

    assert_eq!(visited.len(), dag.len());
    assert_eq!(probe.content_reads(), 0, "index iteration must not load payloads");
    assert_eq!(
        probe.leaf_reads(),
        0,
        "a built index answers from memory without touching the leaf store"
    );
    assert_eq!(visited[0].0, *dag.root());
    assert_eq!(visited[0].1, None);
}

#[test]
fn iterate_streaming_visits_each_shared_leaf_exactly_once() {
    let temp = TempDir::new("store-iterate-streaming").unwrap();
    // mixed_sizes has a chunk shared by two different files.
    let dag = build(&temp, "mixed_sizes");
    let store = DagStore::from_dag(&dag).unwrap();

    let mut counts: BTreeMap<Cid, usize> = BTreeMap::new();
    store
        .iterate_dag_streaming(|leaf, _| {
            *counts.entry(leaf.cid().clone()).or_default() += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(counts.len(), dag.len());
    assert!(
        counts.values().all(|count| *count == 1),
        "a leaf linked by two parents must still be visited once"
    );
}

// ---- 5.8: parent hash updates ----

#[test]
fn update_parent_hashes_streaming_matches_the_index_and_keeps_content() {
    let temp = TempDir::new("store-parent-hashes").unwrap();
    let dag = build(&temp, "mixed_sizes");

    for batch_size in [0_usize, 1, 3, 1000] {
        let probe = Probe::default();
        let mut store = DagStore::from_dag_with(&dag, probe.leaf_store(), None).unwrap();
        probe.reset();
        store.update_parent_hashes_streaming(batch_size).unwrap();

        let effective = if batch_size == 0 { 10 } else { batch_size };
        let sizes = probe.batch_sizes();
        assert!(!sizes.is_empty(), "batch {batch_size}: leaves must be written back");
        assert!(
            sizes.iter().all(|size| *size <= effective),
            "batch {batch_size}: writes must stay bounded, saw {sizes:?}"
        );
        assert_eq!(
            sizes.iter().sum::<usize>(),
            dag.len(),
            "batch {batch_size}: every leaf is written exactly once"
        );

        let index_parents: BTreeMap<Cid, Option<Cid>> = {
            let index = store.index().unwrap();
            index
                .leaf_hashes()
                .iter()
                .map(|cid| (cid.clone(), index.parent_of(cid).cloned()))
                .collect()
        };
        for (cid, expected_parent) in &index_parents {
            let stored = store.retrieve_leaf(cid).unwrap().unwrap();
            assert_eq!(
                stored.parent_hash(),
                expected_parent.as_ref(),
                "batch {batch_size}: leaf {cid} carries the indexed parent"
            );
            assert_eq!(
                stored.content(),
                dag.get(cid).unwrap().content(),
                "batch {batch_size}: rewriting a leaf must not erase its content"
            );
        }
        store.verify_streaming().unwrap();
    }
}

#[test]
fn update_parent_hashes_streaming_keeps_separately_stored_content() {
    let temp = TempDir::new("store-parent-hashes-split").unwrap();
    let dag = build(&temp, "single_large_file");
    let probe = Probe::default();
    let mut store =
        DagStore::from_dag_with(&dag, probe.leaf_store(), Some(probe.content_store())).unwrap();

    store.update_parent_hashes_streaming(2).unwrap();
    for (cid, original) in dag.leaves() {
        let stored = store.retrieve_leaf(cid).unwrap().unwrap();
        assert_eq!(
            stored.content(),
            original.content(),
            "content held in the content store must survive a metadata rewrite"
        );
    }
    store.verify_streaming().unwrap();
    assert_eq!(store.to_dag().unwrap(), dag);
}

// ---- 5.4: transmission into a store ----

#[test]
fn transmission_packets_rebuild_an_empty_store() {
    let temp = TempDir::new("store-packets").unwrap();
    for fixture in FIXTURES {
        let dag = build(&temp, fixture.name);
        let mut store = DagStore::in_memory();
        for packet in dag.get_leaf_sequence().unwrap() {
            store.add_transmission_packet(&packet).unwrap();
        }
        assert_eq!(store.root(), Some(dag.root()), "{}", fixture.name);
        store.verify_streaming().unwrap();
        assert_eq!(store.to_dag().unwrap(), dag, "{}", fixture.name);
    }
}

#[test]
fn batched_packets_rebuild_an_empty_store_and_pass_verify_streaming() {
    let temp = TempDir::new("store-batches").unwrap();
    for fixture in FIXTURES {
        let dag = build(&temp, fixture.name);
        for batching in [Batching::default(), Batching::Disabled] {
            let mut store = DagStore::in_memory();
            for packet in dag.batched_leaf_sequence_with(batching).unwrap() {
                store.add_batched_transmission_packet(&packet).unwrap();
            }
            assert_eq!(store.root(), Some(dag.root()), "{}", fixture.name);
            store.verify_streaming().unwrap();

            // Core equality rather than whole-DAG equality, deliberately. Batch
            // finalization attaches a parent's Merkle proofs whenever the batch
            // does not carry every one of that parent's children, so a rebuilt
            // DAG can legitimately hold proofs the freshly built one never had.
            // Those proofs are transport metadata and are not hashed; identity,
            // content and links are what has to survive the round trip. The
            // in-memory receiver is compared the same way, for the same reason.
            let rebuilt = store.to_dag().unwrap();
            assert_eq!(rebuilt.root(), dag.root(), "{}", fixture.name);
            assert_eq!(rebuilt.len(), dag.len(), "{}", fixture.name);
            for (cid, expected) in dag.leaves() {
                let actual = rebuilt
                    .get(cid)
                    .unwrap_or_else(|| panic!("{}: missing leaf {cid}", fixture.name));
                assert_eq!(
                    actual.identity_cbor(),
                    expected.identity_cbor(),
                    "{}: {cid}",
                    fixture.name
                );
                assert_eq!(actual.content(), expected.content(), "{}: {cid}", fixture.name);
                assert_eq!(actual.links(), expected.links(), "{}: {cid}", fixture.name);
            }
        }
    }
}

/// Pins the one behaviour that forces the core-field comparison above.
///
/// `mixed_sizes` is the only fixture with a chunk shared by two files. BFS
/// announces that chunk under a single parent, so the other parent's child count
/// in the batch falls short of its declared link count and finalization gives it
/// a full set of Merkle proofs. Worth pinning rather than tolerating silently:
/// it is the difference between "batched transport adds proof metadata" and "the
/// store lost or invented a leaf".
#[test]
fn batched_finalization_attaches_parent_proofs_for_a_shared_chunk() {
    let temp = TempDir::new("store-batch-shared-proofs").unwrap();
    let dag = build(&temp, "mixed_sizes");
    assert!(
        dag.leaves().values().all(|leaf| leaf.proofs().is_empty()),
        "a freshly built full DAG stores no proofs at all"
    );

    let mut store = DagStore::in_memory();
    for packet in dag.batched_leaf_sequence().unwrap() {
        store.add_batched_transmission_packet(&packet).unwrap();
    }
    let rebuilt = store.to_dag().unwrap();
    let with_proofs: Vec<_> = rebuilt
        .leaves()
        .values()
        .filter(|leaf| !leaf.proofs().is_empty())
        .collect();
    assert!(
        !with_proofs.is_empty(),
        "the shared chunk's other parent should arrive carrying proofs"
    );
    for leaf in with_proofs {
        assert!(
            leaf.current_link_count() > 1,
            "only multi-child parents carry proofs"
        );
        for (key, branch) in leaf.proofs() {
            assert_eq!(branch.child(), key, "every stored proof is bound to its key");
        }
    }
    store.verify_streaming().unwrap();
}

#[test]
fn store_rejects_a_packet_whose_declared_parent_does_not_link_it() {
    let temp = TempDir::new("store-packet-forgery").unwrap();
    let dag = build(&temp, "flat_directory");
    let packets = dag.get_leaf_sequence().unwrap();

    let mut store = DagStore::in_memory();
    store.add_transmission_packet(&packets[0]).unwrap();
    store.add_transmission_packet(&packets[1]).unwrap();

    // Re-point the third packet at the second packet's leaf. That leaf is a
    // childless file, so it cannot have linked anything.
    let impostor_parent = packets[1].leaf().cid().to_string();
    let real_parent = packets[2].parent_hash().unwrap().to_string();
    let json = String::from_utf8(packets[2].to_json().unwrap()).unwrap();
    assert_eq!(
        json.matches(real_parent.as_str()).count(),
        1,
        "the parent CID appears only as ParentHash"
    );
    let forged = TransmissionPacket::from_json(
        json.replace(real_parent.as_str(), impostor_parent.as_str()).as_bytes(),
    )
    .unwrap();

    let result = store.add_transmission_packet(&forged);
    assert!(
        matches!(result, Err(Error::ParentMissingLink { .. })),
        "a parent that links nothing must not vouch for a child, got {result:?}"
    );
    assert!(
        !store.has_leaf(forged.leaf().cid()).unwrap(),
        "a rejected packet must not be stored"
    );
}

#[test]
fn store_rejects_a_batch_with_a_forged_relationship_and_stores_nothing() {
    let temp = TempDir::new("store-batch-forgery").unwrap();
    // single_large_file's root links exactly one child, the case where a
    // link-count shortcut would otherwise skip authentication entirely.
    let victim = build(&temp, "single_large_file");
    assert_eq!(victim.root_leaf().current_link_count(), 1);
    let foreign = build(&temp, "nested_directory");

    let mut store = DagStore::in_memory();
    for packet in victim.batched_leaf_sequence().unwrap() {
        store.add_batched_transmission_packet(&packet).unwrap();
    }
    store.verify_streaming().unwrap();
    let before = store.count_leaves_streaming().unwrap();

    let foreign_batches = foreign
        .batched_leaf_sequence_with(Batching::Disabled)
        .unwrap();
    let foreign_packet = foreign_batches
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
        .unwrap()
        .to_string();

    let json = String::from_utf8(foreign_packet.to_json().unwrap()).unwrap();
    assert_eq!(json.matches(foreign_parent.as_str()).count(), 1);
    let forged = BatchedTransmissionPacket::from_json(
        json.replace(foreign_parent.as_str(), victim.root().as_str())
            .as_bytes(),
    )
    .unwrap();

    let result = store.add_batched_transmission_packet(&forged);
    assert!(
        matches!(result, Err(Error::ParentMissingLink { .. })),
        "a foreign leaf claiming the victim root must be rejected, got {result:?}"
    );
    assert!(
        !store.has_leaf(&foreign_leaf).unwrap(),
        "a rejected batch must store nothing at all"
    );
    assert_eq!(store.count_leaves_streaming().unwrap(), before);
    store.verify_streaming().unwrap();
}

// ---- streaming content and recreation ----

#[test]
fn streaming_content_and_recreation_match_the_in_memory_paths() {
    let temp = TempDir::new("store-recreate").unwrap();
    for fixture in FIXTURES {
        let dag = build(&temp, fixture.name);
        let probe = Probe::default();
        let store =
            DagStore::from_dag_with(&dag, probe.leaf_store(), Some(probe.content_store())).unwrap();

        for leaf in dag.leaves().values() {
            if leaf.leaf_type() != LeafType::File {
                continue;
            }
            assert_eq!(
                store.get_content_from_leaf_streaming(leaf.cid()).unwrap(),
                dag.get_content_from_leaf(leaf).unwrap(),
                "{}: {}",
                fixture.name,
                leaf.item_name()
            );
        }

        let streamed = temp.path().join(format!("{}-streamed", fixture.name));
        let materialized = temp.path().join(format!("{}-materialized", fixture.name));
        store.create_directory_streaming(&streamed).unwrap();
        dag.create_directory(&materialized).unwrap();
        assert_eq!(
            read_tree(&streamed),
            read_tree(&materialized),
            "{}: streaming recreation must produce identical bytes",
            fixture.name
        );
    }
}

fn read_tree(root: &std::path::Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        if path.is_dir() {
            for entry in std::fs::read_dir(&path).unwrap() {
                stack.push(entry.unwrap().path());
            }
        } else {
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            files.insert(relative, std::fs::read(&path).unwrap());
        }
    }
    files
}

