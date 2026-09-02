//! Storage-backed DAG operations: PARITY_SPEC layer 5.8, plus the store-backed
//! bullets of 5.1 and 5.4.
//!
//! A [`DagStore`] keeps leaf metadata behind a pluggable [`LeafStore`] and,
//! optionally, leaf payloads behind a separate [`ContentStore`]. The point is that
//! the streaming operations never materialize the whole DAG: verification,
//! traversal, content assembly and directory recreation all pull one leaf at a
//! time, which is what makes a multi-gigabyte repository bundle tractable.
//!
//! Optional store capabilities—batch writes, counting, enumeration, and cached
//! relationships—are default trait methods that report `not supported`.
//! Implementors override the operations they can provide efficiently, while
//! callers retain correct bounded fallbacks.

use crate::dag::{
    compare_chunk_item_names, minimum_parent_index, safe_join, Cid, Dag, DagLeaf, Labels, LeafType,
};
use crate::transmission::{
    verify_branch, verify_complete_classic_root, verify_identity_as, BatchedTransmissionPacket,
    IdentityRole, TransmissionPacket,
};
use crate::{io_error, Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::{Arc, RwLock};

/// Storage for leaf metadata.
///
/// The four required methods are the whole contract. Remaining methods are
/// optional accelerations with correct, slower defaults.
pub trait LeafStore: Send + Sync {
    fn store_leaf(&self, leaf: DagLeaf) -> Result<()>;
    fn retrieve_leaf(&self, cid: &Cid) -> Result<Option<DagLeaf>>;
    fn has_leaf(&self, cid: &Cid) -> Result<bool>;
    fn delete_leaf(&self, cid: &Cid) -> Result<()>;

    /// Store many leaves at once. Defaults to storing them one at a time.
    fn store_leaves(&self, leaves: Vec<DagLeaf>) -> Result<()> {
        for leaf in leaves {
            self.store_leaf(leaf)?;
        }
        Ok(())
    }

    /// Fetch many leaves at once. Missing CIDs are simply absent from the result.
    fn retrieve_leaves(&self, cids: &[Cid]) -> Result<BTreeMap<Cid, DagLeaf>> {
        let mut found = BTreeMap::new();
        for cid in cids {
            if let Some(leaf) = self.retrieve_leaf(cid)? {
                found.insert(cid.clone(), leaf);
            }
        }
        Ok(found)
    }

    /// Total stored leaves, when the backend can answer without a scan.
    fn count(&self) -> Option<usize> {
        None
    }

    /// Every stored leaf CID, when the backend can enumerate cheaply.
    fn all_leaf_hashes(&self) -> Option<Vec<Cid>> {
        None
    }

    /// Cached child to parent edges, when the backend already tracks them.
    ///
    /// Returning `Some` lets [`DagStore::build_index`] skip loading any leaf at
    /// all. `None` means "no cache", and the index is built by BFS traversal
    /// instead.
    fn cached_relationships(&self) -> Option<BTreeMap<Cid, Option<Cid>>> {
        None
    }
}

/// Storage for leaf payloads, kept apart from metadata so that streaming
/// verification can read structure without paying for content.
pub trait ContentStore: Send + Sync {
    fn store_content(&self, cid: &Cid, content: &[u8]) -> Result<()>;
    fn retrieve_content(&self, cid: &Cid) -> Result<Option<Vec<u8>>>;
    fn has_content(&self, cid: &Cid) -> Result<bool>;
    fn delete_content(&self, cid: &Cid) -> Result<()>;
}

/// An in-memory [`LeafStore`].
#[derive(Debug, Default)]
pub struct MemoryLeafStore {
    leaves: RwLock<BTreeMap<Cid, DagLeaf>>,
}

impl MemoryLeafStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        read(&self.leaves).len()
    }

    pub fn is_empty(&self) -> bool {
        read(&self.leaves).is_empty()
    }
}

impl LeafStore for MemoryLeafStore {
    fn store_leaf(&self, leaf: DagLeaf) -> Result<()> {
        write(&self.leaves).insert(leaf.cid().clone(), leaf);
        Ok(())
    }

    fn retrieve_leaf(&self, cid: &Cid) -> Result<Option<DagLeaf>> {
        Ok(read(&self.leaves).get(cid).cloned())
    }

    fn has_leaf(&self, cid: &Cid) -> Result<bool> {
        Ok(read(&self.leaves).contains_key(cid))
    }

    fn delete_leaf(&self, cid: &Cid) -> Result<()> {
        write(&self.leaves).remove(cid);
        Ok(())
    }

    fn store_leaves(&self, leaves: Vec<DagLeaf>) -> Result<()> {
        let mut guard = write(&self.leaves);
        for leaf in leaves {
            guard.insert(leaf.cid().clone(), leaf);
        }
        Ok(())
    }

    fn count(&self) -> Option<usize> {
        Some(read(&self.leaves).len())
    }

    fn all_leaf_hashes(&self) -> Option<Vec<Cid>> {
        Some(read(&self.leaves).keys().cloned().collect())
    }
}

/// An in-memory [`ContentStore`].
#[derive(Debug, Default)]
pub struct MemoryContentStore {
    contents: RwLock<BTreeMap<Cid, Vec<u8>>>,
}

impl MemoryContentStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ContentStore for MemoryContentStore {
    fn store_content(&self, cid: &Cid, content: &[u8]) -> Result<()> {
        write(&self.contents).insert(cid.clone(), content.to_vec());
        Ok(())
    }

    fn retrieve_content(&self, cid: &Cid) -> Result<Option<Vec<u8>>> {
        Ok(read(&self.contents).get(cid).cloned())
    }

    fn has_content(&self, cid: &Cid) -> Result<bool> {
        Ok(read(&self.contents).contains_key(cid))
    }

    fn delete_content(&self, cid: &Cid) -> Result<()> {
        write(&self.contents).remove(cid);
        Ok(())
    }
}

// A poisoned lock means some other thread panicked while holding it. The map is
// still structurally intact -- BTreeMap insert/remove cannot leave a torn value --
// so recovering the guard is strictly better than turning an unrelated panic into
// a cascade of panics in every later store call.
fn read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Lightweight traversal metadata: hashes and edges only, never leaf payloads.
///
/// `leaf_hashes` is in BFS order, so a parent always precedes its children. That
/// ordering is load-bearing for transmission: a receiver that applies leaves in
/// index order can always verify a child against a parent it already holds.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DagIndex {
    leaf_hashes: Vec<Cid>,
    children: BTreeMap<Cid, Vec<Cid>>,
    parents: BTreeMap<Cid, Option<Cid>>,
}

impl DagIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every indexed leaf, parents before children.
    pub fn leaf_hashes(&self) -> &[Cid] {
        &self.leaf_hashes
    }

    pub fn children_of(&self, parent: &Cid) -> &[Cid] {
        self.children.get(parent).map_or(&[], Vec::as_slice)
    }

    /// The parent recorded for `child`, or `None` for the root or an unknown CID.
    pub fn parent_of(&self, child: &Cid) -> Option<&Cid> {
        self.parents.get(child).and_then(Option::as_ref)
    }

    pub fn contains(&self, cid: &Cid) -> bool {
        self.parents.contains_key(cid)
    }

    pub fn len(&self) -> usize {
        self.leaf_hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaf_hashes.is_empty()
    }
}

/// Storage-backed DAG operations.
pub struct DagStore {
    root: Option<Cid>,
    labels: Labels,
    leaf_count: u64,
    leaf_store: Box<dyn LeafStore>,
    content_store: Option<Box<dyn ContentStore>>,
    separate_content: bool,
    index: Option<DagIndex>,
    // Tracked separately from `index` because add_to_index builds an index
    // incrementally during upload, and that index is not complete until
    // mark_index_built says so.
    index_built: bool,
}

impl DagStore {
    /// An empty store backed by memory.
    pub fn in_memory() -> Self {
        Self::empty(Box::new(MemoryLeafStore::new()), None)
    }

    /// An empty store, for building a DAG incrementally from packets.
    pub fn empty(
        leaf_store: Box<dyn LeafStore>,
        content_store: Option<Box<dyn ContentStore>>,
    ) -> Self {
        Self {
            root: None,
            labels: Labels::new(),
            leaf_count: 0,
            leaf_store,
            separate_content: content_store.is_some(),
            content_store,
            index: None,
            index_built: false,
        }
    }

    /// Import an existing DAG into a memory-backed store.
    pub fn from_dag(dag: &Dag) -> Result<Self> {
        Self::from_dag_with(dag, Box::new(MemoryLeafStore::new()), None)
    }

    /// Import an existing DAG into the given backends.
    pub fn from_dag_with(
        dag: &Dag,
        leaf_store: Box<dyn LeafStore>,
        content_store: Option<Box<dyn ContentStore>>,
    ) -> Result<Self> {
        let mut store = Self::empty(leaf_store, content_store);
        for leaf in dag.leaves().values() {
            store.store_leaf(leaf.clone())?;
        }
        store.labels = dag.labels().clone();
        store.set_root(dag.root().clone())?;
        Ok(store)
    }

    pub fn root(&self) -> Option<&Cid> {
        self.root.as_ref()
    }

    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    pub fn labels(&self) -> &Labels {
        &self.labels
    }

    /// Point the store at a root and adopt that root's declared leaf count.
    pub fn set_root(&mut self, root: Cid) -> Result<()> {
        if let Some(leaf) = self.retrieve_leaf(&root)? {
            self.leaf_count = leaf.leaf_count();
        }
        self.root = Some(root);
        Ok(())
    }

    fn require_root(&self) -> Result<&Cid> {
        self.root.as_ref().ok_or(Error::MissingRoot)
    }

    /// Store a leaf, splitting content off when a content store is configured.
    pub fn store_leaf(&self, leaf: DagLeaf) -> Result<()> {
        match (&self.content_store, leaf.content()) {
            (Some(contents), Some(content)) if self.separate_content && !content.is_empty() => {
                contents.store_content(leaf.cid(), content)?;
                let mut without_content = leaf;
                without_content.content = None;
                self.leaf_store.store_leaf(without_content)
            }
            _ => self.leaf_store.store_leaf(leaf),
        }
    }

    /// Retrieve a leaf, re-attaching separately stored content.
    pub fn retrieve_leaf(&self, cid: &Cid) -> Result<Option<DagLeaf>> {
        let Some(mut leaf) = self.leaf_store.retrieve_leaf(cid)? else {
            return Ok(None);
        };
        if let Some(contents) = &self.content_store {
            let wants_content = self.separate_content
                && leaf.content_hash().is_some()
                && leaf.content().is_none_or(<[u8]>::is_empty);
            if wants_content {
                if let Some(content) = contents.retrieve_content(cid)? {
                    // The content store hands back an owned Vec; `Arc::new` moves
                    // it into the shared handle without copying the bytes.
                    leaf.content = Some(Arc::new(content));
                }
            }
        }
        Ok(Some(leaf))
    }

    /// Retrieve a leaf exactly as the leaf store holds it, without re-attaching
    /// separately stored content.
    ///
    /// With a content store configured this yields metadata only, keeping streaming
    /// verification cheap. Without one, the leaf store owns the whole leaf and the
    /// payload is returned too; this lets `update_parent_hashes_streaming` write
    /// leaves back without erasing inline content.
    pub fn retrieve_leaf_without_content(&self, cid: &Cid) -> Result<Option<DagLeaf>> {
        self.leaf_store.retrieve_leaf(cid)
    }

    pub fn has_leaf(&self, cid: &Cid) -> Result<bool> {
        self.leaf_store.has_leaf(cid)
    }

    pub fn delete_leaf(&self, cid: &Cid) -> Result<()> {
        if let Some(contents) = &self.content_store {
            contents.delete_content(cid)?;
        }
        self.leaf_store.delete_leaf(cid)
    }

    /// Store many leaves, using the backend's batch path when it has one.
    pub fn store_leaves_in_batches(&self, leaves: Vec<DagLeaf>) -> Result<()> {
        if leaves.is_empty() {
            return Ok(());
        }
        if self.content_store.is_some() && self.separate_content {
            // Content splitting is per leaf, so fall back to the single-leaf path
            // rather than writing payloads into the metadata store.
            for leaf in leaves {
                self.store_leaf(leaf)?;
            }
            return Ok(());
        }
        self.leaf_store.store_leaves(leaves)
    }

    // ---- index lifecycle (PARITY_SPEC 5.8) ----

    /// Build the traversal index, from cached relationships when the backend has
    /// them and by BFS traversal otherwise.
    pub fn build_index(&mut self) -> Result<()> {
        let root = self.require_root()?.clone();
        match self.leaf_store.cached_relationships() {
            Some(relationships) => self.build_index_from_cache(&root, &relationships),
            None => self.build_index_by_traversal(&root),
        }
    }

    fn build_index_from_cache(
        &mut self,
        root: &Cid,
        relationships: &BTreeMap<Cid, Option<Cid>>,
    ) -> Result<()> {
        let mut index = DagIndex::new();
        for (child, parent) in relationships {
            if let Some(parent) = parent {
                index
                    .children
                    .entry(parent.clone())
                    .or_default()
                    .push(child.clone());
            }
        }
        // Sorted so a cache that hands back edges in any order still yields one
        // BFS sequence.
        for children in index.children.values_mut() {
            children.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        }

        // A relationship cache stores one parent per child, so a shared chunk's
        // other parent edges are already discarded before we get here and cannot
        // be re-derived from them. Route this through the same single rule as
        // every other path anyway, so a cache that does supply canonical parents
        // stays canonical. The contract that follows: cached_relationships must
        // report the LOWEST parent CID for a child with several parents, or
        // return None so the caller falls back to full traversal.
        index.parents = crate::dag::minimum_parent_index(
            index
                .children
                .iter()
                .map(|(parent, children)| (parent, children.as_slice())),
        )
        .into_iter()
        .map(|(child, parent)| (child, Some(parent)))
        .collect();
        index.parents.insert(root.clone(), None);

        let mut visited = BTreeSet::new();
        let mut queue = std::collections::VecDeque::from([root.clone()]);
        while let Some(current) = queue.pop_front() {
            if !visited.insert(current.clone()) {
                continue;
            }
            index.leaf_hashes.push(current.clone());
            for child in index.children.get(&current).cloned().unwrap_or_default() {
                if !visited.contains(&child) {
                    queue.push_back(child);
                }
            }
        }

        if let Some(leaf) = self.leaf_store.retrieve_leaf(root)? {
            self.leaf_count = leaf.leaf_count();
        }
        self.index = Some(index);
        self.index_built = true;
        Ok(())
    }

    fn build_index_by_traversal(&mut self, root: &Cid) -> Result<()> {
        let mut index = DagIndex::new();
        let mut visited = BTreeSet::new();
        let mut queue = std::collections::VecDeque::from([root.clone()]);
        let mut leaf_count = self.leaf_count;
        while let Some(current) = queue.pop_front() {
            if !visited.insert(current.clone()) {
                continue;
            }
            let Some(leaf) = self.leaf_store.retrieve_leaf(&current)? else {
                // A partial DAG legitimately stops here.
                continue;
            };
            index.leaf_hashes.push(current.clone());
            if !leaf.links().is_empty() {
                index
                    .children
                    .insert(current.clone(), leaf.links().to_vec());
                for child in leaf.links() {
                    if !visited.contains(child) {
                        queue.push_back(child.clone());
                    }
                }
            }
            if &current == root {
                leaf_count = leaf.leaf_count();
            }
        }

        // The walk above fixes leaf_hashes order (parents before children, which
        // transmission requires) and collects every parent -> children edge. The
        // child -> parent direction is resolved only now, because a shared
        // chunk's FIRST-SEEN parent depends on traversal order while its
        // parent_hash must not: Dag::from_parts pins it to the lowest parent CID,
        // so a store load has to agree with a decode of the same DAG. Recording
        // the traversal parent here is exactly what made those two disagree.
        index.parents = crate::dag::minimum_parent_index(
            index
                .children
                .iter()
                .map(|(parent, children)| (parent, children.as_slice())),
        )
        .into_iter()
        .map(|(child, parent)| (child, Some(parent)))
        .collect();
        index.parents.insert(root.clone(), None);

        self.leaf_count = leaf_count;
        self.index = Some(index);
        self.index_built = true;
        Ok(())
    }

    pub fn has_index(&self) -> bool {
        self.index_built
    }

    pub fn index(&self) -> Option<&DagIndex> {
        self.index.as_ref()
    }

    pub fn clear_index(&mut self) {
        self.index = None;
        self.index_built = false;
    }

    /// Record one leaf's place in the index while streaming an upload.
    ///
    /// Re-adding a CID is a no-op, so a shared chunk announced by two parents
    /// retains the first indexed parent.
    pub fn add_to_index(&mut self, leaf: Cid, parent: Option<Cid>, children: Vec<Cid>) {
        let index = self.index.get_or_insert_with(DagIndex::new);
        if index.parents.contains_key(&leaf) {
            return;
        }
        index.leaf_hashes.push(leaf.clone());
        index.parents.insert(leaf.clone(), parent);
        if !children.is_empty() {
            index.children.insert(leaf, children);
        }
    }

    /// Mark an incrementally built index complete.
    pub fn mark_index_built(&mut self) {
        self.index_built = true;
    }

    fn ensure_index(&mut self) -> Result<()> {
        if !self.index_built || self.index.is_none() {
            self.build_index()?;
        }
        Ok(())
    }

    /// Walk the DAG using only the index: leaf CID and parent CID, no payloads.
    pub fn iterate_dag_with_index<F>(&mut self, mut visit: F) -> Result<()>
    where
        F: FnMut(&Cid, Option<&Cid>) -> Result<()>,
    {
        self.require_root()?;
        self.ensure_index()?;
        let index = self.index.as_ref().ok_or(Error::Invariant {
            detail: "index is missing immediately after being built",
        })?;
        for leaf in &index.leaf_hashes {
            let parent = index.parents.get(leaf).and_then(Option::as_ref);
            visit(leaf, parent)?;
        }
        Ok(())
    }

    /// Walk the DAG depth-first, loading one leaf at a time and never the payload.
    pub fn iterate_dag_streaming<F>(&self, mut visit: F) -> Result<()>
    where
        F: FnMut(&DagLeaf, Option<&DagLeaf>) -> Result<()>,
    {
        let root = self.require_root()?.clone();
        let mut visited = BTreeSet::new();
        let mut stack = vec![(root, None::<Cid>)];
        while let Some((cid, parent_cid)) = stack.pop() {
            if !visited.insert(cid.clone()) {
                continue;
            }
            let leaf =
                self.retrieve_leaf_without_content(&cid)?
                    .ok_or_else(|| Error::MissingLeaf {
                        cid: cid.to_string(),
                    })?;
            let parent = match &parent_cid {
                Some(parent_cid) => self.retrieve_leaf_without_content(parent_cid)?,
                None => None,
            };
            visit(&leaf, parent.as_ref())?;
            // Reverse before pushing so stack traversal preserves link order.
            for child in leaf.links().iter().rev() {
                if !visited.contains(child) {
                    stack.push((child.clone(), Some(cid.clone())));
                }
            }
        }
        Ok(())
    }

    /// Write each leaf's parent hash into storage, in bounded batches.
    ///
    /// The leaves are read back through [`Self::retrieve_leaf_without_content`] and
    /// written straight back, so inline payloads survive the rewrite and
    /// separately stored payloads are never touched. A zero batch size selects the
    /// bounded default of ten leaves.
    pub fn update_parent_hashes_streaming(&mut self, batch_size: usize) -> Result<()> {
        self.require_root()?;
        self.ensure_index()?;
        let batch_size = if batch_size == 0 { 10 } else { batch_size };
        let plan: Vec<(Cid, Option<Cid>)> = {
            let index = self.index.as_ref().ok_or(Error::Invariant {
                detail: "index is missing immediately after being built",
            })?;
            index
                .leaf_hashes
                .iter()
                .map(|cid| (cid.clone(), index.parents.get(cid).cloned().flatten()))
                .collect()
        };

        let mut batch = Vec::with_capacity(batch_size);
        for (cid, parent) in plan {
            let Some(mut leaf) = self.retrieve_leaf_without_content(&cid)? else {
                continue;
            };
            leaf.set_parent_hash(parent);
            batch.push(leaf);
            if batch.len() >= batch_size {
                self.store_leaves_in_batches(std::mem::take(&mut batch))?;
                batch.reserve(batch_size);
            }
        }
        if !batch.is_empty() {
            self.store_leaves_in_batches(batch)?;
        }
        Ok(())
    }

    // ---- materialization and verification (PARITY_SPEC 5.1) ----

    /// Load every stored leaf into an in-memory [`Dag`].
    pub fn to_dag(&self) -> Result<Dag> {
        let root = self.require_root()?.clone();
        let mut leaves = BTreeMap::new();
        match self.leaf_store.all_leaf_hashes() {
            Some(hashes) => {
                for cid in hashes {
                    if let Some(leaf) = self.retrieve_leaf(&cid)? {
                        leaves.insert(cid, leaf);
                    }
                }
            }
            None => {
                for cid in self.collect_existing_leaf_hashes_from_root()? {
                    if let Some(leaf) = self.retrieve_leaf(&cid)? {
                        leaves.insert(cid, leaf);
                    }
                }
            }
        }
        Dag::from_parts(root, leaves)
    }

    /// Whether fewer leaves are stored than the root claims the DAG has.
    pub fn is_partial(&self) -> Result<bool> {
        let root = self.require_root()?;
        let Some(root_leaf) = self.retrieve_leaf_without_content(root)? else {
            return Ok(true);
        };
        let stored = match self.leaf_store.count() {
            Some(count) => count,
            None => self.collect_existing_leaf_hashes_from_root()?.len(),
        };
        Ok(u64::try_from(stored).map_or(true, |stored| stored < root_leaf.leaf_count()))
    }

    pub fn count_leaves_streaming(&self) -> Result<usize> {
        if self.index_built {
            if let Some(index) = &self.index {
                if !index.is_empty() {
                    return Ok(index.len());
                }
            }
        }
        if let Some(count) = self.leaf_store.count() {
            return Ok(count);
        }
        Ok(self.collect_existing_leaf_hashes_from_root()?.len())
    }

    /// Verify by materializing the DAG. Correct, but loads everything.
    pub fn verify(&self) -> Result<()> {
        self.to_dag()?.verify()
    }

    /// Verify without materializing the DAG.
    ///
    /// Full DAGs are checked structurally, one leaf at a time. Partial DAGs are
    /// checked against the stored Merkle proofs instead of demanding that every
    /// child be present locally.
    pub fn verify_streaming(&self) -> Result<()> {
        self.require_root()?;
        if self.is_partial()? {
            self.verify_with_proofs_streaming()
        } else {
            self.verify_full_dag_streaming()
        }
    }

    fn verify_full_dag_streaming(&self) -> Result<()> {
        let root = self.require_root()?.clone();
        let root_leaf = self
            .retrieve_leaf_without_content(&root)?
            .ok_or(Error::MissingRoot)?;
        verify_identity_as(&root_leaf, IdentityRole::Root)?;
        if root_leaf.current_link_count() > 0
            && root_leaf.links().len() == root_leaf.current_link_count()
        {
            verify_children_against_classic_root(&root_leaf)?;
        }

        let mut visited = BTreeSet::from([root]);
        let mut stack = vec![root_leaf];
        while let Some(parent) = stack.pop() {
            for child_cid in parent.links() {
                if !visited.insert(child_cid.clone()) {
                    continue;
                }
                let child = self
                    .retrieve_leaf_without_content(child_cid)?
                    .ok_or_else(|| Error::MissingLeaf {
                        cid: child_cid.to_string(),
                    })?;
                verify_identity_as(&child, IdentityRole::NonRoot)?;
                if parent.current_link_count() > 0
                    && parent.links().len() == parent.current_link_count()
                {
                    verify_children_against_classic_root(&parent)?;
                }
                stack.push(child);
            }
        }
        Ok(())
    }

    fn verify_with_proofs_streaming(&self) -> Result<()> {
        let root = self.require_root()?.clone();
        let root_leaf = self
            .retrieve_leaf_without_content(&root)?
            .ok_or(Error::MissingRoot)?;
        verify_identity_as(&root_leaf, IdentityRole::Root)?;
        self.verify_root_children_streaming(&root_leaf)?;

        let hashes = self.collect_all_leaf_hashes_for_partial()?;
        // One child to parent index, resolved by lowest parent CID, so a shared
        // chunk walks the same path to the root on every run no matter what order
        // the hashes came back in.
        let mut links_by_parent: BTreeMap<Cid, Vec<Cid>> = BTreeMap::new();
        for cid in &hashes {
            if let Some(leaf) = self.retrieve_leaf_without_content(cid)? {
                links_by_parent.insert(cid.clone(), leaf.links().to_vec());
            }
        }
        let parent_of = minimum_parent_index(
            links_by_parent
                .iter()
                .map(|(parent, links)| (parent, links.as_slice())),
        );

        for cid in &hashes {
            if cid == &root {
                continue;
            }
            let Some(leaf) = self.retrieve_leaf_without_content(cid)? else {
                continue;
            };
            verify_identity_as(&leaf, IdentityRole::NonRoot)?;
            self.verify_path_to_root_streaming(&leaf, &parent_of)?;
        }
        Ok(())
    }

    fn verify_root_children_streaming(&self, root_leaf: &DagLeaf) -> Result<()> {
        if root_leaf.current_link_count() == 0 {
            return Ok(());
        }
        let mut present = 0_usize;
        for child in root_leaf.links() {
            if self.has_leaf(child)? {
                present += 1;
            }
        }
        let complete = root_leaf.links().len() == root_leaf.current_link_count();
        if present == root_leaf.current_link_count() && complete {
            return verify_children_against_classic_root(root_leaf);
        }
        if root_leaf.current_link_count() == 1 {
            if present > 0 && !root_leaf.links().is_empty() {
                let child = &root_leaf.links()[0];
                if root_leaf.classic_merkle_root() != child.as_str().as_bytes() {
                    return Err(Error::ClassicRootMismatch {
                        cid: root_leaf.cid().to_string(),
                    });
                }
            }
            return Ok(());
        }
        if root_leaf.proofs().is_empty() && present < root_leaf.current_link_count() {
            return Err(Error::IncompletePartialDag {
                cid: root_leaf.cid().to_string(),
                expected: root_leaf.current_link_count(),
                present,
            });
        }
        Ok(())
    }

    fn verify_path_to_root_streaming(
        &self,
        leaf: &DagLeaf,
        parent_of: &BTreeMap<Cid, Cid>,
    ) -> Result<()> {
        let root = self.require_root()?;
        let mut current = leaf.clone();
        let mut seen = BTreeSet::from([current.cid().clone()]);
        while current.cid() != root {
            let parent_cid =
                parent_of
                    .get(current.cid())
                    .ok_or_else(|| Error::BrokenPathToRoot {
                        cid: leaf.cid().to_string(),
                    })?;
            let parent = self
                .retrieve_leaf_without_content(parent_cid)?
                .ok_or_else(|| Error::BrokenPathToRoot {
                    cid: leaf.cid().to_string(),
                })?;
            if parent.cid() != root {
                verify_identity_as(&parent, IdentityRole::NonRoot)?;
            }
            self.verify_parent_link_streaming(&parent, current.cid())?;
            if !seen.insert(parent.cid().clone()) {
                return Err(Error::CycleDetected {
                    cid: parent.cid().to_string(),
                });
            }
            current = parent;
        }
        Ok(())
    }

    fn verify_parent_link_streaming(&self, parent: &DagLeaf, child: &Cid) -> Result<()> {
        // A parent that does not list the child cannot vouch for it, whatever
        // proofs it carries. Dag::verify_partial enforces the same thing.
        if !parent.links().contains(child) {
            return Err(Error::ParentMissingLink {
                parent: parent.cid().to_string(),
                child: child.to_string(),
            });
        }
        let complete = parent.links().len() == parent.current_link_count();
        if complete && parent.current_link_count() > 0 {
            let mut present = 0_usize;
            for link in parent.links() {
                if self.has_leaf(link)? {
                    present += 1;
                }
            }
            if present == parent.current_link_count() {
                return verify_children_against_classic_root(parent);
            }
            return self.verify_with_proof_streaming(parent, child);
        }
        if parent.current_link_count() > 1 {
            return self.verify_with_proof_streaming(parent, child);
        }
        Ok(())
    }

    fn verify_with_proof_streaming(&self, parent: &DagLeaf, child: &Cid) -> Result<()> {
        let branch = parent.proof_for(child).ok_or_else(|| Error::MissingProof {
            parent: parent.cid().to_string(),
            child: child.to_string(),
        })?;
        // The proof is filed under the child, so the branch must also name that
        // child: otherwise a valid proof for a sibling verifies here.
        if branch.child() != child {
            return Err(Error::ProofKeyMismatch {
                key: child.to_string(),
                child: branch.child().to_string(),
            });
        }
        verify_branch(parent, branch)
    }

    fn collect_all_leaf_hashes_for_partial(&self) -> Result<Vec<Cid>> {
        match self.leaf_store.all_leaf_hashes() {
            Some(mut hashes) => {
                hashes.sort_by(|left, right| left.as_str().cmp(right.as_str()));
                Ok(hashes)
            }
            None => self.collect_existing_leaf_hashes_from_root(),
        }
    }

    fn collect_existing_leaf_hashes_from_root(&self) -> Result<Vec<Cid>> {
        let root = self.require_root()?.clone();
        let mut visited = BTreeSet::new();
        let mut hashes = Vec::new();
        let mut stack = vec![root];
        while let Some(cid) = stack.pop() {
            if visited.contains(&cid) {
                continue;
            }
            if !self.leaf_store.has_leaf(&cid)? {
                continue;
            }
            visited.insert(cid.clone());
            hashes.push(cid.clone());
            if let Some(leaf) = self.retrieve_leaf_without_content(&cid)? {
                for child in leaf.links().iter().rev() {
                    if !visited.contains(child) {
                        stack.push(child.clone());
                    }
                }
            }
        }
        Ok(hashes)
    }

    // ---- content and recreation ----

    /// Assemble a file leaf's content, loading one chunk at a time.
    ///
    /// Chunks are ordered by their numeric `ItemName`, never by link position:
    /// link order is not part of the CID, so a DAG that arrived through batched
    /// transmission or a partial fetch can legitimately carry them in any order.
    pub fn get_content_from_leaf_streaming(&self, cid: &Cid) -> Result<Vec<u8>> {
        let leaf = self
            .retrieve_leaf_without_content(cid)?
            .ok_or_else(|| Error::MissingLeaf {
                cid: cid.to_string(),
            })?;
        if leaf.links().is_empty() {
            let full = self.retrieve_leaf(cid)?.ok_or_else(|| Error::MissingLeaf {
                cid: cid.to_string(),
            })?;
            verify_leaf_content_hash(&full)?;
            return Ok(full.content().unwrap_or_default().to_vec());
        }

        let mut chunks = Vec::with_capacity(leaf.links().len());
        for chunk_cid in leaf.links() {
            let chunk = self
                .retrieve_leaf(chunk_cid)?
                .ok_or_else(|| Error::MissingLeaf {
                    cid: chunk_cid.to_string(),
                })?;
            verify_leaf_content_hash(&chunk)?;
            chunks.push(chunk);
        }
        chunks.sort_by(|left, right| compare_chunk_item_names(left.item_name(), right.item_name()));

        let mut content = Vec::new();
        for chunk in &chunks {
            content.extend_from_slice(chunk.content().unwrap_or_default());
        }
        Ok(content)
    }

    /// Recreate the directory tree on disk, one leaf at a time.
    pub fn create_directory_streaming(&self, output_path: impl AsRef<Path>) -> Result<()> {
        let root = self.require_root()?.clone();
        let root_leaf = self
            .retrieve_leaf_without_content(&root)?
            .ok_or(Error::MissingRoot)?;
        self.create_directory_leaf_streaming(&root_leaf, output_path.as_ref())
    }

    fn create_directory_leaf_streaming(&self, leaf: &DagLeaf, path: &Path) -> Result<()> {
        match leaf.leaf_type() {
            LeafType::Directory => {
                fs::create_dir_all(path)
                    .map_err(|error| io_error("create directory", path, error))?;
                for child_cid in leaf.links() {
                    let child =
                        self.retrieve_leaf_without_content(child_cid)?
                            .ok_or_else(|| Error::MissingLeaf {
                                cid: child_cid.to_string(),
                            })?;
                    // safe_join rejects empty, dot, dot-dot, absolute and separator
                    // bearing names, so a hostile DAG cannot write outside the
                    // target directory.
                    let child_path = safe_join(path, child.item_name())?;
                    self.create_directory_leaf_streaming(&child, &child_path)?;
                }
                Ok(())
            }
            LeafType::File => {
                let content = self.get_content_from_leaf_streaming(leaf.cid())?;
                fs::write(path, content).map_err(|error| io_error("write file", path, error))
            }
            LeafType::Chunk => Ok(()),
        }
    }

    // ---- transmission into a store (PARITY_SPEC 5.4) ----

    /// Verify a single transmission packet and store its leaf.
    pub fn add_transmission_packet(&mut self, packet: &TransmissionPacket) -> Result<()> {
        let leaf = packet.leaf();
        let Some(parent_cid) = packet.parent_hash() else {
            verify_identity_as(leaf, IdentityRole::Root)?;
            if let Some(existing) = &self.root {
                if existing != leaf.cid() {
                    return Err(Error::ConflictingTransmissionRoot {
                        expected: existing.to_string(),
                        received: leaf.cid().to_string(),
                    });
                }
            }
            self.store_leaf(leaf.clone())?;
            self.root = Some(leaf.cid().clone());
            self.leaf_count = leaf.leaf_count();
            return Ok(());
        };

        verify_identity_as(leaf, IdentityRole::NonRoot)?;
        if let Some(parent) = self.retrieve_leaf_without_content(parent_cid)? {
            if !parent.links().contains(leaf.cid()) {
                return Err(Error::ParentMissingLink {
                    parent: parent.cid().to_string(),
                    child: leaf.cid().to_string(),
                });
            }
            if parent.current_link_count() > 1 {
                let branch =
                    packet
                        .proofs()
                        .get(leaf.cid())
                        .ok_or_else(|| Error::MissingProof {
                            parent: parent.cid().to_string(),
                            child: leaf.cid().to_string(),
                        })?;
                if branch.child() != leaf.cid() {
                    return Err(Error::ProofKeyMismatch {
                        key: leaf.cid().to_string(),
                        child: branch.child().to_string(),
                    });
                }
                verify_branch(&parent, branch)?;
            }
        }
        self.store_leaf(leaf.clone())
    }

    /// Verify a batched transmission packet and store its leaves.
    ///
    /// Nothing is written unless every leaf in the batch passes, so a rejected
    /// packet cannot leave the store half-updated.
    pub fn add_batched_transmission_packet(
        &mut self,
        packet: &BatchedTransmissionPacket,
    ) -> Result<()> {
        if packet.leaves().is_empty() {
            return Ok(());
        }
        let in_batch: BTreeMap<Cid, &DagLeaf> = packet
            .leaves()
            .iter()
            .map(|leaf| (leaf.cid().clone(), leaf))
            .collect();

        let mut new_root: Option<&DagLeaf> = None;
        for leaf in packet.leaves() {
            let parent_cid = packet.parent_for(leaf.cid()).ok_or_else(|| {
                Error::MissingTransmissionRelationship {
                    child: leaf.cid().to_string(),
                }
            })?;
            let Some(parent_cid) = parent_cid else {
                verify_identity_as(leaf, IdentityRole::Root)?;
                if let Some(existing) = &self.root {
                    if existing != leaf.cid() {
                        return Err(Error::ConflictingTransmissionRoot {
                            expected: existing.to_string(),
                            received: leaf.cid().to_string(),
                        });
                    }
                }
                new_root = Some(leaf);
                continue;
            };
            verify_identity_as(leaf, IdentityRole::NonRoot)?;

            // Resolve the declared parent from the batch first, then the store. A
            // parent that is nowhere to be found cannot have vouched for this
            // child, and accepting it anyway is how a foreign leaf gets attached to
            // an honest root.
            let parent = match in_batch.get(parent_cid) {
                Some(parent) => (*parent).clone(),
                None => self
                    .retrieve_leaf_without_content(parent_cid)?
                    .ok_or_else(|| Error::UnavailableTransmissionParent {
                        parent: parent_cid.to_string(),
                        child: leaf.cid().to_string(),
                    })?,
            };
            if !parent.links().contains(leaf.cid()) {
                return Err(Error::ParentMissingLink {
                    parent: parent.cid().to_string(),
                    child: leaf.cid().to_string(),
                });
            }
        }

        self.store_leaves_in_batches(packet.leaves().to_vec())?;
        if let Some(root) = new_root {
            self.root = Some(root.cid().clone());
            self.leaf_count = root.leaf_count();
        }
        Ok(())
    }

    /// Calculate labels by materializing the DAG, then adopt them.
    pub fn calculate_labels(&mut self) -> Result<()> {
        let mut dag = self.to_dag()?;
        dag.calculate_labels()?;
        self.labels = dag.labels().clone();
        Ok(())
    }
}

impl std::fmt::Debug for DagStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DagStore")
            .field("root", &self.root)
            .field("leaf_count", &self.leaf_count)
            .field("separate_content", &self.separate_content)
            .field("index_built", &self.index_built)
            .field("indexed_leaves", &self.index.as_ref().map(DagIndex::len))
            .finish()
    }
}

fn verify_children_against_classic_root(parent: &DagLeaf) -> Result<()> {
    match parent.current_link_count() {
        0 => Ok(()),
        1 => {
            if parent.links().is_empty()
                || parent.classic_merkle_root() == parent.links()[0].as_str().as_bytes()
            {
                Ok(())
            } else {
                Err(Error::ClassicRootMismatch {
                    cid: parent.cid().to_string(),
                })
            }
        }
        _ => verify_complete_classic_root(parent),
    }
}

// Streaming verification reads leaves without content, so whenever content is
// actually loaded its binding to the committed ContentHash has to be re-checked
// here; otherwise a store could hand back any bytes it liked for a leaf whose
// identity was verified from metadata alone.
fn verify_leaf_content_hash(leaf: &DagLeaf) -> Result<()> {
    let Some(content) = leaf.content() else {
        return Ok(());
    };
    let expected = leaf
        .content_hash()
        .ok_or_else(|| Error::MissingContentHash {
            cid: leaf.cid().to_string(),
        })?;
    if crate::encoding::sha256(content) != *expected {
        return Err(Error::ContentHashMismatch {
            cid: leaf.cid().to_string(),
        });
    }
    Ok(())
}
