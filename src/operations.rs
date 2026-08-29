use crate::classic::{ClassicMerkleTree, Digest};
use crate::dag::{
    assemble_chunk_content, classic_tree_for_links, encode_root_identity, metadata_array,
    safe_join, Cid, ClassicTreeBranch, Dag, DagLeaf, Labels, LeafType,
};
use crate::{io_error, Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

impl Dag {
    pub fn is_partial(&self) -> bool {
        let Some(root) = self.try_root_leaf() else {
            return true;
        };
        u64::try_from(self.len()).map_or(true, |count| count < root.leaf_count())
    }

    pub fn verify(&self) -> Result<()> {
        if self.is_partial() {
            self.verify_partial()
        } else {
            self.verify_full()
        }
    }

    fn verify_full(&self) -> Result<()> {
        let root = self.try_root_leaf().ok_or(Error::MissingRoot)?;
        verify_root_sizes(self, root)?;
        root.verify_identity()?;

        let mut visited = BTreeSet::new();
        let mut stack = vec![self.root().clone()];
        while let Some(cid) = stack.pop() {
            let leaf = self.get(&cid).ok_or_else(|| Error::MissingLeaf {
                cid: cid.to_string(),
            })?;
            if !visited.insert(cid.clone()) {
                continue;
            }
            if &cid != self.root() {
                leaf.verify_identity()?;
            }
            verify_complete_classic_root(leaf)?;
            for child in leaf.links().iter().rev() {
                stack.push(child.clone());
            }
        }

        if visited.len() != self.len() {
            return Err(Error::UnreachableLeaves {
                count: self.len() - visited.len(),
            });
        }
        Ok(())
    }

    fn verify_partial(&self) -> Result<()> {
        let root = self.try_root_leaf().ok_or(Error::MissingRoot)?;
        root.verify_identity()?;

        for leaf in self.leaves().values() {
            if leaf.links().len() > leaf.current_link_count() {
                return Err(Error::LinkCountMismatch {
                    cid: leaf.cid().to_string(),
                    expected: leaf.current_link_count(),
                    actual: leaf.links().len(),
                });
            }
            if leaf.cid() != self.root() {
                leaf.verify_identity()?;
            }
            // A retained leaf whose link list is still complete commits to those
            // exact link values through its classic Merkle root, so recompute it.
            // Leaf identity covers ClassicMerkleRoot and CurrentLinkCount but not
            // the link CIDs themselves, and the parent loop below skips the root,
            // so without this an unpruned root-only partial accepts any
            // same-length list of syntactically valid CIDs. Genuinely pruned link
            // lists are shorter than the declared count and stay proof-verified.
            if leaf.links().len() == leaf.current_link_count() {
                verify_complete_classic_root(leaf)?;
            }
            for (key, branch) in leaf.proofs() {
                if key != branch.child() {
                    return Err(Error::ProofKeyMismatch {
                        key: key.to_string(),
                        child: branch.child().to_string(),
                    });
                }
            }
        }

        let parent_of = self.build_parent_index();
        for leaf in self.leaves().values() {
            if leaf.cid() == self.root() {
                continue;
            }
            let mut current = leaf.cid().clone();
            let mut path = BTreeSet::new();
            while &current != self.root() {
                if !path.insert(current.clone()) {
                    return Err(Error::CycleDetected {
                        cid: current.to_string(),
                    });
                }
                let parent_cid =
                    parent_of
                        .get(&current)
                        .ok_or_else(|| Error::BrokenPathToRoot {
                            cid: leaf.cid().to_string(),
                        })?;
                let parent = self.get(parent_cid).ok_or_else(|| Error::MissingLeaf {
                    cid: parent_cid.to_string(),
                })?;
                verify_partial_parent(self, parent, &current)?;
                current = parent_cid.clone();
            }
        }
        Ok(())
    }

    pub fn get_content_from_leaf(&self, leaf: &DagLeaf) -> Result<Vec<u8>> {
        if leaf.links().is_empty() {
            return Ok(leaf.content().unwrap_or_default().to_vec());
        }
        assemble_chunk_content(self, leaf, u64::MAX)
    }

    pub fn create_directory(&self, output_path: impl AsRef<Path>) -> Result<()> {
        let root = self.try_root_leaf().ok_or(Error::MissingRoot)?;
        create_directory_leaf(self, root, output_path.as_ref())
    }

    pub fn calculate_labels(&mut self) -> Result<()> {
        let mut labels = Labels::new();
        let mut next = 1_usize;
        self.visit_unique(|leaf, _| {
            if leaf.cid() != self.root() {
                labels.insert(next.to_string(), leaf.cid().clone());
                next = next
                    .checked_add(1)
                    .ok_or(Error::SizeOverflow { field: "label" })?;
            }
            Ok(())
        })?;
        self.labels = labels;
        Ok(())
    }

    pub fn clear_labels(&mut self) {
        self.labels.clear();
    }

    pub fn labels(&self) -> &Labels {
        &self.labels
    }

    pub fn get_label(&self, cid: &Cid) -> Result<String> {
        if cid == self.root() {
            return Ok("0".to_owned());
        }
        if self.labels.is_empty() {
            return Err(Error::LabelsNotCalculated);
        }
        self.labels
            .iter()
            .find_map(|(label, candidate)| (candidate == cid).then(|| label.clone()))
            .ok_or_else(|| Error::LabelNotFound {
                label: cid.to_string(),
            })
    }

    pub fn get_hashes_by_label_range(&self, start: usize, end: usize) -> Result<Vec<Cid>> {
        if self.labels.is_empty() {
            return Err(Error::LabelsNotCalculated);
        }
        if start < 1 || end < start || end > self.labels.len() {
            return Err(Error::InvalidLabelRange { start, end });
        }
        (start..=end)
            .map(|index| {
                let label = index.to_string();
                self.labels
                    .get(&label)
                    .cloned()
                    .ok_or(Error::LabelNotFound { label })
            })
            .collect()
    }

    pub fn get_partial(&self, requested: &[Cid], prune_links: bool) -> Result<Self> {
        if requested.is_empty() {
            return Err(Error::EmptyPartialRequest);
        }

        let parent_of = self.build_parent_index();
        let mut retained = BTreeSet::from([self.root().clone()]);
        for cid in requested {
            if !self.leaves().contains_key(cid) {
                return Err(Error::MissingRequestedLeaf {
                    cid: cid.to_string(),
                });
            }
            let mut current = cid.clone();
            let mut path = BTreeSet::new();
            loop {
                retained.insert(current.clone());
                if &current == self.root() {
                    break;
                }
                if !path.insert(current.clone()) {
                    return Err(Error::CycleDetected {
                        cid: current.to_string(),
                    });
                }
                current =
                    parent_of
                        .get(&current)
                        .cloned()
                        .ok_or_else(|| Error::BrokenPathToRoot {
                            cid: cid.to_string(),
                        })?;
            }
        }

        let mut leaves = BTreeMap::new();
        for cid in &retained {
            let leaf = self.get(cid).ok_or_else(|| Error::MissingLeaf {
                cid: cid.to_string(),
            })?;
            leaves.insert(cid.clone(), leaf.clone());
        }

        for parent_cid in &retained {
            let source = self.get(parent_cid).ok_or_else(|| Error::MissingLeaf {
                cid: parent_cid.to_string(),
            })?;
            for child in source.links() {
                if !retained.contains(child) || source.current_link_count() <= 1 {
                    continue;
                }
                let proof = if let Some(branch) = source.proof_for(child) {
                    if branch.child() != child {
                        return Err(Error::ProofKeyMismatch {
                            key: child.to_string(),
                            child: branch.child().to_string(),
                        });
                    }
                    branch.proof().clone()
                } else if source.links().len() == source.current_link_count() {
                    source.proof_for_child(child)?
                } else {
                    return Err(Error::IncompleteProofSource {
                        parent: parent_cid.to_string(),
                        child: child.to_string(),
                    });
                };
                leaves
                    .get_mut(parent_cid)
                    .expect("retained parent was cloned")
                    .insert_bound_proof(
                        child.clone(),
                        ClassicTreeBranch::new(child.clone(), proof),
                    )?;
            }
        }

        if prune_links {
            for leaf in leaves.values_mut() {
                leaf.retain_links(&retained);
            }
        }
        Self::from_parts(self.root().clone(), leaves)
    }
}

fn verify_root_sizes(dag: &Dag, root: &DagLeaf) -> Result<()> {
    let content_complete = dag
        .leaves()
        .values()
        .all(|leaf| leaf.content_hash().is_none() || leaf.content().is_some());
    if !content_complete || !root_sizes_checkable(dag, root) {
        return Ok(());
    }

    let mut content_size = 0_u64;
    let mut non_root_storage_size = 0_u64;
    for leaf in dag.leaves().values() {
        if let Some(content) = leaf.content() {
            content_size = checked_add(
                content_size,
                u64::try_from(content.len()).map_err(|_| Error::SizeOverflow {
                    field: "ContentSize",
                })?,
                "ContentSize",
            )?;
        }
        if leaf.cid() != dag.root() {
            non_root_storage_size =
                checked_add(non_root_storage_size, leaf.storage_size()?, "DagSize")?;
        }
    }
    verify_root_sizes_against(root, content_size, non_root_storage_size)
}

/// Whether a root's `ContentSize`/`DagSize` can be held to a DAG at all: the
/// leaf count must match, the root must actually carry totals, and every
/// leaf's links must be complete. Content completeness is the caller's
/// question — a retained DAG answers it from its payloads, a streamed one
/// from what passed its sink.
fn root_sizes_checkable(dag: &Dag, root: &DagLeaf) -> bool {
    let count_matches = u64::try_from(dag.len()).ok() == Some(root.leaf_count());
    let totals_available =
        root.content_size() != 0 || root.dag_size() != 0 || root.leaf_count() == 1;
    let links_complete = dag
        .leaves()
        .values()
        .all(|leaf| leaf.links().len() >= leaf.current_link_count());
    count_matches && totals_available && links_complete
}

/// Compare the root's signed totals with sizes summed elsewhere. `DagSize` is
/// the non-root storage projections plus the root's own identity encoded with
/// `DagSize` zeroed, exactly as the builder computed it.
fn verify_root_sizes_against(
    root: &DagLeaf,
    content_size: u64,
    non_root_storage_size: u64,
) -> Result<()> {
    let root_without_size = encode_root_identity(
        root.item_name(),
        root.leaf_type(),
        root.classic_merkle_root(),
        u64::try_from(root.current_link_count()).map_err(|_| Error::SizeOverflow {
            field: "CurrentLinkCount",
        })?,
        root.leaf_count(),
        root.content_size(),
        0,
        root.content_hash(),
        metadata_array(Some(root.additional_data())),
    );
    let dag_size = checked_add(
        non_root_storage_size,
        u64::try_from(root_without_size.len())
            .map_err(|_| Error::SizeOverflow { field: "DagSize" })?,
        "DagSize",
    )?;

    if root.content_size() != content_size {
        return Err(Error::ContentSizeMismatch {
            stored: root.content_size(),
            calculated: content_size,
        });
    }
    if root.dag_size() != dag_size {
        return Err(Error::DagSizeMismatch {
            stored: root.dag_size(),
            calculated: dag_size,
        });
    }
    Ok(())
}

/// The size totals `verify_root_sizes` sums from retained payloads, summed
/// instead while payloads stream past a receiver that keeps none of them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct StreamedSizeTotals {
    /// Every streamed payload's length, the root's included.
    content_size: u64,
    /// Every non-root leaf's storage projection, measured while its payload
    /// was still attached — the figure `verify_root_sizes` reads from a
    /// retained leaf.
    non_root_storage_size: u64,
    /// A leaf that declares a content hash arrived without its payload, so
    /// the totals are incomplete and cannot be held against the root.
    missing_content: bool,
}

impl StreamedSizeTotals {
    /// Account one leaf exactly as `verify_root_sizes` would with its payload
    /// still attached: payload length into `ContentSize`, and for a non-root
    /// leaf the storage projection into `DagSize`.
    pub(crate) fn record(&mut self, leaf: &DagLeaf, is_root: bool) -> Result<()> {
        match leaf.content() {
            Some(content) => {
                self.content_size = checked_add(
                    self.content_size,
                    u64::try_from(content.len()).map_err(|_| Error::SizeOverflow {
                        field: "ContentSize",
                    })?,
                    "ContentSize",
                )?;
            }
            None if leaf.content_hash().is_some() => self.missing_content = true,
            None => {}
        }
        if !is_root {
            self.non_root_storage_size =
                checked_add(self.non_root_storage_size, leaf.storage_size()?, "DagSize")?;
        }
        Ok(())
    }

    /// Hold the root of a finished, content-free skeleton to these totals,
    /// under the same gate `verify_root_sizes` applies to a retained DAG.
    pub(crate) fn verify(&self, dag: &Dag) -> Result<()> {
        let root = dag.try_root_leaf().ok_or(Error::MissingRoot)?;
        if self.missing_content || !root_sizes_checkable(dag, root) {
            return Ok(());
        }
        verify_root_sizes_against(root, self.content_size, self.non_root_storage_size)
    }
}

fn verify_complete_classic_root(leaf: &DagLeaf) -> Result<()> {
    if leaf.links().len() != leaf.current_link_count() {
        return Err(Error::LinkCountMismatch {
            cid: leaf.cid().to_string(),
            expected: leaf.current_link_count(),
            actual: leaf.links().len(),
        });
    }
    let (calculated, _) = classic_tree_for_links(leaf.links())?;
    if calculated.as_slice() != leaf.classic_merkle_root() {
        return Err(Error::ClassicRootMismatch {
            cid: leaf.cid().to_string(),
        });
    }
    Ok(())
}

fn verify_partial_parent(dag: &Dag, parent: &DagLeaf, child: &Cid) -> Result<()> {
    if !parent.links().contains(child) {
        return Err(Error::ParentMissingLink {
            parent: parent.cid().to_string(),
            child: child.to_string(),
        });
    }
    match parent.current_link_count() {
        0 => Err(Error::ParentMissingLink {
            parent: parent.cid().to_string(),
            child: child.to_string(),
        }),
        1 => {
            if parent.classic_merkle_root() == child.as_str().as_bytes() {
                Ok(())
            } else {
                Err(Error::ClassicRootMismatch {
                    cid: parent.cid().to_string(),
                })
            }
        }
        _ => {
            let all_children_present = parent.links().len() == parent.current_link_count()
                && parent.links().iter().all(|cid| dag.get(cid).is_some());
            if all_children_present {
                return verify_complete_classic_root(parent);
            }
            let branch = parent.proof_for(child).ok_or_else(|| Error::MissingProof {
                parent: parent.cid().to_string(),
                child: child.to_string(),
            })?;
            if branch.child() != child {
                return Err(Error::ProofKeyMismatch {
                    key: child.to_string(),
                    child: branch.child().to_string(),
                });
            }
            let root: &Digest = parent.classic_merkle_root().try_into().map_err(|_| {
                Error::ClassicRootMismatch {
                    cid: parent.cid().to_string(),
                }
            })?;
            ClassicMerkleTree::verify_against(child.as_str().as_bytes(), branch.proof(), root)
        }
    }
}

fn create_directory_leaf(dag: &Dag, leaf: &DagLeaf, path: &Path) -> Result<()> {
    match leaf.leaf_type() {
        LeafType::Directory => {
            fs::create_dir_all(path).map_err(|error| io_error("create directory", path, error))?;
            for link in leaf.links() {
                let child = dag.get(link).ok_or_else(|| Error::MissingLeaf {
                    cid: link.to_string(),
                })?;
                let child_path = safe_join(path, child.item_name())?;
                create_directory_leaf(dag, child, &child_path)?;
            }
            Ok(())
        }
        LeafType::File => {
            let content = dag.get_content_from_leaf(leaf)?;
            fs::write(path, content).map_err(|error| io_error("write file", path, error))
        }
        LeafType::Chunk => Ok(()),
    }
}

fn checked_add(left: u64, right: u64, field: &'static str) -> Result<u64> {
    left.checked_add(right).ok_or(Error::SizeOverflow { field })
}
