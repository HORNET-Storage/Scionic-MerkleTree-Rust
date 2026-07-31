use crate::{Cid, Dag, DagLeaf, Error, Result};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiffType {
    Added,
    Removed,
}

impl DiffType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeafDiff {
    diff_type: DiffType,
    cid: Cid,
    leaf: DagLeaf,
}

impl LeafDiff {
    pub fn diff_type(&self) -> DiffType {
        self.diff_type
    }

    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    pub fn leaf(&self) -> &DagLeaf {
        &self.leaf
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DiffSummary {
    added: usize,
    removed: usize,
    total: usize,
}

impl DiffSummary {
    pub fn added(self) -> usize {
        self.added
    }

    pub fn removed(self) -> usize {
        self.removed
    }

    pub fn total(self) -> usize {
        self.total
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DagDiff {
    diffs: BTreeMap<Cid, LeafDiff>,
    summary: DiffSummary,
}

impl DagDiff {
    pub fn diffs(&self) -> &BTreeMap<Cid, LeafDiff> {
        &self.diffs
    }

    pub fn summary(&self) -> DiffSummary {
        self.summary
    }

    pub fn get_added_leaves(&self) -> BTreeMap<Cid, DagLeaf> {
        self.leaves_of_type(DiffType::Added)
    }

    pub fn get_removed_leaves(&self) -> BTreeMap<Cid, DagLeaf> {
        self.leaves_of_type(DiffType::Removed)
    }

    pub fn apply_to_dag(&self, old_dag: &Dag) -> Result<Dag> {
        let added = self.get_added_leaves();
        if added.is_empty() {
            return Ok(old_dag.clone());
        }

        let mut pool = old_dag.leaves().clone();
        pool.extend(added.clone());
        let children: BTreeSet<Cid> = pool
            .values()
            .flat_map(|leaf| leaf.links().iter().cloned())
            .collect();
        let candidates: Vec<Cid> = added
            .iter()
            .filter(|(cid, leaf)| leaf.is_root_shape() && !children.contains(*cid))
            .map(|(cid, _)| cid.clone())
            .collect();
        let root = match candidates.as_slice() {
            [] => return Err(Error::NoDiffRoot),
            [root] => root.clone(),
            _ => return Err(Error::AmbiguousDiffRoot),
        };

        let mut state = BTreeMap::new();
        let mut leaves = BTreeMap::new();
        collect_reachable(&root, &pool, &mut state, &mut leaves)?;
        let dag = Dag::from_parts(root, leaves)?;
        dag.verify()?;
        Ok(dag)
    }

    pub fn create_partial_dag(&self, full_new_dag: &Dag) -> Result<Dag> {
        let added: Vec<Cid> = self.get_added_leaves().into_keys().collect();
        if added.is_empty() {
            return Err(Error::NoAddedLeaves);
        }
        full_new_dag.get_partial(&added, false)
    }

    fn leaves_of_type(&self, diff_type: DiffType) -> BTreeMap<Cid, DagLeaf> {
        self.diffs
            .iter()
            .filter(|(_, record)| record.diff_type == diff_type)
            .map(|(cid, record)| (cid.clone(), record.leaf.clone()))
            .collect()
    }

    fn from_records(diffs: BTreeMap<Cid, LeafDiff>) -> Self {
        let added = diffs
            .values()
            .filter(|record| record.diff_type == DiffType::Added)
            .count();
        let removed = diffs.len() - added;
        Self {
            summary: DiffSummary {
                added,
                removed,
                total: diffs.len(),
            },
            diffs,
        }
    }
}

pub fn diff(old_dag: &Dag, new_dag: &Dag) -> Result<DagDiff> {
    let mut records = BTreeMap::new();
    for (cid, leaf) in new_dag.leaves() {
        if !old_dag.leaves().contains_key(cid) {
            records.insert(
                cid.clone(),
                LeafDiff {
                    diff_type: DiffType::Added,
                    cid: cid.clone(),
                    leaf: leaf.clone(),
                },
            );
        }
    }
    for (cid, leaf) in old_dag.leaves() {
        if !new_dag.leaves().contains_key(cid) {
            records.insert(
                cid.clone(),
                LeafDiff {
                    diff_type: DiffType::Removed,
                    cid: cid.clone(),
                    leaf: leaf.clone(),
                },
            );
        }
    }
    Ok(DagDiff::from_records(records))
}

pub fn diff_from_new_leaves(
    original_dag: &Dag,
    new_leaves: &BTreeMap<Cid, DagLeaf>,
) -> Result<DagDiff> {
    for (key, leaf) in new_leaves {
        if key != leaf.cid() {
            return Err(Error::CidKeyMismatch {
                key: key.to_string(),
                cid: leaf.cid().to_string(),
            });
        }
    }

    let root = new_leaves
        .iter()
        .filter(|(_, leaf)| leaf.is_root_shape())
        .max_by(|(left_cid, left), (right_cid, right)| {
            left.leaf_count()
                .cmp(&right.leaf_count())
                .then_with(|| right_cid.cmp(left_cid))
        })
        .map(|(cid, _)| cid.clone())
        .ok_or(Error::MissingNewRoot)?;

    let mut pool = original_dag.leaves().clone();
    pool.extend(new_leaves.clone());
    let mut state = BTreeMap::new();
    let mut reachable = BTreeMap::new();
    collect_reachable(&root, &pool, &mut state, &mut reachable)?;

    let mut records = BTreeMap::new();
    for (cid, leaf) in new_leaves {
        if !original_dag.leaves().contains_key(cid) {
            records.insert(
                cid.clone(),
                LeafDiff {
                    diff_type: DiffType::Added,
                    cid: cid.clone(),
                    leaf: leaf.clone(),
                },
            );
        }
    }
    for (cid, leaf) in original_dag.leaves() {
        if !reachable.contains_key(cid) {
            records.insert(
                cid.clone(),
                LeafDiff {
                    diff_type: DiffType::Removed,
                    cid: cid.clone(),
                    leaf: leaf.clone(),
                },
            );
        }
    }
    Ok(DagDiff::from_records(records))
}

fn collect_reachable(
    cid: &Cid,
    pool: &BTreeMap<Cid, DagLeaf>,
    state: &mut BTreeMap<Cid, u8>,
    output: &mut BTreeMap<Cid, DagLeaf>,
) -> Result<()> {
    match state.get(cid) {
        Some(1) => {
            return Err(Error::CycleDetected {
                cid: cid.to_string(),
            });
        }
        Some(2) => return Ok(()),
        _ => {}
    }
    let leaf = pool.get(cid).ok_or_else(|| Error::MissingPoolLeaf {
        cid: cid.to_string(),
    })?;
    state.insert(cid.clone(), 1);
    output.insert(cid.clone(), leaf.clone());
    for child in leaf.links() {
        collect_reachable(child, pool, state, output)?;
    }
    state.insert(cid.clone(), 2);
    Ok(())
}
