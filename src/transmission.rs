use crate::classic::{ClassicMerkleTree, Digest};
use crate::dag::{
    classic_tree_for_links, encode_non_root_identity, encode_root_identity, metadata_array, Cid,
    ClassicTreeBranch, Dag, DagLeaf,
};
use crate::encoding::{
    cbor_decode_shared, cbor_encode, sha256, sorted_wire_map, CborValue, KeyOrder,
};
use crate::serialization::{
    cbor_get, cbor_map, cbor_optional_text, cbor_optional_unsigned, cbor_required_text,
    decode_leaf, decode_proofs, json_get, json_leaf_to_cbor, json_object, json_proof_to_cbor,
    json_required_string, json_string, leaf_wire_value, parse_json, proof_wire_value, write_json,
    JsonValue, WireKey,
};
use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::num::NonZeroUsize;

pub const DEFAULT_BATCH_TARGET: usize = 4 * 1024 * 1024;

static PACKET_LEAF: WireKey =
    WireKey::new("TransmissionPacket.Leaf", "Leaf", &["Leaf", "leaf"]);
static PACKET_PARENT_HASH: WireKey = WireKey::new(
    "TransmissionPacket.ParentHash",
    "ParentHash",
    &["ParentHash", "parentHash"],
);
static PACKET_PROOFS: WireKey =
    WireKey::new("TransmissionPacket.proofs", "proofs", &["proofs"]);
static BATCH_LEAVES: WireKey = WireKey::new(
    "BatchedTransmissionPacket.Leaves",
    "Leaves",
    &["Leaves", "leaves"],
);
static BATCH_RELATIONSHIPS: WireKey = WireKey::new(
    "BatchedTransmissionPacket.Relationships",
    "Relationships",
    &["Relationships", "relationships"],
);
static BATCH_PACKET_INDEX: WireKey = WireKey::new(
    "BatchedTransmissionPacket.PacketIndex",
    "PacketIndex",
    &["PacketIndex", "packetIndex"],
);
static BATCH_TOTAL_PACKETS: WireKey = WireKey::new(
    "BatchedTransmissionPacket.TotalPackets",
    "TotalPackets",
    &["TotalPackets", "totalPackets"],
);
static PACKET_LEAF_HASH: WireKey =
    WireKey::new("DagLeaf.Hash", "Hash", &["Hash", "hash"]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransmissionPacket {
    leaf: DagLeaf,
    parent_hash: Option<Cid>,
    proofs: BTreeMap<Cid, ClassicTreeBranch>,
}

impl TransmissionPacket {
    pub fn leaf(&self) -> &DagLeaf {
        &self.leaf
    }

    pub fn parent_hash(&self) -> Option<&Cid> {
        self.parent_hash.as_ref()
    }

    pub fn is_root(&self) -> bool {
        self.parent_hash.is_none()
    }

    pub fn proofs(&self) -> &BTreeMap<Cid, ClassicTreeBranch> {
        &self.proofs
    }

    pub fn proof_for(&self, child: &Cid) -> Option<&ClassicTreeBranch> {
        self.proofs.get(child)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        encode_json(&transmission_packet_wire_value(self, KeyOrder::Json))
    }

    pub fn from_json(input: &[u8]) -> Result<Self> {
        let value = parse_json(input)?;
        let wire = json_transmission_packet_to_cbor(&value)?;
        transmission_packet_from_wire_value(&wire)
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        Ok(cbor_encode(&transmission_packet_wire_value(
            self,
            KeyOrder::Cbor,
        )))
    }

    pub fn from_cbor(input: &[u8]) -> Result<Self> {
        let value = cbor_decode_shared(input)?;
        transmission_packet_from_wire_value(&value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Batching {
    ApproximateBytes(NonZeroUsize),
    Disabled,
}

impl Default for Batching {
    fn default() -> Self {
        Self::ApproximateBytes(
            NonZeroUsize::new(DEFAULT_BATCH_TARGET).expect("default batch target is nonzero"),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchedTransmissionPacket {
    leaves: Vec<DagLeaf>,
    relationships: BTreeMap<Cid, Option<Cid>>,
    packet_index: u64,
    total_packets: u64,
}

impl BatchedTransmissionPacket {
    pub fn leaves(&self) -> &[DagLeaf] {
        &self.leaves
    }

    pub fn relationships(&self) -> &BTreeMap<Cid, Option<Cid>> {
        &self.relationships
    }

    pub fn parent_for(&self, child: &Cid) -> Option<Option<&Cid>> {
        self.relationships
            .get(child)
            .map(|parent| parent.as_ref())
    }

    pub fn packet_index(&self) -> u64 {
        self.packet_index
    }

    pub fn total_packets(&self) -> u64 {
        self.total_packets
    }

    pub fn root_leaf(&self) -> Option<&DagLeaf> {
        self.leaves
            .iter()
            .find(|leaf| self.relationships.get(leaf.cid()) == Some(&None))
            .or_else(|| self.leaves.first())
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        encode_json(&batched_packet_wire_value(self, KeyOrder::Json))
    }

    pub fn from_json(input: &[u8]) -> Result<Self> {
        let value = parse_json(input)?;
        let wire = json_batched_packet_to_cbor(&value)?;
        batched_packet_from_wire_value(&wire)
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        Ok(cbor_encode(&batched_packet_wire_value(self, KeyOrder::Cbor)))
    }

    pub fn from_cbor(input: &[u8]) -> Result<Self> {
        let value = cbor_decode_shared(input)?;
        batched_packet_from_wire_value(&value)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TransmissionReceiver {
    root: Option<Cid>,
    leaves: BTreeMap<Cid, DagLeaf>,
}

impl TransmissionReceiver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_root(root: Cid) -> Self {
        Self {
            root: Some(root),
            leaves: BTreeMap::new(),
        }
    }

    pub fn root(&self) -> Option<&Cid> {
        self.root.as_ref()
    }

    pub fn leaves(&self) -> &BTreeMap<Cid, DagLeaf> {
        &self.leaves
    }

    pub fn verify_transmission_packet(&self, packet: &TransmissionPacket) -> Result<()> {
        verify_root_marker(self.root.as_ref(), None, packet.leaf.cid(), packet.is_root())?;
        verify_transmission_packet_against(&self.leaves, packet)
    }

    pub fn apply_transmission_packet(&mut self, packet: TransmissionPacket) {
        if packet.is_root() && self.root.is_none() {
            self.root = Some(packet.leaf.cid().clone());
        }
        apply_transmission_packet_to(&mut self.leaves, packet);
    }

    pub fn apply_and_verify_transmission_packet(
        &mut self,
        packet: TransmissionPacket,
    ) -> Result<()> {
        self.verify_transmission_packet(&packet)?;
        self.apply_transmission_packet(packet);
        Ok(())
    }

    pub fn into_dag(self) -> Result<Dag> {
        let root = self.root.ok_or(Error::MissingRoot)?;
        Dag::from_parts(root, self.leaves)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BatchedDagReceiver {
    root: Option<Cid>,
    expected_root: Option<Cid>,
    leaves: BTreeMap<Cid, DagLeaf>,
}

impl BatchedDagReceiver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_expected_root(root: Cid) -> Self {
        Self {
            root: None,
            expected_root: Some(root),
            leaves: BTreeMap::new(),
        }
    }

    pub fn root(&self) -> Option<&Cid> {
        self.root.as_ref().or(self.expected_root.as_ref())
    }

    pub fn leaves(&self) -> &BTreeMap<Cid, DagLeaf> {
        &self.leaves
    }

    pub fn verify_packet(&self, packet: &BatchedTransmissionPacket) -> Result<()> {
        verify_batched_root_markers(self.root.as_ref(), self.expected_root.as_ref(), packet)?;
        verify_batched_packet_against(&self.leaves, packet)
    }

    pub fn apply_packet(&mut self, packet: &BatchedTransmissionPacket) {
        for leaf in &packet.leaves {
            if packet.relationships.get(leaf.cid()) == Some(&None) && self.root.is_none() {
                self.root = Some(leaf.cid().clone());
            }
        }
        apply_batched_packet_to(&mut self.leaves, packet);
    }

    pub fn apply_and_verify(&mut self, packet: &BatchedTransmissionPacket) -> Result<()> {
        self.verify_packet(packet)?;
        self.apply_packet(packet);
        Ok(())
    }

    pub fn finish_verified(self) -> Result<Dag> {
        let root = match (self.root, self.expected_root) {
            (Some(found), Some(expected)) if found != expected => {
                return Err(Error::ConflictingTransmissionRoot {
                    expected: expected.to_string(),
                    received: found.to_string(),
                });
            }
            (Some(found), _) => found,
            (None, Some(expected)) => expected,
            (None, None) => return Err(Error::MissingRoot),
        };
        let dag = Dag::from_parts(root, self.leaves)?;
        dag.verify()?;
        Ok(dag)
    }
}

impl Dag {
    pub fn get_leaf_sequence(&self) -> Result<Vec<TransmissionPacket>> {
        let Some(root_leaf) = self.try_root_leaf() else {
            return Ok(Vec::new());
        };
        let partial = self.is_partial();
        let mut sequence = vec![TransmissionPacket {
            leaf: root_leaf.clone(),
            parent_hash: None,
            proofs: BTreeMap::new(),
        }];
        let mut visited = BTreeSet::from([self.root().clone()]);
        let mut queue = VecDeque::from([self.root().clone()]);

        while let Some(parent_cid) = queue.pop_front() {
            let parent = self
                .get(&parent_cid)
                .ok_or_else(|| Error::MissingLeaf {
                    cid: parent_cid.to_string(),
                })?;
            let mut children = parent.links().to_vec();
            children.sort_by(|left, right| left.as_str().cmp(right.as_str()));
            for child_cid in children {
                if visited.contains(&child_cid) {
                    continue;
                }
                let Some(child) = self.get(&child_cid) else {
                    continue;
                };
                let mut proofs = BTreeMap::new();
                let branch = if partial {
                    parent.proof_for(&child_cid).cloned()
                } else {
                    transmission_proof_for_child(parent, &child_cid)?
                };
                if let Some(branch) = branch {
                    proofs.insert(child_cid.clone(), branch);
                }
                sequence.push(TransmissionPacket {
                    leaf: child.clone(),
                    parent_hash: Some(parent_cid.clone()),
                    proofs,
                });
                visited.insert(child_cid.clone());
                queue.push_back(child_cid);
            }
        }
        Ok(sequence)
    }

    pub fn verify_transmission_packet(&self, packet: &TransmissionPacket) -> Result<()> {
        verify_transmission_packet_against(&self.leaves, packet)
    }

    pub fn apply_transmission_packet(&mut self, packet: TransmissionPacket) {
        apply_transmission_packet_to(&mut self.leaves, packet);
    }

    pub fn apply_and_verify_transmission_packet(
        &mut self,
        packet: TransmissionPacket,
    ) -> Result<()> {
        self.verify_transmission_packet(&packet)?;
        self.apply_transmission_packet(packet);
        Ok(())
    }

    pub fn remove_all_content(&mut self) {
        for leaf in self.leaves.values_mut() {
            leaf.content = None;
        }
    }

    pub fn batched_leaf_sequence(&self) -> Result<Vec<BatchedTransmissionPacket>> {
        self.batched_leaf_sequence_with(Batching::default())
    }

    pub fn batched_leaf_sequence_with(
        &self,
        batching: Batching,
    ) -> Result<Vec<BatchedTransmissionPacket>> {
        if batching == Batching::Disabled {
            let packets = self.get_leaf_sequence()?;
            let total_packets = u64::try_from(packets.len()).map_err(|_| Error::SizeOverflow {
                field: "TotalPackets",
            })?;
            return packets
                .into_iter()
                .enumerate()
                .map(|(index, packet)| {
                    let child = packet.leaf.cid().clone();
                    Ok(BatchedTransmissionPacket {
                        leaves: vec![packet.leaf],
                        relationships: BTreeMap::from([(child, packet.parent_hash)]),
                        packet_index: u64::try_from(index).map_err(|_| Error::SizeOverflow {
                            field: "PacketIndex",
                        })?,
                        total_packets,
                    })
                })
                .collect();
        }

        let Batching::ApproximateBytes(target) = batching else {
            unreachable!("disabled batching returned above");
        };
        let Some(root_leaf) = self.try_root_leaf() else {
            return Ok(Vec::new());
        };
        let mut batches = Vec::new();
        let mut current = BatchedTransmissionPacket {
            leaves: vec![root_leaf.clone()],
            relationships: BTreeMap::from([(self.root().clone(), None)]),
            packet_index: 0,
            total_packets: 0,
        };
        let mut current_size = estimate_leaf_size(root_leaf)?;
        let mut parents_in_batch = BTreeSet::from([self.root().clone()]);
        // `visited` is only ever probed and inserted into, never iterated, so it
        // does not owe anyone an order -- and hashing a CID once beats the seven
        // 59-byte string comparisons an ordered set pays per lookup.
        let mut visited = HashSet::from([self.root().clone()]);
        let mut queue = VecDeque::from([self.root().clone()]);
        // A parent's proof set is derived only from its own sorted links, so a
        // parent that straddles several batches rebuilds the identical classic
        // tree and regenerates the identical proofs every time. Memoize it: the
        // root alone carries dozens of links and spans most of the run.
        let mut proof_cache: HashMap<Cid, BTreeMap<Cid, ClassicTreeBranch>> = HashMap::new();

        while let Some(parent_cid) = queue.pop_front() {
            let parent = self
                .get(&parent_cid)
                .ok_or_else(|| Error::MissingLeaf {
                    cid: parent_cid.to_string(),
                })?;
            let mut children = parent.links().to_vec();
            children.sort_by(|left, right| left.as_str().cmp(right.as_str()));
            for child_cid in children {
                if visited.contains(&child_cid) {
                    continue;
                }
                let Some(child) = self.get(&child_cid) else {
                    continue;
                };
                let child_size = estimate_leaf_size(child)?;
                if current_size
                    .checked_add(child_size)
                    .ok_or(Error::SizeOverflow {
                        field: "batch estimate",
                    })?
                    > target.get()
                    && !current.leaves.is_empty()
                {
                    self.finalize_batch(&mut current, &parents_in_batch, &mut proof_cache)?;
                    batches.push(current);
                    current = BatchedTransmissionPacket {
                        leaves: Vec::new(),
                        relationships: BTreeMap::new(),
                        packet_index: 0,
                        total_packets: 0,
                    };
                    current_size = 0;
                    parents_in_batch.clear();
                }
                current.leaves.push(child.clone());
                current
                    .relationships
                    .insert(child_cid.clone(), Some(parent_cid.clone()));
                current_size = current_size
                    .checked_add(child_size)
                    .ok_or(Error::SizeOverflow {
                        field: "batch estimate",
                    })?;
                visited.insert(child_cid.clone());
                // Only leaves that can actually carry proofs belong in the parent
                // set. A content chunk with one link or none would reach
                // finalize_batch just to hit the `current_link_count() <= 1`
                // guard, after paying for a set insert, a scan and a DAG lookup.
                // On a chunk-heavy DAG this is the difference between revisiting
                // every leaf and revisiting only the interior nodes.
                if child.current_link_count() > 1 {
                    parents_in_batch.insert(child_cid.clone());
                }
                queue.push_back(child_cid);
            }
        }

        if !current.leaves.is_empty() {
            self.finalize_batch(&mut current, &parents_in_batch, &mut proof_cache)?;
            batches.push(current);
        }
        let total_packets = u64::try_from(batches.len()).map_err(|_| Error::SizeOverflow {
            field: "TotalPackets",
        })?;
        for (index, batch) in batches.iter_mut().enumerate() {
            batch.packet_index = u64::try_from(index).map_err(|_| Error::SizeOverflow {
                field: "PacketIndex",
            })?;
            batch.total_packets = total_packets;
        }
        Ok(batches)
    }

    pub fn verify_batched_transmission_packet(
        &self,
        packet: &BatchedTransmissionPacket,
    ) -> Result<()> {
        verify_batched_packet_against(&self.leaves, packet)
    }

    pub fn apply_batched_transmission_packet(&mut self, packet: &BatchedTransmissionPacket) {
        apply_batched_packet_to(&mut self.leaves, packet);
    }

    pub fn apply_and_verify_batched_transmission_packet(
        &mut self,
        packet: &BatchedTransmissionPacket,
    ) -> Result<()> {
        self.verify_batched_transmission_packet(packet)?;
        self.apply_batched_transmission_packet(packet);
        Ok(())
    }

    fn finalize_batch(
        &self,
        batch: &mut BatchedTransmissionPacket,
        parents_in_batch: &BTreeSet<Cid>,
        proof_cache: &mut HashMap<Cid, BTreeMap<Cid, ClassicTreeBranch>>,
    ) -> Result<()> {
        // Only the parents this batch will actually inspect need a child count.
        // Counting every relationship clones a CID and touches the map once per
        // leaf in the batch, and on a chunk-heavy DAG all but a handful of those
        // entries are then never read back.
        let mut children_in_batch = BTreeMap::<Cid, usize>::new();
        for parent in batch.relationships.values().flatten() {
            if !parents_in_batch.contains(parent) {
                continue;
            }
            let count = children_in_batch.entry(parent.clone()).or_default();
            *count = count.checked_add(1).ok_or(Error::SizeOverflow {
                field: "batch relationship count",
            })?;
        }
        let partial = self.is_partial();
        for parent_cid in parents_in_batch {
            // The caller only admits multi-link leaves into `parents_in_batch`,
            // so this scan runs once per interior node in the batch rather than
            // once per leaf in it.
            let Some(index) = batch
                .leaves
                .iter()
                .position(|leaf| leaf.cid() == parent_cid)
            else {
                continue;
            };
            let Some(original) = self.get(parent_cid) else {
                continue;
            };
            // The root enters the set unconditionally, so a single-link root
            // still has to be turned away here.
            if original.current_link_count() <= 1 {
                continue;
            }
            if children_in_batch.get(parent_cid).copied().unwrap_or(0)
                == original.current_link_count()
            {
                batch.leaves[index].proofs.clear();
            } else if partial {
                batch.leaves[index].proofs = original.proofs.clone();
            } else {
                // A parent's proof set is derived only from its own sorted
                // links, so a parent that straddles several batches would
                // otherwise rebuild the identical tree once per batch.
                if !proof_cache.contains_key(parent_cid) {
                    let mut links = original.links().to_vec();
                    links.sort_by(|left, right| left.as_str().cmp(right.as_str()));
                    let (_, tree) = classic_tree_for_links(&links)?;
                    let tree = tree.ok_or(Error::Invariant {
                        detail: "multi-link leaf has no classic tree",
                    })?;
                    let mut proofs = BTreeMap::new();
                    for child in links {
                        let proof = tree.proof_for_key(child.as_str())?.clone();
                        proofs.insert(
                            child.clone(),
                            ClassicTreeBranch::new(child, proof),
                        );
                    }
                    proof_cache.insert(parent_cid.clone(), proofs);
                }
                batch.leaves[index].proofs = proof_cache[parent_cid].clone();
            }
        }
        Ok(())
    }
}

fn transmission_proof_for_child(
    parent: &DagLeaf,
    child: &Cid,
) -> Result<Option<ClassicTreeBranch>> {
    if parent.links().len() <= 1 {
        return Ok(None);
    }
    let proof = parent.proof_for_child(child)?;
    Ok(Some(ClassicTreeBranch::new(child.clone(), proof)))
}

fn verify_transmission_packet_against(
    leaves: &BTreeMap<Cid, DagLeaf>,
    packet: &TransmissionPacket,
 ) -> Result<()> {
    if packet.is_root() {
        return verify_identity_as(&packet.leaf, IdentityRole::Root);
    }
    verify_identity_as(&packet.leaf, IdentityRole::NonRoot)?;
    let parent_cid = packet
        .parent_hash
        .as_ref()
        .expect("non-root packet has a parent");
    // An absent parent is accepted, matching Go. That is safe rather than lax:
    // apply_transmission_packet_to installs no edge when the parent is unknown, so
    // nothing unauthenticated enters the graph. A parent-child edge is only ever
    // created from a parent's own authenticated link list.
    if let Some(parent) = leaves.get(parent_cid) {
        // Gate on the AUTHENTICATED link count, not the retained list. A pruned
        // partial parent can declare CurrentLinkCount = 2 while retaining a single
        // link; gating on links().len() would skip proof verification entirely for
        // exactly the case where a proof is the only thing binding the child.
        if parent.current_link_count() > 1 {
            let branch = packet
                .proofs
                .get(packet.leaf.cid())
                .ok_or_else(|| Error::MissingProof {
                    parent: parent_cid.to_string(),
                    child: packet.leaf.cid().to_string(),
                })?;
            // Bind the branch to this packet's leaf. Looking the proof up by map
            // key is not sufficient, because verify_branch authenticates
            // branch.child(): a branch filed under key C but declaring Leaf = D
            // would prove D while the packet actually delivers C.
            if branch.child() != packet.leaf.cid() {
                return Err(Error::ProofKeyMismatch {
                    key: packet.leaf.cid().to_string(),
                    child: branch.child().to_string(),
                });
            }
            verify_branch(parent, branch)?;
        }
    }
    Ok(())
}

fn apply_transmission_packet_to(
    leaves: &mut BTreeMap<Cid, DagLeaf>,
    packet: TransmissionPacket,
 ) {
    let child = packet.leaf.cid().clone();
    let parent = packet.parent_hash.clone();
    let proof = packet.proofs.get(&child).cloned();
    leaves.insert(child.clone(), packet.leaf);
    if let Some(parent_cid) = parent {
        if let Some(parent_leaf) = leaves.get_mut(&parent_cid) {
            if !parent_leaf.links.contains(&child) {
                parent_leaf.links.push(child.clone());
            }
        }
        if let (Some(parent_leaf), Some(branch)) = (leaves.get_mut(&parent_cid), proof) {
            parent_leaf.proofs.insert(child, branch);
        }
    }
}

fn verify_batched_packet_against(
    leaves: &BTreeMap<Cid, DagLeaf>,
    packet: &BatchedTransmissionPacket,
 ) -> Result<()> {
    let batch_leaves = packet
        .leaves
        .iter()
        .map(|leaf| (leaf.cid().clone(), leaf))
        .collect::<BTreeMap<_, _>>();
    let mut verified_parents = BTreeSet::new();
    for child in &packet.leaves {
        let parent = packet
            .relationships
            .get(child.cid())
            .ok_or_else(|| Error::MissingTransmissionRelationship {
                child: child.cid().to_string(),
            })?;
        let Some(parent_cid) = parent else {
            verify_identity_as(child, IdentityRole::Root)?;
            continue;
        };
        verify_identity_as(child, IdentityRole::NonRoot)?;
        let (parent_leaf, parent_from_batch) = if let Some(parent) = batch_leaves.get(parent_cid) {
            (*parent, true)
        } else if let Some(parent) = leaves.get(parent_cid) {
            (parent, false)
        } else {
            return Err(Error::UnavailableTransmissionParent {
                parent: parent_cid.to_string(),
                child: child.cid().to_string(),
            });
        };
        // The declared parent must actually link this child. Each early return
        // below skips proof checking, and apply_batched_packet_to then pushes the
        // relationship child onto the parent's links unconditionally, so without
        // this check a batch can install an edge the parent never committed to:
        // an honest root with CurrentLinkCount == 1 plus a foreign leaf claiming
        // that root as its parent is enough to corrupt the receiver.
        //
        // Dag::verify_partial already enforces this invariant with
        // ParentMissingLink; the batched path must not be weaker than it. Go builds
        // relationships from real parent links, so this rejects nothing Go emits.
        if !parent_leaf.links().contains(child.cid()) {
            return Err(Error::ParentMissingLink {
                parent: parent_cid.to_string(),
                child: child.cid().to_string(),
            });
        }
        if parent_leaf.current_link_count() <= 1 {
            continue;
        }
        if parent_leaf.proofs().is_empty() {
            if verified_parents.insert(parent_cid.clone()) {
                verify_complete_classic_root(parent_leaf)?;
            }
            continue;
        }
        let Some(branch) = parent_leaf.proof_for(child.cid()) else {
            if parent_from_batch {
                continue;
            }
            return Err(Error::MissingProof {
                parent: parent_cid.to_string(),
                child: child.cid().to_string(),
            });
        };
        verify_branch(parent_leaf, branch)?;
    }
    Ok(())
}

fn apply_batched_packet_to(
    leaves: &mut BTreeMap<Cid, DagLeaf>,
    packet: &BatchedTransmissionPacket,
 ) {
    for incoming in &packet.leaves {
        let child = incoming.cid().clone();
        if let Some(existing) = leaves.get_mut(&child) {
            for link in incoming.links() {
                if !existing.links.contains(link) {
                    existing.links.push(link.clone());
                }
            }
            for (key, branch) in incoming.proofs() {
                existing.proofs.insert(key.clone(), branch.clone());
            }
        } else {
            leaves.insert(child.clone(), incoming.clone());
        }
        if let Some(Some(parent_cid)) = packet.relationships.get(&child) {
            if let Some(parent) = leaves.get_mut(parent_cid) {
                if !parent.links.contains(&child) {
                    parent.links.push(child);
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum IdentityRole {
    Root,
    NonRoot,
}

pub(crate) fn verify_identity_as(leaf: &DagLeaf, role: IdentityRole) -> Result<()> {
    let merkle_root = leaf
        .classic_merkle_root_wire()
        .ok_or_else(|| Error::LeafCidMismatch {
            cid: leaf.cid().to_string(),
        })?;
    let link_count =
        u64::try_from(leaf.current_link_count()).map_err(|_| Error::SizeOverflow {
            field: "CurrentLinkCount",
        })?;
    let identity = match role {
        IdentityRole::Root => encode_root_identity(
            leaf.item_name(),
            leaf.leaf_type(),
            merkle_root,
            link_count,
            leaf.leaf_count(),
            leaf.content_size(),
            leaf.dag_size(),
            leaf.content_hash(),
            metadata_array(Some(leaf.additional_data())),
        ),
        IdentityRole::NonRoot => encode_non_root_identity(
            leaf.item_name(),
            leaf.leaf_type(),
            merkle_root,
            link_count,
            leaf.content_hash(),
            metadata_array(Some(leaf.additional_data())),
        ),
    };
    if Cid::from_cbor(&identity) != *leaf.cid() {
        return Err(Error::LeafCidMismatch {
            cid: leaf.cid().to_string(),
        });
    }
    if let Some(content) = leaf.content() {
        let expected = leaf.content_hash().ok_or_else(|| Error::MissingContentHash {
            cid: leaf.cid().to_string(),
        })?;
        if sha256(content) != *expected {
            return Err(Error::ContentHashMismatch {
                cid: leaf.cid().to_string(),
            });
        }
    }
    Ok(())
}

pub(crate) fn verify_complete_classic_root(parent: &DagLeaf) -> Result<()> {
    if parent.links().len() != parent.current_link_count() {
        return Err(Error::LinkCountMismatch {
            cid: parent.cid().to_string(),
            expected: parent.current_link_count(),
            actual: parent.links().len(),
        });
    }
    let (calculated, _) = classic_tree_for_links(parent.links())?;
    if calculated.as_slice() != parent.classic_merkle_root() {
        return Err(Error::ClassicRootMismatch {
            cid: parent.cid().to_string(),
        });
    }
    Ok(())
}

pub(crate) fn verify_branch(parent: &DagLeaf, branch: &ClassicTreeBranch) -> Result<()> {
    let root: &Digest = parent
        .classic_merkle_root()
        .try_into()
        .map_err(|_| Error::ClassicRootMismatch {
            cid: parent.cid().to_string(),
        })?;
    ClassicMerkleTree::verify_against(
        branch.child().as_str().as_bytes(),
        branch.proof(),
        root,
    )
}

fn verify_root_marker(
    root: Option<&Cid>,
    expected: Option<&Cid>,
    received: &Cid,
    is_root: bool,
 ) -> Result<()> {
    if !is_root {
        return Ok(());
    }
    for candidate in [root, expected].into_iter().flatten() {
        if candidate != received {
            return Err(Error::ConflictingTransmissionRoot {
                expected: candidate.to_string(),
                received: received.to_string(),
            });
        }
    }
    Ok(())
}

fn verify_batched_root_markers(
    root: Option<&Cid>,
    expected: Option<&Cid>,
    packet: &BatchedTransmissionPacket,
 ) -> Result<()> {
    let mut packet_root: Option<&Cid> = None;
    for leaf in &packet.leaves {
        if packet.relationships.get(leaf.cid()) != Some(&None) {
            continue;
        }
        if let Some(first) = packet_root {
            if first != leaf.cid() {
                return Err(Error::ConflictingTransmissionRoot {
                    expected: first.to_string(),
                    received: leaf.cid().to_string(),
                });
            }
        } else {
            packet_root = Some(leaf.cid());
        }
        verify_root_marker(root, expected, leaf.cid(), true)?;
    }
    Ok(())
}

fn estimate_leaf_size(leaf: &DagLeaf) -> Result<usize> {
    let mut size = 0_usize;
    estimate_add(&mut size, leaf.cid().as_str().len())?;
    estimate_add(&mut size, leaf.item_name().len())?;
    estimate_add(&mut size, leaf.leaf_type().as_str().len())?;
    estimate_add(&mut size, leaf.content().map_or(0, <[u8]>::len))?;
    estimate_add(&mut size, leaf.content_hash().map_or(0, |_| 32))?;
    estimate_add(
        &mut size,
        leaf.classic_merkle_root_wire().map_or(0, <[u8]>::len),
    )?;
    estimate_add(
        &mut size,
        leaf.links()
            .len()
            .checked_mul(64)
            .ok_or(Error::SizeOverflow {
                field: "batch estimate",
            })?,
    )?;
    for (key, value) in leaf.additional_data() {
        estimate_add(&mut size, key.len())?;
        estimate_add(&mut size, value.len())?;
    }
    estimate_add(
        &mut size,
        leaf.proofs()
            .len()
            .checked_mul(10 * 32)
            .ok_or(Error::SizeOverflow {
                field: "batch estimate",
            })?,
    )?;
    estimate_add(&mut size, 32)?;
    estimate_add(&mut size, 100)?;
    Ok(size)
}

fn estimate_add(total: &mut usize, value: usize) -> Result<()> {
    *total = total.checked_add(value).ok_or(Error::SizeOverflow {
        field: "batch estimate",
    })?;
    Ok(())
}

fn transmission_packet_wire_value(packet: &TransmissionPacket, order: KeyOrder) -> CborValue {
    let mut pairs = vec![
        ("Leaf".to_owned(), leaf_wire_value(&packet.leaf, order)),
        (
            "ParentHash".to_owned(),
            CborValue::Text(
                packet
                    .parent_hash
                    .as_ref()
                    .map_or_else(String::new, ToString::to_string),
            ),
        ),
    ];
    if !packet.proofs.is_empty() {
        pairs.push((
            "proofs".to_owned(),
            sorted_wire_map(
                packet
                    .proofs
                    .iter()
                    .map(|(key, branch)| (key.to_string(), proof_wire_value(branch)))
                    .collect(),
                order,
            ),
        ));
    }
    CborValue::Map(pairs)
}

fn transmission_packet_from_wire_value(value: &CborValue) -> Result<TransmissionPacket> {
    let map = cbor_map(value, "transmission packet")?;
    let leaf_value = cbor_get(map, &PACKET_LEAF)?
        .ok_or_else(|| invalid_data("missing transmission packet Leaf"))?;
    let leaf = decode_packet_leaf(leaf_value)?;
    let parent_text = cbor_optional_text(cbor_get(map, &PACKET_PARENT_HASH)?)?.unwrap_or("");
    let parent_hash = if parent_text.is_empty() {
        None
    } else {
        Some(Cid::parse(parent_text)?)
    };
    // Bind each outer proof to its map key at decode time. Go always files a
    // packet proof under the child it proves (GetLeafSequence sets
    // Proofs[childHash] with branch.Leaf = childHash), so key binding rejects
    // nothing the reference can produce while closing the key/branch mismatch.
    let proofs = decode_proofs(cbor_get(map, &PACKET_PROOFS)?, true)?;
    Ok(TransmissionPacket {
        leaf,
        parent_hash,
        proofs,
    })
}

fn batched_packet_wire_value(packet: &BatchedTransmissionPacket, order: KeyOrder) -> CborValue {
    CborValue::Map(vec![
        (
            "Leaves".to_owned(),
            CborValue::Array(
                packet
                    .leaves
                    .iter()
                    .map(|leaf| leaf_wire_value(leaf, order))
                    .collect(),
            ),
        ),
        (
            "Relationships".to_owned(),
            sorted_wire_map(
                packet
                    .relationships
                    .iter()
                    .map(|(child, parent)| {
                        (
                            child.to_string(),
                            CborValue::Text(
                                parent
                                    .as_ref()
                                    .map_or_else(String::new, ToString::to_string),
                            ),
                        )
                    })
                    .collect(),
                order,
            ),
        ),
        (
            "PacketIndex".to_owned(),
            CborValue::Unsigned(packet.packet_index),
        ),
        (
            "TotalPackets".to_owned(),
            CborValue::Unsigned(packet.total_packets),
        ),
    ])
}

fn batched_packet_from_wire_value(value: &CborValue) -> Result<BatchedTransmissionPacket> {
    let map = cbor_map(value, "batched transmission packet")?;
    let relationships = decode_relationships(cbor_get(map, &BATCH_RELATIONSHIPS)?)?;
    let leaves = match cbor_get(map, &BATCH_LEAVES)? {
        None | Some(CborValue::Null) => Vec::new(),
        Some(CborValue::Array(values)) => values
            .iter()
            .map(decode_packet_leaf)
            .collect::<Result<Vec<_>>>()?,
        _ => return Err(invalid_data("batched packet Leaves is not an array")),
    };
    let packet_index =
        cbor_optional_unsigned(cbor_get(map, &BATCH_PACKET_INDEX)?)?.unwrap_or(0);
    let total_packets =
        cbor_optional_unsigned(cbor_get(map, &BATCH_TOTAL_PACKETS)?)?.unwrap_or(0);
    Ok(BatchedTransmissionPacket {
        leaves,
        relationships,
        packet_index,
        total_packets,
    })
}

fn decode_packet_leaf(value: &CborValue) -> Result<DagLeaf> {
    let map = cbor_map(value, "transmission packet leaf")?;
    let hash = Cid::parse(cbor_required_text(
        cbor_get(map, &PACKET_LEAF_HASH)?,
        "Hash",
    )?)?;
    decode_leaf(&hash, value, true)
}

fn decode_relationships(
    value: Option<&CborValue>,
 ) -> Result<BTreeMap<Cid, Option<Cid>>> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    if matches!(value, CborValue::Null) {
        return Ok(BTreeMap::new());
    }
    cbor_map(value, "Relationships")?
        .iter()
        .map(|(child, parent)| {
            let child = Cid::parse(child)?;
            let parent = cbor_required_text(Some(parent), "relationship parent")?;
            let parent = if parent.is_empty() {
                None
            } else {
                Some(Cid::parse(parent)?)
            };
            Ok((child, parent))
        })
        .collect()
}

fn json_transmission_packet_to_cbor(value: &JsonValue) -> Result<CborValue> {
    let object = json_object(value, "transmission packet")?;
    let leaf = json_get(object, &PACKET_LEAF)?
        .ok_or_else(|| invalid_json("missing transmission packet Leaf"))?;
    let mut pairs = vec![
        ("Leaf".to_owned(), json_leaf_to_cbor(leaf)?),
        (
            "ParentHash".to_owned(),
            CborValue::Text(
                json_get(object, &PACKET_PARENT_HASH)?
                    .map(|value| json_string(value, "ParentHash"))
                    .transpose()?
                    .unwrap_or("")
                    .to_owned(),
            ),
        ),
    ];
    if let Some(proofs) = json_get(object, &PACKET_PROOFS)? {
        pairs.push((
            "proofs".to_owned(),
            json_proof_map_to_cbor(proofs, "proofs")?,
        ));
    }
    Ok(CborValue::Map(pairs))
}

fn json_batched_packet_to_cbor(value: &JsonValue) -> Result<CborValue> {
    let object = json_object(value, "batched transmission packet")?;
    let mut pairs = Vec::new();
    if let Some(leaves) = json_get(object, &BATCH_LEAVES)? {
        let converted = match leaves {
            JsonValue::Null => CborValue::Null,
            JsonValue::Array(values) => CborValue::Array(
                values
                    .iter()
                    .map(json_leaf_to_cbor)
                    .collect::<Result<Vec<_>>>()?,
            ),
            _ => return Err(invalid_json("batched packet Leaves is not an array")),
        };
        pairs.push(("Leaves".to_owned(), converted));
    }
    if let Some(relationships) = json_get(object, &BATCH_RELATIONSHIPS)? {
        let converted = match relationships {
            JsonValue::Null => CborValue::Null,
            JsonValue::Object(values) => CborValue::Map(
                values
                    .iter()
                    .map(|(child, parent)| {
                        Ok((
                            child.clone(),
                            CborValue::Text(
                                json_required_string(Some(parent), "relationship parent")?
                                    .to_owned(),
                            ),
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
            _ => return Err(invalid_json("Relationships is not an object")),
        };
        pairs.push(("Relationships".to_owned(), converted));
    }
    if let Some(index) = json_get(object, &BATCH_PACKET_INDEX)? {
        pairs.push((
            "PacketIndex".to_owned(),
            json_unsigned(index, "PacketIndex")?,
        ));
    }
    if let Some(total) = json_get(object, &BATCH_TOTAL_PACKETS)? {
        pairs.push((
            "TotalPackets".to_owned(),
            json_unsigned(total, "TotalPackets")?,
        ));
    }
    Ok(CborValue::Map(pairs))
}

fn json_proof_map_to_cbor(value: &JsonValue, field: &'static str) -> Result<CborValue> {
    match value {
        JsonValue::Null => Ok(CborValue::Null),
        JsonValue::Object(values) => Ok(CborValue::Map(
            values
                .iter()
                .map(|(key, proof)| Ok((key.clone(), json_proof_to_cbor(proof)?)))
                .collect::<Result<Vec<_>>>()?,
        )),
        _ => Err(invalid_json(format!("{field} is not an object"))),
    }
}

fn json_unsigned(value: &JsonValue, field: &'static str) -> Result<CborValue> {
    match value {
        JsonValue::Number(number) => Ok(CborValue::Unsigned(*number)),
        _ => Err(invalid_json(format!(
            "{field} is not an unsigned integer"
        ))),
    }
}

fn encode_json(value: &CborValue) -> Result<Vec<u8>> {
    let mut output = String::new();
    write_json(value, &mut output, 0)?;
    Ok(output.into_bytes())
}

fn invalid_data(detail: impl Into<String>) -> Error {
    Error::InvalidData {
        detail: detail.into(),
    }
}

fn invalid_json(detail: impl Into<String>) -> Error {
    Error::InvalidJson {
        detail: detail.into(),
    }
}
