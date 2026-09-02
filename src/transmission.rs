use crate::classic::{ClassicMerkleTree, Digest};
use crate::dag::{
    classic_tree_for_links, encode_non_root_identity, encode_root_identity, metadata_array, Cid,
    ClassicTreeBranch, Dag, DagLeaf,
};
use crate::encoding::{
    cbor_decode_shared, cbor_encode, sha256, sorted_wire_map, CborValue, KeyOrder,
};
use crate::serialization::{
    cbor_get, cbor_map, cbor_required_text, cbor_required_unsigned, decode_leaf, decode_proofs,
    ensure_cbor_fields, ensure_json_fields, json_get, json_leaf_to_cbor, json_object,
    json_proof_to_cbor, json_required_string, leaf_wire_value, parse_json, proof_wire_value,
    write_json, JsonValue, WireKey,
};
use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::num::NonZeroUsize;

pub const DEFAULT_BATCH_TARGET: usize = 4 * 1024 * 1024;
const MAX_TRANSMISSION_PACKET_COUNT: usize = 65_536;
const MAX_TRANSMISSION_PACKETS: u64 = MAX_TRANSMISSION_PACKET_COUNT as u64;
const MAX_TRANSMISSION_LEAVES_PER_PACKET: usize = 65_536;

static PACKET_LEAF: WireKey = WireKey::new("Leaf");
static PACKET_PARENT_HASH: WireKey = WireKey::new("ParentHash");
static PACKET_PROOFS: WireKey = WireKey::new("proofs");
static BATCH_LEAVES: WireKey = WireKey::new("Leaves");
static BATCH_RELATIONSHIPS: WireKey = WireKey::new("Relationships");
static BATCH_PACKET_INDEX: WireKey = WireKey::new("PacketIndex");
static BATCH_TOTAL_PACKETS: WireKey = WireKey::new("TotalPackets");
static PACKET_LEAF_HASH: WireKey = WireKey::new("Hash");

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
        self.relationships.get(child).map(|parent| parent.as_ref())
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
        Ok(cbor_encode(&batched_packet_wire_value(
            self,
            KeyOrder::Cbor,
        )))
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
        verify_root_marker(
            self.root.as_ref(),
            None,
            packet.leaf.cid(),
            packet.is_root(),
        )?;
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

pub type StreamingLeafSink<'a, E> = dyn FnMut(&DagLeaf, &[u8]) -> std::result::Result<(), E> + 'a;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BatchedDagReceiver {
    root: Option<Cid>,
    expected_root: Option<Cid>,
    leaves: BTreeMap<Cid, DagLeaf>,
    next_packet_index: u64,
    declared_total_packets: Option<u64>,
    /// `Some` once a packet has streamed through `apply_and_verify_streaming`:
    /// the receiver then holds a content-free skeleton, and these are the size
    /// totals `finish_verified` holds the root to in place of retained payloads.
    streamed: Option<crate::operations::StreamedSizeTotals>,
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
            next_packet_index: 0,
            declared_total_packets: None,
            streamed: None,
        }
    }

    pub fn root(&self) -> Option<&Cid> {
        self.root.as_ref().or(self.expected_root.as_ref())
    }

    pub fn leaves(&self) -> &BTreeMap<Cid, DagLeaf> {
        &self.leaves
    }

    fn verify_packet_position(&self, packet: &BatchedTransmissionPacket) -> Result<()> {
        validate_packet_counters(packet.packet_index, packet.total_packets)?;
        if packet.packet_index != self.next_packet_index {
            return Err(invalid_data(format!(
                "expected PacketIndex {}, received {}",
                self.next_packet_index, packet.packet_index
            )));
        }
        if let Some(expected) = self.declared_total_packets {
            if packet.total_packets != expected {
                return Err(invalid_data(format!(
                    "TotalPackets changed from {expected} to {}",
                    packet.total_packets
                )));
            }
        }
        Ok(())
    }

    fn record_packet(&mut self, packet: &BatchedTransmissionPacket) {
        self.declared_total_packets
            .get_or_insert(packet.total_packets);
        self.next_packet_index = packet.packet_index + 1;
    }

    pub fn verify_packet(&self, packet: &BatchedTransmissionPacket) -> Result<()> {
        self.verify_packet_position(packet)?;
        verify_batched_root_markers(self.root.as_ref(), self.expected_root.as_ref(), packet)?;
        verify_batched_packet_against(&self.leaves, packet)
    }

    pub fn apply_packet(&mut self, packet: &BatchedTransmissionPacket) {
        self.adopt_root(packet);
        apply_batched_packet_to(&mut self.leaves, packet, false);
        self.record_packet(packet);
    }

    pub fn apply_and_verify(&mut self, packet: &BatchedTransmissionPacket) -> Result<()> {
        if self.streamed.is_some() {
            return Err(Error::Invariant {
                detail: "a receiver that streams payloads cannot retain later packets",
            });
        }
        self.verify_packet(packet)?;
        self.apply_packet(packet);
        Ok(())
    }

    /// `apply_and_verify` for a receiver that must not hold payloads.
    ///
    /// The packet passes exactly the checks `apply_and_verify` runs. Then every
    /// leaf the receiver has not seen before hands its payload to `sink` and is
    /// kept without it, so a payload reaches the sink only after its hash
    /// matched the leaf's content hash and the leaf's place under the declared
    /// root was proven for this packet. The receiver changes only once every
    /// delivery succeeded: a failing sink leaves it exactly as it was.
    /// `finish_verified` still holds the root's signed `ContentSize`/`DagSize`
    /// to the payloads that streamed through, so a root that lies about its
    /// sizes is refused whether or not the payloads were retained.
    pub fn apply_and_verify_streaming<E: From<Error>>(
        &mut self,
        packet: &BatchedTransmissionPacket,
        sink: &mut StreamingLeafSink<'_, E>,
    ) -> std::result::Result<(), E> {
        if self.streamed.is_none() && !self.leaves.is_empty() {
            return Err(Error::Invariant {
                detail: "streaming must begin with a receiver's first packet",
            }
            .into());
        }
        self.verify_packet(packet)?;
        let mut totals = self.streamed.clone().unwrap_or_default();
        let mut delivered = BTreeSet::new();
        for leaf in &packet.leaves {
            if self.leaves.contains_key(leaf.cid()) || !delivered.insert(leaf.cid().clone()) {
                continue;
            }
            let is_root = packet.relationships.get(leaf.cid()) == Some(&None);
            totals.record(leaf, is_root)?;
            if let Some(content) = leaf.content() {
                sink(leaf, content)?;
            }
        }
        self.adopt_root(packet);
        apply_batched_packet_to(&mut self.leaves, packet, true);
        self.record_packet(packet);
        self.streamed = Some(totals);
        Ok(())
    }

    fn adopt_root(&mut self, packet: &BatchedTransmissionPacket) {
        for leaf in &packet.leaves {
            if packet.relationships.get(leaf.cid()) == Some(&None) && self.root.is_none() {
                self.root = Some(leaf.cid().clone());
            }
        }
    }

    pub fn finish_verified(self) -> Result<Dag> {
        if let Some(expected) = self.declared_total_packets {
            if self.next_packet_index != expected {
                return Err(invalid_data(format!(
                    "batched transmission ended after {} of {expected} packets",
                    self.next_packet_index
                )));
            }
        }
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
        if let Some(totals) = &self.streamed {
            totals.verify(&dag)?;
        }
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
            let parent = self.get(&parent_cid).ok_or_else(|| Error::MissingLeaf {
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
            if !packets.is_empty() {
                validate_packet_counters(0, total_packets)?;
            }
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
            let parent = self.get(&parent_cid).ok_or_else(|| Error::MissingLeaf {
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
                let exceeds_target =
                    current_size
                        .checked_add(child_size)
                        .ok_or(Error::SizeOverflow {
                            field: "batch estimate",
                        })?
                        > target.get();
                if (exceeds_target && !current.leaves.is_empty())
                    || current.leaves.len() >= MAX_TRANSMISSION_LEAVES_PER_PACKET
                {
                    self.finalize_batch(&mut current, &parents_in_batch, &mut proof_cache)?;
                    if batches.len() >= MAX_TRANSMISSION_PACKET_COUNT {
                        return Err(invalid_data(format!(
                            "generated transmission exceeds {MAX_TRANSMISSION_PACKETS} packets"
                        )));
                    }
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
            if batches.len() >= MAX_TRANSMISSION_PACKET_COUNT {
                return Err(invalid_data(format!(
                    "generated transmission exceeds {MAX_TRANSMISSION_PACKETS} packets"
                )));
            }
            batches.push(current);
        }
        let total_packets = u64::try_from(batches.len()).map_err(|_| Error::SizeOverflow {
            field: "TotalPackets",
        })?;
        validate_packet_counters(0, total_packets)?;
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
        apply_batched_packet_to(&mut self.leaves, packet, false);
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
                        proofs.insert(child.clone(), ClassicTreeBranch::new(child, proof));
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
    // An absent parent is safe to accept: `apply_transmission_packet_to` installs
    // no edge when the parent is unknown. A parent-child edge is created only
    // from the parent's authenticated link list.
    if let Some(parent) = leaves.get(parent_cid) {
        // Gate on the AUTHENTICATED link count, not the retained list. A pruned
        // partial parent can declare CurrentLinkCount = 2 while retaining a single
        // link; gating on links().len() would skip proof verification entirely for
        // exactly the case where a proof is the only thing binding the child.
        if parent.current_link_count() > 1 {
            let branch =
                packet
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

fn apply_transmission_packet_to(leaves: &mut BTreeMap<Cid, DagLeaf>, packet: TransmissionPacket) {
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
        let parent = packet.relationships.get(child.cid()).ok_or_else(|| {
            Error::MissingTransmissionRelationship {
                child: child.cid().to_string(),
            }
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
        // `Dag::verify_partial` enforces the same invariant with
        // `ParentMissingLink`; the batched path must not be weaker.
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
    without_content: bool,
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
        } else if without_content {
            leaves.insert(child.clone(), incoming.without_content());
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
    let link_count = u64::try_from(leaf.current_link_count()).map_err(|_| Error::SizeOverflow {
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
        let expected = leaf
            .content_hash()
            .ok_or_else(|| Error::MissingContentHash {
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
    let root: &Digest =
        parent
            .classic_merkle_root()
            .try_into()
            .map_err(|_| Error::ClassicRootMismatch {
                cid: parent.cid().to_string(),
            })?;
    ClassicMerkleTree::verify_against(branch.child().as_str().as_bytes(), branch.proof(), root)
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
    ensure_cbor_fields(
        map,
        &[&PACKET_LEAF, &PACKET_PARENT_HASH],
        &[&PACKET_PROOFS],
        "transmission packet",
    )?;
    let leaf_value = cbor_get(map, &PACKET_LEAF)?
        .ok_or_else(|| invalid_data("missing transmission packet Leaf"))?;
    let leaf = decode_packet_leaf(leaf_value)?;
    let parent_text = cbor_required_text(
        cbor_get(map, &PACKET_PARENT_HASH)?,
        "transmission packet ParentHash",
    )?;
    let parent_hash = if parent_text.is_empty() {
        None
    } else {
        Some(Cid::parse(parent_text)?)
    };
    // Every proof is filed under the canonical CID of the child it proves.
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

fn validate_packet_counters(packet_index: u64, total_packets: u64) -> Result<()> {
    if total_packets == 0 || total_packets > MAX_TRANSMISSION_PACKETS {
        return Err(invalid_data(format!(
            "TotalPackets must be between 1 and {MAX_TRANSMISSION_PACKETS}"
        )));
    }
    if packet_index >= total_packets {
        return Err(invalid_data(format!(
            "PacketIndex {packet_index} is outside TotalPackets {total_packets}"
        )));
    }
    Ok(())
}

fn batched_packet_from_wire_value(value: &CborValue) -> Result<BatchedTransmissionPacket> {
    let map = cbor_map(value, "batched transmission packet")?;
    ensure_cbor_fields(
        map,
        &[
            &BATCH_LEAVES,
            &BATCH_RELATIONSHIPS,
            &BATCH_PACKET_INDEX,
            &BATCH_TOTAL_PACKETS,
        ],
        &[],
        "batched transmission packet",
    )?;
    let leaves = match cbor_get(map, &BATCH_LEAVES)?
        .ok_or_else(|| invalid_data("missing batched packet Leaves"))?
    {
        CborValue::Array(values) if !values.is_empty() => values
            .iter()
            .map(decode_packet_leaf)
            .collect::<Result<Vec<_>>>()?,
        CborValue::Array(_) => return Err(invalid_data("batched packet Leaves is empty")),
        _ => return Err(invalid_data("batched packet Leaves is not an array")),
    };
    let relationships = decode_relationships(cbor_get(map, &BATCH_RELATIONSHIPS)?)?;
    let packet_index = cbor_required_unsigned(cbor_get(map, &BATCH_PACKET_INDEX)?, "PacketIndex")?;
    let total_packets =
        cbor_required_unsigned(cbor_get(map, &BATCH_TOTAL_PACKETS)?, "TotalPackets")?;
    validate_packet_counters(packet_index, total_packets)?;
    let leaf_ids: BTreeSet<Cid> = leaves.iter().map(|leaf| leaf.cid().clone()).collect();
    if leaf_ids.len() != leaves.len() {
        return Err(invalid_data("batched packet contains duplicate leaves"));
    }
    if leaf_ids.len() != relationships.len() || !leaf_ids.iter().eq(relationships.keys()) {
        return Err(invalid_data(
            "Relationships must contain exactly one entry for every packet leaf",
        ));
    }
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

fn decode_relationships(value: Option<&CborValue>) -> Result<BTreeMap<Cid, Option<Cid>>> {
    let value = value.ok_or_else(|| invalid_data("missing Relationships"))?;
    let mut relationships = BTreeMap::new();
    for (child, parent) in cbor_map(value, "Relationships")? {
        let child = Cid::parse(child)?;
        let parent = cbor_required_text(Some(parent), "relationship parent")?;
        let parent = if parent.is_empty() {
            None
        } else {
            Some(Cid::parse(parent)?)
        };
        if relationships.insert(child, parent).is_some() {
            return Err(invalid_data(
                "Relationships contains duplicate canonical child identifiers",
            ));
        }
    }
    Ok(relationships)
}

fn json_transmission_packet_to_cbor(value: &JsonValue) -> Result<CborValue> {
    let object = json_object(value, "transmission packet")?;
    ensure_json_fields(
        object,
        &[&PACKET_LEAF, &PACKET_PARENT_HASH],
        &[&PACKET_PROOFS],
        "transmission packet",
    )?;
    let leaf = json_get(object, &PACKET_LEAF)?
        .ok_or_else(|| invalid_json("missing transmission packet Leaf"))?;
    let parent = json_required_string(json_get(object, &PACKET_PARENT_HASH)?, "ParentHash")?;
    let mut pairs = vec![
        ("Leaf".to_owned(), json_leaf_to_cbor(leaf)?),
        ("ParentHash".to_owned(), CborValue::Text(parent.to_owned())),
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
    ensure_json_fields(
        object,
        &[
            &BATCH_LEAVES,
            &BATCH_RELATIONSHIPS,
            &BATCH_PACKET_INDEX,
            &BATCH_TOTAL_PACKETS,
        ],
        &[],
        "batched transmission packet",
    )?;
    let leaves = match json_get(object, &BATCH_LEAVES)?
        .ok_or_else(|| invalid_json("missing batched packet Leaves"))?
    {
        JsonValue::Array(values) => CborValue::Array(
            values
                .iter()
                .map(json_leaf_to_cbor)
                .collect::<Result<Vec<_>>>()?,
        ),
        _ => return Err(invalid_json("batched packet Leaves is not an array")),
    };
    let relationships = match json_get(object, &BATCH_RELATIONSHIPS)?
        .ok_or_else(|| invalid_json("missing Relationships"))?
    {
        JsonValue::Object(values) => CborValue::Map(
            values
                .iter()
                .map(|(child, parent)| {
                    Ok((
                        child.clone(),
                        CborValue::Text(
                            json_required_string(Some(parent), "relationship parent")?.to_owned(),
                        ),
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
        ),
        _ => return Err(invalid_json("Relationships is not an object")),
    };
    let packet_index = json_get(object, &BATCH_PACKET_INDEX)?
        .ok_or_else(|| invalid_json("missing PacketIndex"))?;
    let total_packets = json_get(object, &BATCH_TOTAL_PACKETS)?
        .ok_or_else(|| invalid_json("missing TotalPackets"))?;
    Ok(CborValue::Map(vec![
        ("Leaves".to_owned(), leaves),
        ("Relationships".to_owned(), relationships),
        (
            "PacketIndex".to_owned(),
            json_unsigned(packet_index, "PacketIndex")?,
        ),
        (
            "TotalPackets".to_owned(),
            json_unsigned(total_packets, "TotalPackets")?,
        ),
    ]))
}

fn json_proof_map_to_cbor(value: &JsonValue, field: &'static str) -> Result<CborValue> {
    let JsonValue::Object(values) = value else {
        return Err(invalid_json(format!("{field} is not an object")));
    };
    Ok(CborValue::Map(
        values
            .iter()
            .map(|(key, proof)| Ok((key.clone(), json_proof_to_cbor(proof)?)))
            .collect::<Result<Vec<_>>>()?,
    ))
}

fn json_unsigned(value: &JsonValue, field: &'static str) -> Result<CborValue> {
    match value {
        JsonValue::Number(number) => Ok(CborValue::Unsigned(*number)),
        _ => Err(invalid_json(format!("{field} is not an unsigned integer"))),
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

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use crate::dag::{DagStats, LeafBuilder, LeafType, Metadata};
    use std::num::NonZeroUsize;
    use std::sync::Arc;

    /// A file DAG assembled in memory with the real builder: one root file
    /// leaf over `chunks` chunk leaves of 64 bytes, so every CID, proof and
    /// size total is genuine. `content_lie` and `dag_lie` are added to the
    /// totals the root signs, to build a root that lies about its sizes.
    fn chunked_dag(chunks: usize, content_lie: u64, dag_lie: u64) -> Dag {
        let mut file = LeafBuilder::new("payload.bin", LeafType::File);
        let mut leaves = BTreeMap::new();
        let mut content_size = 0_u64;
        let mut dag_size = 0_u64;
        for index in 0..chunks {
            let data = (0..64)
                .map(|offset| b'A' + ((index * 64 + offset) % 26) as u8)
                .collect::<Vec<u8>>();
            let leaf = LeafBuilder::new(index.to_string(), LeafType::Chunk)
                .with_data(data)
                .build(None)
                .unwrap();
            content_size += 64;
            dag_size += leaf.storage_size().unwrap();
            file.add_link(leaf.cid().clone());
            leaves.insert(leaf.cid().clone(), leaf);
        }
        let stats = DagStats::new(
            chunks as u64,
            content_size + content_lie,
            dag_size + dag_lie,
        );
        let root = file
            .build_root_with_stats(stats, Some(&Metadata::new()))
            .unwrap();
        let root_cid = root.cid().clone();
        leaves.insert(root_cid.clone(), root);
        Dag::from_parts(root_cid, leaves).unwrap()
    }

    fn packets(dag: &Dag) -> Vec<BatchedTransmissionPacket> {
        let batches = dag
            .batched_leaf_sequence_with(Batching::ApproximateBytes(NonZeroUsize::new(160).unwrap()))
            .unwrap();
        assert!(batches.len() > 2, "the fixture must span several packets");
        batches
    }

    fn retained(packets: &[BatchedTransmissionPacket]) -> Result<Dag> {
        let mut receiver = BatchedDagReceiver::new();
        for packet in packets {
            receiver.apply_and_verify(packet)?;
        }
        receiver.finish_verified()
    }

    fn streamed(packets: &[BatchedTransmissionPacket]) -> Result<(Dag, BTreeMap<Cid, Vec<u8>>)> {
        let mut receiver = BatchedDagReceiver::new();
        let mut delivered = BTreeMap::new();
        for packet in packets {
            receiver.apply_and_verify_streaming::<Error>(packet, &mut |leaf, bytes| {
                assert!(
                    delivered
                        .insert(leaf.cid().clone(), bytes.to_vec())
                        .is_none(),
                    "a payload was delivered twice"
                );
                Ok(())
            })?;
        }
        Ok((receiver.finish_verified()?, delivered))
    }

    /// Receivers attach each packet's transmission proof to the parent leaf
    /// they verified it against, so a received DAG equals its source only
    /// once those proofs are set aside.
    fn without_proofs(dag: &Dag) -> Dag {
        let leaves = dag
            .leaves()
            .iter()
            .map(|(cid, leaf)| {
                let mut leaf = leaf.clone();
                leaf.proofs.clear();
                (cid.clone(), leaf)
            })
            .collect();
        Dag::from_parts(dag.root().clone(), leaves).unwrap()
    }

    #[test]
    fn streaming_a_transfer_yields_the_retained_skeleton_and_every_payload_once() {
        let source = chunked_dag(10, 0, 0);
        source.verify().unwrap();
        let packets = packets(&source);
        let full = retained(&packets).unwrap();
        assert_eq!(without_proofs(&full), source);

        let (skeleton, delivered) = streamed(&packets).unwrap();
        let mut stripped = full.clone();
        stripped.remove_all_content();
        assert_eq!(skeleton, stripped);
        assert!(!skeleton.is_partial());
        assert!(skeleton
            .leaves()
            .values()
            .all(|leaf| leaf.content().is_none()));
        assert_eq!(delivered.len(), 10);
        for (cid, bytes) in &delivered {
            assert_eq!(source.get(cid).unwrap().content(), Some(bytes.as_slice()));
        }
    }

    #[test]
    fn streaming_refuses_exactly_what_retaining_refuses() {
        // A root whose signed totals do not match the payloads that streamed.
        for (content_lie, dag_lie) in [(1, 0), (0, 1)] {
            let liar = chunked_dag(10, content_lie, dag_lie);
            let direct = liar.verify().unwrap_err();
            let packets = packets(&liar);
            let retained_error = retained(&packets).unwrap_err();
            let streamed_error = streamed(&packets).unwrap_err();
            assert_eq!(format!("{retained_error:?}"), format!("{direct:?}"));
            assert_eq!(format!("{streamed_error:?}"), format!("{retained_error:?}"));
            if content_lie > 0 {
                assert!(matches!(streamed_error, Error::ContentSizeMismatch { .. }));
            } else {
                assert!(matches!(streamed_error, Error::DagSizeMismatch { .. }));
            }
        }

        // A payload that does not hash to its leaf's content hash.
        let source = chunked_dag(10, 0, 0);
        let packets = packets(&source);
        let mut tampered = packets[1].clone();
        let victim = tampered
            .leaves
            .iter_mut()
            .find(|leaf| leaf.content().is_some())
            .expect("the second packet carries a payload");
        victim.content = Some(Arc::new(b"tampered".to_vec()));
        let mut retaining = BatchedDagReceiver::new();
        retaining.apply_and_verify(&packets[0]).unwrap();
        let retained_error = retaining.apply_and_verify(&tampered).unwrap_err();
        let mut streaming = BatchedDagReceiver::new();
        streaming
            .apply_and_verify_streaming::<Error>(&packets[0], &mut |_, _| Ok(()))
            .unwrap();
        let before = streaming.clone();
        let streamed_error = streaming
            .apply_and_verify_streaming::<Error>(&tampered, &mut |_, _| {
                panic!("a tampered payload must never reach the sink")
            })
            .unwrap_err();
        assert!(matches!(streamed_error, Error::ContentHashMismatch { .. }));
        assert_eq!(format!("{streamed_error:?}"), format!("{retained_error:?}"));
        assert_eq!(streaming, before);

        // A correctly positioned packet whose parent the receiver has not seen.
        let mut orphan = packets[1].clone();
        orphan.packet_index = 0;
        let mut fresh = BatchedDagReceiver::new();
        let retained_error = fresh.apply_and_verify(&orphan).unwrap_err();
        let mut streaming = BatchedDagReceiver::new();
        let streamed_error = streaming
            .apply_and_verify_streaming::<Error>(&orphan, &mut |_, _| {
                panic!("an orphan payload must never reach the sink")
            })
            .unwrap_err();
        assert!(matches!(
            streamed_error,
            Error::UnavailableTransmissionParent { .. }
        ));
        assert_eq!(format!("{streamed_error:?}"), format!("{retained_error:?}"));
        assert_eq!(streaming, BatchedDagReceiver::new());
    }

    #[test]
    fn a_failing_sink_leaves_the_receiver_untouched_and_modes_never_mix() {
        let source = chunked_dag(10, 0, 0);
        let packets = packets(&source);
        let mut receiver = BatchedDagReceiver::new();
        receiver
            .apply_and_verify_streaming::<Error>(&packets[0], &mut |_, _| Ok(()))
            .unwrap();
        let before = receiver.clone();
        let error = receiver
            .apply_and_verify_streaming::<Error>(&packets[1], &mut |_, _| {
                Err(Error::Invariant {
                    detail: "sink refused",
                })
            })
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Invariant {
                detail: "sink refused"
            }
        ));
        assert_eq!(receiver, before);

        // Retaining after streaming, and streaming after retaining, are both
        // refused without touching the receiver.
        assert!(matches!(
            receiver.apply_and_verify(&packets[1]),
            Err(Error::Invariant { .. })
        ));
        assert_eq!(receiver, before);
        let mut mixed = BatchedDagReceiver::new();
        mixed.apply_and_verify(&packets[0]).unwrap();
        let mixed_before = mixed.clone();
        assert!(matches!(
            mixed.apply_and_verify_streaming::<Error>(&packets[1], &mut |_, _| Ok(())),
            Err(Error::Invariant { .. })
        ));
        assert_eq!(mixed, mixed_before);

        // The same packet streams through once the sink accepts it.
        for packet in &packets[1..] {
            receiver
                .apply_and_verify_streaming::<Error>(packet, &mut |_, _| Ok(()))
                .unwrap();
        }
        let skeleton = receiver.finish_verified().unwrap();
        assert_eq!(skeleton.root(), source.root());
        assert!(!skeleton.is_partial());
    }
    #[test]
    fn receiver_rejects_replayed_skipped_inconsistent_and_incomplete_batches() {
        let source = chunked_dag(10, 0, 0);
        let batches = packets(&source);
        let mut receiver = BatchedDagReceiver::new();
        receiver.apply_and_verify(&batches[0]).unwrap();
        let after_first = receiver.clone();

        assert!(matches!(
            receiver.apply_and_verify(&batches[0]),
            Err(Error::InvalidData { .. })
        ));
        assert_eq!(receiver, after_first);
        assert!(matches!(
            receiver.apply_and_verify(&batches[2]),
            Err(Error::InvalidData { .. })
        ));
        assert_eq!(receiver, after_first);

        let mut inconsistent = batches[1].clone();
        inconsistent.total_packets += 1;
        assert!(matches!(
            receiver.apply_and_verify(&inconsistent),
            Err(Error::InvalidData { .. })
        ));
        assert_eq!(receiver, after_first);
        assert!(matches!(
            receiver.clone().finish_verified(),
            Err(Error::InvalidData { detail }) if detail.contains("ended after 1 of")
        ));

        for batch in &batches[1..] {
            receiver.apply_and_verify(batch).unwrap();
        }
        assert_eq!(receiver.finish_verified().unwrap().root(), source.root());
    }

    #[test]
    fn strict_packet_schemas_reject_aliases_unknown_fields_and_invalid_counters() {
        let source = chunked_dag(10, 0, 0);
        let batches = packets(&source);
        assert!(batches[0].root_leaf().is_some());
        assert!(batches[1].root_leaf().is_none());

        let canonical = batched_packet_wire_value(&batches[0], KeyOrder::Cbor);
        assert!(batched_packet_from_wire_value(&canonical).is_ok());

        let mut alias = canonical.clone();
        let CborValue::Map(pairs) = &mut alias else {
            unreachable!();
        };
        pairs.iter_mut().find(|(key, _)| key == "Leaves").unwrap().0 = "leaves".to_owned();
        assert!(batched_packet_from_wire_value(&alias).is_err());

        let mut unknown = canonical.clone();
        let CborValue::Map(pairs) = &mut unknown else {
            unreachable!();
        };
        pairs.push(("Unknown".to_owned(), CborValue::Null));
        assert!(batched_packet_from_wire_value(&unknown).is_err());

        let mut zero_total = canonical;
        let CborValue::Map(pairs) = &mut zero_total else {
            unreachable!();
        };
        pairs
            .iter_mut()
            .find(|(key, _)| key == "TotalPackets")
            .unwrap()
            .1 = CborValue::Unsigned(0);
        assert!(batched_packet_from_wire_value(&zero_total).is_err());

        let single = source.get_leaf_sequence().unwrap().remove(0);
        let mut missing_parent = transmission_packet_wire_value(&single, KeyOrder::Cbor);
        let CborValue::Map(pairs) = &mut missing_parent else {
            unreachable!();
        };
        pairs.retain(|(key, _)| key != "ParentHash");
        assert!(transmission_packet_from_wire_value(&missing_parent).is_err());
    }
}
