use crate::classic::{ClassicMerkleTree, Digest, MerkleProof};
use crate::encoding::{
    base32_lower_decode, cbor_encode, cid_bytes_for_cbor, cid_text, sha256, CborValue,
};
use crate::fastcdc::{stream_fastcdc_chunks, CHUNKING_FASTCDC_V1, CHUNKING_TAG_KEY};
use crate::{io_error, Error, Result};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::fs::{self, DirEntry, File};
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Legacy fixed-mode chunk size (2 MiB). New trees default to fastcdc-v1
/// content-defined chunking ([`Chunking::FastCdcV1`]), which targets this
/// same size per chunk; `with_chunk_size` selects the legacy fixed mode.
pub const DEFAULT_CHUNK_SIZE: usize = 2 * 1024 * 1024;
pub const MAX_IN_MEMORY_LEAF_BYTES: usize = 64 * 1024 * 1024;
pub type Metadata = BTreeMap<String, String>;
pub type Labels = BTreeMap<String, Cid>;
pub type LeafProcessor = dyn Fn(&Path, &str, &DirEntry, bool, LeafType) -> Option<Metadata>;
pub type SyncLeafProcessor =
    dyn Fn(&Path, &str, &DirEntry, bool, LeafType) -> Option<Metadata> + Sync;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Cid {
    /// The base32 text form, shared rather than owned.
    ///
    /// A CID is copied constantly -- as a map key, a link, a queue entry, a
    /// visited-set member -- and `DagLeaf::clone` clones a whole `Vec<Cid>` of
    /// links, so a 73-chunk file leaf used to cost 73 string allocations per
    /// clone. Go's `string` is immutable and shares its backing array, making
    /// the same copy free; `Arc<str>` is the equivalent, and the text is
    /// derived from `bytes` so it is immutable by construction.
    text: Arc<str>,
    bytes: [u8; 36],
}

impl Cid {
    pub fn from_cbor(cbor: &[u8]) -> Self {
        let bytes = cid_bytes_for_cbor(cbor);
        let text = Arc::from(cid_text(&bytes));
        Self { text, bytes }
    }

    pub fn parse(value: &str) -> Result<Self> {
        let payload = value.strip_prefix('b').ok_or_else(|| Error::InvalidCid {
            value: value.to_owned(),
        })?;
        let decoded = base32_lower_decode(payload).map_err(|_| Error::InvalidCid {
            value: value.to_owned(),
        })?;
        let bytes: [u8; 36] = decoded.try_into().map_err(|_| Error::InvalidCid {
            value: value.to_owned(),
        })?;
        if bytes[..4] != [0x01, 0x51, 0x12, 0x20] || cid_text(&bytes) != value {
            return Err(Error::InvalidCid {
                value: value.to_owned(),
            });
        }
        Ok(Self {
            text: Arc::from(value),
            bytes,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn as_bytes(&self) -> &[u8; 36] {
        &self.bytes
    }
}

impl FromStr for Cid {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Cid").field(&self.text).finish()
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LeafType {
    File,
    Chunk,
    Directory,
}

impl LeafType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Chunk => "chunk",
            Self::Directory => "directory",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "file" => Ok(Self::File),
            "chunk" => Ok(Self::Chunk),
            "directory" => Ok(Self::Directory),
            _ => Err(Error::InvalidLeafType {
                value: value.to_owned(),
            }),
        }
    }
}

impl FromStr for LeafType {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl fmt::Display for LeafType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DagStats {
    leaf_count: u64,
    content_size: u64,
    dag_size: u64,
}

impl DagStats {
    pub const fn new(leaf_count: u64, content_size: u64, dag_size: u64) -> Self {
        Self {
            leaf_count,
            content_size,
            dag_size,
        }
    }

    pub fn leaf_count(self) -> u64 {
        self.leaf_count
    }

    pub fn content_size(self) -> u64 {
        self.content_size
    }

    pub fn dag_size(self) -> u64 {
        self.dag_size
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Chunking {
    /// fastcdc-v1 content-defined chunking (the Go repo's normative
    /// `docs/fastcdc-v1.md`): 512 KiB min / 2 MiB target / 8 MiB max,
    /// gear-hash boundaries. The DEFAULT for new trees; roots built under
    /// it carry the `"chunking": "fastcdc-v1"` tag in their additional
    /// data.
    FastCdcV1,
    /// Legacy fixed-size slabs (the pre-fastcdc default cut 2 MiB slabs).
    Fixed(NonZeroUsize),
    /// One whole-file leaf regardless of size (bounded by the in-memory
    /// limit).
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DagWorkerCount {
    Auto,
    PerEntry,
    Fixed(NonZeroUsize),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DagBuildOptions {
    chunking: Chunking,
    root_metadata: Metadata,
    timestamp_root: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelDagBuildOptions {
    base: DagBuildOptions,
    workers: DagWorkerCount,
}

impl Default for DagBuildOptions {
    fn default() -> Self {
        Self {
            chunking: Chunking::FastCdcV1,
            root_metadata: Metadata::new(),
            timestamp_root: false,
        }
    }
}

impl DagBuildOptions {
    pub fn with_chunk_size(mut self, chunk_size: usize) -> Result<Self> {
        let chunk_size_u64 = usize_to_u64(chunk_size, "chunk size")?;
        ensure_in_memory_limit("chunk buffer", chunk_size_u64)?;
        self.chunking = Chunking::Fixed(
            NonZeroUsize::new(chunk_size).ok_or(Error::InvalidChunkSize { value: chunk_size })?,
        );
        Ok(self)
    }

    pub fn with_chunking_disabled(mut self) -> Self {
        self.chunking = Chunking::Disabled;
        self
    }

    /// Restore the default content-defined chunking (fastcdc-v1) — the
    /// mirror of the Go library's `SetDefaultChunkSize`.
    pub fn with_fastcdc(mut self) -> Self {
        self.chunking = Chunking::FastCdcV1;
        self
    }

    pub fn with_root_metadata(mut self, metadata: Metadata) -> Self {
        self.root_metadata = metadata;
        self
    }

    pub fn with_timestamp_root(mut self, enabled: bool) -> Self {
        self.timestamp_root = enabled;
        self
    }

    pub fn with_parallel(self) -> ParallelDagBuildOptions {
        ParallelDagBuildOptions {
            base: self,
            workers: DagWorkerCount::Auto,
        }
    }

    pub fn with_parallel_workers(self, workers: isize) -> ParallelDagBuildOptions {
        ParallelDagBuildOptions {
            base: self,
            workers: dag_worker_count(workers),
        }
    }

    pub fn chunking(&self) -> Chunking {
        self.chunking
    }

    pub fn root_metadata(&self) -> &Metadata {
        &self.root_metadata
    }

    pub fn timestamp_root(&self) -> bool {
        self.timestamp_root
    }
}

impl ParallelDagBuildOptions {
    pub fn with_chunk_size(mut self, chunk_size: usize) -> Result<Self> {
        self.base = self.base.with_chunk_size(chunk_size)?;
        Ok(self)
    }

    pub fn with_chunking_disabled(mut self) -> Self {
        self.base = self.base.with_chunking_disabled();
        self
    }

    pub fn with_root_metadata(mut self, metadata: Metadata) -> Self {
        self.base = self.base.with_root_metadata(metadata);
        self
    }

    pub fn with_timestamp_root(mut self, enabled: bool) -> Self {
        self.base = self.base.with_timestamp_root(enabled);
        self
    }

    pub fn with_parallel(mut self) -> Self {
        self.workers = DagWorkerCount::Auto;
        self
    }

    pub fn with_parallel_workers(mut self, workers: isize) -> Self {
        self.workers = dag_worker_count(workers);
        self
    }

    pub fn with_sequential(self) -> DagBuildOptions {
        self.base
    }

    pub fn chunking(&self) -> Chunking {
        self.base.chunking()
    }

    pub fn root_metadata(&self) -> &Metadata {
        self.base.root_metadata()
    }

    pub fn timestamp_root(&self) -> bool {
        self.base.timestamp_root()
    }

    pub fn parallel_workers(&self) -> DagWorkerCount {
        self.workers
    }
}

fn dag_worker_count(workers: isize) -> DagWorkerCount {
    match workers {
        0 => DagWorkerCount::Auto,
        ..=-1 => DagWorkerCount::PerEntry,
        _ => DagWorkerCount::Fixed(
            NonZeroUsize::new(usize::try_from(workers).expect("positive worker count fits usize"))
                .expect("positive worker count is nonzero"),
        ),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassicTreeBranch {
    child: Cid,
    proof: MerkleProof,
}

impl ClassicTreeBranch {
    pub fn child(&self) -> &Cid {
        &self.child
    }

    pub fn proof(&self) -> &MerkleProof {
        &self.proof
    }

    pub(crate) fn new(child: Cid, proof: MerkleProof) -> Self {
        Self { child, proof }
    }
}

#[derive(Clone, Debug)]
pub struct DagLeaf {
    pub(crate) cid: Cid,
    /// The leaf's name, shared rather than owned.
    ///
    /// For the same reason `content` and `Cid::text` are shared: a chunk leaf's
    /// other fields are all empty (no links, no proofs, no metadata), so this
    /// `String` was the single heap allocation every `DagLeaf::clone` paid.
    /// Measured on a 141-leaf DAG, cloning leaves cost 20.3 us of a 102 us
    /// batched-sequence run -- a fifth of the whole workload -- and Go pays none
    /// of it because its `Clone()` copies an immutable string header.
    ///
    /// Sharing is safe because a leaf's name is immutable: the CID commits to
    /// `ItemName` through the identity CBOR, so mutating it in place would
    /// invalidate the leaf's identity. `Arc<str>` hands out no `&mut`, and the
    /// name is only ever replaced wholesale when a new leaf is built.
    pub(crate) item_name: Arc<str>,
    pub(crate) leaf_type: LeafType,
    pub(crate) content_hash: Option<Digest>,
    /// The leaf payload, shared rather than owned.
    ///
    /// `DagLeaf` is cloned constantly -- every transmission packet, every store
    /// read, every batch -- and with a plain `Vec<u8>` each of those clones
    /// memcpy'd the whole payload. Measured on a 20 MiB corpus that single copy
    /// was the entire gap against Go: strip content and Rust's leaf sequence
    /// already beat Go's, so the deficit was memory traffic, not algorithms.
    ///
    /// Sharing is safe here because leaf content is immutable: a leaf's CID
    /// commits to `sha256(content)`, so mutating the bytes in place would
    /// invalidate its identity. Nothing mutates through this handle -- the
    /// payload is only ever replaced wholesale (`content = None`, or a fresh
    /// `Arc` from a content store), which repoints the handle instead of
    /// writing through it. That is the same discipline Go's `Clone()` documents
    /// for its shared `Content` slice, except Rust enforces it: `Arc<Vec<u8>>`
    /// hands out no `&mut` while a second owner exists.
    pub(crate) content: Option<Arc<Vec<u8>>>,
    pub(crate) classic_merkle_root: Option<Vec<u8>>,
    pub(crate) current_link_count: usize,
    pub(crate) leaf_count: u64,
    pub(crate) content_size: u64,
    pub(crate) dag_size: u64,
    pub(crate) links: Vec<Cid>,
    pub(crate) additional_data: Metadata,
    pub(crate) proofs: BTreeMap<Cid, ClassicTreeBranch>,
    /// Which parent this leaf was reached through.
    ///
    /// Derived context, never identity. It is absent from the identity CBOR,
    /// from the storage projection, and from the wire shape, exactly as Go keeps
    /// `DagLeaf.ParentHash` out of `SerializableDagLeaf`. A content-identical
    /// chunk can hang under several parents at once, so this records only the one
    /// a given reconstruction attributed it to -- always the lowest parent CID --
    /// and carries no authority: verification must never trust it in place of a
    /// real link or proof.
    pub(crate) parent_hash: Option<Cid>,
}

impl Eq for DagLeaf {}

impl PartialEq for DagLeaf {
    fn eq(&self, other: &Self) -> bool {
        // parent_hash is deliberately excluded. It is derived context rather than
        // part of the leaf, and comparing it would make a freshly built DAG
        // unequal to that same DAG after a serialization round trip even though
        // every hashed and transmitted byte is identical.
        //
        // Destructured exhaustively on purpose: adding a field to DagLeaf then
        // becomes a compile error here instead of a silently skipped comparison.
        let Self {
            cid,
            item_name,
            leaf_type,
            content_hash,
            content,
            classic_merkle_root,
            current_link_count,
            leaf_count,
            content_size,
            dag_size,
            links,
            additional_data,
            proofs,
            parent_hash: _,
        } = self;
        *cid == other.cid
            && *item_name == other.item_name
            && *leaf_type == other.leaf_type
            && *content_hash == other.content_hash
            && *content == other.content
            && *classic_merkle_root == other.classic_merkle_root
            && *current_link_count == other.current_link_count
            && *leaf_count == other.leaf_count
            && *content_size == other.content_size
            && *dag_size == other.dag_size
            && *links == other.links
            && *additional_data == other.additional_data
            && *proofs == other.proofs
    }
}

impl DagLeaf {
    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    pub fn item_name(&self) -> &str {
        &self.item_name
    }

    pub fn leaf_type(&self) -> LeafType {
        self.leaf_type
    }

    pub fn content_hash(&self) -> Option<&Digest> {
        self.content_hash.as_ref()
    }

    pub fn content(&self) -> Option<&[u8]> {
        // `as_deref` would stop at `&Vec<u8>` now that the payload is shared,
        // so the slice is taken explicitly. The public signature is unchanged.
        self.content.as_ref().map(|content| content.as_slice())
    }

    /// The payload as a shared handle, so a builder can adopt an existing
    /// leaf's content without copying it.
    pub(crate) fn content_arc(&self) -> Option<Arc<Vec<u8>>> {
        self.content.clone()
    }

    /// The same leaf without its payload: identity, links, proofs, sizes and
    /// metadata stay, `content` becomes `None`. The copy still verifies,
    /// because the CID commits to the payload through `content_hash`, which
    /// stays. The source keeps its shared payload untouched.
    pub fn without_content(&self) -> Self {
        let mut leaf = self.clone();
        leaf.content = None;
        leaf
    }

    pub fn classic_merkle_root(&self) -> &[u8] {
        self.classic_merkle_root.as_deref().unwrap_or_default()
    }

    pub(crate) fn classic_merkle_root_wire(&self) -> Option<&[u8]> {
        self.classic_merkle_root.as_deref()
    }

    pub fn current_link_count(&self) -> usize {
        self.current_link_count
    }

    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    pub fn content_size(&self) -> u64 {
        self.content_size
    }

    pub fn dag_size(&self) -> u64 {
        self.dag_size
    }

    pub fn links(&self) -> &[Cid] {
        &self.links
    }

    pub fn additional_data(&self) -> &Metadata {
        &self.additional_data
    }

    pub fn proofs(&self) -> &BTreeMap<Cid, ClassicTreeBranch> {
        &self.proofs
    }

    pub fn proof_for(&self, child: &Cid) -> Option<&ClassicTreeBranch> {
        self.proofs.get(child)
    }

    pub fn is_root_shape(&self) -> bool {
        self.leaf_count != 0
    }

    pub fn identity_cbor(&self) -> Vec<u8> {
        if self.is_root_shape() {
            encode_root_identity(
                &self.item_name,
                self.leaf_type,
                self.classic_merkle_root(),
                self.current_link_count as u64,
                self.leaf_count,
                self.content_size,
                self.dag_size,
                self.content_hash.as_ref(),
                metadata_array(Some(&self.additional_data)),
            )
        } else {
            encode_non_root_identity(
                &self.item_name,
                self.leaf_type,
                self.classic_merkle_root(),
                self.current_link_count as u64,
                self.content_hash.as_ref(),
                metadata_array(Some(&self.additional_data)),
            )
        }
    }

    /// Returns the encoded length of the leaf's storage/accounting projection.
    ///
    /// This projection is used only for Go-compatible `DagSize` accounting and is
    /// intentionally distinct from the JSON/CBOR wire representation.
    pub fn storage_size(&self) -> Result<u64> {
        storage_shape_len(self)
    }

    #[cfg(test)]
    fn storage_cbor(&self) -> Vec<u8> {
        encode_storage_shape(self)
    }

    pub fn verify_identity(&self) -> Result<()> {
        if Cid::from_cbor(&self.identity_cbor()) != self.cid {
            return Err(Error::LeafCidMismatch {
                cid: self.cid.to_string(),
            });
        }
        if let Some(content) = &self.content {
            let expected = self.content_hash.ok_or_else(|| Error::MissingContentHash {
                cid: self.cid.to_string(),
            })?;
            if sha256(content.as_slice()) != expected {
                return Err(Error::ContentHashMismatch {
                    cid: self.cid.to_string(),
                });
            }
        }
        Ok(())
    }

    pub fn proof_for_child(&self, child: &Cid) -> Result<MerkleProof> {
        if self.links.len() <= 1 {
            return Err(Error::InvalidMerkleLeafCount {
                count: self.links.len(),
            });
        }
        let tree = classic_tree_for_links(&self.links)?
            .1
            .ok_or(Error::Invariant {
                detail: "multi-link leaf has no classic tree",
            })?;
        tree.proof_for_key(child.as_str()).cloned()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        cid: Cid,
        item_name: String,
        leaf_type: LeafType,
        content_hash: Option<Digest>,
        content: Option<Arc<Vec<u8>>>,
        classic_merkle_root: Option<Vec<u8>>,
        current_link_count: usize,
        leaf_count: u64,
        content_size: u64,
        dag_size: u64,
        links: Vec<Cid>,
        additional_data: Metadata,
        proofs: BTreeMap<Cid, ClassicTreeBranch>,
    ) -> Self {
        Self {
            cid,
            item_name: item_name.into(),
            leaf_type,
            content_hash,
            // Already shared by the caller. The decoder hands over the `Arc` it
            // built while reading, so a decoded payload is never copied twice.
            content,
            classic_merkle_root,
            current_link_count,
            leaf_count,
            content_size,
            dag_size,
            links,
            additional_data,
            proofs,
            parent_hash: None,
        }
    }

    /// The parent this leaf was reached through, when a reconstruction recorded
    /// one. Absent on freshly built leaves, matching Go, where only
    /// `FromSerializable` and `UpdateParentHashesStreaming` populate it.
    ///
    /// This is context, not evidence. It is never hashed and never serialized, so
    /// a peer can claim anything it likes here; check links and Merkle proofs
    /// instead when deciding whether an edge is real.
    pub fn parent_hash(&self) -> Option<&Cid> {
        self.parent_hash.as_ref()
    }

    pub(crate) fn set_parent_hash(&mut self, parent: Option<Cid>) {
        self.parent_hash = parent;
    }

    pub(crate) fn retain_links(&mut self, retained: &BTreeSet<Cid>) {
        self.links.retain(|link| retained.contains(link));
    }

    pub(crate) fn insert_bound_proof(&mut self, key: Cid, branch: ClassicTreeBranch) -> Result<()> {
        if key != branch.child {
            return Err(Error::ProofKeyMismatch {
                key: key.to_string(),
                child: branch.child.to_string(),
            });
        }
        self.proofs.insert(key, branch);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeafBuilder {
    item_name: Arc<str>,
    leaf_type: LeafType,
    data: Option<Arc<Vec<u8>>>,
    links: Vec<Cid>,
}

impl LeafBuilder {
    pub fn new(item_name: impl Into<Arc<str>>, leaf_type: LeafType) -> Self {
        Self {
            item_name: item_name.into(),
            leaf_type,
            data: None,
            links: Vec::new(),
        }
    }

    pub fn set_data(&mut self, data: impl Into<Vec<u8>>) -> &mut Self {
        // `Arc::new` moves the Vec's header rather than copying its bytes, so
        // building a leaf costs exactly what it did when this was a plain Vec.
        // `Arc<[u8]>::from(vec)` would have reallocated and memcpy'd instead,
        // paying at creation for what it saves at clone -- the wrong trade for
        // a library whose hot path is building DAGs.
        self.data = Some(Arc::new(data.into()));
        self
    }

    /// Adopt an existing leaf's payload without copying it.
    pub(crate) fn set_shared_data(&mut self, data: Arc<Vec<u8>>) -> &mut Self {
        self.data = Some(data);
        self
    }

    /// The staged payload as bytes.
    ///
    /// `Option::as_deref` stops at `&Vec<u8>` for a shared payload, so the
    /// slice is taken explicitly.
    fn data_bytes(&self) -> Option<&[u8]> {
        self.data.as_ref().map(|data| data.as_slice())
    }

    pub fn with_data(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.set_data(data);
        self
    }

    pub fn add_link(&mut self, cid: Cid) -> &mut Self {
        self.links.push(cid);
        self
    }

    pub fn with_link(mut self, cid: Cid) -> Self {
        self.add_link(cid);
        self
    }

    pub fn links(&self) -> &[Cid] {
        &self.links
    }

    pub fn build(&self, metadata: Option<&Metadata>) -> Result<DagLeaf> {
        validate_leaf_data(self.data_bytes())?;
        let (merkle_root, _) = classic_tree_for_links(&self.links)?;
        let normalized_metadata = metadata.cloned().unwrap_or_default();
        let content_hash = self.data_bytes().map(sha256);
        let identity = encode_non_root_identity(
            &self.item_name,
            self.leaf_type,
            &merkle_root,
            self.links.len() as u64,
            content_hash.as_ref(),
            metadata_array(Some(&normalized_metadata)),
        );
        Ok(self.finish_leaf(
            Cid::from_cbor(&identity),
            merkle_root,
            content_hash,
            normalized_metadata,
            0,
            0,
            0,
        ))
    }

    pub fn build_root_with_stats(
        &self,
        stats: DagStats,
        metadata: Option<&Metadata>,
    ) -> Result<DagLeaf> {
        validate_leaf_data(self.data_bytes())?;
        let (merkle_root, _) = classic_tree_for_links(&self.links)?;
        let content_hash = self.data_bytes().map(sha256);
        let leaf_count = checked_add(stats.leaf_count, 1, "LeafCount")?;
        let root_content_size = usize_to_u64(
            self.data.as_ref().map_or(0, |data| data.len()),
            "ContentSize",
        )?;
        let content_size = checked_add(stats.content_size, root_content_size, "ContentSize")?;
        let temporary = encode_root_identity(
            &self.item_name,
            self.leaf_type,
            &merkle_root,
            self.links.len() as u64,
            leaf_count,
            content_size,
            0,
            content_hash.as_ref(),
            metadata_array(metadata),
        );
        let temporary_size = usize_to_u64(temporary.len(), "DagSize")?;
        let dag_size = checked_add(stats.dag_size, temporary_size, "DagSize")?;
        let normalized_metadata = metadata.cloned().unwrap_or_default();
        let identity = encode_root_identity(
            &self.item_name,
            self.leaf_type,
            &merkle_root,
            self.links.len() as u64,
            leaf_count,
            content_size,
            dag_size,
            content_hash.as_ref(),
            metadata_array(Some(&normalized_metadata)),
        );
        Ok(self.finish_leaf(
            Cid::from_cbor(&identity),
            merkle_root,
            content_hash,
            normalized_metadata,
            leaf_count,
            content_size,
            dag_size,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_leaf(
        &self,
        cid: Cid,
        classic_merkle_root: Vec<u8>,
        content_hash: Option<Digest>,
        additional_data: Metadata,
        leaf_count: u64,
        content_size: u64,
        dag_size: u64,
    ) -> DagLeaf {
        let mut links = self.links.clone();
        if self.leaf_type == LeafType::Directory {
            links.sort();
        }
        DagLeaf {
            cid,
            item_name: self.item_name.clone(),
            leaf_type: self.leaf_type,
            content_hash,
            // An `Arc` clone: the finished leaf shares the builder's payload
            // instead of duplicating it, which used to be a full memcpy per leaf.
            content: self.data.clone(),
            classic_merkle_root: Some(classic_merkle_root),
            current_link_count: self.links.len(),
            leaf_count,
            content_size,
            dag_size,
            links,
            additional_data,
            proofs: BTreeMap::new(),
            parent_hash: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DagBuilder {
    leaves: BTreeMap<Cid, DagLeaf>,
    stats: DagStats,
}

impl DagBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_leaf(&mut self, leaf: DagLeaf) -> Result<bool> {
        if self.leaves.contains_key(leaf.cid()) {
            return Ok(false);
        }
        validate_leaf_data(leaf.content())?;
        let serialized_size = leaf.storage_size()?;
        self.stats.leaf_count = checked_add(self.stats.leaf_count, 1, "LeafCount")?;
        if let Some(content) = leaf.content() {
            self.stats.content_size = checked_add(
                self.stats.content_size,
                usize_to_u64(content.len(), "ContentSize")?,
                "ContentSize",
            )?;
        }
        self.stats.dag_size = checked_add(self.stats.dag_size, serialized_size, "DagSize")?;
        self.leaves.insert(leaf.cid().clone(), leaf);
        Ok(true)
    }

    fn extend_batch(&mut self, batch: LeafBatch) -> Result<()> {
        for leaf in batch.leaves {
            self.add_leaf(leaf)?;
        }
        Ok(())
    }

    pub fn stats(&self) -> DagStats {
        self.stats
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn leaves(&self) -> &BTreeMap<Cid, DagLeaf> {
        &self.leaves
    }

    pub fn finish(
        mut self,
        root_builder: &LeafBuilder,
        metadata: Option<&Metadata>,
    ) -> Result<Dag> {
        let root = root_builder.build_root_with_stats(self.stats, metadata)?;
        let root_cid = root.cid().clone();
        self.leaves.insert(root_cid.clone(), root);
        Ok(Dag {
            root: root_cid,
            leaves: self.leaves,
            labels: Labels::new(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Dag {
    pub(crate) root: Cid,
    pub(crate) leaves: BTreeMap<Cid, DagLeaf>,
    pub(crate) labels: Labels,
}

impl PartialEq for Dag {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root && self.leaves == other.leaves
    }
}

impl Eq for Dag {}

impl Dag {
    pub fn root(&self) -> &Cid {
        &self.root
    }

    pub fn try_root_leaf(&self) -> Option<&DagLeaf> {
        self.leaves.get(&self.root)
    }

    pub fn root_leaf(&self) -> &DagLeaf {
        self.try_root_leaf()
            .expect("a constructed DAG always contains its root")
    }

    pub fn leaves(&self) -> &BTreeMap<Cid, DagLeaf> {
        &self.leaves
    }

    pub fn get(&self, cid: &Cid) -> Option<&DagLeaf> {
        self.leaves.get(cid)
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub(crate) fn from_parts(root: Cid, leaves: BTreeMap<Cid, DagLeaf>) -> Result<Self> {
        if !leaves.contains_key(&root) {
            return Err(Error::MissingRoot);
        }
        for (key, leaf) in &leaves {
            if key != leaf.cid() {
                return Err(Error::CidKeyMismatch {
                    key: key.to_string(),
                    cid: leaf.cid().to_string(),
                });
            }
        }
        let mut dag = Self {
            root,
            leaves,
            labels: Labels::new(),
        };
        // A DAG assembled from parts -- decoded, received, or diff-applied --
        // derives each leaf's parent, the way Go's FromSerializable does.
        // minimum_parent_index resolves a shared chunk's several parents to the
        // lowest parent CID, so decoding the same bytes twice attributes the same
        // parent to every leaf. Resolving in map order instead is precisely the
        // nondeterminism that made Go's verification fail about one run in thirty.
        let parents = dag.build_parent_index();
        for (cid, parent) in parents {
            if let Some(leaf) = dag.leaves.get_mut(&cid) {
                leaf.parent_hash = Some(parent);
            }
        }
        Ok(dag)
    }

    pub(crate) fn build_parent_index(&self) -> BTreeMap<Cid, Cid> {
        minimum_parent_index(
            self.leaves
                .iter()
                .map(|(parent, leaf)| (parent, leaf.links())),
        )
    }

    pub fn visit_unique<F>(&self, mut visitor: F) -> Result<()>
    where
        F: FnMut(&DagLeaf, Option<&DagLeaf>) -> Result<()>,
    {
        let parent_of = self.build_parent_index();
        let mut visited = BTreeSet::new();
        let mut stack = vec![self.root.clone()];
        while let Some(cid) = stack.pop() {
            let leaf = self.leaves.get(&cid).ok_or_else(|| Error::MissingLeaf {
                cid: cid.to_string(),
            })?;
            if !visited.insert(cid.clone()) {
                continue;
            }
            let parent = if cid == self.root {
                None
            } else {
                let parent_cid = parent_of.get(&cid).ok_or(Error::Invariant {
                    detail: "a visited non-root leaf has no parent",
                })?;
                Some(
                    self.leaves
                        .get(parent_cid)
                        .ok_or_else(|| Error::MissingLeaf {
                            cid: parent_cid.to_string(),
                        })?,
                )
            };
            visitor(leaf, parent)?;
            for child in leaf.links.iter().rev() {
                stack.push(child.clone());
            }
        }
        Ok(())
    }
}

pub(crate) fn minimum_parent_index<'a, I>(parents: I) -> BTreeMap<Cid, Cid>
where
    I: IntoIterator<Item = (&'a Cid, &'a [Cid])>,
{
    let mut parent_of = BTreeMap::<Cid, Cid>::new();
    for (parent, children) in parents {
        for child in children {
            match parent_of.get(child) {
                Some(existing) if existing.as_str() <= parent.as_str() => {}
                _ => {
                    parent_of.insert(child.clone(), parent.clone());
                }
            }
        }
    }
    parent_of
}

#[derive(Default)]
struct LeafBatch {
    leaves: Vec<DagLeaf>,
}

impl LeafBatch {
    fn push(&mut self, leaf: DagLeaf) {
        self.leaves.push(leaf);
    }

    fn extend(&mut self, mut other: Self) {
        self.leaves.append(&mut other.leaves);
    }
}

struct EntryJob {
    index: usize,
    name: String,
    path: PathBuf,
    entry: DirEntry,
    is_dir: bool,
}

struct IndexedEntryResult {
    index: usize,
    outcome: Result<(DagLeaf, LeafBatch)>,
}

trait ProcessorFn: Fn(&Path, &str, &DirEntry, bool, LeafType) -> Option<Metadata> {}

impl<T> ProcessorFn for T where
    T: Fn(&Path, &str, &DirEntry, bool, LeafType) -> Option<Metadata> + ?Sized
{
}

trait EntryScheduler<P: ProcessorFn + ?Sized>: Copy {
    fn process_jobs(
        self,
        jobs: Vec<EntryJob>,
        options: &DagBuildOptions,
        processor: Option<&P>,
    ) -> Vec<IndexedEntryResult>;
}

#[derive(Clone, Copy)]
struct SequentialScheduler;

impl<P: ProcessorFn + ?Sized> EntryScheduler<P> for SequentialScheduler {
    fn process_jobs(
        self,
        jobs: Vec<EntryJob>,
        options: &DagBuildOptions,
        processor: Option<&P>,
    ) -> Vec<IndexedEntryResult> {
        jobs.into_iter()
            .map(|job| {
                let index = job.index;
                IndexedEntryResult {
                    index,
                    outcome: process_entry(job, options, processor, self),
                }
            })
            .collect()
    }
}

#[derive(Clone, Copy)]
struct ParallelScheduler {
    workers: DagWorkerCount,
}

impl<P: ProcessorFn + Sync + ?Sized> EntryScheduler<P> for ParallelScheduler {
    fn process_jobs(
        self,
        jobs: Vec<EntryJob>,
        options: &DagBuildOptions,
        processor: Option<&P>,
    ) -> Vec<IndexedEntryResult> {
        if jobs.len() > 1 {
            let worker_count = resolve_worker_count(self.workers, jobs.len());
            process_entries_parallel(jobs, worker_count, options, processor, self)
        } else {
            jobs.into_iter()
                .map(|job| {
                    let index = job.index;
                    IndexedEntryResult {
                        index,
                        outcome: process_entry(job, options, processor, self),
                    }
                })
                .collect()
        }
    }
}

fn resolve_worker_count(mode: DagWorkerCount, entry_count: usize) -> usize {
    if entry_count == 0 {
        return 0;
    }
    let requested = match mode {
        DagWorkerCount::Auto => std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(1),
        DagWorkerCount::PerEntry => entry_count,
        DagWorkerCount::Fixed(count) => count.get(),
    };
    requested.min(entry_count)
}

pub fn create_dag(path: impl AsRef<Path>) -> Result<Dag> {
    create_dag_with_options(path, &DagBuildOptions::default())
}

pub fn create_dag_with_options(path: impl AsRef<Path>, options: &DagBuildOptions) -> Result<Dag> {
    create_dag_impl(
        path.as_ref(),
        options,
        None::<&LeafProcessor>,
        SequentialScheduler,
    )
}

pub fn create_dag_custom(
    path: impl AsRef<Path>,
    options: &DagBuildOptions,
    processor: Option<&LeafProcessor>,
) -> Result<Dag> {
    create_dag_impl(path.as_ref(), options, processor, SequentialScheduler)
}

pub fn create_dag_parallel(
    path: impl AsRef<Path>,
    options: &ParallelDagBuildOptions,
) -> Result<Dag> {
    create_dag_impl(
        path.as_ref(),
        &options.base,
        None::<&SyncLeafProcessor>,
        ParallelScheduler {
            workers: options.workers,
        },
    )
}

pub fn create_dag_custom_parallel(
    path: impl AsRef<Path>,
    options: &ParallelDagBuildOptions,
    processor: Option<&SyncLeafProcessor>,
) -> Result<Dag> {
    create_dag_impl(
        path.as_ref(),
        &options.base,
        processor,
        ParallelScheduler {
            workers: options.workers,
        },
    )
}

fn create_dag_impl<P, S>(
    path: &Path,
    options: &DagBuildOptions,
    processor: Option<&P>,
    scheduler: S,
) -> Result<Dag>
where
    P: ProcessorFn + ?Sized,
    S: EntryScheduler<P>,
{
    validate_chunking(options.chunking())?;
    let filesystem_metadata = fs::metadata(path).map_err(|error| io_error("stat", path, error))?;
    let root_name = root_item_name(path)?;
    let mut effective_root_metadata = if options.timestamp_root() {
        timestamp_root_metadata()?
    } else {
        options.root_metadata().clone()
    };
    // The library owns the chunking tag: a root cut with fastcdc-v1 records
    // it in its additional data (overwriting any caller-supplied value),
    // because a tag that does not reflect how the tree was actually cut
    // breaks delta tooling. Legacy fixed/disabled modes stamp nothing
    // (absent tag ⇒ fixed-2m). Stamped AFTER the timestamp replacement
    // above, matching the Go library's order exactly — root metadata is
    // hashed into the root CID, so the order is cross-language normative.
    if options.chunking() == Chunking::FastCdcV1 {
        effective_root_metadata.insert(CHUNKING_TAG_KEY.to_owned(), CHUNKING_FASTCDC_V1.to_owned());
    }
    let (provisional, batch) = if filesystem_metadata.is_dir() {
        process_directory(path, root_name, None, true, options, processor, scheduler)?
    } else {
        process_file(path, root_name, None, true, options, processor)?
    };
    let mut dag_builder = DagBuilder::new();
    dag_builder.extend_batch(batch)?;
    let mut root_builder = LeafBuilder::new(provisional.item_name(), provisional.leaf_type());
    for link in provisional.links() {
        root_builder.add_link(link.clone());
    }
    if let Some(content) = provisional.content_arc() {
        root_builder.set_shared_data(content);
    }
    dag_builder.finish(&root_builder, Some(&effective_root_metadata))
}

fn collect_entry_jobs(path: &Path) -> Result<Vec<EntryJob>> {
    let read_dir = fs::read_dir(path).map_err(|error| io_error("read directory", path, error))?;
    let mut entries = Vec::<(String, PathBuf, DirEntry, bool)>::new();
    for entry in read_dir {
        let entry = entry.map_err(|error| io_error("read directory entry", path, error))?;
        let entry_path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::NonUtf8FileName {
                path: entry_path.clone(),
            })?;
        let is_dir = entry
            .file_type()
            .map_err(|error| io_error("inspect directory entry", &entry_path, error))?
            .is_dir();
        entries.push((name, entry_path, entry, is_dir));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries
        .into_iter()
        .enumerate()
        .map(|(index, (name, path, entry, is_dir))| EntryJob {
            index,
            name,
            path,
            entry,
            is_dir,
        })
        .collect())
}

fn process_entry<P, S>(
    job: EntryJob,
    options: &DagBuildOptions,
    processor: Option<&P>,
    scheduler: S,
) -> Result<(DagLeaf, LeafBatch)>
where
    P: ProcessorFn + ?Sized,
    S: EntryScheduler<P>,
{
    if job.is_dir {
        process_directory(
            &job.path,
            job.name,
            Some(&job.entry),
            false,
            options,
            processor,
            scheduler,
        )
    } else {
        process_file(
            &job.path,
            job.name,
            Some(&job.entry),
            false,
            options,
            processor,
        )
    }
}

fn process_entries_parallel<P>(
    jobs: Vec<EntryJob>,
    worker_count: usize,
    options: &DagBuildOptions,
    processor: Option<&P>,
    scheduler: ParallelScheduler,
) -> Vec<IndexedEntryResult>
where
    P: ProcessorFn + Sync + ?Sized,
{
    let queue = Mutex::new(VecDeque::from(jobs));
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            handles.push(scope.spawn(|| {
                let mut results = Vec::new();
                loop {
                    let job = queue
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .pop_front();
                    let Some(job) = job else {
                        break;
                    };
                    let index = job.index;
                    results.push(IndexedEntryResult {
                        index,
                        outcome: process_entry(job, options, processor, scheduler),
                    });
                }
                results
            }));
        }
        let mut results = Vec::new();
        for handle in handles {
            match handle.join() {
                Ok(mut worker_results) => results.append(&mut worker_results),
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
        results
    })
}

#[allow(clippy::too_many_arguments)]
fn process_directory<P, S>(
    path: &Path,
    item_name: String,
    entry: Option<&DirEntry>,
    is_root: bool,
    options: &DagBuildOptions,
    processor: Option<&P>,
    scheduler: S,
) -> Result<(DagLeaf, LeafBatch)>
where
    P: ProcessorFn + ?Sized,
    S: EntryScheduler<P>,
{
    let additional_data = metadata_for_entry(
        None,
        path,
        &item_name,
        entry,
        is_root,
        LeafType::Directory,
        processor,
    );
    let jobs = collect_entry_jobs(path)?;
    let mut results = scheduler.process_jobs(jobs, options, processor);
    results.sort_by_key(|result| result.index);
    let mut leaf_builder = LeafBuilder::new(item_name, LeafType::Directory);
    let mut batch = LeafBatch::default();
    for result in results {
        let (child, child_batch) = result.outcome?;
        batch.extend(child_batch);
        leaf_builder.add_link(child.cid().clone());
        batch.push(child);
    }
    Ok((leaf_builder.build(additional_data.as_ref())?, batch))
}

#[allow(clippy::too_many_arguments)]
fn process_file<P: ProcessorFn + ?Sized>(
    path: &Path,
    item_name: String,
    entry: Option<&DirEntry>,
    is_root: bool,
    options: &DagBuildOptions,
    processor: Option<&P>,
) -> Result<(DagLeaf, LeafBatch)> {
    let additional_data = metadata_for_entry(
        None,
        path,
        &item_name,
        entry,
        is_root,
        LeafType::File,
        processor,
    );
    let mut file = File::open(path).map_err(|error| io_error("open file", path, error))?;
    let mut leaf_builder = LeafBuilder::new(item_name, LeafType::File);
    let mut batch = LeafBatch::default();
    match options.chunking() {
        Chunking::Disabled => {
            leaf_builder.set_data(read_disabled_file(&mut file, path)?);
        }
        Chunking::FastCdcV1 => {
            // Same first-chunk deferral as the fixed path below: a file
            // that cuts to a single chunk stores its data on the file leaf
            // and produces no chunk leaves.
            let mut first_chunk: Option<Vec<u8>> = None;
            let mut produced = 0_usize;
            stream_fastcdc_chunks(&mut file, path, |chunk, index| {
                if index == 0 {
                    first_chunk = Some(chunk);
                } else {
                    if index == 1 {
                        let first = first_chunk.take().ok_or(Error::Invariant {
                            detail: "first file chunk was lost",
                        })?;
                        add_chunk(&mut leaf_builder, &mut batch, 0, first)?;
                    }
                    add_chunk(&mut leaf_builder, &mut batch, index, chunk)?;
                }
                produced = index + 1;
                Ok(())
            })?;
            if produced == 1 {
                leaf_builder.set_data(first_chunk.take().ok_or(Error::Invariant {
                    detail: "single file chunk was lost",
                })?);
            }
        }
        Chunking::Fixed(chunk_size) => {
            let mut remaining = file
                .metadata()
                .map_err(|error| io_error("stat open file", path, error))?
                .len();
            if remaining != 0 {
                let chunk_size = usize_to_u64(chunk_size.get(), "chunk size")?;
                ensure_in_memory_limit("chunk buffer", chunk_size)?;
                let mut first_chunk: Option<Vec<u8>> = None;
                let mut index = 0_usize;
                while remaining != 0 {
                    let next_size = remaining.min(chunk_size);
                    ensure_in_memory_limit("chunk buffer", next_size)?;
                    let next_size_usize =
                        usize::try_from(next_size).map_err(|_| Error::SizeOverflow {
                            field: "chunk size",
                        })?;
                    let mut chunk = Vec::new();
                    reserve_exact_bytes(&mut chunk, next_size_usize, "chunk buffer", next_size)?;
                    chunk.resize(next_size_usize, 0);
                    file.read_exact(&mut chunk)
                        .map_err(|error| io_error("read file chunk", path, error))?;
                    if index == 0 {
                        first_chunk = Some(chunk);
                    } else {
                        if index == 1 {
                            let first = first_chunk.take().ok_or(Error::Invariant {
                                detail: "first file chunk was lost",
                            })?;
                            add_chunk(&mut leaf_builder, &mut batch, 0, first)?;
                        }
                        add_chunk(&mut leaf_builder, &mut batch, index, chunk)?;
                    }
                    remaining -= next_size;
                    index += 1;
                }
                if index == 1 {
                    leaf_builder.set_data(first_chunk.take().ok_or(Error::Invariant {
                        detail: "single file chunk was lost",
                    })?);
                }
            }
        }
    }
    Ok((leaf_builder.build(additional_data.as_ref())?, batch))
}

fn read_disabled_file(file: &mut File, path: &Path) -> Result<Vec<u8>> {
    let declared_size = file
        .metadata()
        .map_err(|error| io_error("stat open file", path, error))?
        .len();
    ensure_in_memory_limit("file content", declared_size)?;
    let reserve = usize::try_from(declared_size).map_err(|_| Error::SizeOverflow {
        field: "file content",
    })?;
    let mut data = Vec::new();
    reserve_exact_bytes(&mut data, reserve, "file content", declared_size)?;
    let mut buffer = [0_u8; 8192];
    loop {
        if data.len() == MAX_IN_MEMORY_LEAF_BYTES {
            let mut probe = [0_u8; 1];
            let read = file
                .read(&mut probe)
                .map_err(|error| io_error("probe file growth", path, error))?;
            if read != 0 {
                return Err(Error::InMemoryLimitExceeded {
                    resource: "file content",
                    requested: MAX_IN_MEMORY_LEAF_BYTES as u64 + 1,
                    limit: MAX_IN_MEMORY_LEAF_BYTES as u64,
                });
            }
            break;
        }
        let available = (MAX_IN_MEMORY_LEAF_BYTES - data.len()).min(buffer.len());
        let read = file
            .read(&mut buffer[..available])
            .map_err(|error| io_error("read file", path, error))?;
        if read == 0 {
            break;
        }
        let requested = usize_to_u64(data.len() + read, "file content")?;
        reserve_exact_bytes(&mut data, read, "file content", requested)?;
        data.extend_from_slice(&buffer[..read]);
    }
    Ok(data)
}

fn metadata_for_entry<P: ProcessorFn + ?Sized>(
    base: Option<&Metadata>,
    path: &Path,
    relative_path: &str,
    entry: Option<&DirEntry>,
    is_root: bool,
    leaf_type: LeafType,
    processor: Option<&P>,
) -> Option<Metadata> {
    let custom = match (processor, entry) {
        (Some(processor), Some(entry)) if !is_root => {
            processor(path, relative_path, entry, is_root, leaf_type)
        }
        _ => None,
    };
    merge_metadata(base, custom)
}

fn merge_metadata(base: Option<&Metadata>, custom: Option<Metadata>) -> Option<Metadata> {
    match (base, custom) {
        (None, None) => None,
        (Some(base), None) => Some(base.clone()),
        (None, Some(custom)) => Some(custom),
        (Some(base), Some(custom)) => {
            let mut merged = base.clone();
            merged.extend(custom);
            Some(merged)
        }
    }
}

fn add_chunk(
    file_builder: &mut LeafBuilder,
    batch: &mut LeafBatch,
    index: usize,
    data: Vec<u8>,
) -> Result<()> {
    let chunk = LeafBuilder::new(index.to_string(), LeafType::Chunk)
        .with_data(data)
        .build(None)?;
    file_builder.add_link(chunk.cid().clone());
    batch.push(chunk);
    Ok(())
}

fn chunk_index_from_item_name(name: &str) -> Option<isize> {
    let tail = name.rfind(['/', '\\']).map_or(name, |cut| &name[cut + 1..]);
    tail.parse::<isize>().ok()
}

/// The order in which a chunked file's chunk leaves are concatenated back into
/// the file: by the numeric chunk index in each leaf's item name, exactly as
/// `Dag::get_content_from_leaf` assembles them. Public so a caller that copies
/// verified chunk bytes from its own storage can reproduce the file without
/// holding it whole.
pub fn compare_chunk_item_names(left: &str, right: &str) -> Ordering {
    match (
        chunk_index_from_item_name(left),
        chunk_index_from_item_name(right),
    ) {
        (Some(left), Some(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}

pub(crate) fn safe_join(base: &Path, name: &str) -> Result<PathBuf> {
    let unsafe_name = || Error::UnsafeItemName {
        name: name.to_owned(),
    };
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || Path::new(name).is_absolute()
    {
        return Err(unsafe_name());
    }
    let child = base.join(name);
    let relative = child.strip_prefix(base).map_err(|_| unsafe_name())?;
    if matches!(
        relative.components().next(),
        Some(std::path::Component::ParentDir)
    ) {
        return Err(unsafe_name());
    }
    Ok(child)
}

fn root_item_name(path: &Path) -> Result<String> {
    let raw = path.to_str().ok_or_else(|| Error::NonUtf8FileName {
        path: path.to_path_buf(),
    })?;
    let parent = go_dir(raw);
    go_rel(&parent, raw).ok_or(Error::Invariant {
        detail: "root path cannot be made relative to its lexical parent",
    })
}

fn go_dir(path: &str) -> String {
    let volume_len = go_volume_name_len(path);
    let bytes = path.as_bytes();
    let mut end = bytes.len();
    while end > volume_len && !is_go_separator(bytes[end - 1]) {
        end -= 1;
    }
    let cleaned = go_clean(&path[..end]);
    if cleaned == "." && volume_len > 2 {
        path[..volume_len].to_owned()
    } else {
        cleaned
    }
}

fn go_clean(path: &str) -> String {
    let volume_len = go_volume_name_len(path);
    let volume = &path[..volume_len];
    let remainder = &path[volume_len..];
    let rooted = remainder
        .as_bytes()
        .first()
        .is_some_and(|byte| is_go_separator(*byte))
        || cfg!(windows) && volume_len > 2;
    let mut components = Vec::<&str>::new();
    for component in remainder.split(is_go_separator_char) {
        match component {
            "" | "." => {}
            ".." => {
                if matches!(components.last(), Some(last) if *last != "..") {
                    components.pop();
                } else if !rooted {
                    components.push(component);
                }
            }
            _ => components.push(component),
        }
    }
    let separator = std::path::MAIN_SEPARATOR;
    let mut output = if cfg!(windows) {
        volume
            .chars()
            .map(|character| {
                if character == '/' || character == '\\' {
                    separator
                } else {
                    character
                }
            })
            .collect::<String>()
    } else {
        volume.to_owned()
    };
    let bare_unc_root = cfg!(windows) && volume_len > 2 && remainder.is_empty();
    if rooted
        && !bare_unc_root
        && !output
            .as_bytes()
            .last()
            .is_some_and(|byte| is_go_separator(*byte))
    {
        output.push(separator);
    }
    if components.is_empty() {
        if rooted {
            if output.is_empty() {
                output.push(separator);
            }
            return output;
        }
        if !volume.is_empty() {
            output.push('.');
            return output;
        }
        return ".".to_owned();
    }
    let bare_windows_volume = cfg!(windows) && volume_len == 2 && !rooted;
    if !output.is_empty() && !output.ends_with(separator) && !bare_windows_volume {
        output.push(separator);
    }
    output.push_str(&components.join(&separator.to_string()));
    output
}

fn go_rel(base_path: &str, target_path: &str) -> Option<String> {
    let base = go_clean(base_path);
    let target = go_clean(target_path);
    if go_same_word(&base, &target) {
        return Some(".".to_owned());
    }
    let base_volume_len = go_volume_name_len(&base);
    let target_volume_len = go_volume_name_len(&target);
    let base_volume = &base[..base_volume_len];
    let target_volume = &target[..target_volume_len];
    if !go_same_word(base_volume, target_volume) {
        return None;
    }
    let mut base_remainder = &base[base_volume_len..];
    let mut target_remainder = &target[target_volume_len..];
    if base_remainder == "." {
        base_remainder = "";
    }
    let base_rooted = base_remainder
        .as_bytes()
        .first()
        .is_some_and(|byte| is_go_separator(*byte))
        || cfg!(windows) && base_volume_len > 2;
    let target_rooted = target_remainder
        .as_bytes()
        .first()
        .is_some_and(|byte| is_go_separator(*byte))
        || cfg!(windows) && target_volume_len > 2;
    if base_rooted != target_rooted {
        return None;
    }
    base_remainder = base_remainder.trim_start_matches(is_go_separator_char);
    target_remainder = target_remainder.trim_start_matches(is_go_separator_char);
    let base_components: Vec<&str> = if base_remainder.is_empty() {
        Vec::new()
    } else {
        base_remainder.split(is_go_separator_char).collect()
    };
    let target_components: Vec<&str> = if target_remainder.is_empty() {
        Vec::new()
    } else {
        target_remainder.split(is_go_separator_char).collect()
    };
    let mut common = 0;
    while common < base_components.len()
        && common < target_components.len()
        && go_same_word(base_components[common], target_components[common])
    {
        common += 1;
    }
    if matches!(base_components.get(common), Some(component) if *component == "..") {
        return None;
    }
    let mut relative = Vec::<&str>::new();
    relative.extend(std::iter::repeat_n("..", base_components.len() - common));
    relative.extend_from_slice(&target_components[common..]);
    if relative.is_empty() {
        Some(".".to_owned())
    } else {
        Some(relative.join(std::path::MAIN_SEPARATOR_STR))
    }
}

fn is_go_separator(byte: u8) -> bool {
    byte == b'/' || cfg!(windows) && byte == b'\\'
}

fn is_go_separator_char(character: char) -> bool {
    character == '/' || cfg!(windows) && character == '\\'
}

fn go_same_word(left: &str, right: &str) -> bool {
    if cfg!(windows) {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}

#[cfg(not(windows))]
fn go_volume_name_len(_path: &str) -> usize {
    0
}

#[cfg(windows)]
fn go_volume_name_len(path: &str) -> usize {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        return 2;
    }
    if bytes.len() < 2 || !is_go_separator(bytes[0]) || !is_go_separator(bytes[1]) {
        return 0;
    }
    let mut cursor = 2;
    let server_start = cursor;
    while cursor < bytes.len() && !is_go_separator(bytes[cursor]) {
        cursor += 1;
    }
    if cursor == server_start || cursor == bytes.len() {
        return 0;
    }
    cursor += 1;
    let share_start = cursor;
    while cursor < bytes.len() && !is_go_separator(bytes[cursor]) {
        cursor += 1;
    }
    if cursor == share_start {
        0
    } else {
        cursor
    }
}

fn timestamp_root_metadata() -> Result<Metadata> {
    let timestamp = format_system_time_rfc3339_utc(SystemTime::now())?;
    Ok(Metadata::from([("timestamp".to_owned(), timestamp)]))
}

fn format_system_time_rfc3339_utc(time: SystemTime) -> Result<String> {
    let elapsed = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::SystemTimeBeforeUnixEpoch)?;
    let seconds =
        i64::try_from(elapsed.as_secs()).map_err(|_| Error::SizeOverflow { field: "timestamp" })?;
    Ok(format_epoch_seconds_rfc3339_utc(seconds))
}

fn format_epoch_seconds_rfc3339_utc(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let shifted_days = days + 719_468;
    let era = shifted_days.div_euclid(146_097);
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    let hour = seconds_of_day / 3_600;
    let minute = seconds_of_day % 3_600 / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
fn proof_for_parent_child(parent: &DagLeaf, child: &Cid) -> Result<Option<MerkleProof>> {
    if !parent.links().contains(child) {
        return Err(Error::MissingMerkleKey {
            key: child.to_string(),
        });
    }
    if parent.links().len() <= 1 {
        return Ok(None);
    }
    let tree = classic_tree_for_links(parent.links())?
        .1
        .ok_or(Error::Invariant {
            detail: "multi-link leaf has no classic tree",
        })?;
    Ok(Some(tree.proof_for_key(child.as_str())?.clone()))
}

#[cfg(test)]
fn proofs_for_present_children(
    dag: &Dag,
    present: &BTreeSet<Cid>,
) -> Result<BTreeMap<Cid, BTreeMap<Cid, MerkleProof>>> {
    let mut proofs = BTreeMap::new();
    for parent_cid in present {
        let parent = dag.get(parent_cid).ok_or_else(|| Error::MissingLeaf {
            cid: parent_cid.to_string(),
        })?;
        let mut child_proofs = BTreeMap::new();
        for child in parent.links() {
            if present.contains(child) {
                if let Some(proof) = proof_for_parent_child(parent, child)? {
                    child_proofs.insert(child.clone(), proof);
                }
            }
        }
        if !child_proofs.is_empty() {
            proofs.insert(parent_cid.clone(), child_proofs);
        }
    }
    Ok(proofs)
}

pub(crate) fn assemble_chunk_content(dag: &Dag, file: &DagLeaf, max_bytes: u64) -> Result<Vec<u8>> {
    let mut chunks = Vec::<&DagLeaf>::with_capacity(file.links().len());
    for cid in file.links() {
        let chunk = dag.get(cid).ok_or_else(|| Error::MissingLeaf {
            cid: cid.to_string(),
        })?;
        chunks.push(chunk);
    }
    chunks.sort_by(|left, right| compare_chunk_item_names(left.item_name(), right.item_name()));

    let mut total = 0_u64;
    for chunk in &chunks {
        if let Some(content) = chunk.content() {
            total = checked_add(
                total,
                usize_to_u64(content.len(), "assembled content")?,
                "assembled content",
            )?;
        }
    }
    if total > max_bytes {
        return Err(Error::InMemoryLimitExceeded {
            resource: "assembled content",
            requested: total,
            limit: max_bytes,
        });
    }

    let total_usize = usize::try_from(total).map_err(|_| Error::SizeOverflow {
        field: "assembled content",
    })?;
    let mut output = Vec::new();
    reserve_exact_bytes(&mut output, total_usize, "assembled content", total)?;
    for chunk in chunks {
        if let Some(content) = chunk.content() {
            output.extend_from_slice(content);
        }
    }
    Ok(output)
}

pub(crate) fn classic_tree_for_links(
    links: &[Cid],
) -> Result<(Vec<u8>, Option<ClassicMerkleTree>)> {
    match links {
        [] => Ok((Vec::new(), None)),
        [only] => Ok((only.as_str().as_bytes().to_vec(), None)),
        _ => {
            let blocks = links
                .iter()
                .map(|cid| (cid.as_str().to_owned(), cid.as_str().as_bytes().to_vec()));
            let tree = ClassicMerkleTree::build(blocks)?;
            Ok((tree.root().to_vec(), Some(tree)))
        }
    }
}

pub(crate) fn metadata_array(metadata: Option<&Metadata>) -> CborValue {
    match metadata {
        None => CborValue::Null,
        Some(metadata) => CborValue::Array(
            metadata
                .iter()
                .map(|(key, value)| {
                    CborValue::Map(vec![
                        ("Key".to_owned(), CborValue::Text(key.clone())),
                        ("Value".to_owned(), CborValue::Text(value.clone())),
                    ])
                })
                .collect(),
        ),
    }
}

fn optional_digest(value: Option<&Digest>) -> CborValue {
    value
        .map(|digest| CborValue::Bytes(digest.to_vec()))
        .unwrap_or(CborValue::Null)
}

#[cfg(test)]
fn optional_bytes(value: Option<&[u8]>) -> CborValue {
    value
        .map(|bytes| CborValue::Bytes(bytes.to_vec()))
        .unwrap_or(CborValue::Null)
}

pub(crate) fn encode_non_root_identity(
    item_name: &str,
    leaf_type: LeafType,
    merkle_root: &[u8],
    link_count: u64,
    content_hash: Option<&Digest>,
    additional_data: CborValue,
) -> Vec<u8> {
    cbor_encode(&CborValue::Map(vec![
        ("ItemName".to_owned(), CborValue::Text(item_name.to_owned())),
        (
            "Type".to_owned(),
            CborValue::Text(leaf_type.as_str().to_owned()),
        ),
        (
            "MerkleRoot".to_owned(),
            CborValue::Bytes(merkle_root.to_vec()),
        ),
        (
            "CurrentLinkCount".to_owned(),
            CborValue::Unsigned(link_count),
        ),
        ("ContentHash".to_owned(), optional_digest(content_hash)),
        ("AdditionalData".to_owned(), additional_data),
    ]))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_root_identity(
    item_name: &str,
    leaf_type: LeafType,
    merkle_root: &[u8],
    link_count: u64,
    leaf_count: u64,
    content_size: u64,
    dag_size: u64,
    content_hash: Option<&Digest>,
    additional_data: CborValue,
) -> Vec<u8> {
    cbor_encode(&CborValue::Map(vec![
        ("ItemName".to_owned(), CborValue::Text(item_name.to_owned())),
        (
            "Type".to_owned(),
            CborValue::Text(leaf_type.as_str().to_owned()),
        ),
        (
            "MerkleRoot".to_owned(),
            CborValue::Bytes(merkle_root.to_vec()),
        ),
        (
            "CurrentLinkCount".to_owned(),
            CborValue::Unsigned(link_count),
        ),
        ("LeafCount".to_owned(), CborValue::Unsigned(leaf_count)),
        ("ContentSize".to_owned(), CborValue::Unsigned(content_size)),
        ("DagSize".to_owned(), CborValue::Unsigned(dag_size)),
        ("ContentHash".to_owned(), optional_digest(content_hash)),
        ("AdditionalData".to_owned(), additional_data),
    ]))
}

#[cfg(test)]
fn encode_storage_shape(leaf: &DagLeaf) -> Vec<u8> {
    let links = if leaf.links.is_empty() {
        CborValue::Null
    } else {
        CborValue::Array(
            leaf.links
                .iter()
                .map(|cid| CborValue::Text(cid.to_string()))
                .collect(),
        )
    };
    let additional_data = CborValue::Map(
        leaf.additional_data
            .iter()
            .map(|(key, value)| (key.clone(), CborValue::Text(value.clone())))
            .collect(),
    );
    cbor_encode(&CborValue::Map(vec![
        ("Hash".to_owned(), CborValue::Text(leaf.cid.to_string())),
        (
            "ItemName".to_owned(),
            CborValue::Text(leaf.item_name.to_string()),
        ),
        (
            "Type".to_owned(),
            CborValue::Text(leaf.leaf_type.as_str().to_owned()),
        ),
        (
            "ContentHash".to_owned(),
            optional_digest(leaf.content_hash.as_ref()),
        ),
        ("Content".to_owned(), optional_bytes(leaf.content())),
        (
            "ClassicMerkleRoot".to_owned(),
            optional_bytes(leaf.classic_merkle_root.as_deref()),
        ),
        (
            "CurrentLinkCount".to_owned(),
            CborValue::Unsigned(leaf.current_link_count as u64),
        ),
        ("LeafCount".to_owned(), CborValue::Unsigned(leaf.leaf_count)),
        (
            "ContentSize".to_owned(),
            CborValue::Unsigned(leaf.content_size),
        ),
        ("DagSize".to_owned(), CborValue::Unsigned(leaf.dag_size)),
        ("Links".to_owned(), links),
        ("AdditionalData".to_owned(), additional_data),
    ]))
}

fn checked_add(left: u64, right: u64, field: &'static str) -> Result<u64> {
    left.checked_add(right).ok_or(Error::SizeOverflow { field })
}

fn usize_to_u64(value: usize, field: &'static str) -> Result<u64> {
    u64::try_from(value).map_err(|_| Error::SizeOverflow { field })
}

fn ensure_in_memory_limit(resource: &'static str, requested: u64) -> Result<()> {
    let limit = MAX_IN_MEMORY_LEAF_BYTES as u64;
    if requested > limit {
        Err(Error::InMemoryLimitExceeded {
            resource,
            requested,
            limit,
        })
    } else {
        Ok(())
    }
}

fn validate_chunking(chunking: Chunking) -> Result<()> {
    if let Chunking::Fixed(size) = chunking {
        ensure_in_memory_limit("chunk buffer", usize_to_u64(size.get(), "chunk size")?)?;
    }
    Ok(())
}

fn validate_leaf_data(data: Option<&[u8]>) -> Result<()> {
    if let Some(data) = data {
        ensure_in_memory_limit("leaf content", usize_to_u64(data.len(), "leaf content")?)?;
    }
    Ok(())
}

fn reserve_exact_bytes(
    buffer: &mut Vec<u8>,
    additional: usize,
    resource: &'static str,
    requested: u64,
) -> Result<()> {
    buffer
        .try_reserve_exact(additional)
        .map_err(|_| Error::AllocationFailed {
            resource,
            requested,
        })
}

fn cbor_argument_encoded_len(value: u64) -> u64 {
    match value {
        0..=23 => 1,
        24..=255 => 2,
        256..=65_535 => 3,
        65_536..=4_294_967_295 => 5,
        _ => 9,
    }
}

fn cbor_text_encoded_len(value: &str) -> Result<u64> {
    let bytes = usize_to_u64(value.len(), "DagSize")?;
    checked_add(cbor_argument_encoded_len(bytes), bytes, "DagSize")
}

fn cbor_bytes_encoded_len(value: &[u8]) -> Result<u64> {
    let bytes = usize_to_u64(value.len(), "DagSize")?;
    checked_add(cbor_argument_encoded_len(bytes), bytes, "DagSize")
}

fn add_encoded_len(total: &mut u64, value: u64) -> Result<()> {
    *total = checked_add(*total, value, "DagSize")?;
    Ok(())
}

fn add_text_len(total: &mut u64, value: &str) -> Result<()> {
    add_encoded_len(total, cbor_text_encoded_len(value)?)
}

fn add_bytes_len(total: &mut u64, value: &[u8]) -> Result<()> {
    add_encoded_len(total, cbor_bytes_encoded_len(value)?)
}

fn storage_shape_len(leaf: &DagLeaf) -> Result<u64> {
    let mut total = cbor_argument_encoded_len(12);

    add_text_len(&mut total, "Hash")?;
    add_text_len(&mut total, leaf.cid.as_str())?;
    add_text_len(&mut total, "ItemName")?;
    add_text_len(&mut total, &leaf.item_name)?;
    add_text_len(&mut total, "Type")?;
    add_text_len(&mut total, leaf.leaf_type.as_str())?;
    add_text_len(&mut total, "ContentHash")?;
    match leaf.content_hash.as_ref() {
        Some(hash) => add_bytes_len(&mut total, hash)?,
        None => add_encoded_len(&mut total, 1)?,
    }
    add_text_len(&mut total, "Content")?;
    match leaf.content() {
        Some(content) => add_bytes_len(&mut total, content)?,
        None => add_encoded_len(&mut total, 1)?,
    }
    add_text_len(&mut total, "ClassicMerkleRoot")?;
    match leaf.classic_merkle_root.as_deref() {
        Some(root) => add_bytes_len(&mut total, root)?,
        None => add_encoded_len(&mut total, 1)?,
    }
    add_text_len(&mut total, "CurrentLinkCount")?;
    add_encoded_len(
        &mut total,
        cbor_argument_encoded_len(usize_to_u64(leaf.current_link_count, "CurrentLinkCount")?),
    )?;
    add_text_len(&mut total, "LeafCount")?;
    add_encoded_len(&mut total, cbor_argument_encoded_len(leaf.leaf_count))?;
    add_text_len(&mut total, "ContentSize")?;
    add_encoded_len(&mut total, cbor_argument_encoded_len(leaf.content_size))?;
    add_text_len(&mut total, "DagSize")?;
    add_encoded_len(&mut total, cbor_argument_encoded_len(leaf.dag_size))?;
    add_text_len(&mut total, "Links")?;
    if leaf.links.is_empty() {
        add_encoded_len(&mut total, 1)?;
    } else {
        add_encoded_len(
            &mut total,
            cbor_argument_encoded_len(usize_to_u64(leaf.links.len(), "Links")?),
        )?;
        for link in &leaf.links {
            add_text_len(&mut total, link.as_str())?;
        }
    }
    add_text_len(&mut total, "AdditionalData")?;
    add_encoded_len(
        &mut total,
        cbor_argument_encoded_len(usize_to_u64(leaf.additional_data.len(), "AdditionalData")?),
    )?;
    for (key, value) in &leaf.additional_data {
        add_text_len(&mut total, key)?;
        add_text_len(&mut total, value)?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::fs;
    use std::time::Duration;

    const ITERATIONS: usize = 64;

    /// Cloning a leaf must share its payload rather than copy it.
    ///
    /// This is the change that closed the benchmark gap against Go:
    /// `batched_sequence` went from 24.9x slower to 2x and `leaf_sequence` from
    /// 1.79x to parity, purely by not memcpy'ing content on every clone. A deep
    /// copy would still pass every correctness test in this crate while quietly
    /// undoing that, so the sharing itself is pinned rather than assumed.
    #[test]
    fn cloning_a_leaf_shares_its_payload_instead_of_copying_it() {
        let leaf = LeafBuilder::new("0", LeafType::Chunk)
            .with_data(b"payload".to_vec())
            .build(None)
            .unwrap();
        let copy = leaf.clone();

        let original = leaf.content_arc().expect("the leaf was built with data");
        let copied = copy.content_arc().expect("a clone keeps its payload");
        assert!(
            Arc::ptr_eq(&original, &copied),
            "a clone must share the payload; deep-copying here is exactly what made \
             batched_sequence 24.9x slower than Go"
        );

        // Sharing is only sound because nothing can write through the handle, so
        // outliving the source must leave the copy intact and still verifiable.
        drop(leaf);
        assert_eq!(copy.content(), Some(b"payload".as_slice()));
        copy.verify_identity().unwrap();
    }

    /// Stripping content from a copy of a DAG must not strip the original.
    ///
    /// With payloads shared between a DAG and its clone, this is the operation
    /// that would corrupt the source if it ever wrote through the shared buffer
    /// instead of repointing each leaf's handle. Go documents the same hazard for
    /// its aliased `Content` slice; here the type system forbids the bad version,
    /// and this test proves the good one is what actually ships.
    #[test]
    fn removing_content_from_a_cloned_dag_leaves_the_source_intact() {
        let graph = shared_graph();
        let before: Vec<Option<Vec<u8>>> = graph
            .dag
            .leaves()
            .values()
            .map(|leaf| leaf.content().map(<[u8]>::to_vec))
            .collect();
        assert!(
            before.iter().any(Option::is_some),
            "the fixture must actually carry content, otherwise this test is vacuous"
        );

        let mut stripped = graph.dag.clone();
        stripped.remove_all_content();
        assert!(stripped
            .leaves()
            .values()
            .all(|leaf| leaf.content().is_none()));

        let after: Vec<Option<Vec<u8>>> = graph
            .dag
            .leaves()
            .values()
            .map(|leaf| leaf.content().map(<[u8]>::to_vec))
            .collect();
        assert_eq!(
            after, before,
            "remove_all_content must repoint each clone's handle, never write \
             through the payload it shares with the source"
        );
    }

    /// `without_content` is the per-leaf form of `remove_all_content`: the
    /// copy drops only its payload handle, verifies on identity alone, and
    /// leaves the source's shared payload intact.
    #[test]
    fn a_leaf_without_content_keeps_its_identity_and_leaves_the_source_intact() {
        let leaf = LeafBuilder::new("0", LeafType::Chunk)
            .with_data(b"payload".to_vec())
            .build(None)
            .unwrap();
        let stripped = leaf.without_content();
        assert!(stripped.content().is_none());
        assert_eq!(stripped.cid(), leaf.cid());
        assert_eq!(stripped.content_hash(), leaf.content_hash());
        assert_eq!(stripped.links(), leaf.links());
        assert_eq!(stripped.additional_data(), leaf.additional_data());
        stripped.verify_identity().unwrap();
        assert_eq!(leaf.content(), Some(b"payload".as_slice()));
        leaf.verify_identity().unwrap();
        assert_ne!(
            stripped, leaf,
            "leaf equality compares payloads, so the copy must differ from its source"
        );
    }

    struct SharedGraph {
        dag: Dag,
        shared: Cid,
        lower: Cid,
        higher: Cid,
    }

    fn shared_graph() -> SharedGraph {
        let shared = LeafBuilder::new("0", LeafType::Chunk)
            .with_data(b"shared".to_vec())
            .build(None)
            .unwrap();
        let extra_a = LeafBuilder::new("1", LeafType::Chunk)
            .with_data(b"extra-a".to_vec())
            .build(None)
            .unwrap();
        let extra_b = LeafBuilder::new("2", LeafType::Chunk)
            .with_data(b"extra-b".to_vec())
            .build(None)
            .unwrap();
        let parent_a = LeafBuilder::new("a.bin", LeafType::File)
            .with_link(shared.cid().clone())
            .with_link(extra_a.cid().clone())
            .build(None)
            .unwrap();
        let parent_b = LeafBuilder::new("b.bin", LeafType::File)
            .with_link(shared.cid().clone())
            .with_link(extra_b.cid().clone())
            .build(None)
            .unwrap();
        let (lower, higher) = if parent_a.cid().as_str() < parent_b.cid().as_str() {
            (parent_a, parent_b)
        } else {
            (parent_b, parent_a)
        };
        let root = LeafBuilder::new("root", LeafType::File)
            .with_link(higher.cid().clone())
            .with_link(lower.cid().clone())
            .build(None)
            .unwrap();
        let root_cid = root.cid().clone();
        let shared_cid = shared.cid().clone();
        let lower_cid = lower.cid().clone();
        let higher_cid = higher.cid().clone();
        let leaves = [shared, extra_a, extra_b, lower, higher, root]
            .into_iter()
            .map(|leaf| (leaf.cid().clone(), leaf))
            .collect();
        SharedGraph {
            dag: Dag {
                root: root_cid,
                leaves,
                labels: Labels::new(),
            },
            shared: shared_cid,
            lower: lower_cid,
            higher: higher_cid,
        }
    }

    fn verify_parent_proof(parent: &DagLeaf, child: &Cid, proof: &MerkleProof) {
        let root: &Digest = parent.classic_merkle_root().try_into().unwrap();
        ClassicMerkleTree::verify_against(child.as_str().as_bytes(), proof, root).unwrap();
    }

    fn proof_fingerprint(proof: &MerkleProof) -> Vec<u8> {
        let mut bytes = proof.path().to_be_bytes().to_vec();
        for sibling in proof.siblings() {
            bytes.extend_from_slice(sibling);
        }
        bytes
    }

    #[test]
    fn shared_child_uses_lowest_parent_even_when_dfs_reaches_higher_first() {
        for _ in 0..ITERATIONS {
            let graph = shared_graph();
            let index = graph.dag.build_parent_index();
            assert_eq!(index.get(&graph.shared), Some(&graph.lower));
            let mut visited = BTreeSet::new();
            let mut shared_parent = None;
            graph
                .dag
                .visit_unique(|leaf, parent| {
                    assert!(visited.insert(leaf.cid().clone()));
                    if leaf.cid() == &graph.shared {
                        shared_parent = parent.map(|parent| parent.cid().clone());
                    }
                    Ok(())
                })
                .unwrap();
            assert_eq!(visited, graph.dag.leaves().keys().cloned().collect());
            assert_eq!(shared_parent, Some(graph.lower));
        }
    }

    #[derive(Clone)]
    struct TestPartialDag {
        present: BTreeSet<Cid>,
        proofs: BTreeMap<Cid, BTreeMap<Cid, MerkleProof>>,
    }

    #[test]
    fn partial_dag_carries_a_valid_shared_child_proof_for_every_parent() {
        let graph = shared_graph();
        let present = BTreeSet::from([
            graph.lower.clone(),
            graph.higher.clone(),
            graph.shared.clone(),
        ]);
        let mut baseline = None;
        for _ in 0..ITERATIONS {
            let partial = TestPartialDag {
                present: present.clone(),
                proofs: proofs_for_present_children(&graph.dag, &present).unwrap(),
            };
            assert_eq!(partial.present.len(), 3);
            assert_eq!(partial.proofs.len(), 2);
            let mut checked = 0;
            let mut fingerprint = Vec::new();
            for parent_cid in [&graph.lower, &graph.higher] {
                let parent = graph.dag.get(parent_cid).unwrap();
                assert!(parent.links().len() > 1);
                assert_eq!(
                    parent
                        .links()
                        .iter()
                        .filter(|child| partial.present.contains(*child))
                        .count(),
                    1
                );
                let proof = partial
                    .proofs
                    .get(parent_cid)
                    .and_then(|proofs| proofs.get(&graph.shared))
                    .expect("each pruned parent must carry its own proof");
                verify_parent_proof(parent, &graph.shared, proof);
                fingerprint.extend_from_slice(parent_cid.as_str().as_bytes());
                fingerprint.extend_from_slice(&proof_fingerprint(proof));
                checked += 1;
            }
            assert_eq!(checked, 2);
            match &baseline {
                Some(expected) => assert_eq!(&fingerprint, expected),
                None => baseline = Some(fingerprint),
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TestPacket {
        child: Cid,
        declared_parent: Cid,
        proof: Option<MerkleProof>,
    }

    impl TestPacket {
        fn to_bytes(&self) -> Vec<u8> {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(self.child.as_str().as_bytes());
            bytes.extend_from_slice(self.declared_parent.as_str().as_bytes());
            match &self.proof {
                Some(proof) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&proof_fingerprint(proof));
                }
                None => bytes.push(0),
            }
            bytes
        }

        fn from_bytes(bytes: &[u8], dag: &Dag) -> Self {
            const CID_TEXT_LEN: usize = 59;
            let child_text = std::str::from_utf8(&bytes[..CID_TEXT_LEN]).unwrap();
            let parent_text = std::str::from_utf8(&bytes[CID_TEXT_LEN..CID_TEXT_LEN * 2]).unwrap();
            let child = dag
                .leaves()
                .keys()
                .find(|cid| cid.as_str() == child_text)
                .unwrap()
                .clone();
            let declared_parent = dag
                .leaves()
                .keys()
                .find(|cid| cid.as_str() == parent_text)
                .unwrap()
                .clone();
            let proof = proof_for_parent_child(dag.get(&declared_parent).unwrap(), &child).unwrap();
            Self {
                child,
                declared_parent,
                proof,
            }
        }
    }

    fn packet_sequence(dag: &Dag) -> Vec<TestPacket> {
        let mut queue = VecDeque::from([dag.root().clone()]);
        let mut visited = BTreeSet::from([dag.root().clone()]);
        let mut packets = Vec::new();
        while let Some(parent_cid) = queue.pop_front() {
            let parent = dag.get(&parent_cid).unwrap();
            for child in parent.links() {
                if visited.insert(child.clone()) {
                    packets.push(TestPacket {
                        child: child.clone(),
                        declared_parent: parent_cid.clone(),
                        proof: proof_for_parent_child(parent, child).unwrap(),
                    });
                    queue.push_back(child.clone());
                }
            }
        }
        packets
    }

    #[test]
    fn packet_proof_is_bound_and_placed_under_its_declared_parent() {
        let graph = shared_graph();
        let mut baseline = None;
        for _ in 0..ITERATIONS {
            let packets = packet_sequence(&graph.dag);
            assert_eq!(
                packets
                    .iter()
                    .filter(|packet| packet.child == graph.shared)
                    .count(),
                1
            );
            let shared_packet = packets
                .iter()
                .find(|packet| packet.child == graph.shared)
                .unwrap();
            assert_eq!(shared_packet.declared_parent, graph.higher);
            assert_ne!(shared_packet.declared_parent, graph.lower);
            let mut receiver = BTreeSet::from([graph.dag.root().clone()]);
            let mut proof_placement = BTreeSet::<(Cid, Cid)>::new();
            let mut fingerprint = Vec::new();
            for packet in packets {
                assert!(receiver.contains(&packet.declared_parent));
                let bytes = packet.to_bytes();
                let decoded = TestPacket::from_bytes(&bytes, &graph.dag);
                assert_eq!(decoded.to_bytes(), bytes);
                let parent = graph.dag.get(&decoded.declared_parent).unwrap();
                if let Some(proof) = &decoded.proof {
                    verify_parent_proof(parent, &decoded.child, proof);
                    proof_placement
                        .insert((decoded.declared_parent.clone(), decoded.child.clone()));
                }
                graph
                    .dag
                    .get(&decoded.child)
                    .unwrap()
                    .verify_identity()
                    .unwrap();
                receiver.insert(decoded.child);
                fingerprint.extend_from_slice(&bytes);
            }
            assert_eq!(receiver, graph.dag.leaves().keys().cloned().collect());
            assert!(proof_placement.contains(&(graph.higher.clone(), graph.shared.clone())));
            assert!(!proof_placement.contains(&(graph.lower.clone(), graph.shared.clone())));
            match &baseline {
                Some(expected) => assert_eq!(&fingerprint, expected),
                None => baseline = Some(fingerprint),
            }
        }
    }

    #[derive(Clone)]
    struct TestSerializableDag {
        parents: Vec<(Cid, Vec<Cid>)>,
    }

    impl TestSerializableDag {
        fn to_bytes(&self) -> Vec<u8> {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&(self.parents.len() as u32).to_be_bytes());
            for (parent, children) in &self.parents {
                bytes.extend_from_slice(parent.as_str().as_bytes());
                bytes.extend_from_slice(&(children.len() as u32).to_be_bytes());
                for child in children {
                    bytes.extend_from_slice(child.as_str().as_bytes());
                }
            }
            bytes
        }

        fn from_bytes(bytes: &[u8], dag: &Dag) -> Self {
            const CID_TEXT_LEN: usize = 59;
            let mut cursor = 0;
            let read_u32 = |bytes: &[u8], cursor: &mut usize| {
                let value = u32::from_be_bytes(bytes[*cursor..*cursor + 4].try_into().unwrap());
                *cursor += 4;
                value as usize
            };
            let read_cid = |bytes: &[u8], cursor: &mut usize| {
                let text = std::str::from_utf8(&bytes[*cursor..*cursor + CID_TEXT_LEN]).unwrap();
                *cursor += CID_TEXT_LEN;
                dag.leaves()
                    .keys()
                    .find(|cid| cid.as_str() == text)
                    .unwrap()
                    .clone()
            };
            let parent_count = read_u32(bytes, &mut cursor);
            let mut parents = Vec::with_capacity(parent_count);
            for _ in 0..parent_count {
                let parent = read_cid(bytes, &mut cursor);
                let child_count = read_u32(bytes, &mut cursor);
                let mut children = Vec::with_capacity(child_count);
                for _ in 0..child_count {
                    children.push(read_cid(bytes, &mut cursor));
                }
                parents.push((parent, children));
            }
            assert_eq!(cursor, bytes.len());
            Self { parents }
        }
    }

    #[test]
    fn decoded_parent_mapping_is_minimum_and_enumeration_independent() {
        let graph = shared_graph();
        let serializable = TestSerializableDag {
            parents: graph
                .dag
                .leaves()
                .iter()
                .map(|(parent, leaf)| (parent.clone(), leaf.links().to_vec()))
                .collect(),
        };
        let encoded = serializable.to_bytes();
        let decoded = TestSerializableDag::from_bytes(&encoded, &graph.dag);
        let mut baseline = None;
        for iteration in 0..ITERATIONS {
            let mut view = decoded.parents.clone();
            if iteration % 2 == 1 {
                view.reverse();
            }
            let view_len = view.len();
            view.rotate_left(iteration % view_len);
            let parent_of = minimum_parent_index(
                view.iter()
                    .map(|(parent, children)| (parent, children.as_slice())),
            );
            assert_eq!(parent_of.get(&graph.shared), Some(&graph.lower));
            match &baseline {
                Some(expected) => assert_eq!(&parent_of, expected),
                None => baseline = Some(parent_of),
            }
        }
    }

    /// The store index has to land on the same parent the decode path does.
    ///
    /// A shared chunk has several parents, so "the" parent of that leaf is only
    /// well defined if every code path picks the same one. `Dag::from_parts` pins
    /// it to the LOWEST parent CID; the store index used to record whichever
    /// parent BFS reached FIRST. The identical DAG therefore reported a different
    /// `parent_hash` depending on whether it had been decoded or loaded from a
    /// store -- and nothing on the wire ever contradicted that, because
    /// `parent_hash` is not part of a serialized leaf.
    ///
    /// The test above pins the rule in isolation. This one pins it where it
    /// actually broke: end to end through `DagStore`, on the same fixture, so the
    /// two paths are compared against each other rather than each against its own
    /// expectation.
    ///
    /// `shared_graph`'s root is a FILE leaf on purpose, and this test is why:
    /// only directory leaves sort their links, so listing the higher parent first
    /// survives into the root's links and BFS genuinely reaches the higher parent
    /// first. With a directory root the links would be sorted by CID, BFS would
    /// arrive at the lowest parent anyway, and this would pass against the very
    /// bug it exists to catch.
    #[test]
    fn store_index_picks_the_lowest_parent_for_a_shared_chunk() {
        let graph = shared_graph();

        // Vacuity guards. Without these the assertions below can hold for
        // reasons that have nothing to do with the rule under test.
        let root_leaf = graph
            .dag
            .leaves()
            .get(graph.dag.root())
            .expect("the fixture root must be present");
        assert_eq!(root_leaf.links().len(), 2);
        assert_eq!(
            root_leaf.links()[0],
            graph.higher,
            "the fixture no longer lists the higher parent first; BFS would reach \
             the lowest parent first and this test would prove nothing"
        );
        let parents: Vec<String> = graph
            .dag
            .leaves()
            .iter()
            .filter(|(_, leaf)| leaf.links().contains(&graph.shared))
            .map(|(cid, _)| cid.to_string())
            .collect();
        assert_eq!(
            parents.len(),
            2,
            "expected the shared chunk to have exactly two parents, got {parents:?}"
        );

        let mut store = crate::store::DagStore::from_dag(&graph.dag).unwrap();
        store.build_index().unwrap();
        // Snapshot the index rather than holding a borrow across the mutable
        // update_parent_hashes_streaming call below.
        let index_parents: BTreeMap<Cid, Option<Cid>> = {
            let index = store.index().expect("build_index produced no index");
            index
                .leaf_hashes()
                .iter()
                .map(|cid| (cid.clone(), index.parent_of(cid).cloned()))
                .collect()
        };

        assert_eq!(
            index_parents.get(&graph.shared),
            Some(&Some(graph.lower.clone())),
            "the store index chose the wrong parent for the shared chunk; BFS \
             reaches {} first, which is what the index used to record",
            graph.higher
        );

        // The store index and the deserialization path must agree, leaf for leaf.
        let decoded = Dag::from_cbor(&graph.dag.to_cbor().unwrap()).unwrap();
        for (cid, leaf) in decoded.leaves() {
            if cid == decoded.root() {
                continue;
            }
            assert_eq!(
                index_parents.get(cid).and_then(Option::as_ref),
                leaf.parent_hash(),
                "leaf {cid}: the store index and deserialization disagree"
            );
        }

        // update_parent_hashes_streaming persists whatever the index decided, so
        // it has to land on the same answer rather than re-deriving its own.
        store.update_parent_hashes_streaming(2).unwrap();
        let stored = store
            .retrieve_leaf_without_content(&graph.shared)
            .unwrap()
            .expect("the shared chunk must survive the parent-hash rewrite");
        assert_eq!(stored.parent_hash(), Some(&graph.lower));
    }

    #[test]
    fn chunk_item_name_parser_comparator_and_permuted_assembly_are_numeric() {
        for (name, expected) in [
            ("0", 0),
            ("11", 11),
            ("old/path/10", 10),
            ("old\\path\\2", 2),
            ("mixed/path\\7", 7),
            ("+3", 3),
            ("-1", -1),
            ("02", 2),
        ] {
            assert_eq!(chunk_index_from_item_name(name), Some(expected));
        }
        for name in [
            "",
            "file/",
            "file\\",
            "x",
            "1x",
            " 1",
            "1 ",
            "0x10",
            "1_0",
            "999999999999999999999999999999999999999999",
        ] {
            assert_eq!(chunk_index_from_item_name(name), None, "{name:?}");
        }
        assert_eq!(compare_chunk_item_names("2", "10"), Ordering::Less);
        assert_eq!(
            compare_chunk_item_names("file/2", "other\\10"),
            Ordering::Less
        );
        assert_eq!(compare_chunk_item_names("2", "02"), Ordering::Equal);
        assert_eq!(compare_chunk_item_names("z/0", "a/x"), Ordering::Greater);

        const PERMUTATION: [usize; 12] = [10, 2, 11, 0, 9, 1, 8, 3, 7, 4, 6, 5];
        for prefix in ["", "legacy/", "legacy\\"] {
            let chunks: Vec<DagLeaf> = (0..12)
                .map(|index| {
                    LeafBuilder::new(format!("{prefix}{index}"), LeafType::Chunk)
                        .with_data(vec![index as u8])
                        .build(None)
                        .unwrap()
                })
                .collect();
            let mut file_builder = LeafBuilder::new("file", LeafType::File);
            for index in PERMUTATION {
                file_builder.add_link(chunks[index].cid().clone());
            }
            let file = file_builder.build(None).unwrap();
            let root = file.cid().clone();
            let mut leaves: BTreeMap<Cid, DagLeaf> = chunks
                .into_iter()
                .map(|chunk| (chunk.cid().clone(), chunk))
                .collect();
            leaves.insert(root.clone(), file);
            let dag = Dag {
                root,
                leaves,
                labels: Labels::new(),
            };
            let assembled = assemble_chunk_content(&dag, dag.root_leaf(), 12).unwrap();
            assert_eq!(assembled, (0_u8..12).collect::<Vec<_>>());
            let mut lexical: Vec<&DagLeaf> = dag
                .root_leaf()
                .links()
                .iter()
                .map(|cid| dag.get(cid).unwrap())
                .collect();
            lexical.sort_by(|left, right| left.item_name().cmp(right.item_name()));
            let lexical_bytes: Vec<u8> = lexical
                .iter()
                .flat_map(|chunk| chunk.content().unwrap().iter().copied())
                .collect();
            assert_ne!(lexical_bytes, assembled);
            assert!(matches!(
                assemble_chunk_content(&dag, dag.root_leaf(), 11),
                Err(Error::InMemoryLimitExceeded { .. })
            ));
        }
    }

    #[test]
    fn safe_join_rejects_five_unsafe_classes_and_accepts_basenames() {
        let base = Path::new("base");
        for name in [
            "",
            ".",
            "..",
            "dir/file",
            "dir\\file",
            "../escape",
            "..\\escape",
        ] {
            assert!(matches!(
                safe_join(base, name),
                Err(Error::UnsafeItemName { .. })
            ));
        }
        let absolute = std::env::current_dir().unwrap();
        assert!(absolute.is_absolute());
        assert!(matches!(
            safe_join(base, absolute.to_str().unwrap()),
            Err(Error::UnsafeItemName { .. })
        ));
        for name in ["file.txt", "...", "..hidden", ".gitignore", "a.b.c", "雪"] {
            assert_eq!(safe_join(base, name).unwrap(), base.join(name));
        }
    }

    #[test]
    fn root_item_name_matches_go_dir_then_rel_rules() {
        let separator = std::path::MAIN_SEPARATOR;
        assert_eq!(root_item_name(Path::new("name")).unwrap(), "name");
        assert_eq!(root_item_name(Path::new(".")).unwrap(), ".");
        assert_eq!(root_item_name(Path::new("./")).unwrap(), ".");
        assert_eq!(
            root_item_name(Path::new(&format!("name{separator}"))).unwrap(),
            "."
        );
        assert_eq!(
            root_item_name(Path::new(&separator.to_string())).unwrap(),
            "."
        );
        assert_eq!(root_item_name(Path::new("..")).unwrap(), "..");
        assert_eq!(
            root_item_name(Path::new(&format!("a{separator}b{separator}.."))).unwrap(),
            ".."
        );
        assert_eq!(
            root_item_name(Path::new(&format!("a{separator}.."))).unwrap(),
            format!("..{separator}.")
        );
        #[cfg(windows)]
        {
            assert_eq!(root_item_name(Path::new("C:\\")).unwrap(), ".");
            assert_eq!(root_item_name(Path::new("\\\\server\\share")).unwrap(), ".");
            assert_eq!(
                root_item_name(Path::new("\\\\server\\share\\")).unwrap(),
                "."
            );
        }
    }

    #[test]
    fn timestamp_formatter_is_go_rfc3339_utc_to_whole_seconds() {
        for (seconds, expected) in [
            (0, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_700_000_000, "2023-11-14T22:13:20Z"),
            (1_767_225_599, "2025-12-31T23:59:59Z"),
        ] {
            assert_eq!(format_epoch_seconds_rfc3339_utc(seconds), expected);
        }
        assert_eq!(
            format_system_time_rfc3339_utc(UNIX_EPOCH + Duration::new(1_700_000_000, 999_999_999),)
                .unwrap(),
            "2023-11-14T22:13:20Z"
        );
    }

    #[test]
    fn processor_metadata_wins_collisions_and_memory_limit_is_inclusive() {
        let base = Metadata::from([
            ("k".to_owned(), "base".to_owned()),
            ("keep".to_owned(), "yes".to_owned()),
        ]);
        let custom = Metadata::from([("k".to_owned(), "custom".to_owned())]);
        let merged = merge_metadata(Some(&base), Some(custom)).unwrap();
        assert_eq!(merged.get("k").map(String::as_str), Some("custom"));
        assert_eq!(merged.get("keep").map(String::as_str), Some("yes"));
        assert!(ensure_in_memory_limit("test", MAX_IN_MEMORY_LEAF_BYTES as u64).is_ok());
        assert!(matches!(
            ensure_in_memory_limit("test", MAX_IN_MEMORY_LEAF_BYTES as u64 + 1),
            Err(Error::InMemoryLimitExceeded { .. })
        ));
    }

    #[test]
    fn create_dag_dot_succeeds_with_dot_item_name() {
        static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _lock = CWD_LOCK.lock().unwrap();
        let original = std::env::current_dir().unwrap();
        let temp = original.join(format!("target/dot-root-test-{}", std::process::id()));
        if temp.exists() {
            fs::remove_dir_all(&temp).unwrap();
        }
        fs::create_dir_all(&temp).unwrap();
        fs::write(temp.join("file.txt"), b"dot").unwrap();
        std::env::set_current_dir(&temp).unwrap();
        let result = create_dag(".");
        std::env::set_current_dir(&original).unwrap();
        fs::remove_dir_all(&temp).unwrap();
        let dag = result.unwrap();
        assert_eq!(dag.root_leaf().item_name(), ".");
    }

    #[test]
    fn storage_projection_bytes_remain_pinned_but_test_only() {
        fn position(haystack: &[u8], needle: &[u8]) -> usize {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
                .expect("expected encoded value")
        }

        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }

        let leaf = LeafBuilder::new("shape.txt", LeafType::File)
            .build(None)
            .unwrap();
        let storage = leaf.storage_cbor();
        assert_eq!(storage[0], 0xac);
        let storage_order = [
            b"\x64Hash".as_slice(),
            b"\x68ItemName".as_slice(),
            b"\x64Type".as_slice(),
            b"\x6bContentHash".as_slice(),
            b"\x67Content".as_slice(),
            b"\x71ClassicMerkleRoot".as_slice(),
            b"\x70CurrentLinkCount".as_slice(),
            b"\x69LeafCount".as_slice(),
            b"\x6bContentSize".as_slice(),
            b"\x67DagSize".as_slice(),
            b"\x65Links".as_slice(),
            b"\x6eAdditionalData".as_slice(),
        ];
        let positions: Vec<usize> = storage_order
            .iter()
            .map(|key| position(&storage, key))
            .collect();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        let storage_hex = hex(&storage);
        assert!(storage_hex.contains("71436c61737369634d65726b6c65526f6f7440"));
        assert!(storage_hex.ends_with("654c696e6b73f66e4164646974696f6e616c44617461a0"));
        assert_eq!(leaf.storage_size().unwrap(), storage.len() as u64);

        let child1 = LeafBuilder::new("a", LeafType::File)
            .with_data(b"a".to_vec())
            .build(None)
            .unwrap();
        let child2 = LeafBuilder::new("b", LeafType::File)
            .with_data(b"b".to_vec())
            .build(None)
            .unwrap();
        let file_forward = LeafBuilder::new("large", LeafType::File)
            .with_link(child1.cid().clone())
            .with_link(child2.cid().clone())
            .build(None)
            .unwrap();
        let file_reversed = LeafBuilder::new("large", LeafType::File)
            .with_link(child2.cid().clone())
            .with_link(child1.cid().clone())
            .build(None)
            .unwrap();
        let forward = file_forward.storage_cbor();
        let reversed = file_reversed.storage_cbor();
        assert_ne!(forward, reversed);
        assert_eq!(forward.len(), reversed.len());
        assert!(
            position(&forward, child1.cid().as_str().as_bytes())
                < position(&forward, child2.cid().as_str().as_bytes())
        );
        assert!(
            position(&reversed, child2.cid().as_str().as_bytes())
                < position(&reversed, child1.cid().as_str().as_bytes())
        );

        let directory_forward = LeafBuilder::new("dir", LeafType::Directory)
            .with_link(child1.cid().clone())
            .with_link(child2.cid().clone())
            .build(None)
            .unwrap();
        let directory_reversed = LeafBuilder::new("dir", LeafType::Directory)
            .with_link(child2.cid().clone())
            .with_link(child1.cid().clone())
            .build(None)
            .unwrap();
        assert_eq!(
            directory_forward.storage_cbor(),
            directory_reversed.storage_cbor()
        );

        // Root leaves run encode_root_identity and carry populated LeafCount /
        // ContentSize / DagSize, so they are a genuinely different encode path
        // from the non-root pins above and need their own byte pins. Both
        // invariants must survive that path: a directory root sorts its links so
        // reversed input is byte-identical, while a file root retains the given
        // link order so reversed input differs byte-for-byte at identical length.
        let stats = crate::DagStats::new(2, 0, 0);
        let mut file_forward_builder = LeafBuilder::new("large", LeafType::File);
        file_forward_builder.add_link(child1.cid().clone());
        file_forward_builder.add_link(child2.cid().clone());
        let mut file_reversed_builder = LeafBuilder::new("large", LeafType::File);
        file_reversed_builder.add_link(child2.cid().clone());
        file_reversed_builder.add_link(child1.cid().clone());
        let file_forward_root = file_forward_builder
            .build_root_with_stats(stats, None)
            .unwrap();
        let file_reversed_root = file_reversed_builder
            .build_root_with_stats(stats, None)
            .unwrap();
        assert_eq!(file_forward_root.cid(), file_reversed_root.cid());
        assert_ne!(
            file_forward_root.storage_cbor(),
            file_reversed_root.storage_cbor()
        );
        assert_eq!(
            file_forward_root.storage_cbor().len(),
            file_reversed_root.storage_cbor().len()
        );

        let mut directory_builder = LeafBuilder::new("dir", LeafType::Directory);
        directory_builder.add_link(child1.cid().clone());
        directory_builder.add_link(child2.cid().clone());
        let mut directory_reversed_builder = LeafBuilder::new("dir", LeafType::Directory);
        directory_reversed_builder.add_link(child2.cid().clone());
        directory_reversed_builder.add_link(child1.cid().clone());
        let directory_root = directory_builder
            .build_root_with_stats(stats, None)
            .unwrap();
        let directory_reversed_root = directory_reversed_builder
            .build_root_with_stats(stats, None)
            .unwrap();
        assert_eq!(directory_root.cid(), directory_reversed_root.cid());
        assert_eq!(
            directory_root.storage_cbor(),
            directory_reversed_root.storage_cbor()
        );
    }

    #[test]
    fn storage_null_links_and_wire_empty_links_stay_distinct() {
        let leaf = LeafBuilder::new("empty.txt", LeafType::File)
            .build(None)
            .unwrap();
        let CborValue::Map(storage) = crate::encoding::cbor_decode(&leaf.storage_cbor()).unwrap()
        else {
            panic!("storage projection must be a map");
        };
        assert!(matches!(
            storage
                .iter()
                .find(|(key, _)| key == "Links")
                .map(|(_, value)| value),
            Some(CborValue::Null)
        ));
        let CborValue::Map(wire) =
            crate::serialization::leaf_wire_value(&leaf, crate::encoding::KeyOrder::Cbor)
        else {
            panic!("wire leaf must be a map");
        };
        assert!(matches!(
            wire.iter()
                .find(|(key, _)| key == "Links")
                .map(|(_, value)| value),
            Some(CborValue::Array(links)) if links.is_empty()
        ));
    }
}
