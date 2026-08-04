#![forbid(unsafe_code)]
#![doc = "A byte-compatible Scionic Merkle Tree implementation."]

mod classic;
mod dag;
pub mod diff;
pub mod encoding;
mod fastcdc;
mod operations;
mod serialization;
mod store;
mod transmission;

pub use classic::{ClassicMerkleTree, Digest, MerkleProof};
pub use dag::*;
pub use diff::*;
pub use fastcdc::*;
pub use store::*;
pub use transmission::*;

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidChunkSize {
        value: usize,
    },
    InvalidCborNegative {
        value: i64,
    },
    InvalidCbor {
        detail: &'static str,
    },
    InvalidJson {
        detail: String,
    },
    InvalidBase32,
    InvalidBase64,
    InvalidCid {
        value: String,
    },
    InvalidLeafType {
        value: String,
    },
    InvalidData {
        detail: String,
    },
    DuplicateKey {
        key: String,
    },
    AmbiguousFieldSpellings {
        field: &'static str,
        first: String,
        second: String,
    },
    InvalidMerkleLeafCount {
        count: usize,
    },
    MerklePathTooDeep {
        depth: usize,
    },
    MissingMerkleKey {
        key: String,
    },
    TruncatedVarint,
    VarintOverflow,
    ProofVerificationFailed,
    MissingFileName {
        path: PathBuf,
    },
    NonUtf8FileName {
        path: PathBuf,
    },
    MissingRoot,
    MissingLeaf {
        cid: String,
    },
    LeafCidMismatch {
        cid: String,
    },
    CidKeyMismatch {
        key: String,
        cid: String,
    },
    MissingContentHash {
        cid: String,
    },
    ContentHashMismatch {
        cid: String,
    },
    ContentSizeMismatch {
        stored: u64,
        calculated: u64,
    },
    DagSizeMismatch {
        stored: u64,
        calculated: u64,
    },
    LinkCountMismatch {
        cid: String,
        expected: usize,
        actual: usize,
    },
    ClassicRootMismatch {
        cid: String,
    },
    ParentMissingLink {
        parent: String,
        child: String,
    },
    UnreachableLeaves {
        count: usize,
    },
    EmptyPartialRequest,
    MissingRequestedLeaf {
        cid: String,
    },
    BrokenPathToRoot {
        cid: String,
    },
    IncompletePartialDag {
        cid: String,
        expected: usize,
        present: usize,
    },
    MissingProof {
        parent: String,
        child: String,
    },
    MissingTransmissionRelationship {
        child: String,
    },
    UnavailableTransmissionParent {
        parent: String,
        child: String,
    },
    ConflictingTransmissionRoot {
        expected: String,
        received: String,
    },
    ProofKeyMismatch {
        key: String,
        child: String,
    },
    IncompleteProofSource {
        parent: String,
        child: String,
    },
    CycleDetected {
        cid: String,
    },
    LabelsNotCalculated,
    InvalidLabelRange {
        start: usize,
        end: usize,
    },
    LabelNotFound {
        label: String,
    },
    NoAddedLeaves,
    MissingNewRoot,
    NoDiffRoot,
    AmbiguousDiffRoot,
    MissingPoolLeaf {
        cid: String,
    },
    UnsafeItemName {
        name: String,
    },
    InMemoryLimitExceeded {
        resource: &'static str,
        requested: u64,
        limit: u64,
    },
    AllocationFailed {
        resource: &'static str,
        requested: u64,
    },
    SystemTimeBeforeUnixEpoch,
    SizeOverflow {
        field: &'static str,
    },
    Invariant {
        detail: &'static str,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(f, "failed to {operation} {}: {source}", path.display()),
            Self::InvalidChunkSize { value } => write!(f, "invalid chunk size {value}"),
            Self::InvalidCborNegative { value } => {
                write!(f, "CBOR negative integer must be below zero, got {value}")
            }
            Self::InvalidCbor { detail } => write!(f, "invalid CBOR: {detail}"),
            Self::InvalidJson { detail } => write!(f, "invalid JSON: {detail}"),
            Self::InvalidBase32 => f.write_str("invalid base32lower value"),
            Self::InvalidBase64 => f.write_str("invalid standard padded base64 value"),
            Self::InvalidCid { value } => write!(f, "invalid Scionic CID: {value:?}"),
            Self::InvalidLeafType { value } => write!(f, "invalid leaf type: {value:?}"),
            Self::InvalidData { detail } => write!(f, "invalid DAG data: {detail}"),
            Self::DuplicateKey { key } => write!(f, "duplicate map key: {key:?}"),
            Self::AmbiguousFieldSpellings {
                field,
                first,
                second,
            } => write!(
                f,
                "ambiguous spellings for {field}: {first:?} and {second:?}"
            ),
            Self::InvalidMerkleLeafCount { count } => write!(
                f,
                "classic Merkle trees require at least two leaves, got {count}"
            ),
            Self::MerklePathTooDeep { depth } => write!(
                f,
                "Merkle proof depth {depth} exceeds the u32 path capacity"
            ),
            Self::MissingMerkleKey { key } => write!(f, "Merkle key not found: {key}"),
            Self::TruncatedVarint => f.write_str("truncated unsigned varint"),
            Self::VarintOverflow => f.write_str("unsigned varint overflows u64"),
            Self::ProofVerificationFailed => f.write_str("Merkle proof verification failed"),
            Self::MissingFileName { path } => {
                write!(f, "path has no file name: {}", path.display())
            }
            Self::NonUtf8FileName { path } => {
                write!(f, "path has a non-UTF-8 file name: {}", path.display())
            }
            Self::MissingRoot => f.write_str("DAG root leaf is missing"),
            Self::MissingLeaf { cid } => write!(f, "DAG is missing linked leaf {cid}"),
            Self::LeafCidMismatch { cid } => write!(f, "leaf CID does not match its identity: {cid}"),
            Self::CidKeyMismatch { key, cid } => {
                write!(f, "leaf map key {key} does not match embedded CID {cid}")
            }
            Self::MissingContentHash { cid } => {
                write!(f, "leaf {cid} has content but no content hash")
            }
            Self::ContentHashMismatch { cid } => {
                write!(f, "leaf {cid} content does not match its content hash")
            }
            Self::ContentSizeMismatch { stored, calculated } => write!(
                f,
                "content size mismatch: stored {stored}, calculated {calculated}"
            ),
            Self::DagSizeMismatch { stored, calculated } => write!(
                f,
                "DAG size mismatch: stored {stored}, calculated {calculated}"
            ),
            Self::LinkCountMismatch {
                cid,
                expected,
                actual,
            } => write!(
                f,
                "leaf {cid} has {actual} links but declares {expected}"
            ),
            Self::ClassicRootMismatch { cid } => {
                write!(f, "classic Merkle root mismatch for leaf {cid}")
            }
            Self::ParentMissingLink { parent, child } => {
                write!(f, "parent {parent} does not link child {child}")
            }
            Self::UnreachableLeaves { count } => {
                write!(f, "DAG contains {count} unreachable leaves")
            }
            Self::EmptyPartialRequest => f.write_str("partial DAG request is empty"),
            Self::MissingRequestedLeaf { cid } => write!(f, "requested leaf not found: {cid}"),
            Self::BrokenPathToRoot { cid } => write!(f, "broken path to root for leaf {cid}"),
            Self::IncompletePartialDag {
                cid,
                expected,
                present,
            } => write!(
                f,
                "leaf {cid} declares {expected} links but only {present} children are stored and it carries no proofs"
            ),
            Self::MissingProof { parent, child } => {
                write!(f, "parent {parent} has no proof for child {child}")
            }
            Self::MissingTransmissionRelationship { child } => {
                write!(f, "transmission packet has no relationship for child {child}")
            }
            Self::UnavailableTransmissionParent { parent, child } => write!(
                f,
                "transmission parent {parent} is unavailable for child {child}"
            ),
            Self::ConflictingTransmissionRoot { expected, received } => write!(
                f,
                "transmission root {received} conflicts with expected root {expected}"
            ),
            Self::ProofKeyMismatch { key, child } => {
                write!(f, "stored proof key {key} does not match proof child {child}")
            }
            Self::IncompleteProofSource { parent, child } => write!(
                f,
                "cannot build proof for child {child} from incomplete parent {parent}"
            ),
            Self::CycleDetected { cid } => write!(f, "cycle detected at leaf {cid}"),
            Self::LabelsNotCalculated => f.write_str("labels have not been calculated"),
            Self::InvalidLabelRange { start, end } => {
                write!(f, "invalid inclusive label range {start}..={end}")
            }
            Self::LabelNotFound { label } => write!(f, "label not found: {label}"),
            Self::NoAddedLeaves => f.write_str("diff contains no added leaves"),
            Self::MissingNewRoot => f.write_str("new leaves contain no root-shaped leaf"),
            Self::NoDiffRoot => f.write_str("diff contains no new root candidate"),
            Self::AmbiguousDiffRoot => f.write_str("diff contains several new root candidates"),
            Self::MissingPoolLeaf { cid } => write!(f, "diff leaf pool is missing {cid}"),
            Self::UnsafeItemName { name } => write!(f, "unsafe DAG item name: {name:?}"),
            Self::InMemoryLimitExceeded {
                resource,
                requested,
                limit,
            } => write!(
                f,
                "{resource} requires {requested} bytes, exceeding the {limit}-byte in-memory limit"
            ),
            Self::AllocationFailed {
                resource,
                requested,
            } => write!(f, "failed to allocate {requested} bytes for {resource}"),
            Self::SystemTimeBeforeUnixEpoch => {
                f.write_str("the system clock is before the Unix epoch")
            }
            Self::SizeOverflow { field } => write!(f, "{field} exceeds the supported size"),
            Self::Invariant { detail } => write!(f, "internal invariant failed: {detail}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub(crate) fn io_error(operation: &'static str, path: &Path, source: io::Error) -> Error {
    Error::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
