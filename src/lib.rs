#![forbid(unsafe_code)]
//! Scionic Merkle trees.
//!
//! A tree holds a folder of files, or one file, under one root hash. A file is
//! a list of pieces, a folder is a list of names, and the root covers all of
//! it. Identical pieces, files and folders have identical hashes wherever they
//! are, so a store keeps each of them once. A sender can show a part of a tree
//! without the rest: one name in a folder, one piece of a file, or a stretch of
//! a file's bytes.
//!
//! `spec/FORMAT.md` in this repository says exactly what each hash covers.

mod build;
mod diff;
mod encoding;
mod fastcdc;
mod format;
mod hash;
mod intake;
mod read;
mod store;
mod sync;
pub mod tree;
mod wire;

pub use build::{build, build_with, BuildOptions, Builder, EntryExtra, Links};
pub use diff::{diff, Change};
pub use fastcdc::{
    FASTCDC_GEAR_SEED_PREFIX, FASTCDC_LOOSE_MASK, FASTCDC_MAX_SIZE, FASTCDC_MIN_SIZE,
    FASTCDC_STRICT_MASK, FASTCDC_TARGET_SIZE,
};
pub use format::{
    check_name, file_hash, folder_hash, Cutting, Entry, ExtraData, FileList, FileRun, FolderList,
    FolderRun, Kind, OpenFile, OpenFolder, PieceRef, Record, Target, Totals, CUTTING_FASTCDC_V1,
    CUTTING_KEY, LIST_ITEM_BYTES, MAX_CARRIED_NODES, MAX_ENTRY_BYTES, MAX_EXTRA_BYTES,
    MAX_EXTRA_NAME_BYTES, MAX_EXTRA_VALUES, MAX_EXTRA_VALUE_BYTES, MAX_FOLDER_DEPTH,
    MAX_NAME_BYTES, MAX_PIECE_BYTES, MAX_RECORD_BYTES, TIMESTAMP_KEY,
};
pub use hash::{Hash, Root};
pub use intake::{verify, verify_with, Accepted, Arrived, Intake, Summary, VerifyOptions};
pub use read::{
    file_of, folder_of, lookup, read_file, read_file_to_vec, read_range, record_of, unwritable,
    unwritable_on_windows, write_to_disk,
};
pub use store::{MemoryStore, Store, Stored};
pub use sync::{
    export, fetch, import, serve, Entries, Peer, Remote, Responder, StreamPeer,
    REQUESTS_AHEAD_BYTES,
};
pub use wire::{
    file_list_frame, file_run_frame, folder_list_frame, folder_run_frame, have_frame, piece_frame,
    read_frame, refused_frame, write_frame, Frame, HaveMap, Refusal, Request, BUNDLE_MAGIC,
    FRAME_FILE_LIST, FRAME_FILE_RUN, FRAME_FOLDER_LIST, FRAME_FOLDER_RUN, FRAME_HAVE, FRAME_PIECE,
    FRAME_RECORD, FRAME_REFUSED, MAX_REQUEST_BYTES,
};

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The file system refused something.
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    /// Reading from a stream or writing to one failed.
    Stream {
        operation: &'static str,
        source: io::Error,
    },
    /// Bytes that are not a well-formed thing of the format.
    InvalidData {
        detail: String,
    },
    InvalidBase32,
    InvalidHex,
    /// Text that is not a root.
    InvalidRoot {
        value: String,
    },
    /// A name that the format does not allow.
    InvalidName {
        name: String,
        reason: &'static str,
    },
    /// A thing does not hash to what it has to.
    HashMismatch {
        what: &'static str,
    },
    /// A thing does not have the size it has to.
    SizeMismatch {
        what: &'static str,
        expected: u64,
        actual: u64,
    },
    /// A record's totals are not those of its tree.
    TotalsMismatch {
        field: &'static str,
        recorded: u64,
        counted: u64,
    },
    /// An intake was used again after a part of its tree was refused.
    IntakeFailed,
    /// Something arrived that is not tied to the root, or was not asked for.
    NotWanted {
        what: &'static str,
    },
    /// A store does not hold something that the tree needs.
    Missing {
        what: &'static str,
        hash: Hash,
    },
    /// Folders sit inside one another more deeply than the format allows.
    TooDeep {
        limit: usize,
    },
    /// A name that this system cannot hold as it is.
    UnwritableName {
        name: String,
        reason: &'static str,
    },
    /// A link or a special file, where only files and folders are stored.
    UnsupportedEntry {
        path: PathBuf,
        what: &'static str,
    },
    NonUtf8FileName {
        path: PathBuf,
    },
    /// A peer could not answer, or stopped early.
    Peer {
        detail: String,
    },
    LimitExceeded {
        what: &'static str,
        limit: u64,
        requested: u64,
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
            Self::Stream { operation, source } => write!(f, "failed to {operation}: {source}"),
            Self::InvalidData { detail } => write!(f, "malformed: {detail}"),
            Self::InvalidBase32 => f.write_str("not lowercase base32"),
            Self::InvalidHex => f.write_str("not lowercase hex of the right length"),
            Self::InvalidRoot { value } => write!(f, "not a root: {value:?}"),
            Self::InvalidName { name, reason } => {
                write!(f, "the name {name:?} is not allowed: {reason}")
            }
            Self::HashMismatch { what } => write!(f, "{what} does not hash to what it has to"),
            Self::SizeMismatch {
                what,
                expected,
                actual,
            } => write!(f, "{what} holds {actual} bytes where {expected} are due"),
            Self::TotalsMismatch {
                field,
                recorded,
                counted,
            } => write!(
                f,
                "the record says {recorded} for {field}, and the tree has {counted}"
            ),
            Self::IntakeFailed => f.write_str(
                "an intake is done once a part of its tree was refused: start a new one",
            ),
            Self::NotWanted { what } => {
                write!(f, "{what} is not tied to the root, or was not asked for")
            }
            Self::Missing { what, hash } => write!(f, "{what} {hash} is not held"),
            Self::TooDeep { limit } => {
                write!(f, "folders sit inside one another more than {limit} deep")
            }
            Self::UnwritableName { name, reason } => write!(
                f,
                "the name {name:?} cannot be written on this system: {reason}"
            ),
            Self::UnsupportedEntry { path, what } => write!(
                f,
                "{} is {what}, and only files and folders are stored",
                path.display()
            ),
            Self::NonUtf8FileName { path } => {
                write!(f, "path has a non-UTF-8 file name: {}", path.display())
            }
            Self::Peer { detail } => write!(f, "the peer {detail}"),
            Self::LimitExceeded {
                what,
                limit,
                requested,
            } => write!(f, "{what} needs {requested}, over the limit of {limit}"),
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
            Self::Io { source, .. } | Self::Stream { source, .. } => Some(source),
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
