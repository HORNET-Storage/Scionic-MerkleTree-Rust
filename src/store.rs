//! Where a tree's parts are kept.
//!
//! A store keeps four kinds of thing, each found by its hash: pieces, the
//! lists of files, the lists of folders, and records. Because a thing's hash
//! covers only what the thing is, a piece, a file or a folder that occurs in
//! many trees is kept once.
//!
//! A store checks nothing: it keeps what it is given under the hash it is
//! given. Everything that this library puts into a store is checked first,
//! and everything it takes out is checked again before it is used.

use crate::format::{FileList, FolderList, Kind, PieceRef, Record, Target};
use crate::hash::{Hash, Root};
use crate::{Error, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// The kinds of thing a store keeps.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Stored {
    /// A piece's bytes, under the SHA-256 of them.
    Piece,
    /// A file's whole list, under the file's hash.
    FileList,
    /// A folder's whole list, under the folder's hash.
    FolderList,
    /// A tree's record, under the tree's root.
    Record,
}

/// A place that keeps bytes under hashes.
pub trait Store: Send + Sync {
    /// Keeps `bytes` under `hash`. Keeping what is kept already changes
    /// nothing.
    fn put(&self, kind: Stored, hash: &Hash, bytes: &[u8]) -> Result<()>;

    /// What is kept under `hash`, if anything.
    fn get(&self, kind: Stored, hash: &Hash) -> Result<Option<Arc<[u8]>>>;

    /// Whether anything is kept under `hash`.
    fn has(&self, kind: Stored, hash: &Hash) -> Result<bool> {
        Ok(self.get(kind, hash)?.is_some())
    }

    /// How many bytes are kept under `hash`.
    fn size(&self, kind: Stored, hash: &Hash) -> Result<Option<u64>> {
        Ok(self.get(kind, hash)?.map(|bytes| bytes.len() as u64))
    }

    /// Forgets what is kept under `hash`.
    fn remove(&self, kind: Stored, hash: &Hash) -> Result<()>;
}

/// What a store in memory keeps: bytes, by their kind and their hash.
type Things = HashMap<(Stored, Hash), Arc<[u8]>>;

/// A store in memory.
#[derive(Default)]
pub struct MemoryStore {
    things: RwLock<Things>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Things> {
        self.things
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Things> {
        self.things
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// How many things of `kind` are kept.
    pub fn count(&self, kind: Stored) -> usize {
        self.read().keys().filter(|key| key.0 == kind).count()
    }

    /// How many bytes the things of `kind` hold together.
    pub fn bytes(&self, kind: Stored) -> u64 {
        self.read()
            .iter()
            .filter(|(key, _)| key.0 == kind)
            .map(|(_, bytes)| bytes.len() as u64)
            .sum()
    }

    /// The hashes of the things of `kind`, in order.
    pub fn hashes(&self, kind: Stored) -> Vec<Hash> {
        let mut hashes: Vec<Hash> = self
            .read()
            .keys()
            .filter(|key| key.0 == kind)
            .map(|key| key.1)
            .collect();
        hashes.sort_unstable();
        hashes
    }
}

impl Store for MemoryStore {
    fn put(&self, kind: Stored, hash: &Hash, bytes: &[u8]) -> Result<()> {
        if self.read().contains_key(&(kind, *hash)) {
            return Ok(());
        }
        // Copied before the lock is taken, so that many threads put at once.
        let kept: Arc<[u8]> = Arc::from(bytes);
        self.write().entry((kind, *hash)).or_insert(kept);
        Ok(())
    }

    fn get(&self, kind: Stored, hash: &Hash) -> Result<Option<Arc<[u8]>>> {
        Ok(self.read().get(&(kind, *hash)).cloned())
    }

    fn has(&self, kind: Stored, hash: &Hash) -> Result<bool> {
        Ok(self.read().contains_key(&(kind, *hash)))
    }

    fn remove(&self, kind: Stored, hash: &Hash) -> Result<()> {
        self.write().remove(&(kind, *hash));
        Ok(())
    }
}

/// The store holds, under `hash`, bytes that are not what the hash says.
pub(crate) fn damaged(what: &'static str, hash: &Hash) -> Error {
    Error::Corrupt { what, hash: *hash }
}

/// The record of `root`, read from the store and checked against the root.
pub(crate) fn load_record(store: &dyn Store, root: &Root) -> Result<Option<Record>> {
    let Some(bytes) = store.get(Stored::Record, root.as_hash())? else {
        return Ok(None);
    };
    if Root::of_record(&bytes) != *root {
        return Err(damaged("a stored record", root.as_hash()));
    }
    Record::decode(&bytes).map(Some)
}

/// A list read from a store has to hold the bytes its parent gave it.
fn confirm_size(read: u64, wanted: &Target, what: &'static str) -> Result<()> {
    if read != wanted.size {
        return Err(Error::SizeMismatch {
            what,
            expected: wanted.size,
            actual: read,
        });
    }
    Ok(())
}

/// The list of the folder `folder`, read from the store and checked. Bytes
/// that are not a list with the folder's hash are damaged.
pub(crate) fn load_folder(store: &dyn Store, folder: &Target) -> Result<Option<FolderList>> {
    folder.require(Kind::Folder)?;
    let Some(bytes) = store.get(Stored::FolderList, &folder.hash)? else {
        return Ok(None);
    };
    let what = "a stored folder's list";
    let list = FolderList::decode(&bytes)
        .ok()
        .filter(|list| *list.hash() == folder.hash)
        .ok_or_else(|| damaged(what, &folder.hash))?;
    confirm_size(list.size(), folder, what)?;
    Ok(Some(list))
}

/// The list of the file `file`, read from the store and checked. Bytes that
/// are not a list with the file's hash are damaged.
pub(crate) fn load_file(store: &dyn Store, file: &Target) -> Result<Option<FileList>> {
    file.require(Kind::File)?;
    let Some(bytes) = store.get(Stored::FileList, &file.hash)? else {
        return Ok(None);
    };
    let what = "a stored file's list";
    let list = FileList::decode(&bytes)
        .ok()
        .filter(|list| *list.hash() == file.hash)
        .ok_or_else(|| damaged(what, &file.hash))?;
    confirm_size(list.size(), file, what)?;
    Ok(Some(list))
}

/// Whether `bytes` are the piece that `item` names.
pub(crate) fn check_piece(item: &PieceRef, bytes: &[u8], what: &'static str) -> Result<()> {
    if bytes.len() as u64 != u64::from(item.length) {
        return Err(Error::SizeMismatch {
            what,
            expected: u64::from(item.length),
            actual: bytes.len() as u64,
        });
    }
    if Hash::of(bytes) != item.hash {
        return Err(Error::HashMismatch { what });
    }
    Ok(())
}

/// The bytes of the piece that `item` names, read from the store and checked.
/// Bytes that do not hash to the piece's hash are damaged. Bytes that do, and
/// are not as many as the item says, show that the item is wrong.
pub(crate) fn load_piece(store: &dyn Store, item: &PieceRef) -> Result<Option<Arc<[u8]>>> {
    let Some(bytes) = store.get(Stored::Piece, &item.hash)? else {
        return Ok(None);
    };
    if Hash::of(&bytes) != item.hash {
        return Err(damaged("a stored piece", &item.hash));
    }
    if bytes.len() as u64 != u64::from(item.length) {
        return Err(Error::SizeMismatch {
            what: "a stored piece",
            expected: u64::from(item.length),
            actual: bytes.len() as u64,
        });
    }
    Ok(Some(bytes))
}

pub(crate) fn missing(what: &'static str, hash: &Hash) -> Error {
    Error::Missing { what, hash: *hash }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_store_keeps_each_kind_apart_and_each_thing_once() {
        let store = MemoryStore::new();
        let hash = Hash::of(b"x");
        store.put(Stored::Piece, &hash, b"x").unwrap();
        store.put(Stored::Piece, &hash, b"x").unwrap();
        assert_eq!(store.count(Stored::Piece), 1);
        assert_eq!(store.bytes(Stored::Piece), 1);
        assert!(store.has(Stored::Piece, &hash).unwrap());
        assert!(!store.has(Stored::FileList, &hash).unwrap());
        assert_eq!(store.size(Stored::Piece, &hash).unwrap(), Some(1));
        assert_eq!(store.size(Stored::Record, &hash).unwrap(), None);
        assert_eq!(&*store.get(Stored::Piece, &hash).unwrap().unwrap(), b"x");
        assert_eq!(store.hashes(Stored::Piece), vec![hash]);
        store.remove(Stored::Piece, &hash).unwrap();
        assert!(store.get(Stored::Piece, &hash).unwrap().is_none());
    }

    #[test]
    fn what_is_read_from_a_store_is_checked_before_it_is_used() {
        let store = MemoryStore::new();
        let item = PieceRef::of(b"right").unwrap();
        // A store that holds other bytes under a piece's hash.
        store.put(Stored::Piece, &item.hash, b"wrong").unwrap();
        assert!(matches!(
            load_piece(&store, &item),
            Err(Error::Corrupt { .. })
        ));
        store.remove(Stored::Piece, &item.hash).unwrap();
        store.put(Stored::Piece, &item.hash, b"longer").unwrap();
        assert!(matches!(
            load_piece(&store, &item),
            Err(Error::Corrupt { .. })
        ));
        // The piece itself, named by an item that gives it another length.
        store.remove(Stored::Piece, &item.hash).unwrap();
        store.put(Stored::Piece, &item.hash, b"right").unwrap();
        assert!(matches!(
            load_piece(&store, &PieceRef { length: 4, ..item }),
            Err(Error::SizeMismatch { .. })
        ));

        // A list kept under another list's hash.
        let list = FileList::new(vec![item]).unwrap();
        let other = FileList::new(vec![item, item]).unwrap();
        store
            .put(Stored::FileList, list.hash(), &other.encode())
            .unwrap();
        assert!(matches!(
            load_file(&store, &list.target()),
            Err(Error::Corrupt { .. })
        ));
        // The right list, asked for with another size than it has.
        store
            .put(Stored::FileList, other.hash(), &other.encode())
            .unwrap();
        let resized = Target {
            size: other.size() + 1,
            ..other.target()
        };
        assert!(matches!(
            load_file(&store, &resized),
            Err(Error::SizeMismatch { .. })
        ));
        assert!(load_file(&store, &other.target()).unwrap().is_some());
        // A file's list is not found as a folder's.
        let as_folder = Target {
            kind: Kind::Folder,
            ..other.target()
        };
        assert!(load_folder(&store, &as_folder).unwrap().is_none());
        assert!(load_file(&store, &as_folder).is_err());

        // A record kept under another root.
        let root = Root::of_record(b"one");
        store.put(Stored::Record, root.as_hash(), b"two").unwrap();
        assert!(matches!(
            load_record(&store, &root),
            Err(Error::Corrupt { .. })
        ));
    }
}
