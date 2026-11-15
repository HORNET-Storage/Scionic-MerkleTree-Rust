//! Where a tree's parts are kept.
//!
//! A store keeps four kinds of thing, each found by its hash: chunks, the
//! lists of files, the lists of folders, and records. Because a thing's hash
//! covers only what the thing is, a chunk, a file or a folder that occurs in
//! many trees is kept once.
//!
//! A store checks nothing: it keeps what it is given under the hash it is
//! given. Everything that this library puts into a store is checked first,
//! and everything it takes out is checked again before it is used.

use crate::format::{ChunkRef, FileList, FolderList, Kind, Record, Target};
use crate::hash::{Hash, Root};
use crate::{Error, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// The kinds of thing a store keeps.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Stored {
    /// A chunk's bytes, under the SHA-256 of them.
    Chunk,
    /// A file's whole list, under the file's hash.
    FileList,
    /// A folder's whole list, under the folder's hash.
    FolderList,
    /// A tree's record, under the tree's root.
    Record,
}

/// A place that keeps bytes under hashes.
///
/// A store that can say how long a thing is without reading it should have
/// its own [`Store::size`]: a store on disk above all. Without it, seeing
/// whether a chunk is there takes a read of the whole chunk. A store on disk
/// should have its own [`Store::lend`] too.
pub trait Store: Send + Sync {
    /// Keeps `bytes` under `hash`. Keeping what is kept already changes
    /// nothing.
    fn put(&self, kind: Stored, hash: &Hash, bytes: &[u8]) -> Result<()>;

    /// What is kept under `hash`, if anything.
    fn get(&self, kind: Stored, hash: &Hash) -> Result<Option<Arc<[u8]>>>;

    /// Lends what is kept under `hash` to `with`, and says whether anything
    /// is kept: `with` is called once if it is, and not at all if it is not.
    /// The bytes are lent for that call only, and an error from `with` is
    /// what this gives back.
    ///
    /// The library reads a tree's chunks this way. A store on disk should
    /// have its own, which reads into memory that it uses again: [`Store::get`]
    /// gives fresh memory for every chunk, and some systems take longer to
    /// give that than the reading takes. Unless a store has its own, this
    /// asks `get`.
    fn lend(
        &self,
        kind: Stored,
        hash: &Hash,
        with: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<bool> {
        match self.get(kind, hash)? {
            Some(bytes) => with(&bytes).map(|()| true),
            None => Ok(false),
        }
    }

    /// Whether anything is kept under `hash`. Unless a store has its own,
    /// this asks how long the thing is, so a store that can say that without
    /// reading the bytes is not read.
    fn has(&self, kind: Stored, hash: &Hash) -> Result<bool> {
        Ok(self.size(kind, hash)?.is_some())
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

/// Whether `bytes` are the chunk that `item` names.
pub(crate) fn check_chunk(item: &ChunkRef, bytes: &[u8], what: &'static str) -> Result<()> {
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

/// Has `store` lend the thing under `hash` to `with`, and holds the store to
/// what [`Store::lend`] promises: one call when it says it holds the thing,
/// and none when it says it does not. An error from `with` is given back
/// whatever the store does with it, so that no store can pass over a chunk
/// that was found damaged.
pub(crate) fn lent(
    store: &dyn Store,
    kind: Stored,
    hash: &Hash,
    with: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<bool> {
    let mut calls = 0_u32;
    let mut failed = None;
    let held = store.lend(kind, hash, &mut |bytes| {
        calls += 1;
        let done = if calls == 1 {
            with(bytes)
        } else {
            Err(Error::Invariant {
                detail: "a store lent one thing twice",
            })
        };
        done.map_err(|error| {
            failed.get_or_insert(error);
            // What went wrong is kept here. The store is only told to stop.
            Error::Invariant {
                detail: "what a store lent was refused",
            }
        })
    });
    if let Some(error) = failed {
        return Err(error);
    }
    match (held?, calls) {
        (true, 1) => Ok(true),
        (false, 0) => Ok(false),
        (true, _) => Err(Error::Invariant {
            detail: "a store said it held a thing, and lent nothing",
        }),
        (false, _) => Err(Error::Invariant {
            detail: "a store lent a thing, and said it did not hold it",
        }),
    }
}

/// Lends the chunk that `item` names to `with`, read from the store and
/// checked first, and says whether the store holds it. Bytes that do not hash
/// to the chunk's hash are damaged. Bytes that do, and are not as many as the
/// item says, show that the item is wrong.
pub(crate) fn lend_chunk(
    store: &dyn Store,
    item: &ChunkRef,
    with: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<bool> {
    lent(store, Stored::Chunk, &item.hash, &mut |bytes| {
        if Hash::of(bytes) != item.hash {
            return Err(damaged("a stored chunk", &item.hash));
        }
        if bytes.len() as u64 != u64::from(item.length) {
            return Err(Error::SizeMismatch {
                what: "a stored chunk",
                expected: u64::from(item.length),
                actual: bytes.len() as u64,
            });
        }
        with(bytes)
    })
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
        store.put(Stored::Chunk, &hash, b"x").unwrap();
        store.put(Stored::Chunk, &hash, b"x").unwrap();
        assert_eq!(store.count(Stored::Chunk), 1);
        assert_eq!(store.bytes(Stored::Chunk), 1);
        assert!(store.has(Stored::Chunk, &hash).unwrap());
        assert!(!store.has(Stored::FileList, &hash).unwrap());
        assert_eq!(store.size(Stored::Chunk, &hash).unwrap(), Some(1));
        assert_eq!(store.size(Stored::Record, &hash).unwrap(), None);
        assert_eq!(&*store.get(Stored::Chunk, &hash).unwrap().unwrap(), b"x");
        assert_eq!(store.hashes(Stored::Chunk), vec![hash]);
        store.remove(Stored::Chunk, &hash).unwrap();
        assert!(store.get(Stored::Chunk, &hash).unwrap().is_none());
    }

    /// A store that says how long a thing is, and counts how often a thing
    /// is read from it.
    struct Sized {
        inner: MemoryStore,
        read: std::sync::atomic::AtomicUsize,
    }

    impl Store for Sized {
        fn put(&self, kind: Stored, hash: &Hash, bytes: &[u8]) -> Result<()> {
            self.inner.put(kind, hash, bytes)
        }

        fn get(&self, kind: Stored, hash: &Hash) -> Result<Option<Arc<[u8]>>> {
            self.read.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.get(kind, hash)
        }

        fn size(&self, kind: Stored, hash: &Hash) -> Result<Option<u64>> {
            self.inner.size(kind, hash)
        }

        fn remove(&self, kind: Stored, hash: &Hash) -> Result<()> {
            self.inner.remove(kind, hash)
        }
    }

    #[test]
    fn a_store_that_says_how_long_a_thing_is_is_not_read_to_see_what_it_holds() {
        let store = Sized {
            inner: MemoryStore::new(),
            read: Default::default(),
        };
        let content: Vec<u8> = (0..5000_u32).map(|at| (at % 251) as u8).collect();
        let mut builder = crate::Builder::new(&store, crate::Chunking::fixed(16).unwrap());
        let first = builder.file_from_bytes(&content).unwrap();
        // Built again, every chunk and the list are there already. Seeing
        // that takes no read: for a store on disk, a read is the whole of a
        // chunk.
        let again = builder.file_from_bytes(&content).unwrap();
        assert_eq!(again, first);
        assert!(store.inner.count(Stored::Chunk) > 100);
        assert_eq!(store.read.load(std::sync::atomic::Ordering::Relaxed), 0);
        // And it is still asked rightly.
        assert!(!store.has(Stored::Chunk, &Hash::of(b"not there")).unwrap());
        assert!(store.has(Stored::FileList, &first.hash).unwrap());
        assert!(!store.has(Stored::FolderList, &first.hash).unwrap());
    }

    #[test]
    fn what_is_read_from_a_store_is_checked_before_it_is_used() {
        let store = MemoryStore::new();
        let item = ChunkRef::of(b"right").unwrap();
        // How many times a chunk was handed on.
        let seen = std::cell::Cell::new(0);
        let mut count = |_: &[u8]| {
            seen.set(seen.get() + 1);
            Ok(())
        };
        // A store that holds other bytes under a chunk's hash.
        store.put(Stored::Chunk, &item.hash, b"wrong").unwrap();
        assert!(matches!(
            lend_chunk(&store, &item, &mut count),
            Err(Error::Corrupt { .. })
        ));
        store.remove(Stored::Chunk, &item.hash).unwrap();
        store.put(Stored::Chunk, &item.hash, b"longer").unwrap();
        assert!(matches!(
            lend_chunk(&store, &item, &mut count),
            Err(Error::Corrupt { .. })
        ));
        // The chunk itself, named by an item that gives it another length.
        store.remove(Stored::Chunk, &item.hash).unwrap();
        store.put(Stored::Chunk, &item.hash, b"right").unwrap();
        assert!(matches!(
            lend_chunk(&store, &ChunkRef { length: 4, ..item }, &mut count),
            Err(Error::SizeMismatch { .. })
        ));
        // Nothing that failed a check was handed on.
        assert_eq!(seen.get(), 0);
        assert!(matches!(lend_chunk(&store, &item, &mut count), Ok(true)));
        assert_eq!(seen.get(), 1);

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

    /// A store that lends as it is set to, rightly or not.
    struct Lending {
        inner: MemoryStore,
        /// How many times it hands a thing to `with`.
        calls: usize,
        /// Whether it says that it holds the thing.
        says: bool,
        /// Whether it passes over an error that `with` gives.
        passes_over: bool,
    }

    impl Store for Lending {
        fn put(&self, kind: Stored, hash: &Hash, bytes: &[u8]) -> Result<()> {
            self.inner.put(kind, hash, bytes)
        }

        fn get(&self, kind: Stored, hash: &Hash) -> Result<Option<Arc<[u8]>>> {
            self.inner.get(kind, hash)
        }

        fn lend(
            &self,
            kind: Stored,
            hash: &Hash,
            with: &mut dyn FnMut(&[u8]) -> Result<()>,
        ) -> Result<bool> {
            let bytes = self
                .inner
                .get(kind, hash)?
                .unwrap_or_else(|| Arc::from(&b""[..]));
            for _ in 0..self.calls {
                let done = with(&bytes);
                if !self.passes_over {
                    done?;
                }
            }
            Ok(self.says)
        }

        fn remove(&self, kind: Stored, hash: &Hash) -> Result<()> {
            self.inner.remove(kind, hash)
        }
    }

    #[test]
    fn a_store_is_held_to_what_lending_promises() {
        let item = ChunkRef::of(b"right").unwrap();
        // What lending a chunk gave, and what was handed on of it.
        let lend = |calls, says, passes_over, kept: &[u8]| {
            let store = Lending {
                inner: MemoryStore::new(),
                calls,
                says,
                passes_over,
            };
            store.put(Stored::Chunk, &item.hash, kept).unwrap();
            let mut seen = Vec::new();
            let lent = lend_chunk(&store, &item, &mut |bytes| {
                seen.push(bytes.to_vec());
                Ok(())
            });
            (lent, seen)
        };
        // As promised: one call for what is held, and none for what is not.
        let (lent, seen) = lend(1, true, false, b"right");
        assert!(matches!(lent, Ok(true)));
        assert_eq!(seen, vec![b"right".to_vec()]);
        assert!(matches!(lend(0, false, false, b"right").0, Ok(false)));
        // A second call is refused, and nothing of it is handed on.
        let (lent, seen) = lend(2, true, true, b"right");
        assert!(matches!(lent, Err(Error::Invariant { .. })));
        assert_eq!(seen.len(), 1);
        // Said to be held, and nothing lent; lent, and said not to be held.
        assert!(matches!(
            lend(0, true, false, b"right").0,
            Err(Error::Invariant { .. })
        ));
        assert!(matches!(
            lend(1, false, false, b"right").0,
            Err(Error::Invariant { .. })
        ));
        // Damaged bytes stay an error when the store passes over it, and are
        // never handed on.
        for passes_over in [false, true] {
            let (lent, seen) = lend(1, true, passes_over, b"wrong");
            assert!(matches!(lent, Err(Error::Corrupt { .. })));
            assert!(seen.is_empty());
        }
    }
}
