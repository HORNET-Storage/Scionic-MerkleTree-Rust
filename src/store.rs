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
use crate::wire::FRAME_CHUNK;
use crate::{Error, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

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
/// should have its own [`Store::lend`] and [`Store::read_into`] too.
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

    /// Reads what is kept under `hash` into `into`, when it is as long as
    /// `into` is, and says how long it is: None when nothing is kept. A
    /// thing of another length is not read, and `into` is left as it was.
    ///
    /// The library reads chunks this way where it holds them a while: to
    /// send them, or to read several at once. Their lists say how long they
    /// are, so they are read one after another into memory that serves one
    /// batch after another. A store on disk should have its own, which looks
    /// at how long a thing is before it reads any of it, and reads it
    /// straight into `into`. Unless a store has its own, this asks
    /// [`Store::lend`] and copies what is lent.
    fn read_into(&self, kind: Stored, hash: &Hash, into: &mut [u8]) -> Result<Option<u64>> {
        let mut length = None;
        let held = self.lend(kind, hash, &mut |bytes| {
            length = Some(bytes.len() as u64);
            if bytes.len() == into.len() {
                into.copy_from_slice(bytes);
            }
            Ok(())
        })?;
        Ok(length.filter(|_| held))
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
        check_stored_chunk(item, bytes)?;
        with(bytes)
    })
}

/// Holds bytes read from a store to the chunk that `item` names. Bytes that
/// do not hash to the chunk's hash are damaged. Bytes that do, and are not
/// as many as the item says, show that the item is wrong.
fn check_stored_chunk(item: &ChunkRef, bytes: &[u8]) -> Result<()> {
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
    Ok(())
}

pub(crate) fn missing(what: &'static str, hash: &Hash) -> Error {
    Error::Missing { what, hash: *hash }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The most bytes of chunks that are read ahead of what is done with them.
const AHEAD_BYTES: u64 = 64 << 20;

/// The most chunks that are read ahead, however short.
const AHEAD_COUNT: usize = 1024;

/// The least bytes of chunks that are worth a thread of their own.
const AHEAD_BYTES_BY_EACH: u64 = 1 << 20;

/// How chunks are read ahead.
#[derive(Clone, Copy)]
enum Ahead {
    /// Checked, as [`lend_chunk`] checks them.
    Checked,
    /// As frames to send, as the store holds them: whoever takes them
    /// checks them.
    Framed,
}

/// What is given each chunk that is read ahead, with its place: None for
/// one that the store does not hold.
type Given<'g> = dyn FnMut(usize, Option<&[u8]>) -> Result<()> + 'g;

/// How many bytes a chunk takes when it is read ahead as `ahead` says.
fn slot_length(item: &ChunkRef, ahead: Ahead) -> usize {
    let length = item.length as usize;
    match ahead {
        Ahead::Checked => length,
        Ahead::Framed => length + 1,
    }
}

/// Reads the chunk that `item` names into `slot`, which is as long as
/// [`slot_length`] gives, as `ahead` says, and says whether the store holds
/// it. A chunk that the store holds with another length than `item` gives
/// is not read into `slot`. Read to be checked, it is lent and checked
/// whole instead, which tells whether it is damaged or `item` is wrong. Read
/// to be sent, it is not held: it cannot be the chunk.
fn read_slot(store: &dyn Store, item: &ChunkRef, ahead: Ahead, slot: &mut [u8]) -> Result<bool> {
    let length = u64::from(item.length);
    match ahead {
        Ahead::Checked => match store.read_into(Stored::Chunk, &item.hash, slot)? {
            None => Ok(false),
            Some(held) if held == length => {
                check_stored_chunk(item, slot)?;
                Ok(true)
            }
            Some(_) => match lend_chunk(store, item, &mut |_| Ok(()))? {
                false => Ok(false),
                true => Err(Error::Invariant {
                    detail: "a store gave two lengths for one chunk",
                }),
            },
        },
        Ahead::Framed => {
            let Some((tag, body)) = slot.split_first_mut() else {
                return Err(Error::Invariant {
                    detail: "a chunk's frame has no room for its tag",
                });
            };
            *tag = FRAME_CHUNK;
            Ok(store.read_into(Stored::Chunk, &item.hash, body)? == Some(length))
        }
    }
}

/// Reads chunks from a store ahead of what is done with them, several at
/// once. The chunks of a batch are read one after another into one stretch
/// of memory, each into as many bytes as its list gives it, and that memory
/// serves one batch after another: memory that is used again costs much
/// less than fresh memory. It is no longer than the longest batch, whatever
/// the lengths of the chunks of the batches before.
pub(crate) struct ChunksAhead {
    memory: Vec<u8>,
    threads: usize,
}

impl ChunksAhead {
    pub(crate) fn new() -> Self {
        Self::with_threads(0)
    }

    /// Reads with up to `threads` threads at once; zero is one for each
    /// core.
    pub(crate) fn with_threads(threads: usize) -> Self {
        let threads = match threads {
            0 => std::thread::available_parallelism().map_or(1, usize::from),
            threads => threads,
        };
        Self {
            memory: Vec::new(),
            threads,
        }
    }

    /// Lends the chunks that `items` name to `with`, each with its place
    /// among them, in their order. Each is read from the store and checked
    /// first, as [`lend_chunk`] checks it. Where the chunks are long enough
    /// to be worth it, several are read and checked at once, ahead of `with`;
    /// otherwise each is lent straight from the store. The first chunk that
    /// is missing or damaged is the error, and `with` is given neither it nor
    /// any after it.
    pub(crate) fn lend(
        &mut self,
        store: &dyn Store,
        items: &[ChunkRef],
        with: &mut dyn FnMut(usize, &[u8]) -> Result<()>,
    ) -> Result<()> {
        self.each(
            store,
            items,
            Ahead::Checked,
            &mut |place, bytes| match bytes {
                Some(bytes) => with(place, bytes),
                None => Err(missing("the chunk", &items[place].hash)),
            },
        )
    }

    /// Gives `with` the frames of the chunks that `items` name, in their
    /// order, read from the store as it holds them: whoever takes them checks
    /// them. Where the chunks are long enough to be worth it, several are
    /// read at once, ahead of `with`. A chunk that the store does not hold,
    /// or holds with another length than its item gives, is given as None,
    /// and nothing after it.
    pub(crate) fn frames(
        &mut self,
        store: &dyn Store,
        items: &[ChunkRef],
        with: &mut dyn FnMut(Option<&[u8]>) -> Result<()>,
    ) -> Result<()> {
        self.each(store, items, Ahead::Framed, &mut |_, frame| with(frame))
    }

    /// Gives `with` each chunk that `items` name, read as `ahead` says, with
    /// its place among them, in their order. A chunk that the store does not
    /// hold is given as None, and nothing after it.
    fn each(
        &mut self,
        store: &dyn Store,
        items: &[ChunkRef],
        ahead: Ahead,
        with: &mut Given<'_>,
    ) -> Result<()> {
        let mut first = 0;
        while first < items.len() {
            let mut count = 0;
            let mut bytes = 0_u64;
            for item in items[first..].iter().take(AHEAD_COUNT) {
                if count > 0 && bytes + u64::from(item.length) > AHEAD_BYTES {
                    break;
                }
                bytes += u64::from(item.length);
                count += 1;
            }
            let batch = &items[first..first + count];
            let worth = usize::try_from(bytes / AHEAD_BYTES_BY_EACH).unwrap_or(usize::MAX);
            let workers = self.threads.min(worth.saturating_add(1)).min(count);
            let mut with_place = |index: usize, bytes: Option<&[u8]>| with(first + index, bytes);
            let ended = if workers <= 1 {
                self.one_at_a_time(store, batch, ahead, &mut with_place)?
            } else {
                self.several_at_once(store, batch, ahead, workers, &mut with_place)?
            };
            if ended {
                return Ok(());
            }
            first += count;
        }
        Ok(())
    }

    /// Gives `with` the chunks of `batch`, read one at a time: a checked one
    /// straight from the store. Says whether one was missing.
    fn one_at_a_time(
        &mut self,
        store: &dyn Store,
        batch: &[ChunkRef],
        ahead: Ahead,
        with: &mut Given<'_>,
    ) -> Result<bool> {
        for (index, item) in batch.iter().enumerate() {
            let held = match ahead {
                Ahead::Checked => lend_chunk(store, item, &mut |bytes| with(index, Some(bytes)))?,
                Ahead::Framed => {
                    let frame = self.room(slot_length(item, ahead));
                    let held = read_slot(store, item, ahead, frame)?;
                    if held {
                        with(index, Some(frame))?;
                    }
                    held
                }
            };
            if !held {
                with(index, None)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Reads the chunks of `batch` on `workers` threads, and then gives them
    /// to `with` in their order. Says whether one was missing.
    fn several_at_once(
        &mut self,
        store: &dyn Store,
        batch: &[ChunkRef],
        ahead: Ahead,
        workers: usize,
        with: &mut Given<'_>,
    ) -> Result<bool> {
        let lengths: Vec<usize> = batch.iter().map(|item| slot_length(item, ahead)).collect();
        // Each chunk's own part of the memory, which one thread reads it
        // into.
        let mut rest = self.room(lengths.iter().sum());
        let slots: Vec<Mutex<&mut [u8]>> = lengths
            .iter()
            .map(|&length| {
                let (slot, after) = std::mem::take(&mut rest).split_at_mut(length);
                rest = after;
                Mutex::new(slot)
            })
            .collect();
        let next = AtomicUsize::new(0);
        let work = || {
            let mut done = Vec::new();
            loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = batch.get(index) else {
                    return done;
                };
                let held = read_slot(store, item, ahead, &mut lock(&slots[index]));
                done.push((index, held));
            }
        };
        let mut done = std::thread::scope(|scope| {
            let handles: Vec<_> = (1..workers).map(|_| scope.spawn(work)).collect();
            let mut done = work();
            for handle in handles {
                match handle.join() {
                    Ok(more) => done.extend(more),
                    Err(payload) => std::panic::resume_unwind(payload),
                }
            }
            done
        });
        done.sort_unstable_by_key(|(index, _)| *index);
        for (index, held) in done {
            if !held? {
                with(index, None)?;
                return Ok(true);
            }
            with(index, Some(&lock(&slots[index])))?;
        }
        Ok(false)
    }

    /// The first `length` bytes of the memory, which grows to hold them, and
    /// to no more. What it held is not needed then: fresh memory, which the
    /// system gives cleared, is neither copied nor cleared here.
    fn room(&mut self, length: usize) -> &mut [u8] {
        if self.memory.len() < length {
            self.memory = vec![0; length];
        }
        &mut self.memory[..length]
    }

    /// How many bytes of memory this holds for chunks.
    #[cfg(test)]
    fn memory_held(&self) -> usize {
        self.memory.capacity()
    }
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

    #[test]
    fn chunks_read_ahead_take_no_more_memory_than_the_longest_batch() {
        // In each batch a long chunk comes after short ones, at another place
        // each time. Memory that each place kept for the longest chunk it
        // held would come to all of them.
        let store = MemoryStore::new();
        let long_bytes = vec![7_u8; 1 << 20];
        let long = ChunkRef::of(&long_bytes).unwrap();
        store.put(Stored::Chunk, &long.hash, &long_bytes).unwrap();
        let short = ChunkRef::of(b"s").unwrap();
        store.put(Stored::Chunk, &short.hash, b"s").unwrap();
        let mut ahead = ChunksAhead::with_threads(4);
        for place in 0..64 {
            let mut items = vec![short; place];
            items.push(long);
            let mut given = Vec::new();
            ahead
                .frames(&store, &items, &mut |frame| {
                    given.push(frame.map(<[u8]>::len));
                    Ok(())
                })
                .unwrap();
            let mut lengths: Vec<_> = items
                .iter()
                .map(|item| Some(item.length as usize + 1))
                .collect();
            assert_eq!(given, lengths);
            // Checked, every eighth time: each check hashes the long chunk.
            if place % 8 == 0 {
                given.clear();
                ahead
                    .lend(&store, &items, &mut |_, bytes| {
                        given.push(Some(bytes.len()));
                        Ok(())
                    })
                    .unwrap();
                lengths
                    .iter_mut()
                    .for_each(|length| *length = length.map(|length| length - 1));
                assert_eq!(given, lengths);
            }
        }
        let most = long_bytes.len() + 1 + 64 * 2;
        assert!(ahead.memory_held() <= most, "{} bytes", ahead.memory_held());
    }
}
