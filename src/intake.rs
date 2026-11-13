//! Taking a tree in, and checking a tree that is held.
//!
//! There is one set of checks, and it is here. A tree that arrives from a
//! peer, a tree read from a bundle and a tree that already sits in a store
//! all go through an [`Intake`]:
//!
//! * the record must hash to the root that was asked for;
//! * a list is taken only when a list that is already checked names it, and
//!   only when it has the hash, the size and the chunk lengths it has to;
//! * a chunk is taken only when a file's list that is already checked names
//!   it, and only with the bytes and the length that list gives it;
//! * at the end nothing may be missing, folders may not sit too deep, and
//!   the record's totals must be those of the tree.
//!
//! So parents come first, and nothing is kept before it is tied to the root.
//! A frame never says which hash it belongs under. Its hash is worked out
//! from its bytes.

use crate::fastcdc::StreamChunker;
use crate::format::{
    ChunkRef, Chunking, FileList, FolderList, Kind, Record, Target, Totals, LIST_ITEM_BYTES,
    MAX_CHUNK_BYTES, MAX_FOLDER_DEPTH, MAX_RECORD_BYTES,
};
use crate::hash::{Hash, Root};
use crate::store::{load_record, missing, Store, Stored};
use crate::wire::{Request, FRAME_CHUNK, FRAME_FILE_LIST, FRAME_FOLDER_LIST, FRAME_RECORD};
use crate::{Error, Result};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// The most chunks one request asks for.
const CHUNKS_PER_REQUEST: u32 = 64;

fn invalid(detail: &str) -> Error {
    Error::InvalidData {
        detail: detail.to_owned(),
    }
}

/// What a frame turned out to be, once its hash was worked out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Arrived {
    Record,
    FolderList(Hash),
    FileList(Hash),
    Chunk(Hash),
}

/// What became of a frame that an intake accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accepted {
    pub what: Arrived,
    /// Whether it was kept now. It is not when it was held already.
    pub kept: bool,
}

/// A tree that is whole and checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Summary {
    pub record: Record,
    /// How many different folders the tree has.
    pub folders: u64,
    /// How many different files the tree has.
    pub files: u64,
}

/// How a held tree is checked, beyond what is always checked.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VerifyOptions {
    rechunk: bool,
    discard: bool,
    workers: usize,
}

impl VerifyOptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Also chunks every file's bytes again, and refuses a file whose list is
    /// not the one the chunker gives. With this, the same bytes always have
    /// the same file hash. It costs one more pass over the bytes.
    pub fn rechunk(mut self, on: bool) -> Self {
        self.rechunk = on;
        self
    }

    /// Removes from the store what is damaged there: a chunk, a list or a
    /// record whose bytes are not what its hash says. The check then ends
    /// with one of them as missing, and a fetch of the tree brings them all
    /// again. Without this the check stops at a damaged thing and names it,
    /// and the store is left as it is.
    pub fn discard_damaged(mut self, on: bool) -> Self {
        self.discard = on;
        self
    }

    /// How many chunks are hashed at once. Zero is one for each core.
    pub fn workers(mut self, workers: usize) -> Self {
        self.workers = workers;
        self
    }
}

#[derive(Clone, Copy, Default)]
struct Mode {
    /// Chunk again the files that are held whole.
    rechunk: bool,
    /// Remove from the store what is damaged there, and want it again.
    discard: bool,
}

struct FolderSlot {
    size: u64,
    order: u64,
    held: bool,
    /// The folders directly inside this one.
    inside: Vec<Hash>,
}

struct FileSlot {
    size: u64,
    order: u64,
    held: bool,
}

struct ChunkSlot {
    length: u32,
    /// Where the chunk was first listed, while it is not held: the file,
    /// by the order it was named in, and the chunk's number there.
    wanted_at: Option<(u64, u64)>,
}

/// Takes one tree into a store, checking every part as it arrives.
///
/// An intake is given frames in any order that puts parents first. What the
/// store holds already is found when it is named, and is not asked for.
///
/// A frame that is refused at the door leaves the intake as it was: one that
/// nothing names, one that is malformed, one that was not asked for. A list
/// that is named and then fails a check shows that the tree itself is wrong.
/// The list is not kept, and the intake is done: every later call gives
/// [`Error::IntakeFailed`]. A new intake picks up from what the store holds.
///
/// What the store holds under a hash and is not what the hash says is
/// damaged. An intake removes it from the store and wants it again, so a tree
/// that was harmed where it is kept is made whole by fetching it once more.
/// Nothing a peer sends can make an intake remove what is sound.
pub struct Intake<'s> {
    store: &'s dyn Store,
    root: Root,
    mode: Mode,
    record: Option<Record>,
    /// How the files are chunked, for a tree that has no record yet.
    measuring: Option<Chunking>,
    folders: HashMap<Hash, FolderSlot>,
    files: HashMap<Hash, FileSlot>,
    chunks: HashMap<Hash, ChunkSlot>,
    /// Lists that are named and not held, in the order they were named.
    wanted_lists: BTreeMap<u64, Target>,
    /// Chunks that are named and not held, by where they were first listed.
    wanted_chunks: BTreeMap<(u64, u64), Hash>,
    file_by_order: HashMap<u64, Hash>,
    next_order: u64,
    counted: Totals,
    pending: Vec<Target>,
    /// The files to chunk again, once their chunks are hashed.
    to_rechunk: Vec<Hash>,
    chunker: Option<StreamChunker>,
    /// A step that changes what the intake knows failed half way.
    failed: bool,
}

impl<'s> Intake<'s> {
    /// Starts taking in the tree with this root. If the store holds the
    /// tree's record, everything else it holds of the tree is found now.
    pub fn new(store: &'s dyn Store, root: Root) -> Result<Self> {
        let mode = Mode {
            discard: true,
            ..Mode::default()
        };
        Self::with_mode(store, root, mode)
    }

    fn bare(store: &'s dyn Store, root: Root, mode: Mode) -> Self {
        Self {
            store,
            root,
            mode,
            record: None,
            measuring: None,
            folders: HashMap::new(),
            files: HashMap::new(),
            chunks: HashMap::new(),
            wanted_lists: BTreeMap::new(),
            wanted_chunks: BTreeMap::new(),
            file_by_order: HashMap::new(),
            next_order: 0,
            counted: Totals::default(),
            pending: Vec::new(),
            to_rechunk: Vec::new(),
            chunker: None,
            failed: false,
        }
    }

    fn with_mode(store: &'s dyn Store, root: Root, mode: Mode) -> Result<Self> {
        let mut intake = Self::bare(store, root, mode);
        match load_record(store, &root) {
            Ok(Some(record)) => intake.begin(record)?,
            Ok(None) => {}
            // A record that is damaged where it is kept is fetched again.
            Err(Error::Corrupt { .. }) if mode.discard => {
                store.remove(Stored::Record, root.as_hash())?;
            }
            Err(error) => return Err(error),
        }
        Ok(intake)
    }

    /// Checks every list under `top` as an intake checks it, for a tree that
    /// has no record yet, and counts what its record has to say: each
    /// different chunk and each different list, once. The store must hold
    /// every list. This is how a builder comes by a record's totals, so a
    /// tree that is built has passed the checks of a tree that is taken in.
    pub(crate) fn measure(store: &'s dyn Store, top: Target, chunking: Chunking) -> Result<Totals> {
        let mut intake = Self::bare(store, Root::from_hash(Hash::ZERO), Mode::default());
        intake.measuring = Some(chunking);
        intake.refer(top)?;
        intake.drain()?;
        intake.lists_held()?;
        intake.check_depth(&top)?;
        Ok(intake.counted)
    }

    pub fn root(&self) -> &Root {
        &self.root
    }

    /// The tree's record, once it is in. Its totals say how much the tree
    /// will take before any of it is taken, and an intake stops as soon as a
    /// tree turns out to hold more than its record says.
    pub fn record(&self) -> Option<&Record> {
        self.record.as_ref()
    }

    /// How many lists and chunks are named and not held yet. The record
    /// counts as one while it is not in.
    pub fn outstanding(&self) -> usize {
        usize::from(self.record.is_none()) + self.wanted_lists.len() + self.wanted_chunks.len()
    }

    /// How many bytes of lists the record still leaves room for.
    fn lists_left(&self) -> usize {
        let Some(record) = &self.record else {
            return 0;
        };
        let left = record
            .totals()
            .list_bytes
            .saturating_sub(self.counted.list_bytes);
        usize::try_from(left).unwrap_or(usize::MAX)
    }

    /// The longest chunk the tree's way of chunking allows.
    fn longest_chunk(&self) -> usize {
        match self.record.as_ref().map(Record::chunking) {
            Some(Chunking::Fixed(length)) => length.get() as usize,
            _ => MAX_CHUNK_BYTES,
        }
    }

    /// The longest frame that a stream of this tree can hold, whatever comes
    /// next: for a reader of a stream that was not asked frame by frame, as
    /// a bundle is. Before the record it is the longest record. After it,
    /// it is the longest of a record, a chunk, and all the bytes of lists
    /// that the record gives the tree. What the store holds already may
    /// come too, and is passed over, so this does not shrink as lists come.
    pub fn frame_limit(&self) -> usize {
        let Some(record) = &self.record else {
            return MAX_RECORD_BYTES;
        };
        usize::try_from(record.totals().list_bytes)
            .unwrap_or(usize::MAX)
            .max(self.longest_chunk())
            .saturating_add(1)
            .max(MAX_RECORD_BYTES)
    }

    /// The longest frame that can answer one of this intake's requests. A
    /// peer that sends a longer one is not answering what was asked, and its
    /// frame need not be read: a file's list is no longer than the file's
    /// size allows, no list is longer than the record leaves room for, and a
    /// chunk is no longer than the tree's way of chunking allows.
    pub fn answer_limit(&self, request: &Request) -> usize {
        let limit = match request {
            Request::Record(_) => MAX_RECORD_BYTES,
            Request::Folder(_) => self.lists_left().saturating_add(1),
            Request::File(file) => {
                let most = match (&self.record, self.files.get(file)) {
                    (Some(record), Some(slot)) => record.chunking().count_bounds(slot.size).1,
                    _ => 0,
                };
                usize::try_from(most)
                    .unwrap_or(usize::MAX)
                    .saturating_mul(LIST_ITEM_BYTES)
                    .min(self.lists_left())
                    .saturating_add(1)
            }
            Request::Chunks { .. } | Request::Chunk(_) => self.longest_chunk() + 1,
            _ => 0,
        };
        // A refusal takes two bytes, and is always let through.
        limit.max(2)
    }

    fn begin(&mut self, record: Record) -> Result<()> {
        let top = record.top();
        self.record = Some(record);
        self.refer(top)?;
        self.drain()
    }

    fn recorded(&self) -> Result<&Record> {
        self.record.as_ref().ok_or(Error::NotWanted {
            what: "a frame that comes before the record",
        })
    }

    /// How the tree's files are chunked.
    fn chunking(&self) -> Result<Chunking> {
        match self.measuring {
            Some(chunking) => Ok(chunking),
            None => Ok(self.recorded()?.chunking()),
        }
    }

    /// Every list that is named has to be held.
    fn lists_held(&self) -> Result<()> {
        match self.wanted_lists.values().next() {
            Some(target) => Err(missing(
                match target.kind {
                    Kind::Folder => "the list of the folder",
                    Kind::File => "the list of the file",
                },
                &target.hash,
            )),
            None => Ok(()),
        }
    }

    /// The store holds, under `hash`, bytes that are not what the hash says.
    /// They are removed when this intake may do that, so that they are
    /// wanted again. Otherwise they are an error that names them.
    fn damaged(&self, kind: Stored, hash: &Hash, what: &'static str) -> Result<()> {
        if self.mode.discard {
            self.store.remove(kind, hash)
        } else {
            Err(Error::Corrupt { what, hash: *hash })
        }
    }

    /// Whether the store holds the chunk that `item` names. The chunk's
    /// bytes are counted here, not hashed.
    fn holds(&self, item: &ChunkRef) -> Result<bool> {
        let size = match self.store.size(Stored::Chunk, &item.hash)? {
            None => return Ok(false),
            Some(size) if size == u64::from(item.length) => return Ok(true),
            Some(size) => size,
        };
        // Either the store's bytes are damaged, or the list gives the chunk
        // a length it does not have. Only damaged bytes are ever removed: a
        // list that names a sound chunk wrongly must not cost the store it.
        match self.store.get(Stored::Chunk, &item.hash)? {
            None => Ok(false),
            Some(bytes) if Hash::of(&bytes) == item.hash => Err(Error::SizeMismatch {
                what: "a held chunk",
                expected: u64::from(item.length),
                actual: size,
            }),
            Some(_) => {
                self.damaged(Stored::Chunk, &item.hash, "a stored chunk")?;
                Ok(false)
            }
        }
    }

    /// Notes that a checked parent names `target`.
    fn refer(&mut self, target: Target) -> Result<()> {
        let known = match target.kind {
            Kind::Folder => self.folders.get(&target.hash).map(|slot| slot.size),
            Kind::File => self.files.get(&target.hash).map(|slot| slot.size),
        };
        if let Some(size) = known {
            return if size == target.size {
                Ok(())
            } else {
                Err(Error::SizeMismatch {
                    what: "a file or folder that is named twice",
                    expected: size,
                    actual: target.size,
                })
            };
        }
        let order = self.next_order;
        self.next_order += 1;
        match target.kind {
            Kind::Folder => {
                self.folders.insert(
                    target.hash,
                    FolderSlot {
                        size: target.size,
                        order,
                        held: false,
                        inside: Vec::new(),
                    },
                );
            }
            Kind::File => {
                self.files.insert(
                    target.hash,
                    FileSlot {
                        size: target.size,
                        order,
                        held: false,
                    },
                );
                self.file_by_order.insert(order, target.hash);
            }
        }
        self.pending.push(target);
        Ok(())
    }

    /// Looks in the store for every list that was newly named. A list that
    /// is there is checked like one that arrives, and the lists it names are
    /// looked for in turn. A list that is not there is wanted, and so is one
    /// that is damaged there.
    fn drain(&mut self) -> Result<()> {
        while let Some(target) = self.pending.pop() {
            match target.kind {
                Kind::Folder => {
                    let held = self.store.get(Stored::FolderList, &target.hash)?;
                    let list = held.as_deref().map(|bytes| {
                        FolderList::decode(bytes)
                            .ok()
                            .filter(|list| *list.hash() == target.hash)
                    });
                    match list {
                        Some(Some(list)) => self.admit_folder(&list)?,
                        Some(None) => {
                            let what = "a stored folder's list";
                            self.damaged(Stored::FolderList, &target.hash, what)?;
                            self.want(target);
                        }
                        None => self.want(target),
                    }
                }
                Kind::File => {
                    let held = self.store.get(Stored::FileList, &target.hash)?;
                    let list = held.as_deref().map(|bytes| {
                        FileList::decode(bytes)
                            .ok()
                            .filter(|list| *list.hash() == target.hash)
                    });
                    match list {
                        Some(Some(list)) => self.admit_file(&list)?,
                        Some(None) => {
                            let what = "a stored file's list";
                            self.damaged(Stored::FileList, &target.hash, what)?;
                            self.want(target);
                        }
                        None => self.want(target),
                    }
                }
            }
        }
        Ok(())
    }

    fn want(&mut self, target: Target) {
        let order = match target.kind {
            Kind::Folder => self.folders.get(&target.hash).map(|slot| slot.order),
            Kind::File => self.files.get(&target.hash).map(|slot| slot.order),
        };
        if let Some(order) = order {
            self.wanted_lists.insert(order, target);
        }
    }

    fn count_list_bytes(&mut self, bytes: u64) -> Result<()> {
        self.counted.list_bytes =
            self.counted
                .list_bytes
                .checked_add(bytes)
                .ok_or(Error::SizeOverflow {
                    field: "list bytes",
                })?;
        // A tree that is being measured has no record to be held to yet.
        let Some(record) = &self.record else {
            return Ok(());
        };
        let recorded = record.totals().list_bytes;
        if self.counted.list_bytes > recorded {
            return Err(Error::TotalsMismatch {
                field: "list bytes",
                recorded,
                counted: self.counted.list_bytes,
            });
        }
        Ok(())
    }

    fn count_chunk(&mut self, length: u32) -> Result<()> {
        self.counted.chunks = self
            .counted
            .chunks
            .checked_add(1)
            .ok_or(Error::SizeOverflow { field: "chunks" })?;
        self.counted.chunk_bytes = self
            .counted
            .chunk_bytes
            .checked_add(u64::from(length))
            .ok_or(Error::SizeOverflow {
                field: "chunk bytes",
            })?;
        let Some(record) = &self.record else {
            return Ok(());
        };
        let recorded = record.totals();
        if self.counted.chunks > recorded.chunks {
            return Err(Error::TotalsMismatch {
                field: "chunks",
                recorded: recorded.chunks,
                counted: self.counted.chunks,
            });
        }
        if self.counted.chunk_bytes > recorded.chunk_bytes {
            return Err(Error::TotalsMismatch {
                field: "chunk bytes",
                recorded: recorded.chunk_bytes,
                counted: self.counted.chunk_bytes,
            });
        }
        Ok(())
    }

    /// Takes a folder's list that is named, and notes what it names.
    fn admit_folder(&mut self, list: &FolderList) -> Result<()> {
        let slot = self.folders.get_mut(list.hash()).ok_or(Error::Invariant {
            detail: "a folder is admitted before it is named",
        })?;
        if slot.size != list.size() {
            return Err(Error::SizeMismatch {
                what: "a folder",
                expected: slot.size,
                actual: list.size(),
            });
        }
        slot.held = true;
        slot.inside = list
            .entries()
            .iter()
            .filter(|entry| entry.kind() == Kind::Folder)
            .map(|entry| *entry.hash())
            .collect();
        slot.inside.sort_unstable();
        slot.inside.dedup();
        let order = slot.order;
        self.wanted_lists.remove(&order);
        self.count_list_bytes(list.encoded_len())?;
        for entry in list.entries() {
            self.refer(entry.target())?;
        }
        Ok(())
    }

    /// Takes a file's list that is named, and notes the chunks it names.
    fn admit_file(&mut self, list: &FileList) -> Result<()> {
        let chunking = self.chunking()?;
        list.check_chunking(chunking)?;
        let slot = self.files.get_mut(list.hash()).ok_or(Error::Invariant {
            detail: "a file is admitted before it is named",
        })?;
        if slot.size != list.size() {
            return Err(Error::SizeMismatch {
                what: "a file",
                expected: slot.size,
                actual: list.size(),
            });
        }
        slot.held = true;
        let order = slot.order;
        self.wanted_lists.remove(&order);
        self.count_list_bytes(list.encoded_len())?;
        for (number, item) in (0_u64..).zip(list.items()) {
            if let Some(slot) = self.chunks.get(&item.hash) {
                if slot.length != item.length {
                    return Err(Error::SizeMismatch {
                        what: "a chunk that is listed with two lengths",
                        expected: u64::from(slot.length),
                        actual: u64::from(item.length),
                    });
                }
                continue;
            }
            self.count_chunk(item.length)?;
            let held = self.holds(item)?;
            let wanted_at = (!held).then_some((order, number));
            if let Some(at) = wanted_at {
                self.wanted_chunks.insert(at, item.hash);
            }
            self.chunks.insert(
                item.hash,
                ChunkSlot {
                    length: item.length,
                    wanted_at,
                },
            );
        }
        if self.mode.rechunk && chunking == Chunking::FastCdcV1 {
            self.to_rechunk.push(*list.hash());
        }
        Ok(())
    }

    /// Hashes again every chunk of this tree that the store holds, several
    /// at once. A chunk whose bytes are not what its hash says is damaged.
    fn rehash_held(&mut self, workers: usize) -> Result<()> {
        let mut held: Vec<ChunkRef> = self
            .chunks
            .iter()
            .filter(|(_, slot)| slot.wanted_at.is_none())
            .map(|(hash, slot)| ChunkRef {
                hash: *hash,
                length: slot.length,
            })
            .collect();
        held.sort_unstable_by_key(|item| item.hash);
        let store = self.store;
        let next = AtomicUsize::new(0);
        // Gives the places, in `held`, of the chunks that are damaged.
        let work = || -> Result<Vec<usize>> {
            let mut spoiled = Vec::new();
            loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = held.get(index) else {
                    return Ok(spoiled);
                };
                let bytes = store
                    .get(Stored::Chunk, &item.hash)
                    .and_then(|bytes| bytes.ok_or_else(|| missing("the chunk", &item.hash)));
                match bytes {
                    Ok(bytes) if item.matches(&bytes) => {}
                    Ok(_) => spoiled.push(index),
                    Err(error) => {
                        next.store(held.len(), Ordering::Relaxed);
                        return Err(error);
                    }
                }
            }
        };
        let workers = match workers {
            0 => std::thread::available_parallelism().map_or(1, usize::from),
            workers => workers,
        }
        .min(held.len());
        let results: Vec<Result<Vec<usize>>> = if workers <= 1 {
            vec![work()]
        } else {
            std::thread::scope(|scope| {
                let handles: Vec<_> = (0..workers).map(|_| scope.spawn(work)).collect();
                handles
                    .into_iter()
                    .map(|handle| match handle.join() {
                        Ok(result) => result,
                        Err(payload) => std::panic::resume_unwind(payload),
                    })
                    .collect()
            })
        };
        let mut spoiled = Vec::new();
        for result in results {
            spoiled.extend(result?);
        }
        spoiled.sort_unstable();
        for &index in &spoiled {
            self.damaged(Stored::Chunk, &held[index].hash, "a stored chunk")?;
        }
        match spoiled.first() {
            Some(&index) => Err(missing("the chunk", &held[index].hash)),
            None => Ok(()),
        }
    }

    /// Chunks again every file that is held whole, and holds the result
    /// against the file's list. The chunks were hashed before this.
    fn rechunk_held(&mut self) -> Result<()> {
        for file in std::mem::take(&mut self.to_rechunk) {
            let Some(bytes) = self.store.get(Stored::FileList, &file)? else {
                continue;
            };
            let list = FileList::decode(&bytes)?;
            let whole = list.items().iter().all(|item| {
                self.chunks
                    .get(&item.hash)
                    .is_some_and(|slot| slot.wanted_at.is_none())
            });
            if whole {
                self.rechunk(&list)?;
            }
        }
        Ok(())
    }

    /// Chunks a file's bytes again, and holds the result against its list.
    fn rechunk(&mut self, list: &FileList) -> Result<()> {
        let store = self.store;
        let chunker = self.chunker.get_or_insert_with(StreamChunker::new);
        let mut unread = list.items().iter();
        let mut current: Option<(Arc<[u8]>, usize)> = None;
        let mut unchunked = list.items().iter();
        let mischunked = || invalid("the chunks of a file do not end where its bytes say they end");
        chunker.cut(
            Chunking::FastCdcV1,
            2 * MAX_CHUNK_BYTES,
            |buffer| loop {
                if let Some((bytes, at)) = &mut current {
                    if *at < bytes.len() {
                        let count = buffer.len().min(bytes.len() - *at);
                        buffer[..count].copy_from_slice(&bytes[*at..*at + count]);
                        *at += count;
                        return Ok(count);
                    }
                }
                match unread.next() {
                    Some(item) => {
                        let bytes = store
                            .get(Stored::Chunk, &item.hash)?
                            .filter(|bytes| bytes.len() == item.length as usize)
                            .ok_or_else(|| missing("the chunk", &item.hash))?;
                        current = Some((bytes, 0));
                    }
                    None => return Ok(0),
                }
            },
            |chunks| {
                for chunk in chunks {
                    match unchunked.next() {
                        Some(item) if item.length as usize == chunk.len() => {}
                        _ => return Err(mischunked()),
                    }
                }
                Ok(())
            },
        )?;
        if unchunked.next().is_some() {
            return Err(mischunked());
        }
        Ok(())
    }

    /// Takes one frame: a record, a whole list, or a chunk.
    ///
    /// A frame is accepted when it is what a checked parent names. A frame
    /// that is named and held already is accepted and not kept again. Any
    /// other frame is an error: one that nothing names, one that is
    /// malformed, and one that does not have the size it was given.
    pub fn accept(&mut self, frame: &[u8]) -> Result<Accepted> {
        self.accept_inner(frame, None)
    }

    /// Takes one frame, which has to be exactly `expected`: the answer to
    /// what was asked. Anything else is refused, and nothing of it is kept.
    pub fn accept_expected(&mut self, frame: &[u8], expected: Arrived) -> Result<Accepted> {
        self.accept_inner(frame, Some(expected))
    }

    /// Runs a step that changes what the intake knows of its tree. If the
    /// step fails, the intake knows half of something, and is done.
    fn taking(&mut self, step: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        let done = step(self);
        self.failed |= done.is_err();
        done
    }

    fn accept_inner(&mut self, frame: &[u8], expected: Option<Arrived>) -> Result<Accepted> {
        if self.failed {
            return Err(Error::IntakeFailed);
        }
        let (&tag, body) = frame
            .split_first()
            .ok_or_else(|| invalid("a frame is empty"))?;
        let as_asked = |arrived: Arrived, what: &'static str| match expected {
            Some(expected) if expected != arrived => Err(Error::NotWanted { what }),
            _ => Ok(()),
        };
        match tag {
            FRAME_RECORD => {
                let what = Arrived::Record;
                as_asked(what, "a record")?;
                if Root::of_record(frame) != self.root {
                    return Err(Error::HashMismatch { what: "a record" });
                }
                if self.record.is_some() {
                    return Ok(Accepted { what, kept: false });
                }
                let record = Record::decode(frame)?;
                self.store.put(Stored::Record, self.root.as_hash(), frame)?;
                self.taking(|intake| intake.begin(record))?;
                Ok(Accepted { what, kept: true })
            }
            FRAME_FOLDER_LIST => {
                self.recorded()?;
                let list = FolderList::decode(body)?;
                let what = Arrived::FolderList(*list.hash());
                as_asked(what, "a folder's list")?;
                match self.folders.get(list.hash()) {
                    None => Err(Error::NotWanted {
                        what: "a folder's list",
                    }),
                    Some(slot) if slot.held => Ok(Accepted { what, kept: false }),
                    Some(slot) if slot.size != list.size() => Err(Error::SizeMismatch {
                        what: "a folder",
                        expected: slot.size,
                        actual: list.size(),
                    }),
                    Some(_) => {
                        // The list is kept only once all it says has passed.
                        self.taking(|intake| {
                            intake.admit_folder(&list)?;
                            intake.store.put(Stored::FolderList, list.hash(), body)?;
                            intake.drain()
                        })?;
                        Ok(Accepted { what, kept: true })
                    }
                }
            }
            FRAME_FILE_LIST => {
                self.recorded()?;
                let list = FileList::decode(body)?;
                let what = Arrived::FileList(*list.hash());
                as_asked(what, "a file's list")?;
                match self.files.get(list.hash()) {
                    None => Err(Error::NotWanted {
                        what: "a file's list",
                    }),
                    Some(slot) if slot.held => Ok(Accepted { what, kept: false }),
                    Some(slot) if slot.size != list.size() => Err(Error::SizeMismatch {
                        what: "a file",
                        expected: slot.size,
                        actual: list.size(),
                    }),
                    Some(_) => {
                        // The list is kept only once all it says has passed.
                        self.taking(|intake| {
                            intake.admit_file(&list)?;
                            intake.store.put(Stored::FileList, list.hash(), body)
                        })?;
                        Ok(Accepted { what, kept: true })
                    }
                }
            }
            FRAME_CHUNK => {
                self.recorded()?;
                if body.is_empty() || body.len() > MAX_CHUNK_BYTES {
                    return Err(invalid("a chunk does not hold 1 byte to 8 MiB"));
                }
                let hash = Hash::of(body);
                let what = Arrived::Chunk(hash);
                as_asked(what, "a chunk")?;
                let slot = self
                    .chunks
                    .get_mut(&hash)
                    .ok_or(Error::NotWanted { what: "a chunk" })?;
                let Some(at) = slot.wanted_at else {
                    return Ok(Accepted { what, kept: false });
                };
                if slot.length as usize != body.len() {
                    return Err(Error::SizeMismatch {
                        what: "a chunk",
                        expected: u64::from(slot.length),
                        actual: body.len() as u64,
                    });
                }
                self.store.put(Stored::Chunk, &hash, body)?;
                slot.wanted_at = None;
                self.wanted_chunks.remove(&at);
                Ok(Accepted { what, kept: true })
            }
            _ => Err(invalid("a frame that no tree is taken in by")),
        }
    }

    /// What to ask a peer for next: at most `limit` requests. The record
    /// comes first, then lists, then chunks by their file and their numbers.
    /// Nothing is asked for twice while it is still wanted, so the caller
    /// asks again only after the answers have come, or have failed to.
    pub fn requests(&self, limit: usize) -> Vec<Request> {
        if self.failed {
            return Vec::new();
        }
        if self.record.is_none() {
            return vec![Request::Record(self.root)];
        }
        let mut requests: Vec<Request> = self
            .wanted_lists
            .values()
            .take(limit)
            .map(|target| match target.kind {
                Kind::Folder => Request::Folder(target.hash),
                Kind::File => Request::File(target.hash),
            })
            .collect();
        let mut span: Option<(u64, u64, u32)> = None;
        for &(order, number) in self.wanted_chunks.keys() {
            if let Some((span_order, start, count)) = &mut span {
                if *span_order == order
                    && *start + u64::from(*count) == number
                    && *count < CHUNKS_PER_REQUEST
                {
                    *count += 1;
                    continue;
                }
            }
            if let Some(done) = span.take() {
                self.push_chunks(&mut requests, done);
            }
            if requests.len() >= limit {
                break;
            }
            span = Some((order, number, 1));
        }
        if let Some(done) = span {
            if requests.len() < limit {
                self.push_chunks(&mut requests, done);
            }
        }
        requests
    }

    fn push_chunks(&self, requests: &mut Vec<Request>, (order, start, count): (u64, u64, u32)) {
        if let Some(file) = self.file_by_order.get(&order) {
            requests.push(Request::Chunks {
                file: *file,
                start,
                count,
            });
        }
    }

    /// What the answer to one of this intake's requests has to be: the
    /// frames, in order. A peer may send fewer chunks than were asked for,
    /// and never anything else.
    pub fn expected(&self, request: &Request) -> Vec<Arrived> {
        match request {
            Request::Record(_) => vec![Arrived::Record],
            Request::Folder(folder) => vec![Arrived::FolderList(*folder)],
            Request::File(file) => vec![Arrived::FileList(*file)],
            Request::Chunks { file, start, count } => {
                let Some(order) = self.files.get(file).map(|slot| slot.order) else {
                    return Vec::new();
                };
                (*start..start.saturating_add(u64::from(*count)))
                    .map_while(|number| self.wanted_chunks.get(&(order, number)))
                    .map(|hash| Arrived::Chunk(*hash))
                    .collect()
            }
            _ => Vec::new(),
        }
    }

    /// No path from the top may pass through more folders than the format
    /// allows. A folder that sits at several places is measured once.
    fn check_depth(&self, top: &Target) -> Result<()> {
        if top.kind != Kind::Folder {
            return Ok(());
        }
        let too_deep = || Error::TooDeep {
            limit: MAX_FOLDER_DEPTH,
        };
        // How many folders the longest path down from a folder passes
        // through, that folder counted.
        let mut heights: HashMap<Hash, usize> = HashMap::new();
        let mut path: Vec<(Hash, usize)> = vec![(top.hash, 0)];
        while let Some(&(folder, next)) = path.last() {
            let inside = self
                .folders
                .get(&folder)
                .map_or(&[][..], |slot| slot.inside.as_slice());
            if let Some(child) = inside.get(next) {
                if let Some(last) = path.last_mut() {
                    last.1 += 1;
                }
                match heights.get(child) {
                    Some(height) if path.len() + height > MAX_FOLDER_DEPTH => {
                        return Err(too_deep());
                    }
                    Some(_) => {}
                    None if path.len() >= MAX_FOLDER_DEPTH => return Err(too_deep()),
                    None => path.push((*child, 0)),
                }
            } else {
                let height = 1 + inside
                    .iter()
                    .filter_map(|child| heights.get(child))
                    .max()
                    .copied()
                    .unwrap_or(0);
                heights.insert(folder, height);
                path.pop();
            }
        }
        Ok(())
    }

    /// Ends the intake. The tree must be whole: the record in, every list
    /// and every chunk held, no folder too deep, and the record's totals
    /// right.
    pub fn finish(self) -> Result<Summary> {
        if self.failed {
            return Err(Error::IntakeFailed);
        }
        if let Some(hash) = self.wanted_chunks.values().next() {
            if self.record.is_some() && self.wanted_lists.is_empty() {
                return Err(missing("the chunk", hash));
            }
        }
        self.finish_lists()
    }

    /// Ends the intake as [`Intake::finish`] does, without asking that the
    /// chunks are held: every list must be there and right, and the totals
    /// are counted from the lists.
    pub(crate) fn finish_lists(self) -> Result<Summary> {
        if self.failed {
            return Err(Error::IntakeFailed);
        }
        let Some(record) = &self.record else {
            return Err(missing("the record of", self.root.as_hash()));
        };
        self.lists_held()?;
        self.check_depth(&record.top())?;
        let recorded = record.totals();
        for (field, recorded, counted) in [
            ("chunks", recorded.chunks, self.counted.chunks),
            (
                "chunk bytes",
                recorded.chunk_bytes,
                self.counted.chunk_bytes,
            ),
            ("list bytes", recorded.list_bytes, self.counted.list_bytes),
        ] {
            if recorded != counted {
                return Err(Error::TotalsMismatch {
                    field,
                    recorded,
                    counted,
                });
            }
        }
        Ok(Summary {
            folders: self.folders.len() as u64,
            files: self.files.len() as u64,
            record: record.clone(),
        })
    }
}

/// Checks a whole tree that a store holds: every list, every chunk's bytes,
/// the depth of its folders and the totals in its record. It is the same
/// set of checks that a tree goes through when it is taken in.
pub fn verify(store: &dyn Store, root: &Root) -> Result<Summary> {
    verify_with(store, root, VerifyOptions::default())
}

/// Checks a whole tree that a store holds, with more checks switched on.
///
/// The lists are checked first. Then every chunk is hashed again, several at
/// once, and last, when that is asked for, every file is chunked again.
pub fn verify_with(store: &dyn Store, root: &Root, options: VerifyOptions) -> Result<Summary> {
    let mode = Mode {
        rechunk: options.rechunk,
        discard: options.discard,
    };
    let mut intake = Intake::with_mode(store, *root, mode)?;
    intake.rehash_held(options.workers)?;
    intake.rechunk_held()?;
    intake.finish()
}
