//! Syncing by file hash and chunk number.
//!
//! * A [`Responder`] answers a receiver's requests from a store.
//! * [`fetch`] takes a whole tree from a peer into a store, from the top
//!   down, and skips whatever the store holds already.
//! * A [`Remote`] reads parts of a tree straight from a peer: one name in a
//!   folder, a branch of entries, or a stretch of a file's bytes. It needs no
//!   store, and takes nothing but the parts it is asked for.
//! * [`export`] and [`import`] carry a whole tree as one stream of frames.
//! * [`serve`] answers requests on a connection, and a [`StreamPeer`] asks
//!   them there.
//!
//! Nothing is compared between the two sides. The receiver walks down from
//! the root it trusts, and every answer is checked as it arrives against a
//! hash that is already checked. An answer that is forged, that belongs
//! somewhere else, or that was not asked for is refused. With each request
//! goes the longest frame that can answer it, so a peer cannot make a
//! receiver set aside more memory than the tree it trusts calls for.

use crate::fastcdc::FASTCDC_MIN_SIZE;
use crate::format::{
    check_name, ChunkRef, Chunking, Entry, FileList, FolderBranch, Kind, OpenFile, OpenFolder,
    Record, Target, LIST_ITEM_BYTES, MAX_CARRIED_NODES, MAX_ENTRY_BYTES, MAX_FOLDER_DEPTH,
    MAX_NAME_BYTES, MAX_RECORD_BYTES,
};
use crate::hash::{Hash, Root};
use crate::intake::{Arrived, ChunkFrames, Intake, Summary, TakingIn};
use crate::read::{file_of, folder_of, record_of};
use crate::store::{check_chunk, damaged, lent, ChunksAhead, Store, Stored};
use crate::wire::{
    file_branch_frame, file_list_frame, folder_branch_frame, folder_list_frame, have_frame,
    read_next, refused_frame, write_end, write_frame, write_framed, Frame, HaveMap, Next, Refusal,
    Request, BUNDLE_MAGIC, FRAME_CHUNK, FRAME_FILE_LIST, FRAME_FOLDER_LIST, FRAME_REFUSED,
    MAX_REQUEST_BYTES,
};
use crate::{Error, Result};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex, TryLockError};

/// The most requests [`fetch`] sends before it looks at what is still wanted.
const REQUESTS_PER_ROUND: usize = 64;
/// The most items of a list that one answer shows.
const MAX_BRANCH_ITEMS: u64 = 16_384;
/// The most chunks that one answer sends.
const MAX_CHUNKS_PER_ANSWER: u64 = 256;

fn invalid(detail: &str) -> Error {
    Error::InvalidData {
        detail: detail.to_owned(),
    }
}

fn peer_error(detail: &str) -> Error {
    Error::Peer {
        detail: detail.to_owned(),
    }
}

const OTHER_KIND: Error = Error::NotWanted {
    what: "an answer of another kind than was asked for",
};
const TOO_MUCH: Error = Error::NotWanted {
    what: "more than was asked for",
};

/// The bytes of a branch's frame that are there whatever it shows: its first
/// byte, the list's count, the branch's start, how many items it shows, and how
/// many nodes it carries.
const BRANCH_FIXED_BYTES: usize = 23;

/// How many bytes of requests a [`StreamPeer`] sends ahead of their answers.
/// It is small on purpose. The other end answers one request before it reads
/// the next, so requests that are sent ahead wait in the connection, and a
/// connection that could not hold them would leave both ends waiting for
/// each other. Every connection holds this much.
pub const REQUESTS_AHEAD_BYTES: usize = 2048;

/// Refuses a frame that is longer than its asker takes.
fn within(limit: usize, frame: &[u8]) -> Result<()> {
    if frame.len() > limit {
        return Err(Error::LimitExceeded {
            what: "a frame",
            limit: limit as u64,
            requested: frame.len() as u64,
        });
    }
    Ok(())
}

/// The longest frame that shows `entries` entries of a folder.
fn folder_branch_limit(entries: u64) -> usize {
    let carried = MAX_CARRIED_NODES * (42 + MAX_NAME_BYTES);
    usize::try_from(entries)
        .unwrap_or(usize::MAX)
        .saturating_mul(MAX_ENTRY_BYTES)
        .saturating_add(BRANCH_FIXED_BYTES + carried)
}

/// The longest frame that shows `items` items of a file's list.
fn file_branch_limit(items: u64) -> usize {
    usize::try_from(items)
        .unwrap_or(usize::MAX)
        .saturating_mul(LIST_ITEM_BYTES)
        .saturating_add(BRANCH_FIXED_BYTES + MAX_CARRIED_NODES * 40)
}

/// The most chunks that `length` bytes of a file can lie in. All of them but
/// the first and the last lie in the stretch whole, and no chunk but a
/// file's last is shorter than the tree's way of chunking allows.
fn most_chunks_in(chunking: Chunking, length: u64) -> u64 {
    let shortest = match chunking {
        Chunking::FastCdcV1 => FASTCDC_MIN_SIZE as u64 + 1,
        Chunking::Fixed(chunk) => u64::from(chunk.get()),
    };
    length / shortest + 2
}

/// Something that answers requests: a connection to another machine, or a
/// [`Responder`] in this one.
pub trait Peer {
    /// Sends one request, and hands each frame of the answer to `on_frame`
    /// in the order the frames come. An error from `on_frame` ends the
    /// answer, and is what `ask` returns.
    ///
    /// `limit` is the longest frame the asker takes in answer. A frame that
    /// is longer is an error, and a peer on a connection refuses it by its
    /// length, before any of it is read.
    fn ask(
        &mut self,
        request: &[u8],
        limit: usize,
        on_frame: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()>;

    /// Sends several requests, each with its limit, and hands each frame to
    /// `on_frame` with the place of the request that it answers. Answers
    /// come in the order of the requests.
    ///
    /// This asks one at a time. A peer on a connection sends requests ahead
    /// of their answers, and saves the waiting between them.
    fn ask_all(
        &mut self,
        requests: &[(Vec<u8>, usize)],
        on_frame: &mut dyn FnMut(usize, &[u8]) -> Result<()>,
    ) -> Result<()> {
        for (place, (request, limit)) in requests.iter().enumerate() {
            self.ask(request, *limit, &mut |frame| on_frame(place, frame))?;
        }
        Ok(())
    }
}

/// How many items of lists a responder keeps between requests, for each of
/// the three kinds it keeps, unless it is told otherwise. This many items of
/// files' lists stand for about half a terabyte of files.
const RECENT_ITEMS: u64 = 1 << 18;

/// The most lists of one kind that a responder keeps, however short.
const RECENT_LISTS: usize = 64;

/// The lists that were used last. Reading a list from the store and hashing
/// it takes a pass over the whole of it, so a list that was asked about is
/// kept for the next request. Lists are weighed by their items, and the ones
/// used longest ago go first.
struct Recent<T> {
    kept: Vec<(Hash, Arc<T>, u64)>,
}

impl<T> Recent<T> {
    fn new() -> Self {
        Self { kept: Vec::new() }
    }

    fn get(&mut self, hash: &Hash) -> Option<Arc<T>> {
        let at = self.kept.iter().position(|(kept, _, _)| kept == hash)?;
        let found = self.kept.remove(at);
        let value = Arc::clone(&found.1);
        self.kept.push(found);
        Some(value)
    }

    /// Keeps `value`, and lets go of older ones while there are more than
    /// `most` items or too many lists. The newest one always stays.
    fn keep(&mut self, hash: Hash, value: Arc<T>, items: u64, most: u64) {
        self.kept.retain(|(kept, _, _)| *kept != hash);
        self.kept.push((hash, value, items.max(1)));
        let mut total: u64 = self.kept.iter().map(|(_, _, items)| *items).sum();
        while self.kept.len() > 1 && (total > most || self.kept.len() > RECENT_LISTS) {
            total -= self.kept.remove(0).2;
        }
    }
}

/// Answers requests from a store.
///
/// It answers for whatever the store holds, by hash. It gives what it has and
/// says so when it has nothing: a receiver never has to trust it, because a
/// receiver checks every answer.
///
/// One responder serves many threads at once.
pub struct Responder<'s> {
    store: &'s dyn Store,
    /// The files whose lists were read last.
    lists: Mutex<Recent<FileList>>,
    /// The files and the folders whose trees were built last. Showing a
    /// part of a long list needs its tree.
    files: Mutex<Recent<OpenFile>>,
    folders: Mutex<Recent<OpenFolder>>,
    /// The frame that the last chunk was sent in, filled again for the next.
    frame: Mutex<Vec<u8>>,
    /// Reads the chunks of an answer ahead of sending them, into frames
    /// that are filled again for the next answer.
    ahead: Mutex<ChunksAhead>,
    threads: usize,
    recent: u64,
    have: bool,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Fills `frame` with the frame of a chunk, from its start.
fn refill(frame: &mut Vec<u8>, chunk: &[u8]) {
    frame.clear();
    frame.push(FRAME_CHUNK);
    frame.extend_from_slice(chunk);
}

impl<'s> Responder<'s> {
    pub fn new(store: &'s dyn Store) -> Self {
        Self {
            store,
            lists: Mutex::new(Recent::new()),
            files: Mutex::new(Recent::new()),
            folders: Mutex::new(Recent::new()),
            frame: Mutex::new(Vec::new()),
            ahead: Mutex::new(ChunksAhead::new()),
            threads: 0,
            recent: RECENT_ITEMS,
            have: true,
        }
    }

    /// How many items of lists are kept between requests, for each of the
    /// three kinds: files' lists, files' trees and folders' trees. A list
    /// that is not kept is read from the store and hashed again when it is
    /// next asked about, which takes a pass over the whole of it. An item
    /// kept costs some tens of bytes for a file and some hundreds for a
    /// folder. The list that was used last is kept whatever its length.
    pub fn recent(mut self, items: u64) -> Self {
        self.recent = items;
        self
    }

    /// Whether a peer is told which chunks of a file are held here. Telling
    /// takes a look into the store for every chunk of the file, so a
    /// responder that serves strangers may leave it off. It then answers
    /// such a request as it does for a file it does not hold.
    pub fn have(mut self, on: bool) -> Self {
        self.have = on;
        self
    }

    /// How many threads read the chunks of one answer from the store, ahead
    /// of sending them: 1 is the thread that answers alone, and zero, the
    /// default, is one for each core. Several are worth it when reading a
    /// chunk takes longer than sending it, as from a disk to a fast
    /// receiver. With several, a responder keeps up to 64 MiB of memory
    /// between answers, to read the chunks of the next one into. A responder
    /// that serves many peers at once may give each answer one thread, which
    /// keeps memory for one chunk.
    pub fn threads(mut self, threads: usize) -> Self {
        self.threads = threads;
        self.ahead = Mutex::new(ChunksAhead::with_threads(threads));
        self
    }

    fn file_list(&self, file: &Hash) -> Result<Option<Arc<FileList>>> {
        if let Some(list) = lock(&self.lists).get(file) {
            return Ok(Some(list));
        }
        if let Some(open) = lock(&self.files).get(file) {
            return Ok(Some(open.shared_list()));
        }
        let Some(bytes) = self.store.get(Stored::FileList, file)? else {
            return Ok(None);
        };
        let list = FileList::decode(&bytes)
            .ok()
            .filter(|list| list.hash() == file)
            .ok_or_else(|| damaged("a stored file's list", file))?;
        let list = Arc::new(list);
        lock(&self.lists).keep(*file, Arc::clone(&list), list.count(), self.recent);
        Ok(Some(list))
    }

    fn open_file(&self, file: &Hash) -> Result<Option<Arc<OpenFile>>> {
        if let Some(open) = lock(&self.files).get(file) {
            return Ok(Some(open));
        }
        // Looked up on a line of its own: the lock is let go before the
        // list is hashed, so that other threads are not kept waiting.
        let listed = lock(&self.lists).get(file);
        let open = match listed {
            Some(list) => OpenFile::shared(list)?,
            None => {
                let Some(bytes) = self.store.get(Stored::FileList, file)? else {
                    return Ok(None);
                };
                // Read and hashed once, for the list and for its tree.
                OpenFile::decode(&bytes)
                    .ok()
                    .filter(|open| open.list().hash() == file)
                    .ok_or_else(|| damaged("a stored file's list", file))?
            }
        };
        let open = Arc::new(open);
        let items = open.list().count();
        lock(&self.files).keep(*file, Arc::clone(&open), items, self.recent);
        Ok(Some(open))
    }

    fn open_folder(&self, folder: &Hash) -> Result<Option<Arc<OpenFolder>>> {
        if let Some(open) = lock(&self.folders).get(folder) {
            return Ok(Some(open));
        }
        let Some(bytes) = self.store.get(Stored::FolderList, folder)? else {
            return Ok(None);
        };
        let open = OpenFolder::decode(&bytes)
            .ok()
            .filter(|open| open.list().hash() == folder)
            .ok_or_else(|| damaged("a stored folder's list", folder))?;
        let open = Arc::new(open);
        let items = open.list().count();
        lock(&self.folders).keep(*folder, Arc::clone(&open), items, self.recent);
        Ok(Some(open))
    }

    /// Hands `with` a frame to send chunks in. It is the responder's own,
    /// filled again for each chunk and from one request to the next: memory
    /// that is used again costs much less than fresh memory for every chunk,
    /// which a system has to find and clear first. A thread that finds it in
    /// use, by another thread or by an answer that this one is still giving,
    /// is given a frame of its own, and nobody waits for it.
    fn with_frame(&self, with: impl FnOnce(&mut Vec<u8>) -> Result<()>) -> Result<()> {
        match self.frame.try_lock() {
            Ok(mut kept) => with(&mut kept),
            // The frame is filled from its start each time, so nothing that a
            // thread left in it when it panicked is ever sent.
            Err(TryLockError::Poisoned(poisoned)) => with(&mut poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => with(&mut Vec::new()),
        }
    }

    /// Hands `with` what reads the chunks of an answer ahead of sending
    /// them. As with [`Responder::with_frame`], a thread that finds it in use
    /// is given one of its own.
    fn with_ahead(&self, with: impl FnOnce(&mut ChunksAhead) -> Result<()>) -> Result<()> {
        match self.ahead.try_lock() {
            Ok(mut kept) => with(&mut kept),
            // Each frame is filled from its start each time.
            Err(TryLockError::Poisoned(poisoned)) => with(&mut poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => with(&mut ChunksAhead::with_threads(self.threads)),
        }
    }

    /// Answers one request. Each frame of the answer is handed to
    /// `on_frame`. A request that is malformed is an error. A request for
    /// something the store does not hold is answered with a refusal.
    pub fn answer(
        &self,
        request: &[u8],
        on_frame: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let not_held = refused_frame(Refusal::NotHeld);
        let out_of_range = refused_frame(Refusal::OutOfRange);
        match Request::decode(request)? {
            Request::Record(root) => match self.store.get(Stored::Record, root.as_hash())? {
                Some(bytes) => on_frame(&bytes),
                None => on_frame(&not_held),
            },
            Request::Folder(folder) => match self.store.get(Stored::FolderList, &folder)? {
                Some(bytes) => on_frame(&folder_list_frame(&bytes)),
                None => on_frame(&not_held),
            },
            Request::File(file) => match self.store.get(Stored::FileList, &file)? {
                Some(bytes) => on_frame(&file_list_frame(&bytes)),
                None => on_frame(&not_held),
            },
            Request::Chunk(chunk) => self.with_frame(|frame| {
                let held = lent(self.store, Stored::Chunk, &chunk, &mut |bytes| {
                    refill(frame, bytes);
                    Ok(())
                })?;
                on_frame(if held {
                    frame.as_slice()
                } else {
                    not_held.as_slice()
                })
            }),
            Request::FolderBranch {
                folder,
                start,
                count,
            } => {
                let Some(open) = self.open_folder(&folder)? else {
                    return on_frame(&not_held);
                };
                let total = open.list().count();
                if total == 0 {
                    return on_frame(&folder_branch_frame(&FolderBranch::empty()));
                }
                if start >= total {
                    return on_frame(&out_of_range);
                }
                let end = total.min(start + u64::from(count).min(MAX_BRANCH_ITEMS));
                on_frame(&folder_branch_frame(&open.open(start, end)?))
            }
            Request::FolderName { folder, name } => match self.open_folder(&folder)? {
                Some(open) => on_frame(&folder_branch_frame(&open.open_name(&name)?)),
                None => on_frame(&not_held),
            },
            Request::FileBranch { file, start, count } => {
                let Some(open) = self.open_file(&file)? else {
                    return on_frame(&not_held);
                };
                let total = open.list().count();
                if start >= total {
                    return on_frame(&out_of_range);
                }
                let end = total.min(start + u64::from(count).min(MAX_BRANCH_ITEMS));
                on_frame(&file_branch_frame(&open.open(start, end)?))
            }
            Request::FileBytes {
                file,
                offset,
                length,
            } => {
                let Some(open) = self.open_file(&file)? else {
                    return on_frame(&not_held);
                };
                let size = open.list().size();
                if offset >= size {
                    return on_frame(&out_of_range);
                }
                let (first, after) = open.chunks_for(offset, length.min(size - offset))?;
                let after = after.min(first + MAX_BRANCH_ITEMS);
                on_frame(&file_branch_frame(&open.open(first, after)?))
            }
            Request::Chunks { file, start, count } => {
                let Some(list) = self.file_list(&file)? else {
                    return on_frame(&not_held);
                };
                if start >= list.count() {
                    return on_frame(&out_of_range);
                }
                let count = u64::from(count).min(MAX_CHUNKS_PER_ANSWER) as usize;
                let items = &list.items()[start as usize..];
                let items = &items[..count.min(items.len())];
                // The chunks are read ahead, several at once, and sent in
                // their order. A frame is lent to `on_frame` for the call
                // only: the next chunk is read into it.
                self.with_ahead(|ahead| {
                    ahead.frames(self.store, items, &mut |frame| {
                        on_frame(frame.unwrap_or(not_held.as_slice()))
                    })
                })
            }
            Request::Have(file) => {
                if !self.have {
                    return on_frame(&not_held);
                }
                let Some(list) = self.file_list(&file)? else {
                    return on_frame(&not_held);
                };
                let mut map = HaveMap::new(list.count())?;
                for (number, item) in (0_u64..).zip(list.items()) {
                    if self.store.has(Stored::Chunk, &item.hash)? {
                        map.set(number)?;
                    }
                }
                on_frame(&have_frame(&map))
            }
        }
    }
}

impl Peer for Responder<'_> {
    fn ask(
        &mut self,
        request: &[u8],
        limit: usize,
        on_frame: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        self.answer(request, &mut |frame| {
            within(limit, frame)?;
            on_frame(frame)
        })
    }
}

/// Asks for one frame. A refusal, no frame and more than one frame are
/// errors.
fn ask_one(peer: &mut dyn Peer, request: &Request, limit: usize) -> Result<Vec<u8>> {
    let mut answer: Option<Vec<u8>> = None;
    peer.ask(&request.encode(), limit, &mut |frame| {
        if answer.is_some() {
            return Err(TOO_MUCH);
        }
        answer = Some(frame.to_vec());
        Ok(())
    })?;
    let frame = answer.ok_or_else(|| peer_error("gave no answer"))?;
    if frame.first() == Some(&FRAME_REFUSED) {
        return Err(match Frame::decode(&frame)? {
            Frame::Refused(Refusal::OutOfRange) => {
                peer_error("says that what was asked for lies outside the list or the file")
            }
            _ => peer_error("does not hold what was asked for"),
        });
    }
    Ok(frame)
}

/// Takes the whole tree with this root from a peer into a store.
///
/// It goes from the top down: the record, then each folder's entries and
/// each file's list, then the chunks, by their file and their numbers in it.
/// Whatever the store holds already is skipped by its hash, be it a chunk,
/// a file or a whole folder, and wherever it came from. Every answer has to
/// be exactly what was asked for, and is checked before it is kept.
///
/// A fetch that fails can be started again: it goes on from what the store
/// holds.
pub fn fetch(store: &dyn Store, root: &Root, peer: &mut dyn Peer) -> Result<Summary> {
    let mut intake = Intake::new(store, *root)?;
    // Chunks that come one after another are held, and taken in together
    // by several threads while the next ones come.
    let mut frames = [ChunkFrames::new(), ChunkFrames::new()];
    loop {
        let requests = intake.requests(REQUESTS_PER_ROUND);
        if requests.is_empty() {
            break;
        }
        // What each answer has to be is settled before anything is sent.
        // Nothing that comes in one round changes it: a round asks for each
        // thing once.
        let expected: Vec<Vec<Arrived>> = requests
            .iter()
            .map(|request| intake.expected(request))
            .collect();
        let asks: Vec<(Vec<u8>, usize)> = requests
            .iter()
            .map(|request| (request.encode(), intake.answer_limit(request)))
            .collect();
        let mut taken = vec![0_usize; requests.len()];
        let mut refused = vec![false; requests.len()];
        std::thread::scope(|scope| {
            let mut taking = TakingIn::new(scope, &mut intake, &mut frames);
            let asked = peer.ask_all(&asks, &mut |place, frame| {
                let (Some(expected), Some(taken), Some(refused)) = (
                    expected.get(place),
                    taken.get_mut(place),
                    refused.get_mut(place),
                ) else {
                    return Err(peer_error("answered a request that was not sent"));
                };
                if *refused {
                    return Err(peer_error("sent more after it refused"));
                }
                if frame.first() == Some(&FRAME_REFUSED) {
                    Frame::decode(frame)?;
                    *refused = true;
                    return Ok(());
                }
                let Some(expected) = expected.get(*taken) else {
                    return Err(TOO_MUCH);
                };
                if matches!(expected, Arrived::Chunk(_)) && frame.first() == Some(&FRAME_CHUNK) {
                    taking.hold_copy(frame, Some(*expected))?;
                } else {
                    // What came before is taken in first.
                    taking.intake()?.accept_expected(frame, *expected)?;
                }
                *taken += 1;
                Ok(())
            });
            // What came before a failure is taken in first, and its own
            // failure is the one given.
            taking.finish().and(asked)
        })?;
        if taken.contains(&0) {
            return Err(peer_error("does not hold what the tree needs"));
        }
    }
    intake.finish()
}

/// A branch of a folder's entries, as a peer showed it and as it was checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entries {
    /// How many entries the folder has in all.
    pub total: u64,
    /// The place of the first entry here.
    pub start: u64,
    pub entries: Vec<Entry>,
}

/// Reads parts of one tree straight from a peer, with nothing kept.
///
/// It starts from a root that the caller trusts. Each thing it hands back
/// was shown by the peer and checked against that root: an entry by its
/// place in its folder, and bytes by their place in their file.
pub struct Remote<'p> {
    peer: &'p mut dyn Peer,
    root: Root,
    record: Record,
}

impl<'p> Remote<'p> {
    /// Asks the peer for the record of `root`, and checks it.
    pub fn open(peer: &'p mut dyn Peer, root: &Root) -> Result<Self> {
        let frame = ask_one(peer, &Request::Record(*root), MAX_RECORD_BYTES)?;
        if Root::of_record(&frame) != *root {
            return Err(Error::HashMismatch { what: "a record" });
        }
        let record = Record::decode(&frame)?;
        Ok(Self {
            peer,
            root: *root,
            record,
        })
    }

    pub fn root(&self) -> &Root {
        &self.root
    }

    pub fn record(&self) -> &Record {
        &self.record
    }

    /// What is under `name` in `folder`, or nothing when the folder has no
    /// such name. Either answer is proven by the one entry the peer shows.
    pub fn entry(&mut self, folder: &Target, name: &str) -> Result<Option<Entry>> {
        check_name(name)?;
        folder.require(Kind::Folder)?;
        let frame = ask_one(
            self.peer,
            &Request::FolderName {
                folder: folder.hash,
                name: name.to_owned(),
            },
            folder_branch_limit(1),
        )?;
        let Frame::FolderBranch(branch) = Frame::decode(&frame)? else {
            return Err(OTHER_KIND);
        };
        Ok(branch.check_name(folder, name)?.cloned())
    }

    /// What is at `path` in the tree: names with `/` between them. One
    /// question is asked for each name on the way.
    pub fn lookup(&mut self, path: &str) -> Result<Option<Entry>> {
        let mut current = self.record.top();
        let mut found = None;
        for (folders_passed, name) in path.split('/').enumerate() {
            check_name(name)?;
            if current.kind != Kind::Folder {
                return Ok(None);
            }
            if folders_passed >= MAX_FOLDER_DEPTH {
                return Err(Error::TooDeep {
                    limit: MAX_FOLDER_DEPTH,
                });
            }
            let Some(entry) = self.entry(&current, name)? else {
                return Ok(None);
            };
            current = entry.target();
            found = Some(entry);
        }
        Ok(found)
    }

    /// Up to `count` entries of a folder, from place `start`. Fewer come
    /// back when the folder ends first, or when the peer gives fewer at a
    /// time. An empty folder gives none.
    pub fn entries(&mut self, folder: &Target, start: u64, count: u32) -> Result<Entries> {
        folder.require(Kind::Folder)?;
        let request = Request::FolderBranch {
            folder: folder.hash,
            start,
            count,
        };
        let frame = ask_one(self.peer, &request, folder_branch_limit(u64::from(count)))?;
        let Frame::FolderBranch(branch) = Frame::decode(&frame)? else {
            return Err(OTHER_KIND);
        };
        branch.check(folder)?;
        if branch.count() != 0
            && (branch.start() != start || branch.entries().len() > count as usize)
        {
            return Err(Error::NotWanted {
                what: "a branch that was not asked for",
            });
        }
        Ok(Entries {
            total: branch.count(),
            start: branch.start(),
            entries: branch.entries().to_vec(),
        })
    }

    /// Writes `length` bytes of a file, from byte `offset`, to `out`.
    ///
    /// The peer shows the branch of the file's list that holds the stretch, and
    /// that proves each chunk's number and the byte it starts at. Then the
    /// chunks are asked for by their numbers, and each is checked against
    /// the list before any of its bytes is written. Nothing else of the file
    /// is taken.
    pub fn read(
        &mut self,
        file: &Target,
        offset: u64,
        length: u64,
        out: &mut dyn Write,
    ) -> Result<()> {
        file.require(Kind::File)?;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= file.size)
            .ok_or_else(|| invalid("a stretch of bytes is outside the file"))?;
        let chunking = self.record.chunking();
        let mut at = offset;
        while at < end {
            let request = Request::FileBytes {
                file: file.hash,
                offset: at,
                length: end - at,
            };
            let branch_limit = file_branch_limit(most_chunks_in(chunking, end - at));
            let frame = ask_one(self.peer, &request, branch_limit)?;
            let Frame::FileBranch(branch) = Frame::decode(&frame)? else {
                return Err(OTHER_KIND);
            };
            let branch_start = branch.check(file, Some(chunking))?;
            let items = branch.items();
            // The branch has to begin with the chunk that holds the first byte
            // still due, and may not reach past the chunk that holds the last.
            let before_last: u64 = items[..items.len() - 1]
                .iter()
                .map(|item| u64::from(item.length))
                .sum();
            let holds_first = branch_start <= at && at < branch_start + u64::from(items[0].length);
            if !holds_first || branch_start + before_last >= end {
                return Err(Error::NotWanted {
                    what: "a branch that does not hold the bytes asked for",
                });
            }
            let chunks = Request::Chunks {
                file: file.hash,
                start: branch.start(),
                count: items.len() as u32,
            };
            // No chunk that is due is longer than the longest in the branch.
            let longest = items
                .iter()
                .map(|item| item.length as usize)
                .max()
                .unwrap_or(0);
            let mut taken = 0_usize;
            let mut chunk_start = branch_start;
            let mut refused = false;
            self.peer.ask(&chunks.encode(), longest + 1, &mut |frame| {
                if refused {
                    return Err(peer_error("sent more after it refused"));
                }
                match Frame::decode(frame)? {
                    Frame::Refused(_) => refused = true,
                    Frame::Chunk(bytes) => {
                        let item = items.get(taken).ok_or(TOO_MUCH)?;
                        check_chunk(item, bytes, "a chunk")?;
                        let chunk_end = chunk_start + u64::from(item.length);
                        let from = (at - chunk_start) as usize;
                        let to = (end.min(chunk_end) - chunk_start) as usize;
                        out.write_all(&bytes[from..to])
                            .map_err(|source| Error::Stream {
                                operation: "write a file's bytes",
                                source,
                            })?;
                        at = end.min(chunk_end);
                        chunk_start = chunk_end;
                        taken += 1;
                    }
                    _ => return Err(OTHER_KIND),
                }
                Ok(())
            })?;
            if taken == 0 {
                return Err(peer_error("does not hold the chunks asked for"));
            }
        }
        Ok(())
    }

    /// Which chunks of a file the peer says it holds, one bit a chunk. This
    /// is what the peer says about itself: nothing proves it, and a chunk it
    /// claims is still checked when it comes. Only the number of chunks is
    /// held to what the file's size allows.
    pub fn have(&mut self, file: &Target) -> Result<HaveMap> {
        file.require(Kind::File)?;
        let chunking = self.record.chunking();
        let most = chunking.count_bounds(file.size).1;
        let limit = usize::try_from(most.div_ceil(8))
            .unwrap_or(usize::MAX)
            .saturating_add(9);
        let frame = ask_one(self.peer, &Request::Have(file.hash), limit)?;
        let Frame::Have(map) = Frame::decode(&frame)? else {
            return Err(OTHER_KIND);
        };
        chunking.check_count(file.size, map.count())?;
        Ok(map)
    }
}

/// Writes a whole tree to `out` as one stream: the bundle's first bytes,
/// the record, and then every list and every chunk once, each after what
/// names it. [`import`] reads it back.
pub fn export(store: &dyn Store, root: &Root, out: &mut dyn Write) -> Result<()> {
    let record = record_of(store, root)?;
    out.write_all(&BUNDLE_MAGIC)
        .map_err(|source| Error::Stream {
            operation: "write a bundle",
            source,
        })?;
    write_frame(out, &record.encode())?;
    let mut lists: HashSet<(Kind, Hash)> = HashSet::new();
    let mut chunks: HashSet<Hash> = HashSet::new();
    let mut ahead = ChunksAhead::new();
    let mut pending = vec![record.top()];
    while let Some(target) = pending.pop() {
        if !lists.insert((target.kind, target.hash)) {
            continue;
        }
        match target.kind {
            Kind::Folder => {
                let list = folder_of(store, &target)?;
                write_framed(out, FRAME_FOLDER_LIST, &list.encode())?;
                pending.extend(list.entries().iter().rev().map(Entry::target));
            }
            Kind::File => {
                let list = file_of(store, &target)?;
                write_framed(out, FRAME_FILE_LIST, &list.encode())?;
                let new: Vec<ChunkRef> = list
                    .items()
                    .iter()
                    .filter(|item| chunks.insert(item.hash))
                    .copied()
                    .collect();
                ahead.lend(store, &new, &mut |_, bytes| {
                    write_framed(out, FRAME_CHUNK, bytes)
                })?;
            }
        }
    }
    Ok(())
}

/// Reads a bundle that [`export`] wrote, and takes the tree with this root
/// from it into a store. Every frame goes through the same checks as a
/// frame from a peer, and the tree must be whole when the stream ends. A
/// frame for something the store holds already is passed over. A frame that
/// nothing in the tree names is an error.
pub fn import(store: &dyn Store, root: &Root, input: &mut dyn Read) -> Result<Summary> {
    let mut magic = [0_u8; 8];
    input
        .read_exact(&mut magic)
        .map_err(|source| Error::Stream {
            operation: "read a bundle",
            source,
        })?;
    if magic != BUNDLE_MAGIC {
        return Err(invalid("a stream does not start as a bundle does"));
    }
    let mut intake = Intake::new(store, *root)?;
    // Chunks that come one after another are held, and taken in together
    // by several threads while the next ones are read, once the record is
    // in. Each frame is read into a buffer of theirs, and one more buffer
    // serves every other frame of the bundle.
    let mut frames = [ChunkFrames::new(), ChunkFrames::new()];
    let mut frame = Vec::new();
    // What the intake takes changes only when it takes a frame that is not
    // a chunk's, and those are taken here.
    let mut limit = intake.frame_limit();
    let mut recorded = intake.record().is_some();
    std::thread::scope(|scope| {
        let mut taking = TakingIn::new(scope, &mut intake, &mut frames);
        let read = loop {
            let next = match read_next(input, limit, taking.next_buffer()) {
                Ok(next) => next,
                Err(error) => break Err(error),
            };
            match next {
                Next::Frame if recorded && taking.next_is_chunk() => {
                    if let Err(error) = taking.hold(None) {
                        break Err(error);
                    }
                }
                Next::Frame => {
                    // What came before is taken in first.
                    std::mem::swap(&mut frame, taking.next_buffer());
                    let accepted = taking.intake().and_then(|intake| {
                        intake.accept(&frame)?;
                        limit = intake.frame_limit();
                        recorded = intake.record().is_some();
                        Ok(())
                    });
                    if let Err(error) = accepted {
                        break Err(error);
                    }
                }
                Next::End => break Err(invalid("a frame is empty")),
                Next::Closed => break Ok(()),
            }
        };
        // What came before a failure is taken in first, and its own failure
        // is the one given.
        taking.finish().and(read)
    })?;
    intake.finish()
}

/// Answers the requests that come in on a connection, until it ends.
///
/// A request comes as a frame does: its length in four bytes, and then its
/// bytes. The answer goes out as its frames, each with its length before it,
/// and then a length of zero. Requests are answered one at a time, in the
/// order they come.
///
/// A request that is malformed or too long ends the serving with an error.
/// What is not held is answered with a refusal, and the serving goes on.
pub fn serve(store: &dyn Store, input: &mut dyn Read, output: &mut dyn Write) -> Result<()> {
    let responder = Responder::new(store);
    let mut request = Vec::new();
    loop {
        match read_next(input, MAX_REQUEST_BYTES, &mut request)? {
            Next::Frame => {}
            Next::End => return Err(invalid("a request is empty")),
            Next::Closed => return Ok(()),
        }
        responder.answer(&request, &mut |frame| write_frame(output, frame))?;
        write_end(output)?;
        output.flush().map_err(|source| Error::Stream {
            operation: "send an answer",
            source,
        })?;
    }
}

/// A peer at the other end of a connection, where [`serve`] answers.
///
/// `input` is what the other end sends, and `output` is what it reads. An
/// answer that is left half read, because a frame of it was refused, leaves
/// the connection where nobody knows what comes next. Nothing more is asked
/// on it then: open a new one.
pub struct StreamPeer<R, W> {
    input: R,
    output: W,
    broken: bool,
    /// One buffer for every frame that is read, from answer to answer.
    frame: Vec<u8>,
}

impl<R: Read, W: Write> StreamPeer<R, W> {
    pub fn new(input: R, output: W) -> Self {
        Self {
            input,
            output,
            broken: false,
            frame: Vec::new(),
        }
    }
}

impl<R: Read, W: Write> Peer for StreamPeer<R, W> {
    fn ask(
        &mut self,
        request: &[u8],
        limit: usize,
        on_frame: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        self.ask_all(&[(request.to_vec(), limit)], &mut |_, frame| {
            on_frame(frame)
        })
    }

    fn ask_all(
        &mut self,
        requests: &[(Vec<u8>, usize)],
        on_frame: &mut dyn FnMut(usize, &[u8]) -> Result<()>,
    ) -> Result<()> {
        if self.broken {
            return Err(peer_error(
                "is on a connection that an earlier answer left half read",
            ));
        }
        self.broken = true;
        let mut answered = 0;
        while answered < requests.len() {
            // Send ahead what the connection is sure to hold, and one
            // request at the least.
            let mut sent = answered;
            let mut ahead = 0;
            while let Some((request, _)) = requests.get(sent) {
                let bytes = request.len() + 4;
                if sent > answered && ahead + bytes > REQUESTS_AHEAD_BYTES {
                    break;
                }
                write_frame(&mut self.output, request)?;
                ahead += bytes;
                sent += 1;
            }
            self.output.flush().map_err(|source| Error::Stream {
                operation: "send a request",
                source,
            })?;
            for (place, (_, limit)) in requests.iter().enumerate().take(sent).skip(answered) {
                loop {
                    match read_next(&mut self.input, *limit, &mut self.frame)? {
                        Next::Frame => on_frame(place, &self.frame)?,
                        Next::End => break,
                        Next::Closed => {
                            return Err(peer_error("closed the connection inside an answer"));
                        }
                    }
                }
            }
            answered = sent;
        }
        self.broken = false;
        Ok(())
    }
}
