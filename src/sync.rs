//! Syncing by file hash and piece number.
//!
//! * A [`Responder`] answers a receiver's requests from a store.
//! * [`fetch`] takes a whole tree from a peer into a store, from the top
//!   down, and skips whatever the store holds already.
//! * A [`Remote`] reads parts of a tree straight from a peer: one name in a
//!   folder, a run of entries, or a stretch of a file's bytes. It needs no
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
    check_name, Cutting, Entry, FileList, FolderList, FolderRun, Kind, OpenFile, OpenFolder,
    Record, Target, LIST_ITEM_BYTES, MAX_CARRIED_NODES, MAX_ENTRY_BYTES, MAX_FOLDER_DEPTH,
    MAX_NAME_BYTES, MAX_RECORD_BYTES,
};
use crate::hash::{Hash, Root};
use crate::intake::{Arrived, Intake, Summary};
use crate::read::{file_of, folder_of, record_of};
use crate::store::{check_piece, load_piece, missing, Store, Stored};
use crate::wire::{
    file_list_frame, file_run_frame, folder_list_frame, folder_run_frame, have_frame, piece_frame,
    read_frame, read_next, refused_frame, write_end, write_frame, Frame, HaveMap, Next, Refusal,
    Request, BUNDLE_MAGIC, FRAME_REFUSED, MAX_REQUEST_BYTES,
};
use crate::{Error, Result};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

/// The most requests [`fetch`] sends before it looks at what is still wanted.
const REQUESTS_PER_ROUND: usize = 64;
/// The most items of a list that one answer shows.
const MAX_RUN_ITEMS: u64 = 16_384;
/// The most pieces that one answer sends.
const MAX_PIECES_PER_ANSWER: u64 = 256;

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

/// The bytes of a run's frame that are there whatever it shows: its first
/// byte, the list's count, the run's start, how many items it shows, and how
/// many nodes it carries.
const RUN_FIXED_BYTES: usize = 23;

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
fn folder_run_limit(entries: u64) -> usize {
    let carried = MAX_CARRIED_NODES * (42 + MAX_NAME_BYTES);
    usize::try_from(entries)
        .unwrap_or(usize::MAX)
        .saturating_mul(MAX_ENTRY_BYTES)
        .saturating_add(RUN_FIXED_BYTES + carried)
}

/// The longest frame that shows `items` items of a file's list.
fn file_run_limit(items: u64) -> usize {
    usize::try_from(items)
        .unwrap_or(usize::MAX)
        .saturating_mul(LIST_ITEM_BYTES)
        .saturating_add(RUN_FIXED_BYTES + MAX_CARRIED_NODES * 40)
}

/// The most pieces that `length` bytes of a file can lie in. All of them but
/// the first and the last lie in the stretch whole, and no piece but a
/// file's last is shorter than the tree's way of cutting allows.
fn most_pieces_in(cutting: Cutting, length: u64) -> u64 {
    let shortest = match cutting {
        Cutting::FastCdcV1 => FASTCDC_MIN_SIZE as u64 + 1,
        Cutting::Fixed(piece) => u64::from(piece.get()),
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

/// Answers requests from a store.
///
/// It answers for whatever the store holds, by hash. It gives what it has and
/// says so when it has nothing: a receiver never has to trust it, because a
/// receiver checks every answer.
pub struct Responder<'s> {
    store: &'s dyn Store,
    /// The file whose list was read last.
    list: Mutex<Option<Arc<FileList>>>,
    /// The file and the folder whose trees were built last. Showing a part
    /// of a long list needs its tree, and building it takes a pass over the
    /// list, so the last one is kept for the next request.
    file: Mutex<Option<Arc<OpenFile>>>,
    folder: Mutex<Option<Arc<OpenFolder>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl<'s> Responder<'s> {
    pub fn new(store: &'s dyn Store) -> Self {
        Self {
            store,
            list: Mutex::new(None),
            file: Mutex::new(None),
            folder: Mutex::new(None),
        }
    }

    fn file_list(&self, file: &Hash) -> Result<Option<Arc<FileList>>> {
        if let Some(list) = lock(&self.list).as_ref().filter(|list| list.hash() == file) {
            return Ok(Some(Arc::clone(list)));
        }
        let Some(bytes) = self.store.get(Stored::FileList, file)? else {
            return Ok(None);
        };
        let list = FileList::decode(&bytes)?;
        if list.hash() != file {
            return Err(Error::HashMismatch {
                what: "a stored file's list",
            });
        }
        let list = Arc::new(list);
        *lock(&self.list) = Some(Arc::clone(&list));
        Ok(Some(list))
    }

    fn open_file(&self, file: &Hash) -> Result<Option<Arc<OpenFile>>> {
        if let Some(open) = lock(&self.file)
            .as_ref()
            .filter(|open| open.list().hash() == file)
        {
            return Ok(Some(Arc::clone(open)));
        }
        let Some(list) = self.file_list(file)? else {
            return Ok(None);
        };
        let open = Arc::new(OpenFile::new(FileList::clone(&list))?);
        *lock(&self.file) = Some(Arc::clone(&open));
        Ok(Some(open))
    }

    fn open_folder(&self, folder: &Hash) -> Result<Option<Arc<OpenFolder>>> {
        if let Some(open) = lock(&self.folder)
            .as_ref()
            .filter(|open| open.list().hash() == folder)
        {
            return Ok(Some(Arc::clone(open)));
        }
        let Some(bytes) = self.store.get(Stored::FolderList, folder)? else {
            return Ok(None);
        };
        let list = FolderList::decode(&bytes)?;
        if list.hash() != folder {
            return Err(Error::HashMismatch {
                what: "a stored folder's list",
            });
        }
        let open = Arc::new(OpenFolder::new(list)?);
        *lock(&self.folder) = Some(Arc::clone(&open));
        Ok(Some(open))
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
            Request::Piece(piece) => match self.store.get(Stored::Piece, &piece)? {
                Some(bytes) => on_frame(&piece_frame(&bytes)),
                None => on_frame(&not_held),
            },
            Request::FolderRun {
                folder,
                start,
                count,
            } => {
                let Some(open) = self.open_folder(&folder)? else {
                    return on_frame(&not_held);
                };
                let total = open.list().count();
                if total == 0 {
                    return on_frame(&folder_run_frame(&FolderRun::empty()));
                }
                if start >= total {
                    return on_frame(&out_of_range);
                }
                let end = total.min(start + u64::from(count).min(MAX_RUN_ITEMS));
                on_frame(&folder_run_frame(&open.open(start, end)?))
            }
            Request::FolderName { folder, name } => match self.open_folder(&folder)? {
                Some(open) => on_frame(&folder_run_frame(&open.open_name(&name)?)),
                None => on_frame(&not_held),
            },
            Request::FileRun { file, start, count } => {
                let Some(open) = self.open_file(&file)? else {
                    return on_frame(&not_held);
                };
                let total = open.list().count();
                if start >= total {
                    return on_frame(&out_of_range);
                }
                let end = total.min(start + u64::from(count).min(MAX_RUN_ITEMS));
                on_frame(&file_run_frame(&open.open(start, end)?))
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
                let (first, after) = open.pieces_for(offset, length.min(size - offset))?;
                let after = after.min(first + MAX_RUN_ITEMS);
                on_frame(&file_run_frame(&open.open(first, after)?))
            }
            Request::Pieces { file, start, count } => {
                let Some(list) = self.file_list(&file)? else {
                    return on_frame(&not_held);
                };
                if start >= list.count() {
                    return on_frame(&out_of_range);
                }
                let count = u64::from(count).min(MAX_PIECES_PER_ANSWER) as usize;
                for item in list.items()[start as usize..].iter().take(count) {
                    match self.store.get(Stored::Piece, &item.hash)? {
                        Some(bytes) => on_frame(&piece_frame(&bytes))?,
                        None => return on_frame(&not_held),
                    }
                }
                Ok(())
            }
            Request::Have(file) => {
                let Some(list) = self.file_list(&file)? else {
                    return on_frame(&not_held);
                };
                let mut map = HaveMap::new(list.count())?;
                for (number, item) in (0_u64..).zip(list.items()) {
                    if self.store.has(Stored::Piece, &item.hash)? {
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
/// each file's list, then the pieces, by their file and their numbers in it.
/// Whatever the store holds already is skipped by its hash, be it a piece,
/// a file or a whole folder, and wherever it came from. Every answer has to
/// be exactly what was asked for, and is checked before it is kept.
///
/// A fetch that fails can be started again: it goes on from what the store
/// holds.
pub fn fetch(store: &dyn Store, root: &Root, peer: &mut dyn Peer) -> Result<Summary> {
    let mut intake = Intake::new(store, *root)?;
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
        peer.ask_all(&asks, &mut |place, frame| {
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
            intake.accept_expected(frame, *expected)?;
            *taken += 1;
            Ok(())
        })?;
        if taken.contains(&0) {
            return Err(peer_error("does not hold what the tree needs"));
        }
    }
    intake.finish()
}

/// A run of a folder's entries, as a peer showed it and as it was checked.
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
            folder_run_limit(1),
        )?;
        let Frame::FolderRun(run) = Frame::decode(&frame)? else {
            return Err(OTHER_KIND);
        };
        Ok(run.check_name(folder, name)?.cloned())
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
        let request = Request::FolderRun {
            folder: folder.hash,
            start,
            count,
        };
        let frame = ask_one(self.peer, &request, folder_run_limit(u64::from(count)))?;
        let Frame::FolderRun(run) = Frame::decode(&frame)? else {
            return Err(OTHER_KIND);
        };
        run.check(folder)?;
        if run.count() != 0 && (run.start() != start || run.entries().len() > count as usize) {
            return Err(Error::NotWanted {
                what: "a run that was not asked for",
            });
        }
        Ok(Entries {
            total: run.count(),
            start: run.start(),
            entries: run.entries().to_vec(),
        })
    }

    /// Writes `length` bytes of a file, from byte `offset`, to `out`.
    ///
    /// The peer shows the run of the file's list that holds the stretch, and
    /// that proves each piece's number and the byte it starts at. Then the
    /// pieces are asked for by their numbers, and each is checked against
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
        let cutting = self.record.cutting();
        let mut at = offset;
        while at < end {
            let request = Request::FileBytes {
                file: file.hash,
                offset: at,
                length: end - at,
            };
            let run_limit = file_run_limit(most_pieces_in(cutting, end - at));
            let frame = ask_one(self.peer, &request, run_limit)?;
            let Frame::FileRun(run) = Frame::decode(&frame)? else {
                return Err(OTHER_KIND);
            };
            let run_start = run.check(file, Some(cutting))?;
            let items = run.items();
            // The run has to begin with the piece that holds the first byte
            // still due, and may not reach past the piece that holds the last.
            let before_last: u64 = items[..items.len() - 1]
                .iter()
                .map(|item| u64::from(item.length))
                .sum();
            let holds_first = run_start <= at && at < run_start + u64::from(items[0].length);
            if !holds_first || run_start + before_last >= end {
                return Err(Error::NotWanted {
                    what: "a run that does not hold the bytes asked for",
                });
            }
            let pieces = Request::Pieces {
                file: file.hash,
                start: run.start(),
                count: items.len() as u32,
            };
            // No piece that is due is longer than the longest in the run.
            let longest = items
                .iter()
                .map(|item| item.length as usize)
                .max()
                .unwrap_or(0);
            let mut taken = 0_usize;
            let mut piece_start = run_start;
            let mut refused = false;
            self.peer.ask(&pieces.encode(), longest + 1, &mut |frame| {
                if refused {
                    return Err(peer_error("sent more after it refused"));
                }
                match Frame::decode(frame)? {
                    Frame::Refused(_) => refused = true,
                    Frame::Piece(bytes) => {
                        let item = items.get(taken).ok_or(TOO_MUCH)?;
                        check_piece(item, bytes, "a piece")?;
                        let piece_end = piece_start + u64::from(item.length);
                        let from = (at - piece_start) as usize;
                        let to = (end.min(piece_end) - piece_start) as usize;
                        out.write_all(&bytes[from..to])
                            .map_err(|source| Error::Stream {
                                operation: "write a file's bytes",
                                source,
                            })?;
                        at = end.min(piece_end);
                        piece_start = piece_end;
                        taken += 1;
                    }
                    _ => return Err(OTHER_KIND),
                }
                Ok(())
            })?;
            if taken == 0 {
                return Err(peer_error("does not hold the pieces asked for"));
            }
        }
        Ok(())
    }

    /// Which pieces of a file the peer says it holds, one bit a piece. This
    /// is what the peer says about itself: nothing proves it, and a piece it
    /// claims is still checked when it comes. Only the number of pieces is
    /// held to what the file's size allows.
    pub fn have(&mut self, file: &Target) -> Result<HaveMap> {
        file.require(Kind::File)?;
        let cutting = self.record.cutting();
        let most = cutting.count_bounds(file.size).1;
        let limit = usize::try_from(most.div_ceil(8))
            .unwrap_or(usize::MAX)
            .saturating_add(9);
        let frame = ask_one(self.peer, &Request::Have(file.hash), limit)?;
        let Frame::Have(map) = Frame::decode(&frame)? else {
            return Err(OTHER_KIND);
        };
        cutting.check_count(file.size, map.count())?;
        Ok(map)
    }
}

/// Writes a whole tree to `out` as one stream: the bundle's first bytes,
/// the record, and then every list and every piece once, each after what
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
    let mut pieces: HashSet<Hash> = HashSet::new();
    let mut pending = vec![record.top()];
    while let Some(target) = pending.pop() {
        if !lists.insert((target.kind, target.hash)) {
            continue;
        }
        match target.kind {
            Kind::Folder => {
                let list = folder_of(store, &target)?;
                write_frame(out, &folder_list_frame(&list.encode()))?;
                pending.extend(list.entries().iter().rev().map(Entry::target));
            }
            Kind::File => {
                let list = file_of(store, &target)?;
                write_frame(out, &file_list_frame(&list.encode()))?;
                for item in list.items() {
                    if pieces.insert(item.hash) {
                        let bytes = load_piece(store, item)?
                            .ok_or_else(|| missing("the piece", &item.hash))?;
                        write_frame(out, &piece_frame(&bytes))?;
                    }
                }
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
    while let Some(frame) = read_frame(input, intake.frame_limit())? {
        intake.accept(&frame)?;
    }
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
    loop {
        let request = match read_next(input, MAX_REQUEST_BYTES)? {
            Next::Frame(request) => request,
            Next::End => return Err(invalid("a request is empty")),
            Next::Closed => return Ok(()),
        };
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
}

impl<R: Read, W: Write> StreamPeer<R, W> {
    pub fn new(input: R, output: W) -> Self {
        Self {
            input,
            output,
            broken: false,
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
                    match read_next(&mut self.input, *limit)? {
                        Next::Frame(frame) => on_frame(place, &frame)?,
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
