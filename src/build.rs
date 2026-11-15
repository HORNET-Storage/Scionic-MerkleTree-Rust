//! Building a tree: from a folder or a file on disk, or part by part.

use crate::disk::{Found, Held, Refused};
use crate::fastcdc::{chunks_on_threads, StreamChunker, FASTCDC_MAX_SIZE};
use crate::format::{
    check_name, ChunkRef, Chunking, Entry, ExtraData, FileList, FolderList, Kind, Record, Target,
    MAX_FOLDER_DEPTH, TIMESTAMP_KEY,
};
use crate::hash::Root;
use crate::intake::Intake;
use crate::store::{Store, Stored};
use crate::{io_error, Error, Result};
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

/// Reads once, and again when the read was only interrupted.
pub(crate) fn read_some(reader: &mut dyn Read, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buffer) {
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            other => return other,
        }
    }
}

/// How much of a file a builder holds at a time when it works alone: two
/// chunks of the longest kind.
const ROOM_ALONE: usize = 2 * FASTCDC_MAX_SIZE;

/// How much of a file a builder holds at a time when other threads help it:
/// enough chunks to give each of them some.
const ROOM_WITH_HELP: usize = 8 * FASTCDC_MAX_SIZE;

/// The least of a file that lies in memory that is worth a thread of its
/// own, when several threads look through it for where its chunks may end.
const LOOKED_THROUGH_BY_EACH: usize = 4 << 20;

fn cores() -> usize {
    std::thread::available_parallelism().map_or(1, usize::from)
}

/// The threads that are free to help with a long file.
///
/// Where one chunk ends decides where the next begins, so a file is chunked
/// in order, on the thread that asks for it. A file that lies in memory is
/// first looked through by the helpers that are free, each in a stretch of
/// its own, for every place where a chunk may end, and is then chunked from
/// those places alone. Hashing and keeping the chunks is the greater part of
/// the work and needs no order, so it is shared out among that thread and
/// the helpers that are free.
pub(crate) struct Helpers {
    free: AtomicUsize,
}

impl Helpers {
    fn new(free: usize) -> Arc<Self> {
        Arc::new(Self {
            free: AtomicUsize::new(free),
        })
    }

    /// The helpers of a builder that may use `threads` threads, its own
    /// counted. Zero is one thread for each core.
    fn for_threads(threads: usize) -> Arc<Self> {
        let threads = match threads {
            0 => cores(),
            threads => threads,
        };
        Self::new(threads - 1)
    }

    fn any(&self) -> bool {
        self.free.load(Ordering::Relaxed) > 0
    }

    /// Takes up to `most` helpers, and says how many it got.
    fn take(&self, most: usize) -> usize {
        let mut free = self.free.load(Ordering::Relaxed);
        loop {
            let taken = free.min(most);
            if taken == 0 {
                return 0;
            }
            match self.free.compare_exchange_weak(
                free,
                free - taken,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return taken,
                Err(now) => free = now,
            }
        }
    }

    fn give(&self, count: usize) {
        self.free.fetch_add(count, Ordering::Relaxed);
    }
}

/// Builds a tree part by part: files from their bytes, folders from their
/// entries, and at the end the record.
///
/// Everything goes into the store as it is made. A chunk, a file or a folder
/// that the store holds already is not written again.
pub struct Builder<'s> {
    store: &'s dyn Store,
    chunking: Chunking,
    chunker: StreamChunker,
    helpers: Arc<Helpers>,
}

impl<'s> Builder<'s> {
    /// A builder that uses one thread for each core on a long file.
    pub fn new(store: &'s dyn Store, chunking: Chunking) -> Self {
        Self::sharing(store, chunking, Helpers::for_threads(0))
    }

    fn sharing(store: &'s dyn Store, chunking: Chunking, helpers: Arc<Helpers>) -> Self {
        Self {
            store,
            chunking,
            chunker: StreamChunker::new(),
            helpers,
        }
    }

    /// How many threads work on one file: 1 is the calling thread alone, and
    /// zero is one thread for each core. They hash and keep its chunks, and
    /// for a file that lies in memory they also find where its chunks end. A
    /// file that is read is chunked on the calling thread. With help, a
    /// builder holds up to 64 MiB of a long file that it reads at a time;
    /// alone it holds up to 16 MiB.
    pub fn threads(mut self, threads: usize) -> Self {
        self.helpers = Helpers::for_threads(threads);
        self
    }

    /// How this builder chunks files.
    pub fn chunking(&self) -> Chunking {
        self.chunking
    }

    /// Splits everything `reader` gives into chunks, keeps the chunks and the
    /// file's list, and says what the file is. The file is never held in
    /// memory whole: only a window of it, as [`Builder::threads`] says.
    pub fn file(&mut self, reader: &mut dyn Read) -> Result<Target> {
        self.file_from(|buffer| {
            read_some(reader, buffer).map_err(|source| Error::Stream {
                operation: "read a file's bytes",
                source,
            })
        })
    }

    /// The file with these bytes. They are chunked where they lie, and nothing
    /// is copied on the way to the store.
    pub fn file_from_bytes(&mut self, bytes: &[u8]) -> Result<Target> {
        let chunks = match self.chunking {
            Chunking::FastCdcV1 => {
                let wanted = (bytes.len() / LOOKED_THROUGH_BY_EACH).saturating_sub(1);
                let helping = self.helpers.take(wanted);
                let chunks = if helping == 0 {
                    self.chunking.cut(bytes)
                } else {
                    chunks_on_threads(bytes, true, helping + 1)
                };
                self.helpers.give(helping);
                chunks
            }
            Chunking::Fixed(_) => self.chunking.cut(bytes),
        };
        let mut items = Vec::with_capacity(chunks.len());
        keep_chunks(self.store, &self.helpers, &chunks, &mut items)?;
        self.keep_list(items)
    }

    /// The file at `path` on disk.
    pub fn file_at(&mut self, path: &Path) -> Result<Target> {
        let mut file = File::open(path).map_err(|error| io_error("open", path, error))?;
        self.file_from(|buffer| {
            read_some(&mut file, buffer).map_err(|error| io_error("read", path, error))
        })
    }

    fn file_from(&mut self, read: impl FnMut(&mut [u8]) -> Result<usize>) -> Result<Target> {
        let store = self.store;
        let helpers = &self.helpers;
        let room = if helpers.any() {
            ROOM_WITH_HELP
        } else {
            ROOM_ALONE
        };
        let mut items = Vec::new();
        self.chunker.cut(self.chunking, room, read, |chunks| {
            keep_chunks(store, helpers, chunks, &mut items)
        })?;
        self.keep_list(items)
    }

    /// Keeps the list of a file whose chunks are kept, and says what the
    /// file is.
    fn keep_list(&self, items: Vec<ChunkRef>) -> Result<Target> {
        let list = FileList::new(items)?;
        if !self.store.has(Stored::FileList, list.hash())? {
            self.store
                .put(Stored::FileList, list.hash(), &list.encode())?;
        }
        Ok(list.target())
    }

    /// Keeps the folder with these entries, and says what it is. The entries
    /// may come in any order. Two entries with one name are an error.
    pub fn folder(&mut self, mut entries: Vec<Entry>) -> Result<Target> {
        entries.sort_by(|left, right| left.name().as_bytes().cmp(right.name().as_bytes()));
        let list = FolderList::new(entries)?;
        if !self.store.has(Stored::FolderList, list.hash())? {
            self.store
                .put(Stored::FolderList, list.hash(), &list.encode())?;
        }
        Ok(list.target())
    }

    /// Writes the record of the tree that has `top` on top, and gives the
    /// tree's root. The store must hold every list under `top`.
    ///
    /// The whole tree is checked before its record is kept: its sizes, how
    /// its files are chunked, and how deep its folders sit. The checks are the
    /// ones a tree goes through when it is taken in, and the totals in the
    /// record are what those checks counted.
    pub fn finish(self, top: Target, extra: ExtraData) -> Result<Root> {
        let totals = Intake::measure(self.store, top, self.chunking)?;
        let record = Record::new(top, totals, self.chunking, extra)?;
        let bytes = record.encode();
        let root = Root::of_record(&bytes);
        self.store.put(Stored::Record, root.as_hash(), &bytes)?;
        Ok(root)
    }
}

/// Hashes and keeps one chunk, and says what it is. A chunk that the store
/// holds already is not written again.
fn keep_chunk(store: &dyn Store, chunk: &[u8]) -> Result<ChunkRef> {
    let item = ChunkRef::of(chunk)?;
    if !store.has(Stored::Chunk, &item.hash)? {
        store.put(Stored::Chunk, &item.hash, chunk)?;
    }
    Ok(item)
}

/// Hashes and keeps chunks that follow one another in a file, and adds what
/// they are to `items`, in their order. Helpers that are free take a share.
fn keep_chunks(
    store: &dyn Store,
    helpers: &Helpers,
    chunks: &[&[u8]],
    items: &mut Vec<ChunkRef>,
) -> Result<()> {
    // A helper is worth starting only for a few chunks of its own.
    let helping = helpers.take(chunks.len() / 2);
    if helping == 0 {
        for chunk in chunks {
            items.push(keep_chunk(store, chunk)?);
        }
        return Ok(());
    }
    let next = AtomicUsize::new(0);
    let work = || {
        let mut kept = Vec::new();
        loop {
            let index = next.fetch_add(1, Ordering::Relaxed);
            let Some(chunk) = chunks.get(index) else {
                return kept;
            };
            let item = keep_chunk(store, chunk);
            if item.is_err() {
                next.store(chunks.len(), Ordering::Relaxed);
            }
            kept.push((index, item));
        }
    };
    let kept: Vec<(usize, Result<ChunkRef>)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..helping).map(|_| scope.spawn(work)).collect();
        let mut kept = work();
        for handle in handles {
            match handle.join() {
                Ok(more) => kept.extend(more),
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
        kept
    });
    helpers.give(helping);
    let mut found: Vec<Option<ChunkRef>> = vec![None; chunks.len()];
    for (index, item) in kept {
        found[index] = Some(item?);
    }
    for item in found {
        items.push(item.ok_or(Error::Invariant {
            detail: "a chunk was left out of a file",
        })?);
    }
    Ok(())
}

/// What a builder does with a link or a special file that it finds in a
/// folder. Neither is stored in a tree, and a link is never followed: it
/// could lead out of the folder that is being built.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Links {
    /// Stop, and say which one it was.
    #[default]
    Refuse,
    /// Leave it out of the tree.
    Skip,
}

/// How a tree is built from disk.
#[derive(Clone, Debug, Default)]
pub struct BuildOptions {
    chunking: Option<Chunking>,
    extra: ExtraData,
    timestamp: bool,
    workers: usize,
    links: Links,
}

impl BuildOptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// How files are chunked. Without this they are chunked by content, as every
    /// tree outside a test should be.
    pub fn chunking(mut self, chunking: Chunking) -> Self {
        self.chunking = Some(chunking);
        self
    }

    /// Extra data for the tree's record.
    pub fn extra(mut self, extra: ExtraData) -> Self {
        self.extra = extra;
        self
    }

    /// Writes the time of building into the record. Two builds of the same
    /// folder then have different roots.
    pub fn timestamp(mut self, on: bool) -> Self {
        self.timestamp = on;
        self
    }

    /// How many threads build the tree. Zero is one for each core. Files
    /// are chunked several at once, and a thread that has no file of its own
    /// helps to hash the chunks of a long one.
    pub fn workers(mut self, workers: usize) -> Self {
        self.workers = workers;
        self
    }

    pub fn links(mut self, links: Links) -> Self {
        self.links = links;
        self
    }
}

/// Gives the extra data for one entry: its path on disk, its name, and
/// whether it is a file or a folder.
pub type EntryExtra<'a> = dyn Fn(&Path, &str, Kind) -> Result<ExtraData> + Sync + 'a;

/// Builds the tree of the folder or the file at `path` into `store`, and
/// gives its root.
///
/// A folder's own name is not part of its tree, so the same folder gives the
/// same root wherever it is and whatever it is called. Entries have no extra
/// data: [`build_with`] adds some.
pub fn build(store: &dyn Store, path: impl AsRef<Path>, options: &BuildOptions) -> Result<Root> {
    build_tree(store, path.as_ref(), options, None)
}

/// Builds a tree as [`build`] does, and asks `entry_extra` for the extra
/// data of every entry.
pub fn build_with(
    store: &dyn Store,
    path: impl AsRef<Path>,
    options: &BuildOptions,
    entry_extra: &EntryExtra<'_>,
) -> Result<Root> {
    build_tree(store, path.as_ref(), options, Some(entry_extra))
}

fn build_tree(
    store: &dyn Store,
    path: &Path,
    options: &BuildOptions,
    entry_extra: Option<&EntryExtra<'_>>,
) -> Result<Root> {
    let chunking = options.chunking.unwrap_or(Chunking::FastCdcV1);
    let mut extra = options.extra.clone();
    if options.timestamp {
        extra.insert(TIMESTAMP_KEY, timestamp(SystemTime::now())?)?;
    }
    let metadata = fs::metadata(path).map_err(|error| io_error("look at", path, error))?;
    let mut builder = Builder::new(store, chunking).threads(options.workers);
    if !metadata.is_dir() {
        let top = builder.file_at(path)?;
        return builder.finish(top, extra);
    }

    // From here on nothing is reached by its path: the folder is held open,
    // and so is every folder under it while it is read.
    let top = Held::open(path).map_err(|error| io_error("open", path, error))?;
    let (folders, file_targets) =
        walk_and_chunk(store, chunking, &top, options.links, options.workers)?;
    // A folder is found after the folder it is in, so going backwards every
    // folder is made after the folders inside it.
    let mut folder_targets: Vec<Option<Target>> = vec![None; folders.len()];
    for index in (0..folders.len()).rev() {
        let mut entries = Vec::with_capacity(folders[index].children.len());
        for child in &folders[index].children {
            let target = match child.kind {
                Kind::File => *file_targets.get(child.index).ok_or(Error::Invariant {
                    detail: "a file was left out of the build",
                })?,
                Kind::Folder => folder_targets[child.index].ok_or(Error::Invariant {
                    detail: "a folder was made before a folder inside it",
                })?,
            };
            let extra = match entry_extra {
                // A file's path is put together here, for the caller to see,
                // and only when there is a caller to see it. No file is opened
                // by it.
                Some(entry_extra) => match child.kind {
                    Kind::File => entry_extra(
                        &folders[index].path.join(&child.name),
                        &child.name,
                        child.kind,
                    )?,
                    Kind::Folder => {
                        entry_extra(&folders[child.index].path, &child.name, child.kind)?
                    }
                },
                None => ExtraData::new(),
            };
            entries.push(Entry::new(child.name.as_str(), target, extra)?);
        }
        folder_targets[index] = Some(builder.folder(entries)?);
    }
    let top = folder_targets[0].ok_or(Error::Invariant {
        detail: "the top folder was not made",
    })?;
    builder.finish(top, extra)
}

struct Folder {
    path: PathBuf,
    children: Vec<Child>,
}

struct Child {
    name: String,
    kind: Kind,
    /// The child's place among the folders, or among the files.
    index: usize,
}

/// A folder on the way down to the one that is read, held open, with the
/// folders inside it that are still to be read: each by its name and its
/// place among the folders.
type OnTheWay = (Arc<Held>, Vec<(String, usize)>);

/// How many folders' files may wait for the threads that chunk. A folder is
/// kept open while it has files that are not chunked yet, so this bounds how many
/// folders are open at a time.
const FOLDERS_AHEAD: usize = 16;

/// The files that the walk found in one folder, for the threads to chunk. The
/// folder is held open, and each file is opened from it by its name.
struct Batch {
    folder: Arc<Held>,
    /// Each file's place among the files, and its name in the folder.
    files: Vec<(usize, String)>,
    /// How many of the files are taken.
    taken: AtomicUsize,
}

impl Batch {
    /// A file that no thread has taken yet. Each file is given once, to
    /// whichever thread asks first.
    fn take(&self) -> Option<&(usize, String)> {
        self.files.get(self.taken.fetch_add(1, Ordering::Relaxed))
    }

    fn all_taken(&self) -> bool {
        self.taken.load(Ordering::Relaxed) >= self.files.len()
    }
}

/// What was there when a folder was read has to be there still when it is
/// opened. If a link took its place meanwhile, the link is not followed.
fn changed(path: &Path, refused: Refused) -> Error {
    let what = match refused {
        Refused::Io(error) => return io_error("open", path, error),
        Refused::Link => "a link now, where a file or a folder was when the build began",
        Refused::Other => "something else now than it was when the build began",
    };
    Error::UnsupportedEntry {
        path: path.to_path_buf(),
        what,
    }
}

/// Chunks and keeps the file `name` of a folder that is held open. The file is
/// opened from the folder itself. Once `stop` is set, the file is given up,
/// however much of it is left.
fn chunk_file_in(
    builder: &mut Builder<'_>,
    folder: &Held,
    name: &str,
    stop: Option<&AtomicBool>,
) -> Result<Target> {
    // The path is for messages, and is put together only for one.
    let path = || folder.path().join(name);
    let mut file = folder
        .open_file(name)
        .map_err(|refused| changed(&path(), refused))?;
    builder.file_from(|buffer| {
        if stop.is_some_and(|stop| stop.load(Ordering::Relaxed)) {
            return Err(STOPPED);
        }
        read_some(&mut file, buffer).map_err(|error| io_error("read", &path(), error))
    })
}

/// What a walk through a folder has found so far.
struct Walk<'a> {
    links: Links,
    folders: Vec<Folder>,
    /// How many files were found.
    files: usize,
    /// Takes the files of each folder, once the folder is read.
    on_files: &'a mut dyn FnMut(Batch) -> Result<()>,
}

impl Walk<'_> {
    /// Reads one folder, which is `depth` folders down from the top, the top
    /// counted. Notes what is in it, hands its files on, and gives the
    /// folders inside it, each with its place among the folders.
    fn read(
        &mut self,
        held: &Arc<Held>,
        index: usize,
        depth: usize,
    ) -> Result<Vec<(String, usize)>> {
        let folder_path = held.path().to_path_buf();
        let listed = held
            .list()
            .map_err(|error| io_error("list", &folder_path, error))?;
        let mut children = Vec::with_capacity(listed.len());
        let mut inside = Vec::new();
        let mut files = Vec::new();
        for (name, found) in listed {
            let name = name.into_string().map_err(|name| Error::NonUtf8FileName {
                path: folder_path.join(name),
            })?;
            check_name(&name)?;
            match found {
                Found::Folder => {
                    if depth >= MAX_FOLDER_DEPTH {
                        return Err(Error::TooDeep {
                            limit: MAX_FOLDER_DEPTH,
                        });
                    }
                    let below = self.folders.len();
                    children.push(Child {
                        name: name.clone(),
                        kind: Kind::Folder,
                        index: below,
                    });
                    self.folders.push(Folder {
                        path: folder_path.join(&name),
                        children: Vec::new(),
                    });
                    inside.push((name, below));
                }
                Found::File => {
                    children.push(Child {
                        name: name.clone(),
                        kind: Kind::File,
                        index: self.files,
                    });
                    files.push((self.files, name));
                    self.files += 1;
                }
                Found::Link | Found::Other => {
                    if self.links == Links::Refuse {
                        return Err(Error::UnsupportedEntry {
                            path: folder_path.join(&name),
                            what: if found == Found::Link {
                                "a link"
                            } else {
                                "a special file"
                            },
                        });
                    }
                }
            }
        }
        children.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
        self.folders[index].children = children;
        if !files.is_empty() {
            (self.on_files)(Batch {
                folder: Arc::clone(held),
                files,
                taken: AtomicUsize::new(0),
            })?;
        }
        Ok(inside)
    }
}

/// Finds every folder and every file under `top`, and hands the files of
/// each folder to `on_files` once the folder is read. A link is never
/// followed. Gives the folders, and how many files there are.
///
/// A folder is opened from the folder it is in, which is held open, and is
/// held open itself while it is read. So no folder on the way to a file can
/// be swapped for a link between the reading of a folder and the opening of
/// what is in it.
fn walk(
    top: &Arc<Held>,
    links: Links,
    on_files: &mut dyn FnMut(Batch) -> Result<()>,
) -> Result<(Vec<Folder>, usize)> {
    let mut walk = Walk {
        links,
        folders: vec![Folder {
            path: top.path().to_path_buf(),
            children: Vec::new(),
        }],
        files: 0,
        on_files,
    };
    // The folders on the way down to the one that is read, each held open,
    // with the folders inside it that are still to be read.
    let mut way: Vec<OnTheWay> = Vec::new();
    let mut next = Some((Arc::clone(top), 0_usize));
    loop {
        if let Some((held, index)) = next.take() {
            let inside = walk.read(&held, index, way.len() + 1)?;
            way.push((held, inside));
        }
        let Some((held, inside)) = way.last_mut() else {
            break;
        };
        match inside.pop() {
            Some((name, index)) => {
                let below = held
                    .open_folder(&name)
                    .map_err(|refused| changed(&walk.folders[index].path, refused))?;
                next = Some((below, index));
            }
            None => {
                way.pop();
            }
        }
    }
    Ok((walk.folders, walk.files))
}

/// What a thread gives when it stopped because the build had failed
/// somewhere else. The error that the caller is given is that failure's.
const STOPPED_DETAIL: &str = "the build was stopped";
const STOPPED: Error = Error::Invariant {
    detail: STOPPED_DETAIL,
};

fn is_stopped(error: &Error) -> bool {
    matches!(error, Error::Invariant { detail } if *detail == STOPPED_DETAIL)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn wait<'a, T>(told: &Condvar, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
    told.wait(guard)
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The folders whose files wait for the threads that chunk, between the
/// thread that walks and those threads.
///
/// Nobody waits here for a thread that is gone. A file that cannot be chunked, a
/// walk that fails and a thread that falls over each set `failed`, and wake
/// whoever waits.
struct Waiting {
    state: Mutex<WaitingState>,
    /// Told when there is a folder to take files from, or none will come.
    more: Condvar,
    /// Told when a folder's files are all taken, so that the walk may go on.
    room: Condvar,
    /// Nothing more is to be chunked.
    failed: AtomicBool,
}

struct WaitingState {
    batches: VecDeque<Arc<Batch>>,
    /// The walk is over: no more folders will come.
    over: bool,
}

impl Waiting {
    fn new() -> Self {
        Self {
            state: Mutex::new(WaitingState {
                batches: VecDeque::new(),
                over: false,
            }),
            more: Condvar::new(),
            room: Condvar::new(),
            failed: AtomicBool::new(false),
        }
    }

    fn has_failed(&self) -> bool {
        self.failed.load(Ordering::Relaxed)
    }

    /// For the walk: adds a folder's files, once there is room for them.
    fn add(&self, batch: Batch) -> Result<()> {
        let one_file = batch.files.len() == 1;
        let mut state = lock(&self.state);
        loop {
            if self.has_failed() {
                return Err(STOPPED);
            }
            if state.batches.len() < FOLDERS_AHEAD {
                break;
            }
            state = wait(&self.room, state);
        }
        state.batches.push_back(Arc::new(batch));
        drop(state);
        if one_file {
            self.more.notify_one();
        } else {
            self.more.notify_all();
        }
        Ok(())
    }

    /// For a thread that chunks: a folder that has files left to take. None
    /// when the walk is over and every file is taken, or when the build has
    /// failed.
    fn next(&self) -> Option<Arc<Batch>> {
        let mut state = lock(&self.state);
        loop {
            if self.has_failed() {
                return None;
            }
            while state.batches.front().is_some_and(|batch| batch.all_taken()) {
                state.batches.pop_front();
                self.room.notify_one();
            }
            if let Some(batch) = state.batches.front() {
                return Some(Arc::clone(batch));
            }
            if state.over {
                return None;
            }
            state = wait(&self.more, state);
        }
    }

    /// Nothing more is to be chunked. Set with the lock held, so that no thread
    /// can look, miss it, and then wait.
    fn fail(&self) {
        let state = lock(&self.state);
        self.failed.store(true, Ordering::Relaxed);
        drop(state);
        self.more.notify_all();
        self.room.notify_all();
    }

    /// The walk is over.
    fn end(&self) {
        lock(&self.state).over = true;
        self.more.notify_all();
    }
}

/// Held by each thread of a build while it works. A thread that falls over
/// tells the others as it goes, so that none of them waits for it.
struct Working<'a>(&'a Waiting);

impl Drop for Working<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.fail();
        }
    }
}

/// Finds every folder and every file under `top`, and chunks and keeps the
/// files while they are found, several at once. Gives the folders, and what
/// each file is.
fn walk_and_chunk(
    store: &dyn Store,
    chunking: Chunking,
    top: &Arc<Held>,
    links: Links,
    threads: usize,
) -> Result<(Vec<Folder>, Vec<Target>)> {
    let threads = match threads {
        0 => cores(),
        threads => threads,
    };
    // A thread that has no file left gives itself up to help with the long
    // files that are still being chunked.
    let helpers = Helpers::new(0);
    if threads == 1 {
        // One thread walks and chunks in turn.
        let mut builder = Builder::sharing(store, chunking, helpers);
        let mut targets = Vec::new();
        let (folders, _) = walk(top, links, &mut |batch| {
            for (index, name) in &batch.files {
                if *index != targets.len() {
                    return Err(Error::Invariant {
                        detail: "a file was chunked out of its turn",
                    });
                }
                targets.push(chunk_file_in(&mut builder, &batch.folder, name, None)?);
            }
            Ok(())
        })?;
        return Ok((folders, targets));
    }
    let waiting = Waiting::new();
    let work = || -> Result<Vec<(usize, Target)>> {
        let _working = Working(&waiting);
        let mut builder = Builder::sharing(store, chunking, Arc::clone(&helpers));
        let mut done = Vec::new();
        let mut first_error = None;
        while let Some(batch) = waiting.next() {
            // Every thread that is free takes files from the same folder,
            // one each, until the folder has none left.
            while let Some((index, name)) = batch.take() {
                if waiting.has_failed() {
                    break;
                }
                let stop = Some(&waiting.failed);
                match chunk_file_in(&mut builder, &batch.folder, name, stop) {
                    Ok(target) => done.push((*index, target)),
                    Err(error) => {
                        first_error.get_or_insert(error);
                        waiting.fail();
                    }
                }
            }
        }
        helpers.give(1);
        match first_error {
            Some(error) => Err(error),
            None => Ok(done),
        }
    };
    let (walked, chunked) = std::thread::scope(|scope| {
        let _working = Working(&waiting);
        let handles: Vec<_> = (0..threads).map(|_| scope.spawn(work)).collect();
        let walked = walk(top, links, &mut |batch| waiting.add(batch));
        // A walk that failed stops the chunking too: a thread gives up the
        // file it is on, however long that file is.
        if walked.is_err() {
            waiting.fail();
        }
        // With the walk over, the threads run out of files and end.
        waiting.end();
        let chunked: Vec<Result<Vec<(usize, Target)>>> = handles
            .into_iter()
            .map(|handle| match handle.join() {
                Ok(result) => result,
                Err(payload) => std::panic::resume_unwind(payload),
            })
            .collect();
        (walked, chunked)
    });
    // The failure that came first in its thread is the one to tell. A thread
    // that only stopped for another's failure has nothing to tell.
    let mut done = Vec::new();
    let mut stopped = false;
    for result in chunked {
        match result {
            Ok(part) => done.extend(part),
            Err(error) if is_stopped(&error) => stopped = true,
            Err(error) => return Err(error),
        }
    }
    let (folders, files) = walked?;
    if stopped {
        return Err(STOPPED);
    }
    let mut targets: Vec<Option<Target>> = vec![None; files];
    for (index, target) in done {
        targets[index] = Some(target);
    }
    let targets = targets
        .into_iter()
        .map(|target| {
            target.ok_or(Error::Invariant {
                detail: "a file was left out of the build",
            })
        })
        .collect::<Result<Vec<Target>>>()?;
    Ok((folders, targets))
}

/// The time as text: `2026-11-12T08:30:00Z`, in UTC, to the second.
fn timestamp(time: SystemTime) -> Result<String> {
    let elapsed = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::SystemTimeBeforeUnixEpoch)?;
    let seconds =
        i64::try_from(elapsed.as_secs()).map_err(|_| Error::SizeOverflow { field: "timestamp" })?;
    Ok(format_epoch_seconds(seconds))
}

fn format_epoch_seconds(seconds: i64) -> String {
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
mod tests {
    use super::*;

    #[test]
    fn the_time_is_written_in_utc_to_the_second() {
        assert_eq!(format_epoch_seconds(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_epoch_seconds(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format_epoch_seconds(1_794_472_200), "2026-11-12T08:30:00Z");
        assert_eq!(format_epoch_seconds(4_102_444_799), "2099-12-31T23:59:59Z");
        assert_eq!(format_epoch_seconds(-1), "1969-12-31T23:59:59Z");
    }
}
