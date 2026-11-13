//! Building a tree: from a folder or a file on disk, or part by part.

use crate::fastcdc::{StreamCutter, FASTCDC_MAX_SIZE};
use crate::format::{
    check_name, Cutting, Entry, ExtraData, FileList, FolderList, Kind, PieceRef, Record, Target,
    MAX_FOLDER_DEPTH, TIMESTAMP_KEY,
};
use crate::hash::Root;
use crate::intake::Intake;
use crate::store::{Store, Stored};
use crate::{io_error, Error, Result};
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
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
/// pieces of the longest kind.
const ROOM_ALONE: usize = 2 * FASTCDC_MAX_SIZE;

/// How much of a file a builder holds at a time when other threads help it:
/// enough pieces to give each of them some.
const ROOM_WITH_HELP: usize = 8 * FASTCDC_MAX_SIZE;

/// How many pieces of a file that lies in memory are handed on at a time.
const PIECES_AT_A_TIME: usize = 64;

fn cores() -> usize {
    std::thread::available_parallelism().map_or(1, usize::from)
}

/// The threads that are free to help with a long file.
///
/// A file is cut on the thread that asks for it, because where one piece
/// ends decides where the next begins. Hashing and keeping the pieces is the
/// greater part of the work and needs no order, so it is shared out among
/// that thread and the helpers that are free.
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
/// Everything goes into the store as it is made. A piece, a file or a folder
/// that the store holds already is not written again.
pub struct Builder<'s> {
    store: &'s dyn Store,
    cutting: Cutting,
    cutter: StreamCutter,
    helpers: Arc<Helpers>,
}

impl<'s> Builder<'s> {
    /// A builder that uses one thread for each core on a long file.
    pub fn new(store: &'s dyn Store, cutting: Cutting) -> Self {
        Self::sharing(store, cutting, Helpers::for_threads(0))
    }

    fn sharing(store: &'s dyn Store, cutting: Cutting, helpers: Arc<Helpers>) -> Self {
        Self {
            store,
            cutting,
            cutter: StreamCutter::new(),
            helpers,
        }
    }

    /// How many threads hash and keep the pieces of one file: 1 is the
    /// calling thread alone, and zero is one thread for each core. A file is
    /// always cut on the calling thread. With help, a builder holds up to
    /// 64 MiB of a long file at a time; alone it holds up to 16 MiB.
    pub fn threads(mut self, threads: usize) -> Self {
        self.helpers = Helpers::for_threads(threads);
        self
    }

    /// How this builder cuts files.
    pub fn cutting(&self) -> Cutting {
        self.cutting
    }

    /// Cuts everything `reader` gives into pieces, keeps the pieces and the
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

    /// The file with these bytes. They are cut where they lie, and nothing
    /// is copied on the way to the store.
    pub fn file_from_bytes(&mut self, bytes: &[u8]) -> Result<Target> {
        let mut items = Vec::new();
        for pieces in self.cutting.cut(bytes).chunks(PIECES_AT_A_TIME) {
            keep_pieces(self.store, &self.helpers, pieces, &mut items)?;
        }
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
        self.cutter.cut(self.cutting, room, read, |pieces| {
            keep_pieces(store, helpers, pieces, &mut items)
        })?;
        self.keep_list(items)
    }

    /// Keeps the list of a file whose pieces are kept, and says what the
    /// file is.
    fn keep_list(&self, items: Vec<PieceRef>) -> Result<Target> {
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
    /// its files are cut, and how deep its folders sit. The checks are the
    /// ones a tree goes through when it is taken in, and the totals in the
    /// record are what those checks counted.
    pub fn finish(self, top: Target, extra: ExtraData) -> Result<Root> {
        let totals = Intake::measure(self.store, top, self.cutting)?;
        let record = Record::new(top, totals, self.cutting, extra)?;
        let bytes = record.encode();
        let root = Root::of_record(&bytes);
        self.store.put(Stored::Record, root.as_hash(), &bytes)?;
        Ok(root)
    }
}

/// Hashes and keeps one piece, and says what it is. A piece that the store
/// holds already is not written again.
fn keep_piece(store: &dyn Store, piece: &[u8]) -> Result<PieceRef> {
    let item = PieceRef::of(piece)?;
    if !store.has(Stored::Piece, &item.hash)? {
        store.put(Stored::Piece, &item.hash, piece)?;
    }
    Ok(item)
}

/// Hashes and keeps pieces that follow one another in a file, and adds what
/// they are to `items`, in their order. Helpers that are free take a share.
fn keep_pieces(
    store: &dyn Store,
    helpers: &Helpers,
    pieces: &[&[u8]],
    items: &mut Vec<PieceRef>,
) -> Result<()> {
    // A helper is worth starting only for a few pieces of its own.
    let helping = helpers.take(pieces.len() / 2);
    if helping == 0 {
        for piece in pieces {
            items.push(keep_piece(store, piece)?);
        }
        return Ok(());
    }
    let next = AtomicUsize::new(0);
    let work = || {
        let mut kept = Vec::new();
        loop {
            let index = next.fetch_add(1, Ordering::Relaxed);
            let Some(piece) = pieces.get(index) else {
                return kept;
            };
            let item = keep_piece(store, piece);
            if item.is_err() {
                next.store(pieces.len(), Ordering::Relaxed);
            }
            kept.push((index, item));
        }
    };
    let kept: Vec<(usize, Result<PieceRef>)> = std::thread::scope(|scope| {
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
    let mut found: Vec<Option<PieceRef>> = vec![None; pieces.len()];
    for (index, item) in kept {
        found[index] = Some(item?);
    }
    for item in found {
        items.push(item.ok_or(Error::Invariant {
            detail: "a piece was left out of a file",
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
    cutting: Option<Cutting>,
    extra: ExtraData,
    timestamp: bool,
    workers: usize,
    links: Links,
}

impl BuildOptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// How files are cut. Without this they are cut by content, as every
    /// tree outside a test should be.
    pub fn cutting(mut self, cutting: Cutting) -> Self {
        self.cutting = Some(cutting);
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
    /// are cut several at once, and a thread that has no file of its own
    /// helps to hash the pieces of a long one.
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
    build_with(store, path, options, &|_, _, _| Ok(ExtraData::new()))
}

/// Builds a tree as [`build`] does, and asks `entry_extra` for the extra
/// data of every entry.
pub fn build_with(
    store: &dyn Store,
    path: impl AsRef<Path>,
    options: &BuildOptions,
    entry_extra: &EntryExtra<'_>,
) -> Result<Root> {
    let path = path.as_ref();
    let cutting = options.cutting.unwrap_or(Cutting::FastCdcV1);
    let mut extra = options.extra.clone();
    if options.timestamp {
        extra.insert(TIMESTAMP_KEY, timestamp(SystemTime::now())?)?;
    }
    let metadata = fs::metadata(path).map_err(|error| io_error("look at", path, error))?;
    let mut builder = Builder::new(store, cutting).threads(options.workers);
    if !metadata.is_dir() {
        let top = builder.file_at(path)?;
        return builder.finish(top, extra);
    }

    let (folders, files) = walk(path, options.links)?;
    let file_targets = store_files(store, cutting, &files, options.workers)?;
    // A folder is found after the folder it is in, so going backwards every
    // folder is made after the folders inside it.
    let mut folder_targets: Vec<Option<Target>> = vec![None; folders.len()];
    for index in (0..folders.len()).rev() {
        let mut entries = Vec::with_capacity(folders[index].children.len());
        for child in &folders[index].children {
            let (target, child_path) = match child.kind {
                Kind::File => (file_targets[child.index], files[child.index].as_path()),
                Kind::Folder => (
                    folder_targets[child.index].ok_or(Error::Invariant {
                        detail: "a folder was made before a folder inside it",
                    })?,
                    folders[child.index].path.as_path(),
                ),
            };
            let extra = entry_extra(child_path, &child.name, child.kind)?;
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

/// Finds every folder and every file under `top`. Nothing is read yet. A
/// link is never followed.
fn walk(top: &Path, links: Links) -> Result<(Vec<Folder>, Vec<PathBuf>)> {
    let mut folders = vec![Folder {
        path: top.to_path_buf(),
        children: Vec::new(),
    }];
    // How many folders lie on the way to each folder, itself counted.
    let mut depths = vec![1_usize];
    let mut files = Vec::new();
    let mut next = 0;
    while next < folders.len() {
        let folder_path = folders[next].path.clone();
        let mut children = Vec::new();
        let listing =
            fs::read_dir(&folder_path).map_err(|error| io_error("list", &folder_path, error))?;
        for entry in listing {
            let entry = entry.map_err(|error| io_error("list", &folder_path, error))?;
            let path = entry.path();
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::NonUtf8FileName { path: path.clone() })?;
            check_name(&name)?;
            let file_type = entry
                .file_type()
                .map_err(|error| io_error("look at", &path, error))?;
            if file_type.is_dir() {
                if depths[next] >= MAX_FOLDER_DEPTH {
                    return Err(Error::TooDeep {
                        limit: MAX_FOLDER_DEPTH,
                    });
                }
                children.push(Child {
                    name,
                    kind: Kind::Folder,
                    index: folders.len(),
                });
                folders.push(Folder {
                    path,
                    children: Vec::new(),
                });
                depths.push(depths[next] + 1);
            } else if file_type.is_file() {
                children.push(Child {
                    name,
                    kind: Kind::File,
                    index: files.len(),
                });
                files.push(path);
            } else if links == Links::Refuse {
                return Err(Error::UnsupportedEntry {
                    path,
                    what: if file_type.is_symlink() {
                        "a link"
                    } else {
                        "a special file"
                    },
                });
            }
        }
        children.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
        folders[next].children = children;
        next += 1;
    }
    Ok((folders, files))
}

/// Cuts and keeps every file, several at once, and gives what each one is.
fn store_files(
    store: &dyn Store,
    cutting: Cutting,
    files: &[PathBuf],
    workers: usize,
) -> Result<Vec<Target>> {
    let threads = match workers {
        0 => cores(),
        workers => workers,
    };
    let workers = threads.min(files.len());
    // The threads that have no file of their own help with the long files.
    let helpers = Helpers::new(threads - workers);
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let work = || -> Result<Vec<(usize, Target)>> {
        let mut builder = Builder::sharing(store, cutting, Arc::clone(&helpers));
        let mut done = Vec::new();
        while !failed.load(Ordering::Relaxed) {
            let index = next.fetch_add(1, Ordering::Relaxed);
            let Some(path) = files.get(index) else {
                break;
            };
            match builder.file_at(path) {
                Ok(target) => done.push((index, target)),
                Err(error) => {
                    failed.store(true, Ordering::Relaxed);
                    return Err(error);
                }
            }
        }
        // This thread has no file left, and may help with the ones that
        // are still being cut.
        helpers.give(1);
        Ok(done)
    };
    let results: Vec<Result<Vec<(usize, Target)>>> = if workers <= 1 {
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
    let mut targets: Vec<Option<Target>> = vec![None; files.len()];
    for result in results {
        for (index, target) in result? {
            targets[index] = Some(target);
        }
    }
    targets
        .into_iter()
        .map(|target| {
            target.ok_or(Error::Invariant {
                detail: "a file was left out of the build",
            })
        })
        .collect()
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
