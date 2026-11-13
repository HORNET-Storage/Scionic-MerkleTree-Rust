//! Building a tree: from a folder or a file on disk, or part by part.

use crate::fastcdc::StreamCutter;
use crate::format::{
    check_name, Cutting, Entry, ExtraData, FileList, FolderList, Kind, PieceRef, Record, Target,
    Totals, MAX_FOLDER_DEPTH, TIMESTAMP_KEY,
};
use crate::hash::{Hash, Root};
use crate::intake::Intake;
use crate::store::{load_file, load_folder, missing, Store, Stored};
use crate::{io_error, Error, Result};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

/// Builds a tree part by part: files from their bytes, folders from their
/// entries, and at the end the record.
///
/// Everything goes into the store as it is made. A piece, a file or a folder
/// that the store holds already is not written again.
pub struct Builder<'s> {
    store: &'s dyn Store,
    cutting: Cutting,
    cutter: StreamCutter,
}

impl<'s> Builder<'s> {
    pub fn new(store: &'s dyn Store, cutting: Cutting) -> Self {
        Self {
            store,
            cutting,
            cutter: StreamCutter::new(),
        }
    }

    /// How this builder cuts files.
    pub fn cutting(&self) -> Cutting {
        self.cutting
    }

    /// Cuts everything `reader` gives into pieces, keeps the pieces and the
    /// file's list, and says what the file is. No more than one piece of the
    /// file is held in memory at a time.
    pub fn file(&mut self, reader: &mut dyn Read) -> Result<Target> {
        self.file_from(|buffer| {
            read_some(reader, buffer).map_err(|source| Error::Stream {
                operation: "read a file's bytes",
                source,
            })
        })
    }

    /// The file with these bytes.
    pub fn file_from_bytes(&mut self, mut bytes: &[u8]) -> Result<Target> {
        self.file(&mut bytes)
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
        let mut items = Vec::new();
        self.cutter.cut(self.cutting, read, |piece| {
            let item = PieceRef::of(piece)?;
            if !store.has(Stored::Piece, &item.hash)? {
                store.put(Stored::Piece, &item.hash, piece)?;
            }
            items.push(item);
            Ok(())
        })?;
        let list = FileList::new(items)?;
        if !store.has(Stored::FileList, list.hash())? {
            store.put(Stored::FileList, list.hash(), &list.encode())?;
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
    /// tree's root. The store must hold every list under `top`. The whole
    /// tree is checked before its record is kept: its sizes, how its files
    /// are cut, and how deep its folders sit.
    pub fn finish(self, top: Target, extra: ExtraData) -> Result<Root> {
        let totals = totals_of(self.store, &top)?;
        let record = Record::new(top, totals, self.cutting, extra)?;
        let bytes = record.encode();
        let root = Root::of_record(&bytes);
        let held_before = self.store.has(Stored::Record, root.as_hash())?;
        self.store.put(Stored::Record, root.as_hash(), &bytes)?;
        let checked = Intake::new(self.store, root).and_then(|intake| intake.finish_lists());
        if let Err(error) = checked {
            if !held_before {
                self.store.remove(Stored::Record, root.as_hash())?;
            }
            return Err(error);
        }
        Ok(root)
    }
}

/// Counts what a record says about its tree: each different piece and each
/// different list, once.
fn totals_of(store: &dyn Store, top: &Target) -> Result<Totals> {
    let mut totals = Totals::default();
    let mut lists: HashSet<(Kind, Hash)> = HashSet::new();
    let mut pieces: HashMap<Hash, u32> = HashMap::new();
    let mut pending = vec![*top];
    let overflow = || Error::SizeOverflow {
        field: "a tree's totals",
    };
    while let Some(target) = pending.pop() {
        if !lists.insert((target.kind, target.hash)) {
            continue;
        }
        match target.kind {
            Kind::Folder => {
                let list = load_folder(store, &target)?
                    .ok_or_else(|| missing("the list of the folder", &target.hash))?;
                totals.list_bytes = totals
                    .list_bytes
                    .checked_add(list.encoded_len())
                    .ok_or_else(overflow)?;
                pending.extend(list.entries().iter().map(Entry::target));
            }
            Kind::File => {
                let list = load_file(store, &target)?
                    .ok_or_else(|| missing("the list of the file", &target.hash))?;
                totals.list_bytes = totals
                    .list_bytes
                    .checked_add(list.encoded_len())
                    .ok_or_else(overflow)?;
                for item in list.items() {
                    if pieces.insert(item.hash, item.length).is_none() {
                        totals.pieces += 1;
                        totals.piece_bytes = totals
                            .piece_bytes
                            .checked_add(u64::from(item.length))
                            .ok_or_else(overflow)?;
                    }
                }
            }
        }
    }
    Ok(totals)
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

    /// How many files are cut at once. Zero is one for each core.
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
    let mut builder = Builder::new(store, cutting);
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
    let workers = match workers {
        0 => std::thread::available_parallelism().map_or(1, usize::from),
        workers => workers,
    }
    .min(files.len());
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let work = || -> Result<Vec<(usize, Target)>> {
        let mut builder = Builder::new(store, cutting);
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
