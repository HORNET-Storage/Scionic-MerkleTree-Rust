//! Reading a tree that a store holds: finding a path, reading a file or a
//! stretch of it, and writing the tree out to disk.
//!
//! Everything read from the store is checked again before it is used: a list
//! against the hash it was asked for by, and a piece against the hash and the
//! length its file gives it. A file's bytes are handed out only when every
//! piece they need is there. Otherwise it is an error, never a shorter file.

use crate::disk::{Held, Refused};
use crate::format::{
    check_name, Entry, FileList, FolderList, Kind, OpenFile, PieceRef, Record, Target,
    MAX_FOLDER_DEPTH,
};
use crate::hash::{Hash, Root};
use crate::store::{load_file, load_folder, load_piece, load_record, missing, Store, Stored};
use crate::{io_error, Error, Result};
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn invalid(detail: &str) -> Error {
    Error::InvalidData {
        detail: detail.to_owned(),
    }
}

/// The record of the tree with this root.
pub fn record_of(store: &dyn Store, root: &Root) -> Result<Record> {
    load_record(store, root)?.ok_or_else(|| missing("the record of", root.as_hash()))
}

/// The entries of a folder.
pub fn folder_of(store: &dyn Store, folder: &Target) -> Result<FolderList> {
    load_folder(store, folder)?.ok_or_else(|| missing("the list of the folder", &folder.hash))
}

/// The list of a file's pieces.
pub fn file_of(store: &dyn Store, file: &Target) -> Result<FileList> {
    load_file(store, file)?.ok_or_else(|| missing("the list of the file", &file.hash))
}

/// What is at `path` in a tree: names with `/` between them, as in
/// `weights/model.safetensors`. Nothing is there when a name on the way is
/// missing, or is a file. A path that leads through more folders than a tree
/// may have is an error.
pub fn lookup(store: &dyn Store, root: &Root, path: &str) -> Result<Option<Entry>> {
    let mut current = record_of(store, root)?.top();
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
        let list = folder_of(store, &current)?;
        let Some(entry) = list.get(name) else {
            return Ok(None);
        };
        current = entry.target();
        found = Some(entry.clone());
    }
    Ok(found)
}

/// Writes all of a file's bytes to `out`.
pub fn read_file(store: &dyn Store, file: &Target, out: &mut dyn Write) -> Result<()> {
    read_range(store, file, 0, file.size, out)
}

/// A file's bytes, in memory.
pub fn read_file_to_vec(store: &dyn Store, file: &Target) -> Result<Vec<u8>> {
    let size = usize::try_from(file.size).map_err(|_| Error::SizeOverflow {
        field: "a file read into memory",
    })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| Error::AllocationFailed {
            resource: "a file read into memory",
            requested: file.size,
        })?;
    read_file(store, file, &mut bytes)?;
    Ok(bytes)
}

/// Writes `length` bytes of a file, from byte `offset`, to `out`.
///
/// Before the first byte goes out, every piece of the stretch is looked for.
/// If one is missing, nothing is written. Each piece is then checked against
/// its hash as it is written.
///
/// The file's list is read and checked on every call. For many stretches of
/// one long file, open its list once and use [`read_open`].
pub fn read_range(
    store: &dyn Store,
    file: &Target,
    offset: u64,
    length: u64,
    out: &mut dyn Write,
) -> Result<()> {
    let list = file_of(store, file)?;
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= list.size())
        .ok_or_else(|| invalid("a stretch of bytes is outside the file"))?;
    if length == 0 {
        return Ok(());
    }
    // The pieces that hold the stretch, each with the byte it starts at.
    let mut wanted = Vec::new();
    let mut start = 0_u64;
    for item in list.items() {
        if start >= end {
            break;
        }
        let after = start + u64::from(item.length);
        if after > offset {
            wanted.push((*item, start));
        }
        start = after;
    }
    write_stretch(store, &wanted, offset, end, out)
}

/// Writes `length` bytes of a file whose list is open, from byte `offset`,
/// to `out`. It does what [`read_range`] does, and finds the pieces without
/// a pass over the list.
pub fn read_open(
    store: &dyn Store,
    file: &OpenFile,
    offset: u64,
    length: u64,
    out: &mut dyn Write,
) -> Result<()> {
    if length == 0 {
        return if offset <= file.list().size() {
            Ok(())
        } else {
            Err(invalid("a stretch of bytes is outside the file"))
        };
    }
    let (first, after) = file.pieces_for(offset, length)?;
    let mut wanted = Vec::new();
    for number in first..after {
        let item = usize::try_from(number)
            .ok()
            .and_then(|place| file.list().items().get(place));
        let (Some(item), Some(start)) = (item, file.start_of(number)) else {
            return Err(Error::Invariant {
                detail: "an open file names a piece it does not have",
            });
        };
        wanted.push((*item, start));
    }
    write_stretch(store, &wanted, offset, offset + length, out)
}

/// Writes the bytes from `offset` up to `end` out of the pieces that hold
/// them. Each piece comes with the byte of the file it starts at.
fn write_stretch(
    store: &dyn Store,
    wanted: &[(PieceRef, u64)],
    offset: u64,
    end: u64,
    out: &mut dyn Write,
) -> Result<()> {
    for (item, _) in wanted {
        match store.size(Stored::Piece, &item.hash)? {
            Some(size) if size == u64::from(item.length) => {}
            Some(size) => {
                return Err(Error::SizeMismatch {
                    what: "a stored piece",
                    expected: u64::from(item.length),
                    actual: size,
                })
            }
            None => return Err(missing("the piece", &item.hash)),
        }
    }
    for (item, start) in wanted {
        let bytes = load_piece(store, item)?.ok_or_else(|| missing("the piece", &item.hash))?;
        let from = offset.saturating_sub(*start) as usize;
        let to = (end.min(start + u64::from(item.length)) - start) as usize;
        out.write_all(&bytes[from..to])
            .map_err(|source| Error::Stream {
                operation: "write a file's bytes",
                source,
            })?;
    }
    Ok(())
}

/// Why this system cannot hold a name as it is, if it cannot.
///
/// A tree can hold a name that one system cannot. What is checked here is
/// what would make a name land somewhere else than it says: on another file,
/// on a device, or outside the folder.
pub fn unwritable(name: &str) -> Option<&'static str> {
    if check_name(name).is_err() {
        return Some("the format does not allow it");
    }
    if cfg!(windows) {
        return unwritable_on_windows(name);
    }
    None
}

/// Why Windows cannot hold a name as it is, if it cannot.
pub fn unwritable_on_windows(name: &str) -> Option<&'static str> {
    let forbidden = |letter: char| {
        matches!(letter, '<' | '>' | ':' | '"' | '|' | '?' | '*' | '\\' | '/') || letter < ' '
    };
    if name.chars().any(forbidden) {
        return Some("it holds a character that Windows does not allow in a name");
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Some("Windows drops a dot or a space at the end of a name");
    }
    // A device name is one whatever follows its first dot: `NUL.txt` is `NUL`.
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let stem = stem.to_ascii_uppercase();
    let numbered = |port: &str| {
        stem.strip_prefix(port).is_some_and(|number| {
            let mut letters = number.chars();
            matches!(
                (letters.next(), letters.next()),
                (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
            )
        })
    };
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || numbered("COM")
        || numbered("LPT")
    {
        return Some("Windows takes it for a device");
    }
    None
}

fn unwritable_error(name: &str, reason: &'static str) -> Error {
    Error::UnwritableName {
        name: name.chars().take(80).collect(),
        reason,
    }
}

/// The most files and folders that [`write_to_disk`] makes unless it is told
/// otherwise.
pub const DEFAULT_MAX_WRITTEN_ENTRIES: u64 = 1_000_000;

/// How far writing a tree out may go.
///
/// A tree keeps each folder once, however many places the folder has in it,
/// and writing it out makes the folder at every one of those places. So a
/// tree of a few small lists can stand for more folders than any disk
/// holds: a folder with two names for one folder, a hundred deep. Both
/// limits are held before anything is written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteOptions {
    max_entries: u64,
    max_bytes: u64,
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl WriteOptions {
    /// At most [`DEFAULT_MAX_WRITTEN_ENTRIES`] files and folders, and as many
    /// bytes as the tree has.
    pub fn new() -> Self {
        Self {
            max_entries: DEFAULT_MAX_WRITTEN_ENTRIES,
            max_bytes: u64::MAX,
        }
    }

    /// The most files and folders that may be made, the top one counted.
    pub fn max_entries(mut self, most: u64) -> Self {
        self.max_entries = most;
        self
    }

    /// The most bytes that may be written. A tree's record says how many it
    /// takes: the size of what is on top, with a file or a piece that the
    /// tree uses twice counted twice.
    pub fn max_bytes(mut self, most: u64) -> Self {
        self.max_bytes = most;
        self
    }
}

/// Writes a tree out to disk: its top folder as the new folder `dest`, or
/// its top file as the new file `dest`.
///
/// Writing is stricter than holding. `dest` must not exist. Before anything
/// is written, the whole tree is looked through: every list and every piece
/// must be there, no folder may sit too deep, every name must be one that
/// this system can hold as it is, and what would be made must fit within
/// [`WriteOptions::new`]. Every file and folder is then created as new.
/// Where two names of one folder would land on the same file, as `File` and
/// `file` do on Windows and macOS, the second one is refused, and so is a
/// name that the system keeps differently from how it was given. A name is
/// never changed to make it fit: the error says which name it was.
///
/// A tree holds no links, and every folder written into is one this call
/// created, so nothing is written outside `dest`. After an error, what was
/// written so far stays.
pub fn write_to_disk(store: &dyn Store, root: &Root, dest: impl AsRef<Path>) -> Result<()> {
    write_to_disk_with(store, root, dest, &WriteOptions::new())
}

/// Writes a tree out to disk as [`write_to_disk`] does, within other limits.
pub fn write_to_disk_with(
    store: &dyn Store,
    root: &Root,
    dest: impl AsRef<Path>,
    options: &WriteOptions,
) -> Result<()> {
    let dest = dest.as_ref();
    let top = record_of(store, root)?.top();

    // First: find everything, count what would be made, and write nothing.
    let entries = match top.kind {
        Kind::File => {
            require_pieces(store, &file_of(store, &top)?)?;
            1
        }
        Kind::Folder => survey(store, &top)?,
    };
    if entries > options.max_entries {
        return Err(Error::LimitExceeded {
            what: "the files and folders that writing the tree out makes",
            limit: options.max_entries,
            requested: entries,
        });
    }
    if top.size > options.max_bytes {
        return Err(Error::LimitExceeded {
            what: "the bytes that writing the tree out takes",
            limit: options.max_bytes,
            requested: top.size,
        });
    }
    if top.kind == Kind::File {
        // The place a caller names is the caller's.
        let out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dest)
            .map_err(|error| io_error("create the file", dest, error))?;
        return fill_file(store, &top, out, dest);
    }

    // Then: write. From here on nothing is reached by its path. The new
    // folder is held open, and so is every folder under it while it is
    // filled, so no folder on the way can be swapped for a link.
    //
    // A folder is made with its folder's other entries, and filled when its
    // turn comes. The folders on the way down to the one that is filled stay
    // open, and no others.
    let held = Held::create(dest).map_err(|error| not_made(dest, error))?;
    let mut way: Vec<ToFill> = Vec::new();
    let mut next = Some((held, top));
    loop {
        if let Some((held, folder)) = next.take() {
            let inside = fill_folder(store, &held, &folder)?;
            way.push((held, inside));
        }
        let Some((held, inside)) = way.last_mut() else {
            break;
        };
        match inside.pop() {
            Some((name, folder)) => {
                let below = held
                    .open_folder(&name)
                    .map_err(|refused| reopened(&held.path().join(&name), refused))?;
                next = Some((below, folder));
            }
            None => {
                way.pop();
            }
        }
    }
    Ok(())
}

/// A folder on the way down to the one that is filled, held open, with the
/// folders inside it that are still to be filled.
type ToFill = (Arc<Held>, Vec<(String, Target)>);

/// Fills a new folder that is held open: writes its files, makes the folders
/// inside it, and holds what it then lists against what it was given. Gives
/// the folders inside it, which are still to be filled.
fn fill_folder(
    store: &dyn Store,
    held: &Arc<Held>,
    folder: &Target,
) -> Result<Vec<(String, Target)>> {
    let list = folder_of(store, folder)?;
    let mut inside = Vec::new();
    for entry in list.entries() {
        let name = entry.name();
        let child = child_path(held.path(), name)?;
        match entry.kind() {
            Kind::File => {
                let out = held.create_file(name).map_err(|error| {
                    if taken(&child, &error) {
                        unwritable_error(name, "another name of its folder lands on the same place")
                    } else {
                        io_error("create the file", &child, error)
                    }
                })?;
                fill_file(store, &entry.target(), out, &child)?;
            }
            Kind::Folder => {
                // Made now, with the names beside it. It is opened again
                // when its turn comes, so that a folder of many folders
                // does not keep them all open.
                held.create_folder(name)
                    .map_err(|error| not_made(&child, error))?;
                inside.push((name.to_owned(), entry.target()));
            }
        }
    }
    // The folder must now hold exactly the names it was given.
    confirm_names(held, &list)?;
    Ok(inside)
}

/// Looks through a whole tree before it is written out, each folder once,
/// however many places it has. Every list and every piece must be there,
/// every name must be one this system can hold, and no folder may sit too
/// deep. Gives how many files and folders writing the tree makes, the top
/// one counted, and a folder with several places counted at each.
fn survey(store: &dyn Store, top: &Target) -> Result<u64> {
    let too_deep = || Error::TooDeep {
        limit: MAX_FOLDER_DEPTH,
    };
    // For each folder that is done: how many files and folders are below
    // it, and how many folders deep it goes, itself counted.
    let mut done: HashMap<Hash, (u64, usize)> = HashMap::new();
    let mut checked_files: HashSet<Hash> = HashSet::new();
    // The folders on the way down: each with its list, and with the place
    // of the entry that is looked at next.
    let first = folder_of(store, top)?;
    check_names(&first)?;
    let mut path: Vec<(Hash, FolderList, usize)> = vec![(top.hash, first, 0)];
    while let Some((_, list, next)) = path.last_mut() {
        let entry = list
            .entries()
            .get(*next)
            .map(|entry| (entry.kind(), entry.target()));
        *next += 1;
        match entry {
            Some((Kind::File, file)) => {
                if checked_files.insert(file.hash) {
                    require_pieces(store, &file_of(store, &file)?)?;
                }
            }
            Some((Kind::Folder, folder)) => {
                if done.contains_key(&folder.hash) {
                    continue;
                }
                if path.len() >= MAX_FOLDER_DEPTH {
                    return Err(too_deep());
                }
                let inside = folder_of(store, &folder)?;
                check_names(&inside)?;
                path.push((folder.hash, inside, 0));
            }
            None => {
                // Every entry is looked at, and every folder inside is done.
                let Some((hash, list, _)) = path.pop() else {
                    break;
                };
                let mut below = 0_u64;
                let mut deep = 1_usize;
                for entry in list.entries() {
                    below = below.saturating_add(1);
                    if entry.kind() == Kind::Folder {
                        let (inside, depth) =
                            done.get(entry.hash()).copied().ok_or(Error::Invariant {
                                detail: "a folder is counted before the folders inside it",
                            })?;
                        below = below.saturating_add(inside);
                        deep = deep.max(depth + 1);
                    }
                }
                if deep > MAX_FOLDER_DEPTH {
                    return Err(too_deep());
                }
                done.insert(hash, (below, deep));
            }
        }
    }
    let (below, _) = done.get(&top.hash).copied().ok_or(Error::Invariant {
        detail: "the top folder is not counted",
    })?;
    Ok(below.saturating_add(1))
}

/// Every name of a folder has to be one that this system can hold as it is.
fn check_names(folder: &FolderList) -> Result<()> {
    for entry in folder.entries() {
        if let Some(reason) = unwritable(entry.name()) {
            return Err(unwritable_error(entry.name(), reason));
        }
    }
    Ok(())
}

/// The path of `name` in `folder`. It has to be directly inside it.
fn child_path(folder: &Path, name: &str) -> Result<PathBuf> {
    let child = folder.join(name);
    if child.parent() != Some(folder)
        || child.file_name().and_then(|last| last.to_str()) != Some(name)
    {
        return Err(unwritable_error(
            name,
            "it would not land inside its folder",
        ));
    }
    Ok(child)
}

/// Every piece of a file has to be held, with the length its list gives it.
fn require_pieces(store: &dyn Store, list: &FileList) -> Result<()> {
    for item in list.items() {
        match store.size(Stored::Piece, &item.hash)? {
            Some(size) if size == u64::from(item.length) => {}
            Some(size) => {
                return Err(Error::SizeMismatch {
                    what: "a stored piece",
                    expected: u64::from(item.length),
                    actual: size,
                })
            }
            None => return Err(missing("the piece", &item.hash)),
        }
    }
    Ok(())
}

/// Whether something is at `path`, be it a file, a folder or a link. Systems
/// do not agree on the error they give for making a thing where another one
/// is, so the place is looked at.
fn taken(path: &Path, error: &std::io::Error) -> bool {
    error.kind() == ErrorKind::AlreadyExists || fs::symlink_metadata(path).is_ok()
}

/// Why a folder was not made at `path`.
fn not_made(path: &Path, error: std::io::Error) -> Error {
    match path.file_name().and_then(|name| name.to_str()) {
        Some(name) if taken(path, &error) => {
            unwritable_error(name, "something is there already under that name")
        }
        _ => io_error("create the folder", path, error),
    }
}

/// A folder that was made has to be that folder still when its turn comes.
fn reopened(path: &Path, refused: Refused) -> Error {
    match refused {
        Refused::Io(error) => io_error("open the folder", path, error),
        Refused::Link | Refused::Other => {
            invalid("a folder that was written was swapped for something else before it was filled")
        }
    }
}

/// Writes a file's bytes into a file that was just made. `path` is for
/// messages.
fn fill_file(store: &dyn Store, file: &Target, mut out: fs::File, path: &Path) -> Result<()> {
    read_file(store, file, &mut out).map_err(|error| match error {
        Error::Stream { source, .. } => io_error("write", path, source),
        other => other,
    })
}

/// A folder that was written must list exactly the names it was given, byte
/// for byte. Where the system changed a name, the tree was not written as it
/// is.
fn confirm_names(held: &Held, folder: &FolderList) -> Result<()> {
    let path = held.path();
    let written: HashSet<std::ffi::OsString> = held
        .list()
        .map_err(|error| io_error("list", path, error))?
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    for entry in folder.entries() {
        if !written.contains(std::ffi::OsStr::new(entry.name())) {
            return Err(unwritable_error(
                entry.name(),
                "this system keeps it under another name",
            ));
        }
    }
    if written.len() != folder.entries().len() {
        return Err(invalid(
            "a folder that was written holds a name it was not given",
        ));
    }
    Ok(())
}
