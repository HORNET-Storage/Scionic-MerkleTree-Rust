//! Reading a tree that a store holds: finding a path, reading a file or a
//! stretch of it, and writing the tree out to disk.
//!
//! Everything read from the store is checked again before it is used: a list
//! against the hash it was asked for by, and a piece against the hash and the
//! length its file gives it. A file's bytes are handed out only when every
//! piece they need is there. Otherwise it is an error, never a shorter file.

use crate::format::{
    check_name, Entry, FileList, FolderList, Kind, Record, Target, MAX_FOLDER_DEPTH,
};
use crate::hash::Root;
use crate::store::{load_file, load_folder, load_piece, load_record, missing, Store, Stored};
use crate::{io_error, Error, Result};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

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
    for (item, _) in &wanted {
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
        let bytes = load_piece(store, &item)?.ok_or_else(|| missing("the piece", &item.hash))?;
        let from = offset.saturating_sub(start) as usize;
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

/// What writing a tree out needs to know of it before anything is written.
struct Planned {
    folder: FolderList,
    path: PathBuf,
}

/// Writes a tree out to disk: its top folder as the new folder `dest`, or
/// its top file as the new file `dest`.
///
/// Writing is stricter than holding. `dest` must not exist. Before anything
/// is written, the whole tree is looked through: every list and every piece
/// must be there, and every name must be one that this system can hold as
/// it is. Every file and folder is then created as new. Where two names of
/// one folder would land on the same file, as `File` and `file` do on
/// Windows and macOS, the second one is refused, and so is a name that the
/// system keeps differently from how it was given. A name is never changed
/// to make it fit: the error says which name it was.
///
/// A tree holds no links, and every folder written into is one this call
/// created, so nothing is written outside `dest`. After an error, what was
/// written so far stays.
pub fn write_to_disk(store: &dyn Store, root: &Root, dest: impl AsRef<Path>) -> Result<()> {
    let dest = dest.as_ref();
    let top = record_of(store, root)?.top();
    if top.kind == Kind::File {
        require_pieces(store, &file_of(store, &top)?)?;
        return write_file(store, &top, dest, None);
    }

    // First pass: find everything, and write nothing.
    let mut planned: Vec<Planned> = Vec::new();
    let mut pending = vec![(top, dest.to_path_buf(), 1_usize)];
    let mut checked_files = std::collections::HashSet::new();
    while let Some((folder, path, depth)) = pending.pop() {
        if depth > MAX_FOLDER_DEPTH {
            return Err(Error::TooDeep {
                limit: MAX_FOLDER_DEPTH,
            });
        }
        let list = folder_of(store, &folder)?;
        for entry in list.entries() {
            if let Some(reason) = unwritable(entry.name()) {
                return Err(unwritable_error(entry.name(), reason));
            }
            let child = child_path(&path, entry.name())?;
            match entry.kind() {
                Kind::Folder => pending.push((entry.target(), child, depth + 1)),
                Kind::File => {
                    if checked_files.insert(*entry.hash()) {
                        require_pieces(store, &file_of(store, &entry.target())?)?;
                    }
                }
            }
        }
        planned.push(Planned { folder: list, path });
    }

    // Second pass: write. A folder is planned after the folder it is in, so
    // going forwards every folder exists before anything is put into it.
    for Planned { folder, path } in &planned {
        create_new_dir(path)?;
        for entry in folder.entries() {
            if entry.kind() == Kind::File {
                let child = child_path(path, entry.name())?;
                write_file(store, &entry.target(), &child, Some(entry.name()))?;
            }
        }
    }
    // Last: every folder must hold exactly the names it was given.
    for Planned { folder, path } in &planned {
        confirm_names(path, folder)?;
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

fn create_new_dir(path: &Path) -> Result<()> {
    fs::create_dir(path).map_err(|error| {
        if error.kind() == ErrorKind::AlreadyExists {
            match path.file_name().and_then(|name| name.to_str()) {
                Some(name) => unwritable_error(name, "something is there already under that name"),
                None => io_error("create the folder", path, error),
            }
        } else {
            io_error("create the folder", path, error)
        }
    })
}

fn write_file(store: &dyn Store, file: &Target, path: &Path, name: Option<&str>) -> Result<()> {
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| match name {
            Some(name) if error.kind() == ErrorKind::AlreadyExists => {
                unwritable_error(name, "another name of its folder lands on the same file")
            }
            _ => io_error("create the file", path, error),
        })?;
    read_file(store, file, &mut out).map_err(|error| match error {
        Error::Stream { source, .. } => io_error("write", path, source),
        other => other,
    })
}

/// A folder that was written must list exactly the names it was given, byte
/// for byte. Where the system changed a name, the tree was not written as it
/// is.
fn confirm_names(path: &Path, folder: &FolderList) -> Result<()> {
    let mut written = std::collections::HashSet::with_capacity(folder.entries().len());
    for entry in fs::read_dir(path).map_err(|error| io_error("list", path, error))? {
        let entry = entry.map_err(|error| io_error("list", path, error))?;
        written.insert(entry.file_name());
    }
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
