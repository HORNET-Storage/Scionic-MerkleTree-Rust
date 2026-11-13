//! Folders on disk, held open.
//!
//! A path is looked up afresh every time it is used. Whoever can write to a
//! folder on the way can swap it for a link between two uses, and send the
//! second use somewhere else. So nothing here is reached by its whole path but
//! the one place a caller names. From there on a folder is held open, and what
//! is in it is reached from the folder itself, one name at a time, and never
//! through a link.
//!
//! * On Unix a held folder is an open descriptor. What is in it is opened
//!   from that descriptor, with links refused by the system itself.
//! * On Windows a held folder is a handle that does not share deletion. The
//!   folder can be neither renamed nor replaced while it is held, and a held
//!   folder keeps the folders above it held. What is in it is opened by its
//!   path, as itself, and refused when it turns out to be a link. The path
//!   is in the form that Windows takes letter for letter, so a name is the
//!   name that was listed and no other.
//!
//! On every system a name is one name: an empty one, a dot name, or one with
//! a separator in it is refused before the system sees it.
//! * Elsewhere a held folder is its path, and no more is promised than the
//!   standard library gives.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// What a name in a folder is, without following it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Found {
    File,
    Folder,
    Link,
    Other,
}

/// Why something in a held folder was not opened.
#[derive(Debug)]
pub(crate) enum Refused {
    /// A link is there.
    Link,
    /// Something other than what was asked for is there.
    Other,
    /// The system said no.
    Io(io::Error),
}

impl From<io::Error> for Refused {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// A folder that is held open.
pub(crate) struct Held {
    path: PathBuf,
    inner: imp::Inner,
}

impl Held {
    /// Holds the folder at `path`, as the caller names it: a link on the way
    /// to it, or at its end, is the caller's.
    pub(crate) fn open(path: &Path) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            path: path.to_path_buf(),
            inner: imp::Inner::open(path)?,
        }))
    }

    /// Makes a new folder at `path`, and holds it. Anything that is there
    /// already is an error.
    pub(crate) fn create(path: &Path) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            path: path.to_path_buf(),
            inner: imp::Inner::create(path)?,
        }))
    }

    /// Where the folder was when it was opened. For messages: nothing is
    /// opened by this.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The names in the folder, and what each is. Nothing is followed.
    pub(crate) fn list(&self) -> io::Result<Vec<(OsString, Found)>> {
        self.inner.list(&self.path)
    }

    /// Holds the folder `name` in this one. A link is refused.
    pub(crate) fn open_folder(self: &Arc<Self>, name: &str) -> Result<Arc<Self>, Refused> {
        let path = self.path.join(name);
        let inner = imp::Inner::open_folder(self, one_name(name)?, &path)?;
        Ok(Arc::new(Self { path, inner }))
    }

    /// Opens the file `name` in this folder, to read. A link is refused, and
    /// so is anything that is not a plain file.
    pub(crate) fn open_file(&self, name: &str) -> Result<File, Refused> {
        self.inner.open_file(one_name(name)?, &self.path.join(name))
    }

    /// Makes the new folder `name` in this one, and holds it.
    pub(crate) fn create_folder(self: &Arc<Self>, name: &str) -> io::Result<Arc<Self>> {
        let path = self.path.join(name);
        let inner = imp::Inner::create_folder(self, one_name(name)?, &path)?;
        Ok(Arc::new(Self { path, inner }))
    }

    /// Makes the new file `name` in this folder, to write. Anything that is
    /// there already is an error, a link too.
    pub(crate) fn create_file(&self, name: &str) -> io::Result<File> {
        self.inner
            .create_file(one_name(name)?, &self.path.join(name))
    }
}

/// A name in a folder is one name. One that could lead out of the folder, or
/// to a part of a file, is refused before the system sees it: an empty name,
/// a dot name, and a name with a separator or a zero byte in it. On Windows
/// a colon too, which names a second stream of a file's bytes.
fn one_name(name: &str) -> io::Result<&OsStr> {
    let more_than_a_name = name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['/', '\0'])
        || (cfg!(windows) && name.contains(['\\', ':']));
    if more_than_a_name {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "what is opened or made in a folder is named by one name",
        ));
    }
    Ok(OsStr::new(name))
}

/// The names in the folder at `path`, by the standard library.
#[cfg(not(unix))]
fn list_by_path(path: &Path) -> io::Result<Vec<(OsString, Found)>> {
    let mut listed = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let found = if kind.is_symlink() {
            Found::Link
        } else if kind.is_dir() {
            Found::Folder
        } else if kind.is_file() {
            Found::File
        } else {
            Found::Other
        };
        listed.push((entry.file_name(), found));
    }
    Ok(listed)
}

/// Why opening `path` failed, for one that had to be `wanted`.
#[cfg(not(unix))]
fn refused_by_path(path: &Path, error: io::Error, wanted: Found) -> Refused {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Refused::Link,
        Ok(metadata) if metadata.is_dir() != (wanted == Found::Folder) => Refused::Other,
        _ => Refused::Io(error),
    }
}

#[cfg(unix)]
mod imp {
    use super::{Found, Held, Refused};
    use rustix::fs::{fstat, mkdirat, openat, statat, AtFlags, Dir, FileType, Mode, OFlags, CWD};
    use rustix::io::Errno;
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::io;
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStringExt;
    use std::path::Path;
    use std::sync::Arc;

    pub(super) struct Inner {
        fd: OwnedFd,
    }

    fn found(kind: FileType) -> Found {
        match kind {
            FileType::RegularFile => Found::File,
            FileType::Directory => Found::Folder,
            FileType::Symlink => Found::Link,
            _ => Found::Other,
        }
    }

    /// What `name` is now, without following it.
    fn look(fd: &OwnedFd, name: &OsStr) -> io::Result<Found> {
        let stat = statat(fd, name, AtFlags::SYMLINK_NOFOLLOW)?;
        Ok(found(FileType::from_raw_mode(stat.st_mode)))
    }

    /// Why an open that refuses links failed. Systems differ in the error
    /// they give for a link, so what is there is looked at.
    fn refused(fd: &OwnedFd, name: &OsStr, error: Errno, wanted: Found) -> Refused {
        match look(fd, name) {
            Ok(Found::Link) => Refused::Link,
            Ok(found) if found != wanted => Refused::Other,
            _ => Refused::Io(error.into()),
        }
    }

    fn folder_flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }

    fn all_may() -> Mode {
        Mode::RWXU | Mode::RWXG | Mode::RWXO
    }

    impl Inner {
        pub(super) fn open(path: &Path) -> io::Result<Self> {
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
            Ok(Self {
                fd: openat(CWD, path, flags, Mode::empty())?,
            })
        }

        pub(super) fn create(path: &Path) -> io::Result<Self> {
            mkdirat(CWD, path, all_may())?;
            Ok(Self {
                fd: openat(CWD, path, folder_flags(), Mode::empty())?,
            })
        }

        pub(super) fn list(&self, _path: &Path) -> io::Result<Vec<(OsString, Found)>> {
            let mut listed = Vec::new();
            for entry in Dir::read_from(&self.fd)? {
                let entry = entry?;
                let name = entry.file_name().to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                let name = OsString::from_vec(name.to_vec());
                let kind = match entry.file_type() {
                    FileType::Unknown => look(&self.fd, &name)?,
                    kind => found(kind),
                };
                listed.push((name, kind));
            }
            Ok(listed)
        }

        pub(super) fn open_folder(
            above: &Arc<Held>,
            name: &OsStr,
            _path: &Path,
        ) -> Result<Self, Refused> {
            let fd = &above.inner.fd;
            match openat(fd, name, folder_flags(), Mode::empty()) {
                Ok(fd) => Ok(Self { fd }),
                Err(error) => Err(refused(fd, name, error, Found::Folder)),
            }
        }

        pub(super) fn open_file(&self, name: &OsStr, _path: &Path) -> Result<File, Refused> {
            // Not waiting: a pipe that took the file's place would hold a
            // waiting open for ever. A plain file is read the same either way.
            let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
            let fd = match openat(&self.fd, name, flags, Mode::empty()) {
                Ok(fd) => fd,
                Err(error) => return Err(refused(&self.fd, name, error, Found::File)),
            };
            // What was opened is what is read, so it is what has to be a file.
            let stat = fstat(&fd).map_err(io::Error::from)?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
                return Err(Refused::Other);
            }
            Ok(File::from(fd))
        }

        pub(super) fn create_folder(
            above: &Arc<Held>,
            name: &OsStr,
            _path: &Path,
        ) -> io::Result<Self> {
            let fd = &above.inner.fd;
            mkdirat(fd, name, all_may())?;
            Ok(Self {
                fd: openat(fd, name, folder_flags(), Mode::empty())?,
            })
        }

        pub(super) fn create_file(&self, name: &OsStr, _path: &Path) -> io::Result<File> {
            let flags =
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let mode = Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH;
            Ok(File::from(openat(&self.fd, name, flags, mode)?))
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::{list_by_path, refused_by_path, Found, Held, Refused};
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, File, OpenOptions};
    use std::io;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Component, Path, PathBuf, Prefix};
    use std::sync::Arc;

    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    /// Opens a link as itself, and not what it leads to.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    /// Lets a folder be opened as a file is.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    /// Some part of the system stands in for what is stored here: a link, or
    /// a file that is fetched when it is read.
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    pub(super) struct Inner {
        /// The folder's path in the form that Windows takes letter for
        /// letter. Everything in the folder is reached through it.
        exact: PathBuf,
        /// Open for as long as the folder is held. It shares reading and
        /// writing and not deleting, so the folder can be neither renamed nor
        /// replaced meanwhile.
        _pin: File,
        /// The folder this one is in, held as long as this one is.
        _above: Option<Arc<Held>>,
    }

    /// `path` in the form that Windows takes letter for letter.
    ///
    /// Windows changes an ordinary path when it looks it up: a dot or a space
    /// at the end of a name is dropped, and some names are devices wherever
    /// they stand. So a file `a.` would be read as the file `a` beside it. A
    /// path that begins with `\\?\` is looked up as it is written.
    ///
    /// What the caller wrote is first read the way Windows reads it, which is
    /// what the caller means by it. The names that are added to it afterwards
    /// are the ones that a folder listed, and are taken as they are.
    fn exact(path: &Path) -> io::Result<PathBuf> {
        let whole = std::path::absolute(path)?;
        let mut parts = whole.components();
        let mut exact = OsString::from(r"\\?\");
        match parts.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                // `C:\folder` is `\\?\C:\folder`.
                Prefix::Disk(_) => exact.push(prefix.as_os_str()),
                // `\\server\share\folder` is `\\?\UNC\server\share\folder`.
                Prefix::UNC(server, share) => {
                    exact.push("UNC\\");
                    exact.push(server);
                    exact.push("\\");
                    exact.push(share);
                }
                // `\\.\C:\folder` is `\\?\C:\folder`.
                Prefix::DeviceNS(device) => exact.push(device),
                // It is in that form already.
                Prefix::Verbatim(_) | Prefix::VerbatimUNC(..) | Prefix::VerbatimDisk(_) => {
                    return Ok(whole);
                }
            },
            _ => return Ok(whole),
        }
        exact.push(parts.as_path());
        Ok(PathBuf::from(exact))
    }

    /// Opens the folder at `path` so that it stays what and where it is.
    /// Unless `follow` is set, a link is opened as itself, and refused.
    fn pin(path: &Path, follow: bool) -> Result<File, Refused> {
        let mut flags = FILE_FLAG_BACKUP_SEMANTICS;
        if !follow {
            flags |= FILE_FLAG_OPEN_REPARSE_POINT;
        }
        let pin = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(flags)
            .open(path)
            .map_err(|error| refused_by_path(path, error, Found::Folder))?;
        let metadata = pin.metadata()?;
        if metadata.file_type().is_symlink() {
            return Err(Refused::Link);
        }
        if !metadata.is_dir() {
            return Err(Refused::Other);
        }
        Ok(pin)
    }

    fn as_io(refused: Refused) -> io::Error {
        match refused {
            Refused::Io(error) => error,
            Refused::Link => io::Error::new(
                io::ErrorKind::InvalidInput,
                "a link is there, where a folder has to be",
            ),
            Refused::Other => io::Error::new(
                io::ErrorKind::InvalidInput,
                "something that is no folder is there, where a folder has to be",
            ),
        }
    }

    /// Whether two open files are one file: on the same volume, with the
    /// same number there. Where that is not to be had, nothing says that the
    /// two are one.
    pub(super) fn one_file(left: &File, right: &File) -> io::Result<bool> {
        let left = same_file::Handle::from_file(left.try_clone()?)?;
        let right = same_file::Handle::from_file(right.try_clone()?)?;
        Ok(left == right)
    }

    /// Opens `path` as itself, and says whether it is a plain file with
    /// nothing standing in for it. A link is refused, and so is a folder.
    fn open_as_itself(path: &Path, held: bool) -> Result<(File, bool), Refused> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        if held {
            options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        }
        let file = options
            .open(path)
            .map_err(|error| refused_by_path(path, error, Found::File))?;
        let metadata = file.metadata()?;
        if metadata.file_type().is_symlink() {
            return Err(Refused::Link);
        }
        if metadata.is_dir() {
            return Err(Refused::Other);
        }
        let plain = metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0;
        Ok((file, plain))
    }

    impl Inner {
        /// The exact path of `name` in this folder. The name is added as it
        /// is: nothing reads it as a path.
        fn within(&self, name: &OsStr) -> PathBuf {
            let mut path = self.exact.clone().into_os_string();
            if !path.as_encoded_bytes().ends_with(b"\\") {
                path.push("\\");
            }
            path.push(name);
            PathBuf::from(path)
        }

        pub(super) fn open(path: &Path) -> io::Result<Self> {
            let exact = exact(path)?;
            Ok(Self {
                _pin: pin(&exact, true).map_err(as_io)?,
                exact,
                _above: None,
            })
        }

        pub(super) fn create(path: &Path) -> io::Result<Self> {
            let exact = exact(path)?;
            fs::create_dir(&exact)?;
            Ok(Self {
                _pin: pin(&exact, false).map_err(as_io)?,
                exact,
                _above: None,
            })
        }

        pub(super) fn list(&self, _path: &Path) -> io::Result<Vec<(OsString, Found)>> {
            list_by_path(&self.exact)
        }

        pub(super) fn open_folder(
            above: &Arc<Held>,
            name: &OsStr,
            _path: &Path,
        ) -> Result<Self, Refused> {
            let exact = above.inner.within(name);
            Ok(Self {
                _pin: pin(&exact, false)?,
                exact,
                _above: Some(Arc::clone(above)),
            })
        }

        pub(super) fn open_file(&self, name: &OsStr, _path: &Path) -> Result<File, Refused> {
            let exact = self.within(name);
            let (file, plain) = open_as_itself(&exact, false)?;
            if plain {
                // For a plain file, opening it as itself is opening it.
                return Ok(file);
            }
            // Something stands in for this file, as for one that is fetched
            // when it is read, and opened as itself it may not read as the
            // file does. So it is held where it is, looked at again, and
            // opened in the usual way while it cannot be renamed or replaced.
            drop(file);
            let (held, _) = open_as_itself(&exact, true)?;
            let file = File::open(&exact)?;
            // Holding the file keeps its name on it. It does not keep what
            // stands in for it from being changed into a link, which the
            // usual way of opening then follows. So what was opened has to be
            // the file that is held, and not another one.
            if !one_file(&held, &file)? {
                return Err(Refused::Link);
            }
            drop(held);
            Ok(file)
        }

        pub(super) fn create_folder(
            above: &Arc<Held>,
            name: &OsStr,
            _path: &Path,
        ) -> io::Result<Self> {
            let exact = above.inner.within(name);
            fs::create_dir(&exact)?;
            Ok(Self {
                _pin: pin(&exact, false).map_err(as_io)?,
                exact,
                _above: Some(Arc::clone(above)),
            })
        }

        pub(super) fn create_file(&self, name: &OsStr, _path: &Path) -> io::Result<File> {
            // A link that is there under the name is not gone through: the
            // name is taken, and that is an error.
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(self.within(name))
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::{list_by_path, refused_by_path, Found, Held, Refused};
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, File, OpenOptions};
    use std::io;
    use std::path::Path;
    use std::sync::Arc;

    pub(super) struct Inner;

    /// What is at `path` has to be what was asked for, and no link.
    fn check(path: &Path, wanted: Found) -> Result<(), Refused> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(Refused::Link);
        }
        let is = if metadata.is_dir() {
            Found::Folder
        } else if metadata.is_file() {
            Found::File
        } else {
            Found::Other
        };
        if is == wanted {
            Ok(())
        } else {
            Err(Refused::Other)
        }
    }

    impl Inner {
        pub(super) fn open(path: &Path) -> io::Result<Self> {
            fs::read_dir(path).map(|_| Self)
        }

        pub(super) fn create(path: &Path) -> io::Result<Self> {
            fs::create_dir(path).map(|()| Self)
        }

        pub(super) fn list(&self, path: &Path) -> io::Result<Vec<(OsString, Found)>> {
            list_by_path(path)
        }

        pub(super) fn open_folder(
            _above: &Arc<Held>,
            _name: &OsStr,
            path: &Path,
        ) -> Result<Self, Refused> {
            check(path, Found::Folder).map(|()| Self)
        }

        pub(super) fn open_file(&self, _name: &OsStr, path: &Path) -> Result<File, Refused> {
            check(path, Found::File)?;
            File::open(path).map_err(|error| refused_by_path(path, error, Found::File))
        }

        pub(super) fn create_folder(
            _above: &Arc<Held>,
            _name: &OsStr,
            path: &Path,
        ) -> io::Result<Self> {
            fs::create_dir(path).map(|()| Self)
        }

        pub(super) fn create_file(&self, _name: &OsStr, path: &Path) -> io::Result<File> {
            OpenOptions::new().write(true).create_new(true).open(path)
        }
    }
}

#[cfg(test)]
mod tests;
