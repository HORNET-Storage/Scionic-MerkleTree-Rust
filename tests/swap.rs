//! A folder is not left by way of a link that takes a file's or a folder's
//! place while the folder is read, or while a tree is written into it.
//!
//! Each test plays the trick at a set moment: a store does it when the
//! library puts or asks for a certain thing, which is in the middle of the
//! work.

mod support;

use scionic_merkletree::{
    build, lookup, write_to_disk, Error, Hash, MemoryStore, PieceRef, Result, Store, Stored,
};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use support::{bytes, small_options, write, TempDir};

/// A trick, given the bytes that are being put. It says whether it was
/// played, and is then not played again.
type Trick = Box<dyn FnMut(&[u8]) -> bool + Send>;

/// A store that plays a trick in the middle of the library's work: when the
/// first piece is put, or when the thing it watches for is asked for.
struct Tricky {
    inner: MemoryStore,
    watched: Option<(Stored, Hash)>,
    trick: Mutex<Option<Trick>>,
}

impl Tricky {
    fn new(
        watched: Option<(Stored, Hash)>,
        trick: impl FnMut(&[u8]) -> bool + Send + 'static,
    ) -> Self {
        Self {
            inner: MemoryStore::new(),
            watched,
            trick: Mutex::new(Some(Box::new(trick))),
        }
    }

    fn play(&self, bytes: &[u8]) {
        let mut trick = self.trick.lock().unwrap();
        if trick.as_mut().is_some_and(|trick| trick(bytes)) {
            *trick = None;
        }
    }
}

impl Store for Tricky {
    fn put(&self, kind: Stored, hash: &Hash, bytes: &[u8]) -> Result<()> {
        if self.watched.is_none() && kind == Stored::Piece {
            self.play(bytes);
        }
        self.inner.put(kind, hash, bytes)
    }

    fn get(&self, kind: Stored, hash: &Hash) -> Result<Option<Arc<[u8]>>> {
        if self.watched == Some((kind, *hash)) {
            self.play(&[]);
        }
        self.inner.get(kind, hash)
    }

    fn remove(&self, kind: Stored, hash: &Hash) -> Result<()> {
        self.inner.remove(kind, hash)
    }
}

/// Makes a link at `link` that leads to the folder `to`, of the kind that
/// anyone may make. Says whether the system made it.
fn link_to_folder(link: &Path, to: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(to, link).is_ok()
    }
    #[cfg(windows)]
    {
        std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(to)
            .output()
            .is_ok_and(|made| made.status.success())
    }
}

/// Makes a link at `link` that leads to the file `to`. Says whether the
/// system made it: on Windows that takes a right that not every user has.
fn link_to_file(link: &Path, to: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(to, link).is_ok()
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(to, link).is_ok()
    }
}

fn holds_piece(store: &MemoryStore, bytes: &[u8]) -> bool {
    store
        .has(Stored::Piece, &PieceRef::of(bytes).unwrap().hash)
        .unwrap()
}

#[test]
fn a_folder_that_becomes_a_link_while_its_folder_is_read_is_not_entered() {
    let temp = TempDir::new("swap-folder").unwrap();
    let secret = bytes("swap-secret", 16);
    write(temp.path().join("secret/inside"), &secret).unwrap();
    let probe = temp.path().join("probe");
    if !link_to_folder(&probe, &temp.path().join("secret")) {
        return; // this system would not make such a link
    }
    fs::remove_dir(&probe)
        .or_else(|_| fs::remove_file(&probe))
        .unwrap();

    for threads in [1, 4] {
        let top = temp.path().join(format!("top-{threads}"));
        write(top.join("a-file"), &bytes("swap-a", 64)).unwrap();
        write(top.join("z-dir/inside"), &bytes("swap-mine", 16)).unwrap();
        let (dir, moved) = (top.join("z-dir"), top.join("moved"));
        let to = temp.path().join("secret");
        // When the first piece is kept, the folder is given another name,
        // and its own name is given to a link that leads to the secret.
        let store = Tricky::new(None, move |_| {
            if fs::rename(&dir, &moved).is_ok() {
                link_to_folder(&dir, &to);
            }
            true
        });
        let result = build(&store, &top, &small_options().workers(threads));
        // Whatever the timing, the secret is not in the tree.
        assert!(!holds_piece(&store.inner, &secret), "{threads} threads");
        // One thread reads the folder's files before it goes down into the
        // folders, so the link is always there when it does.
        if threads == 1 {
            assert!(
                matches!(result, Err(Error::UnsupportedEntry { .. })),
                "{result:?}"
            );
        }
    }
}

#[test]
fn a_file_that_becomes_a_link_while_its_folder_is_read_is_not_read() {
    let temp = TempDir::new("swap-file").unwrap();
    let secret = bytes("swap-secret-file", 16);
    let secret_path = temp.path().join("secret-file");
    write(&secret_path, &secret).unwrap();
    let probe = temp.path().join("probe");
    if !link_to_file(&probe, &secret_path) {
        return; // this system would not make such a link
    }
    fs::remove_file(&probe).unwrap();

    let top = temp.path().join("top");
    let (x, y) = (bytes("swap-x", 16), bytes("swap-y", 16));
    write(top.join("x"), &x).unwrap();
    write(top.join("y"), &y).unwrap();
    let (x_path, y_path) = (top.join("x"), top.join("y"));
    // Whichever file is cut first, the other one is swapped for a link to
    // the secret before its turn comes.
    let store = Tricky::new(None, move |piece| {
        let other = if piece == x.as_slice() {
            &y_path
        } else {
            &x_path
        };
        fs::remove_file(other).unwrap();
        assert!(link_to_file(other, &secret_path));
        true
    });
    let result = build(&store, &top, &small_options().workers(1));
    assert!(
        matches!(result, Err(Error::UnsupportedEntry { .. })),
        "{result:?}"
    );
    assert!(!holds_piece(&store.inner, &secret));
}

#[test]
fn nothing_is_written_through_a_link_that_takes_a_new_folders_place() {
    let temp = TempDir::new("swap-write").unwrap();
    let (inner, last) = (bytes("swap-inner", 16), bytes("swap-last", 16));
    let source = temp.path().join("source");
    write(source.join("a-file"), &bytes("swap-first", 16)).unwrap();
    write(source.join("z-dir/inner"), &inner).unwrap();
    write(source.join("zz-last"), &last).unwrap();
    let outside = temp.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    let probe = temp.path().join("probe");
    if !link_to_folder(&probe, &outside) {
        return; // this system would not make such a link
    }
    fs::remove_dir(&probe)
        .or_else(|_| fs::remove_file(&probe))
        .unwrap();

    let plain = MemoryStore::new();
    let root = build(&plain, &source, &small_options()).unwrap();
    let folder = lookup(&plain, &root, "z-dir").unwrap().unwrap().target();
    // Two moments. "held": the new folder is open and about to be filled,
    // which is when its list is asked for. "waiting": the new folder is
    // made and waits for its turn, while the file after it is written.
    for (moment, watched) in [
        ("held", (Stored::FolderList, folder.hash)),
        (
            "waiting",
            (Stored::Piece, PieceRef::of(&last).unwrap().hash),
        ),
    ] {
        let dest = temp.path().join(format!("dest-{moment}"));
        let (dir, moved, to) = (dest.join("z-dir"), dest.join("moved"), outside.clone());
        let store = Tricky::new(Some(watched), move |_| {
            if !dir.is_dir() {
                return false; // nothing of the folder is written yet
            }
            // The folder is given another name where the system lets it
            // be, and its own name is given to a link that leads outside.
            if fs::rename(&dir, &moved).is_ok() {
                link_to_folder(&dir, &to);
            }
            true
        });
        assert_eq!(
            build(&store.inner, &source, &small_options()).unwrap(),
            root
        );
        let result = write_to_disk(&store, &root, &dest);
        assert_eq!(
            fs::read_dir(&outside).unwrap().count(),
            0,
            "{moment}: something was written outside ({result:?})"
        );
        // A folder that is held is filled wherever its name has gone. One
        // that waited and is now a link is not gone into.
        match moment {
            "held" => {
                let written = [dest.join("moved/inner"), dest.join("z-dir/inner")];
                assert!(written.iter().any(|path| path.is_file()), "{result:?}");
            }
            _ => assert!(result.is_err(), "{result:?}"),
        }
    }
}
