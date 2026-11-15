//! A tree's whole way round, with a store on disk.
//!
//! Builds a tree from a folder, checks it, fetches it into a second store as
//! a receiver would, reads stretches of its largest file without the rest,
//! writes the tree out again, and holds the copy to the same root. It prints
//! how long each step took.
//!
//! ```sh
//! cargo run --release --example roundtrip -- <folder> <work-dir>
//! ```
//!
//! `<work-dir>` must not exist. The stores and the copy are made in it.
//!
//! The store here keeps each thing as a file named by its hash. It is the
//! smallest store that does not hold a tree in memory, and it shows what a
//! store has to do: keep bytes under a hash, and give them back.

use scionic_merkletree::{
    build, fetch, folder_of, record_of, verify, write_to_disk, BuildOptions, Error, Hash, Kind,
    Remote, Responder, Result, Store, Stored, Target,
};
use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

struct DirStore {
    dir: PathBuf,
    /// Numbers the files that are being written, so that two writers of the
    /// same thing do not write to the same file.
    writing: AtomicU64,
}

fn failed(operation: &'static str, path: &Path, source: std::io::Error) -> Error {
    Error::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

impl DirStore {
    fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            writing: AtomicU64::new(0),
        }
    }

    fn path(&self, kind: Stored, hash: &Hash) -> PathBuf {
        let kind = match kind {
            Stored::Chunk => "chunks",
            Stored::FileList => "files",
            Stored::FolderList => "folders",
            Stored::Record => "records",
        };
        let name = hash.to_hex();
        self.dir.join(kind).join(&name[..2]).join(name)
    }
}

impl Store for DirStore {
    fn put(&self, kind: Stored, hash: &Hash, bytes: &[u8]) -> Result<()> {
        let path = self.path(kind, hash);
        if path.exists() {
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| failed("create", parent, error))?;
        }
        // Written under another name first, so that a file is never found
        // under a hash before all of its bytes are there.
        let number = self.writing.fetch_add(1, Ordering::Relaxed);
        let unfinished = path.with_extension(format!("writing-{number}"));
        fs::write(&unfinished, bytes).map_err(|error| failed("write", &unfinished, error))?;
        match fs::rename(&unfinished, &path) {
            Ok(()) => Ok(()),
            // Another writer was first, with the same bytes.
            Err(_) if path.exists() => {
                let _ = fs::remove_file(&unfinished);
                Ok(())
            }
            Err(error) => Err(failed("keep", &path, error)),
        }
    }

    fn get(&self, kind: Stored, hash: &Hash) -> Result<Option<Arc<[u8]>>> {
        let path = self.path(kind, hash);
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(failed("open", &path, error)),
        };
        let length = file
            .metadata()
            .map_err(|error| failed("look at", &path, error))?
            .len();
        let length = usize::try_from(length).map_err(|_| {
            let too_long = std::io::Error::other("it is longer than this machine can hold");
            failed("read", &path, too_long)
        })?;
        // The bytes are read straight into the memory that is handed out. A
        // `Vec` that is turned into an `Arc` is copied once more, and a chunk
        // is megabytes long.
        let mut bytes: Arc<[u8]> = std::iter::repeat_n(0, length).collect();
        let room = Arc::get_mut(&mut bytes).expect("nothing else holds what was just made");
        file.read_exact(room)
            .map_err(|error| failed("read", &path, error))?;
        Ok(Some(bytes))
    }

    fn size(&self, kind: Stored, hash: &Hash) -> Result<Option<u64>> {
        let path = self.path(kind, hash);
        match fs::metadata(&path) {
            Ok(metadata) => Ok(Some(metadata.len())),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(failed("look at", &path, error)),
        }
    }

    fn remove(&self, kind: Stored, hash: &Hash) -> Result<()> {
        let path = self.path(kind, hash);
        match fs::remove_file(&path) {
            Err(error) if error.kind() != ErrorKind::NotFound => {
                Err(failed("remove", &path, error))
            }
            _ => Ok(()),
        }
    }
}

/// The largest file of a tree, each folder looked into once.
fn largest_file(store: &dyn Store, top: Target) -> Result<Option<Target>> {
    let mut largest: Option<Target> = None;
    let mut seen = std::collections::HashSet::new();
    let mut pending = vec![top];
    while let Some(target) = pending.pop() {
        match target.kind {
            Kind::File if largest.is_none_or(|file| file.size < target.size) => {
                largest = Some(target);
            }
            Kind::File => {}
            Kind::Folder if seen.insert(target.hash) => {
                let list = folder_of(store, &target)?;
                pending.extend(list.entries().iter().map(|entry| entry.target()));
            }
            Kind::Folder => {}
        }
    }
    Ok(largest)
}

fn report(step: &str, started: Instant, bytes: u64) {
    let seconds = started.elapsed().as_secs_f64();
    let rate = bytes as f64 / (1 << 20) as f64 / seconds.max(1e-9);
    println!("{step:<12} {seconds:>8.2} s  {rate:>8.0} MiB/s");
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let (Some(folder), Some(work)) = (arguments.next(), arguments.next()) else {
        eprintln!("usage: roundtrip <folder> <work-dir>");
        std::process::exit(2);
    };
    let work = PathBuf::from(work);
    fs::create_dir(&work)?;

    let source = DirStore::new(work.join("source-store"));
    let started = Instant::now();
    let root = build(&source, &folder, &BuildOptions::new())?;
    let record = record_of(&source, &root)?;
    let (size, totals) = (record.top().size, record.totals());
    report("built", started, size);
    println!("root         {root}");
    println!(
        "the tree     {size} bytes; kept once: {} chunks of {} bytes, and {} bytes of lists",
        totals.chunks, totals.chunk_bytes, totals.list_bytes
    );

    let started = Instant::now();
    let summary = verify(&source, &root)?;
    report("checked", started, totals.chunk_bytes);
    println!(
        "             {} different files in {} different folders",
        summary.files, summary.folders
    );

    let fetched = DirStore::new(work.join("fetched-store"));
    let started = Instant::now();
    fetch(&fetched, &root, &mut Responder::new(&source))?;
    report("fetched", started, totals.chunk_bytes);

    if let Some(file) = largest_file(&source, record.top())? {
        // A stretch of 4 KiB is read from 64 places spread over the file, each
        // asked for on its own, and the time one takes on average is printed:
        // a single read is shorter than some systems' clocks can tell apart.
        let length = file.size.min(4096);
        let places: u64 = 64;
        let mut holder = Responder::new(&source);
        let mut remote = Remote::open(&mut holder, &root)?;
        let mut stretch = Vec::new();
        let started = Instant::now();
        for place in 0..places {
            stretch.clear();
            let offset = (file.size - length) * place / (places - 1);
            remote.read(&file, offset, length, &mut stretch)?;
        }
        println!(
            "a stretch    {:>8.4} s  {} bytes at a time, from {places} places in a file of {} bytes",
            started.elapsed().as_secs_f64() / places as f64,
            stretch.len(),
            file.size
        );
    }

    let written = work.join("written");
    let started = Instant::now();
    write_to_disk(&fetched, &root, &written)?;
    report("written out", started, size);

    let again = DirStore::new(work.join("again-store"));
    let started = Instant::now();
    let rebuilt = build(&again, &written, &BuildOptions::new())?;
    report("built again", started, size);
    if rebuilt != root {
        return Err(format!("the copy has the root {rebuilt}, and not {root}").into());
    }
    println!("the copy has the same root");
    Ok(())
}
