#![allow(dead_code)]

pub mod json;
pub mod oracle;

use scionic_merkletree::{
    BuildOptions, Cutting, Error, Hash, MemoryStore, Peer, Responder, Result, Root, Store, Stored,
};
use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// A folder of its own under the system's temporary folder, removed again
/// when it goes out of scope.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(prefix: &str) -> io::Result<Self> {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "scionic-merkletree-rust-{}-{id}-{prefix}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Writes a file, and the folders on the way to it.
pub fn write(path: impl AsRef<Path>, data: &[u8]) -> io::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, data)
}

/// Bytes that look random and are the same on every run: block `k` is
/// `SHA-256(seed + k)`, and the blocks are joined and cut to `length`.
pub fn bytes(seed: &str, length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 32);
    let mut block: u64 = 0;
    while out.len() < length {
        let mut message = Vec::with_capacity(seed.len() + 8);
        message.extend_from_slice(seed.as_bytes());
        message.extend_from_slice(&block.to_be_bytes());
        out.extend_from_slice(Hash::of(&message).as_bytes());
        block += 1;
    }
    out.truncate(length);
    out
}

/// Cutting into pieces of 16 bytes, so that small files have many pieces.
pub fn small_pieces() -> Cutting {
    Cutting::fixed(16).unwrap()
}

pub fn small_options() -> BuildOptions {
    BuildOptions::new().cutting(small_pieces())
}

/// A folder with files of several sizes, a folder inside a folder, an empty
/// file and an empty folder. Two of its files have the same bytes.
pub fn sample_folder(parent: &Path, name: &str) -> io::Result<PathBuf> {
    let top = parent.join(name);
    write(top.join("readme.txt"), b"a small file")?;
    write(top.join("empty.bin"), b"")?;
    write(top.join("weights/model.bin"), &bytes("model", 1_000))?;
    write(
        top.join("weights/copy-of-model.bin"),
        &bytes("model", 1_000),
    )?;
    write(top.join("weights/shards/a.bin"), &bytes("shard-a", 100))?;
    write(top.join("weights/shards/b.bin"), &bytes("shard-b", 33))?;
    write(top.join("data/exactly-two-pieces.bin"), &bytes("two", 32))?;
    fs::create_dir_all(top.join("nothing-here"))?;
    Ok(top)
}

/// Everything a store holds, by kind and hash, for comparing two stores.
pub fn contents(store: &MemoryStore) -> Vec<(Stored, Hash, Vec<u8>)> {
    let mut all = Vec::new();
    for kind in [
        Stored::Piece,
        Stored::FileList,
        Stored::FolderList,
        Stored::Record,
    ] {
        for hash in store.hashes(kind) {
            let bytes = store.get(kind, &hash).unwrap().unwrap().to_vec();
            all.push((kind, hash, bytes));
        }
    }
    all
}

/// What went over the wire to one peer: every request, the longest frame
/// its asker would take in answer, and every frame of every answer.
#[derive(Default)]
pub struct Wire {
    pub requests: Vec<Vec<u8>>,
    pub limits: Vec<usize>,
    pub frames: Vec<Vec<u8>>,
}

/// Refuses a frame that is longer than its asker takes, as a connection
/// does before it reads the frame.
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

impl Wire {
    /// How many frames of one kind were sent.
    pub fn frames_of(&self, tag: u8) -> usize {
        self.frames
            .iter()
            .filter(|frame| frame.first() == Some(&tag))
            .count()
    }

    /// How many requests of one kind were asked.
    pub fn requests_of(&self, tag: u8) -> usize {
        self.requests
            .iter()
            .filter(|request| request.first() == Some(&tag))
            .count()
    }
}

/// A peer that answers from a store, as an honest one does, and lets a test
/// see and change what goes over the wire.
pub struct TestPeer<'s> {
    responder: Responder<'s>,
    pub wire: Wire,
    /// Changes the frames of an answer before the receiver sees them. It is
    /// given the request, and the frames the honest answer has.
    #[allow(clippy::type_complexity)]
    pub tamper: Option<Box<dyn FnMut(&[u8], Vec<Vec<u8>>) -> Vec<Vec<u8>> + 's>>,
}

impl<'s> TestPeer<'s> {
    pub fn new(store: &'s dyn Store) -> Self {
        Self {
            responder: Responder::new(store),
            wire: Wire::default(),
            tamper: None,
        }
    }

    pub fn tampering(
        store: &'s dyn Store,
        tamper: impl FnMut(&[u8], Vec<Vec<u8>>) -> Vec<Vec<u8>> + 's,
    ) -> Self {
        Self {
            tamper: Some(Box::new(tamper)),
            ..Self::new(store)
        }
    }
}

impl Peer for TestPeer<'_> {
    fn ask(
        &mut self,
        request: &[u8],
        limit: usize,
        on_frame: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        self.wire.requests.push(request.to_vec());
        self.wire.limits.push(limit);
        let mut frames = Vec::new();
        self.responder.answer(request, &mut |frame| {
            frames.push(frame.to_vec());
            Ok(())
        })?;
        if let Some(tamper) = &mut self.tamper {
            frames = tamper(request, frames);
        }
        for frame in frames {
            self.wire.frames.push(frame.clone());
            within(limit, &frame)?;
            on_frame(&frame)?;
        }
        Ok(())
    }
}

/// A peer that says whatever a test makes it say.
pub struct ScriptedPeer<F: FnMut(&[u8]) -> Vec<Vec<u8>>> {
    pub script: F,
}

impl<F: FnMut(&[u8]) -> Vec<Vec<u8>>> Peer for ScriptedPeer<F> {
    fn ask(
        &mut self,
        request: &[u8],
        limit: usize,
        on_frame: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        for frame in (self.script)(request) {
            within(limit, &frame)?;
            on_frame(&frame)?;
        }
        Ok(())
    }
}

/// Builds the sample folder into a new store with small pieces.
pub fn sample_tree(name: &str) -> (TempDir, MemoryStore, Root) {
    let temp = TempDir::new(name).unwrap();
    let folder = sample_folder(temp.path(), "sample").unwrap();
    let store = MemoryStore::new();
    let root = scionic_merkletree::build(&store, &folder, &small_options()).unwrap();
    (temp, store, root)
}

/// How long one end of a pipe waits for the other before it gives up. Two
/// ends that wait for each other would wait for ever, and a test that hangs
/// says nothing.
const PIPE_WAIT: Duration = Duration::from_secs(20);

struct PipeState {
    bytes: VecDeque<u8>,
    /// One of the two ends is gone.
    closed: bool,
}

struct PipeShared {
    state: Mutex<PipeState>,
    changed: Condvar,
    capacity: usize,
}

/// The end of a pipe that is written to.
pub struct PipeWriter(Arc<PipeShared>);

/// The end of a pipe that is read from.
pub struct PipeReader(Arc<PipeShared>);

/// One direction of a connection, inside one process. It holds `capacity`
/// bytes and no more: a writer waits while it is full, as a writer to a
/// real connection does, and a reader waits while it is empty. Dropping the
/// writer ends the stream.
pub fn pipe(capacity: usize) -> (PipeReader, PipeWriter) {
    let shared = Arc::new(PipeShared {
        state: Mutex::new(PipeState {
            bytes: VecDeque::new(),
            closed: false,
        }),
        changed: Condvar::new(),
        capacity,
    });
    (PipeReader(Arc::clone(&shared)), PipeWriter(shared))
}

fn stuck() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "both ends of a pipe wait for each other",
    )
}

impl io::Write for PipeWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let deadline = Instant::now() + PIPE_WAIT;
        let mut state = self.0.state.lock().unwrap();
        while state.bytes.len() >= self.0.capacity {
            if state.closed {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(stuck());
            }
            state = self.0.changed.wait_timeout(state, left).unwrap().0;
        }
        if state.closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let count = bytes.len().min(self.0.capacity - state.bytes.len());
        state.bytes.extend(&bytes[..count]);
        self.0.changed.notify_all();
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Read for PipeReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let deadline = Instant::now() + PIPE_WAIT;
        let mut state = self.0.state.lock().unwrap();
        while state.bytes.is_empty() {
            if state.closed {
                return Ok(0);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(stuck());
            }
            state = self.0.changed.wait_timeout(state, left).unwrap().0;
        }
        let count = out.len().min(state.bytes.len());
        for (slot, byte) in out.iter_mut().zip(state.bytes.drain(..count)) {
            *slot = byte;
        }
        self.0.changed.notify_all();
        Ok(count)
    }
}

fn close(shared: &PipeShared) {
    shared.state.lock().unwrap().closed = true;
    shared.changed.notify_all();
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        close(&self.0);
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        close(&self.0);
    }
}
