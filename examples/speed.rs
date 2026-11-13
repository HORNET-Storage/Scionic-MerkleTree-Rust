//! How fast the parts of building and checking a tree are, on one file held
//! in memory, so that no disk is in the way.
//!
//! ```sh
//! cargo run --release --example speed -- <MiB> [folder]
//! ```
//!
//! It prints, for a file of that many MiB of bytes that look random: chunking
//! alone, hashing alone, building the file into a store in memory, and
//! checking every chunk of it again.
//!
//! With a folder, it also builds that folder from disk into a store in
//! memory, and prints the best of five runs: by then the system holds the
//! files in memory, so it is the library that is measured and not the disk.

use scionic_merkletree::{
    build, record_of, verify, BuildOptions, Builder, Chunking, ExtraData, Hash, MemoryStore, Stored,
};
use std::time::Instant;

/// Bytes that look random and cost little to make: a xorshift generator.
fn filler(length: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut bytes = Vec::with_capacity(length + 8);
    while bytes.len() < length {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(length);
    bytes
}

fn report(step: &str, started: Instant, bytes: usize) {
    let seconds = started.elapsed().as_secs_f64();
    let rate = bytes as f64 / (1 << 20) as f64 / seconds.max(1e-9);
    println!("{step:<22} {seconds:>7.3} s  {rate:>8.0} MiB/s");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let megabytes: usize = match std::env::args().nth(1) {
        Some(argument) => argument.parse()?,
        None => 1024,
    };
    let data = filler(megabytes << 20);

    let started = Instant::now();
    let chunks = Chunking::FastCdcV1.cut(&data);
    report("chunked", started, data.len());
    println!("{:<22} {} chunks", "", chunks.len());

    let started = Instant::now();
    let mut mixed = 0_u8;
    for chunk in &chunks {
        mixed ^= Hash::of(chunk).as_bytes()[0];
    }
    report("hashed", started, data.len());

    let store = MemoryStore::new();
    let started = Instant::now();
    let mut builder = Builder::new(&store, Chunking::FastCdcV1);
    let file = builder.file_from_bytes(&data)?;
    report("built", started, data.len());

    let root = builder.finish(file, ExtraData::new())?;
    let started = Instant::now();
    verify(&store, &root)?;
    report("checked", started, data.len());
    println!("root {root} ({mixed:02x})");

    if let Some(folder) = std::env::args().nth(2) {
        let mut best = f64::MAX;
        let (mut bytes, mut files) = (0, 0);
        for _ in 0..5 {
            let store = MemoryStore::new();
            let started = Instant::now();
            let root = build(&store, &folder, &BuildOptions::new())?;
            best = best.min(started.elapsed().as_secs_f64());
            bytes = record_of(&store, &root)?.top().size;
            files = store.count(Stored::FileList);
        }
        let rate = bytes as f64 / (1 << 20) as f64 / best.max(1e-9);
        println!("{:<22} {best:>7.3} s  {rate:>8.0} MiB/s", "built from disk");
        println!("{:<22} {files} different files, {bytes} bytes", "");
    }
    Ok(())
}
