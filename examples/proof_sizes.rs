//! How small a Merkle branch is beside the list it stands in for.
//!
//! ```sh
//! cargo run --release --example proof_sizes
//! ```
//!
//! In a Merkle DAG, checking one child of a parent takes the parent's whole
//! list of hashes. Here a parent's list is a Merkle tree of its own, so one
//! child is checked with a branch of it. This prints both sizes, in bytes on
//! the wire, for folders of ten to a million entries and for files of ten to
//! half a million chunks. A file of half a million chunks is about a terabyte.

use scionic_merkletree::{
    Builder, Cutting, Entry, ExtraData, MemoryStore, Request, Responder, Result, Store, Stored,
};

/// How many bytes a store's holder answers a request with.
fn answer_bytes(store: &MemoryStore, request: &Request) -> Result<usize> {
    let mut bytes = 0;
    Responder::new(store).answer(&request.encode(), &mut |frame| {
        bytes += frame.len();
        Ok(())
    })?;
    Ok(bytes)
}

fn row(count: usize, list: usize, branch: usize) {
    let smaller = list as f64 / branch as f64;
    println!("{count:>10}  {list:>12}  {branch:>8}  {smaller:>9.0}x");
}

fn main() -> Result<()> {
    println!("One entry of a folder, by its name. Names are 16 bytes long.");
    println!(
        "{:>10}  {:>12}  {:>8}  {:>10}",
        "entries", "whole list", "branch", "smaller by"
    );
    for count in [10_usize, 1_000, 10_000, 1_000_000] {
        let store = MemoryStore::new();
        let mut builder = Builder::new(&store, Cutting::fixed(16)?);
        let file = builder.file_from_bytes(b"the same small file")?;
        let entries = (0..count)
            .map(|number| Entry::new(format!("file-{number:07}.bin"), file, ExtraData::new()))
            .collect::<Result<Vec<_>>>()?;
        let folder = builder.folder(entries)?;
        let list = store
            .get(Stored::FolderList, &folder.hash)?
            .map_or(0, |list| list.len());
        let request = Request::FolderName {
            folder: folder.hash,
            name: format!("file-{:07}.bin", count / 2),
        };
        row(count, list, answer_bytes(&store, &request)?);
    }

    println!();
    println!("One chunk of a file, by its number.");
    println!(
        "{:>10}  {:>12}  {:>8}  {:>10}",
        "chunks", "whole list", "branch", "smaller by"
    );
    for count in [10_usize, 1_000, 10_000, 500_000] {
        // Chunks of one byte, so that a file of many chunks is small.
        let store = MemoryStore::new();
        let mut builder = Builder::new(&store, Cutting::fixed(1)?);
        let bytes: Vec<u8> = (0..count).map(|at| (at % 251) as u8).collect();
        let file = builder.file_from_bytes(&bytes)?;
        let list = store
            .get(Stored::FileList, &file.hash)?
            .map_or(0, |list| list.len());
        let request = Request::FileRun {
            file: file.hash,
            start: (count / 2) as u64,
            count: 1,
        };
        row(count, list, answer_bytes(&store, &request)?);
    }
    Ok(())
}
