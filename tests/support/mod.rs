#![allow(dead_code)]

use scionic_merkletree::{DagBuildOptions, Result};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

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

pub fn options_4096() -> DagBuildOptions {
    DagBuildOptions::default().with_chunk_size(4096).unwrap()
}

pub fn write(path: impl AsRef<Path>, data: &[u8]) -> io::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, data)
}

pub fn alpha_data(size: usize) -> Vec<u8> {
    (0..size).map(|index| b'A' + (index % 26) as u8).collect()
}

pub fn create_fixture(parent: &Path, name: &str) -> io::Result<PathBuf> {
    let root = parent.join(name);
    fs::create_dir(&root)?;
    match name {
        "single_small_file" => {
            write(root.join("small.txt"), &alpha_data(1024))?;
        }
        "single_large_file" => {
            write(root.join("large.txt"), &alpha_data(10 * 1024))?;
        }
        "flat_directory" => {
            for (name, size) in [
                ("file1.txt", 512),
                ("file2.txt", 1024),
                ("file3.txt", 768),
                ("file4.txt", 2048),
                ("file5.txt", 256),
            ] {
                write(root.join(name), &alpha_data(size))?;
            }
        }
        "nested_directory" => {
            for directory in ["subdir1", "subdir2"] {
                for (index, suffix) in ["a", "b"].into_iter().enumerate() {
                    let prefix = if directory == "subdir1" {
                        "file1"
                    } else {
                        "file2"
                    };
                    write(
                        root.join(directory).join(format!("{prefix}{suffix}.txt")),
                        &alpha_data(1024 + index * 512),
                    )?;
                }
            }
        }
        "deep_hierarchy" => {
            let deep = root
                .join("level1")
                .join("level2")
                .join("level3")
                .join("level4")
                .join("level5");
            fs::create_dir_all(&deep)?;
            let mut level = root.clone();
            for index in 1..=5 {
                level = level.join(format!("level{index}"));
                write(
                    level.join(format!("file_at_level_{index}.txt")),
                    &alpha_data(index * 256),
                )?;
            }
        }
        "mixed_sizes" => {
            for (name, size) in [
                ("tiny.txt", 128),
                ("small.txt", 2048),
                ("medium.txt", 5 * 1024),
                ("large.txt", 15 * 1024),
                ("exact_chunk.txt", 4 * 1024),
            ] {
                write(root.join(name), &alpha_data(size))?;
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown fixture",
            ))
        }
    }
    Ok(root)
}

pub struct ExpectedFixture {
    pub name: &'static str,
    pub root: &'static str,
    pub leaves: usize,
    pub chunks: usize,
    pub content_size: u64,
    pub dag_size: u64,
}

pub const FIXTURES: &[ExpectedFixture] = &[
    ExpectedFixture {
        name: "single_small_file",
        root: "bafireiabahlly4rktdhsvhzgd2prjurwuupjo5shdsefkpayhfqefhcvpe",
        leaves: 2,
        chunks: 0,
        content_size: 1024,
        dag_size: 1467,
    },
    ExpectedFixture {
        name: "single_large_file",
        root: "bafireiel7coatk47jhcsatc4xdjxx3jx7fdqteplhtlxb7y27bzwnstvwy",
        leaves: 5,
        chunks: 3,
        content_size: 10_240,
        dag_size: 11_581,
    },
    ExpectedFixture {
        name: "flat_directory",
        root: "bafireigd6awocke3nmagbspbkv2rfiqqai455eimle27u36ljeytyqdb4u",
        leaves: 6,
        chunks: 0,
        content_size: 4608,
        dag_size: 6005,
    },
    ExpectedFixture {
        name: "nested_directory",
        root: "bafireiekzu7qss4gcgk3ochl3ehk3ee3rmsqjdh7bin4twzdhkgsfw2kme",
        leaves: 7,
        chunks: 0,
        content_size: 5120,
        dag_size: 7015,
    },
    ExpectedFixture {
        name: "deep_hierarchy",
        root: "bafireifzuzba5kihvbxfl5ygrse5pca6aamzumemmrjm32yyl5j4cjdj3u",
        leaves: 11,
        chunks: 0,
        content_size: 3840,
        dag_size: 7120,
    },
    ExpectedFixture {
        name: "mixed_sizes",
        root: "bafireibrvfd6b3unpr27mq72pdsksj26y6hq32ahjmy6i7omfresfleloq",
        leaves: 11,
        chunks: 5,
        content_size: 22_656,
        dag_size: 25_612,
    },
];

pub fn _result_type_marker(_: Result<()>) {}
