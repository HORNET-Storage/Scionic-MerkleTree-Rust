//! What changed between two trees.
//!
//! Two trees are compared folder by folder. Where both have the same hash
//! under a name, everything below it is the same, and nothing below it is
//! read.

use crate::format::{Entry, Kind, Target, MAX_FOLDER_DEPTH};
use crate::hash::Root;
use crate::read::{folder_of, record_of};
use crate::store::Store;
use crate::{Error, Result};
use std::cmp::Ordering;

/// One difference between an old tree and a new one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Change {
    /// The new tree has this entry, and the old one has nothing there. A
    /// folder that was added is one change: what is in it is not listed.
    Added { path: String, entry: Entry },
    /// The old tree has this entry, and the new one has nothing there.
    Removed { path: String, entry: Entry },
    /// Both trees have an entry here, and it differs: a file's bytes, or an
    /// entry's extra data. A folder is listed here only for its extra data.
    /// What differs inside it is listed by its own path.
    Changed {
        path: String,
        old: Entry,
        new: Entry,
    },
}

impl Change {
    /// Where in the tree the change is: names with `/` between them.
    pub fn path(&self) -> &str {
        match self {
            Self::Added { path, .. } | Self::Removed { path, .. } | Self::Changed { path, .. } => {
                path
            }
        }
    }
}

/// The differences between two trees that a store holds, sorted by path.
/// Both trees must have a folder on top, or be the same tree.
pub fn diff(store: &dyn Store, old: &Root, new: &Root) -> Result<Vec<Change>> {
    let old_top = record_of(store, old)?.top();
    let new_top = record_of(store, new)?.top();
    if old_top == new_top {
        return Ok(Vec::new());
    }
    if old_top.kind != Kind::Folder || new_top.kind != Kind::Folder {
        return Err(Error::InvalidData {
            detail: "a tree with a file on top has no entries to compare".to_owned(),
        });
    }
    let mut changes = Vec::new();
    let mut pending: Vec<(Target, Target, String, usize)> =
        vec![(old_top, new_top, String::new(), 1)];
    while let Some((old_folder, new_folder, prefix, depth)) = pending.pop() {
        if depth > MAX_FOLDER_DEPTH {
            return Err(Error::TooDeep {
                limit: MAX_FOLDER_DEPTH,
            });
        }
        let old_list = folder_of(store, &old_folder)?;
        let new_list = folder_of(store, &new_folder)?;
        let (olds, news) = (old_list.entries(), new_list.entries());
        let (mut left, mut right) = (0, 0);
        let at = |name: &str| format!("{prefix}{name}");
        loop {
            let order = match (olds.get(left), news.get(right)) {
                (Some(old), Some(new)) => old.name().as_bytes().cmp(new.name().as_bytes()),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => break,
            };
            match order {
                Ordering::Less => {
                    changes.push(Change::Removed {
                        path: at(olds[left].name()),
                        entry: olds[left].clone(),
                    });
                    left += 1;
                }
                Ordering::Greater => {
                    changes.push(Change::Added {
                        path: at(news[right].name()),
                        entry: news[right].clone(),
                    });
                    right += 1;
                }
                Ordering::Equal => {
                    let (old, new) = (&olds[left], &news[right]);
                    let path = at(old.name());
                    if old.kind() != new.kind() {
                        changes.push(Change::Removed {
                            path: path.clone(),
                            entry: old.clone(),
                        });
                        changes.push(Change::Added {
                            path,
                            entry: new.clone(),
                        });
                    } else if old.kind() == Kind::File {
                        if old != new {
                            changes.push(Change::Changed {
                                path,
                                old: old.clone(),
                                new: new.clone(),
                            });
                        }
                    } else {
                        if old.hash() != new.hash() {
                            pending.push((
                                old.target(),
                                new.target(),
                                format!("{path}/"),
                                depth + 1,
                            ));
                        }
                        if old.extra() != new.extra() {
                            changes.push(Change::Changed {
                                path,
                                old: old.clone(),
                                new: new.clone(),
                            });
                        }
                    }
                    left += 1;
                    right += 1;
                }
            }
        }
    }
    changes.sort_by(|left, right| left.path().cmp(right.path()));
    Ok(changes)
}
