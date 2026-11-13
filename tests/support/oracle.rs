//! The format, written a second time and as plainly as it can be.
//!
//! Nothing here is shared with the library but SHA-256. Each function is the
//! rule as `spec/FORMAT.md` states it, with no shortcut: a tree is hashed by
//! halving, a branch is found by walking. It does two jobs. It says what
//! the library's hashes have to be, from another hand. And it forges: it
//! hashes lists that the library refuses to make, such as a folder that is
//! out of order on purpose, the way an author with code of his own could.

use scionic_merkletree::Hash;

pub type H = [u8; 32];

pub fn sha(parts: &[&[u8]]) -> H {
    *Hash::of(&parts.concat()).as_bytes()
}

/// One item of a file's list.
#[derive(Clone, Debug)]
pub struct Item {
    pub hash: H,
    pub length: u32,
}

impl Item {
    pub fn of(bytes: &[u8]) -> Self {
        Self {
            hash: sha(&[bytes]),
            length: bytes.len() as u32,
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        [&self.hash[..], &self.length.to_be_bytes()].concat()
    }
}

/// One entry of a folder's list.
#[derive(Clone, Debug)]
pub struct Entry {
    /// 1 for a file, 2 for a folder.
    pub kind: u8,
    pub size: u64,
    pub hash: H,
    pub name: Vec<u8>,
    /// Named values, in the order they are to be written.
    pub extra: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Entry {
    pub fn file(name: &str, hash: H, size: u64) -> Self {
        Self {
            kind: 1,
            size,
            hash,
            name: name.as_bytes().to_vec(),
            extra: Vec::new(),
        }
    }

    pub fn folder(name: &str, hash: H, size: u64) -> Self {
        Self {
            kind: 2,
            ..Self::file(name, hash, size)
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut out = vec![self.kind];
        out.extend_from_slice(&self.size.to_be_bytes());
        out.extend_from_slice(&self.hash);
        out.extend_from_slice(&(self.name.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.name);
        out.extend_from_slice(&extra_bytes(&self.extra));
        out
    }
}

pub fn extra_bytes(extra: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = (extra.len() as u16).to_be_bytes().to_vec();
    for (name, value) in extra {
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
    }
    out
}

/// A node of a list's tree: its hash, and the bytes of content under it.
pub type Node = (H, u64);

/// A list as its tree sees it: a leaf for each item, and for a folder each
/// entry's name.
#[derive(Clone, Debug)]
pub struct Leaves {
    /// 0x01 for a file's tree, 0x03 for a folder's.
    pub fork_mark: u8,
    pub nodes: Vec<Node>,
    pub names: Vec<Vec<u8>>,
}

pub fn file_leaves(items: &[Item]) -> Leaves {
    Leaves {
        fork_mark: 0x01,
        nodes: items
            .iter()
            .map(|item| (sha(&[&[0x00], &item.bytes()]), u64::from(item.length)))
            .collect(),
        names: Vec::new(),
    }
}

pub fn folder_leaves(entries: &[Entry]) -> Leaves {
    Leaves {
        fork_mark: 0x03,
        nodes: entries
            .iter()
            .map(|entry| (sha(&[&[0x02], &entry.bytes()]), entry.size))
            .collect(),
        names: entries.iter().map(|entry| entry.name.clone()).collect(),
    }
}

/// The largest power of two that is less than `width`.
fn left_half(width: usize) -> usize {
    let mut half = 1;
    while half * 2 < width {
        half *= 2;
    }
    half
}

impl Leaves {
    fn first_name(&self, offset: usize) -> &[u8] {
        if self.fork_mark == 0x03 {
            &self.names[offset]
        } else {
            &[]
        }
    }

    /// The node over the `width` items from `offset`, by the rule.
    pub fn node(&self, offset: usize, width: usize) -> Node {
        if width == 1 {
            return self.nodes[offset];
        }
        let half = left_half(width);
        let left = self.node(offset, half);
        let right = self.node(offset + half, width - half);
        fork(
            self.fork_mark,
            left,
            half as u64,
            right,
            (width - half) as u64,
            self.first_name(offset + half),
        )
    }

    /// The node on top of the list. An empty list has 32 zero bytes.
    pub fn top(&self) -> Node {
        if self.nodes.is_empty() {
            ([0; 32], 0)
        } else {
            self.node(0, self.nodes.len())
        }
    }

    /// The nodes to carry when items `start` up to `end` are shown: one for
    /// each branch that is left out, in the order a checker meets them, each
    /// with the first name under it. The node that begins the list has no
    /// name: it is in no right half, so no fork hashes one for it.
    pub fn carried(&self, start: usize, end: usize) -> Vec<(Node, Vec<u8>)> {
        let mut out = Vec::new();
        self.collect(0, self.nodes.len(), start, end, &mut out);
        out
    }

    fn collect(
        &self,
        offset: usize,
        width: usize,
        start: usize,
        end: usize,
        out: &mut Vec<(Node, Vec<u8>)>,
    ) {
        if offset + width <= start || end <= offset {
            let name = if offset == 0 {
                Vec::new()
            } else {
                self.first_name(offset).to_vec()
            };
            out.push((self.node(offset, width), name));
        } else if width > 1 {
            let half = left_half(width);
            self.collect(offset, half, start, end, out);
            self.collect(offset + half, width - half, start, end, out);
        }
    }
}

pub fn fork(
    mark: u8,
    left: Node,
    left_items: u64,
    right: Node,
    right_items: u64,
    name: &[u8],
) -> Node {
    let hash = sha(&[
        &[mark],
        &left.0,
        &left.1.to_be_bytes(),
        &left_items.to_be_bytes(),
        &right.0,
        &right.1.to_be_bytes(),
        &right_items.to_be_bytes(),
        if mark == 0x03 { name } else { &[] },
    ]);
    (hash, left.1 + right.1)
}

/// A file's hash and size, from its list.
pub fn file_hash(items: &[Item]) -> Node {
    let top = file_leaves(items).top();
    let hash = sha(&[
        &[0x10],
        &(items.len() as u64).to_be_bytes(),
        &top.1.to_be_bytes(),
        &top.0,
    ]);
    (hash, top.1)
}

/// A folder's hash and size, from its list as it is given: nothing is
/// sorted, and nothing is checked.
pub fn folder_hash(entries: &[Entry]) -> Node {
    let top = folder_leaves(entries).top();
    let hash = sha(&[
        &[0x11],
        &(entries.len() as u64).to_be_bytes(),
        &top.1.to_be_bytes(),
        &top.0,
    ]);
    (hash, top.1)
}

pub fn file_list_bytes(items: &[Item]) -> Vec<u8> {
    items.iter().flat_map(Item::bytes).collect()
}

pub fn folder_list_bytes(entries: &[Entry]) -> Vec<u8> {
    entries.iter().flat_map(Entry::bytes).collect()
}

/// A record's bytes. Its hash is the root.
pub fn record_bytes(
    kind: u8,
    size: u64,
    hash: &H,
    totals: (u64, u64, u64),
    extra: &[(Vec<u8>, Vec<u8>)],
) -> Vec<u8> {
    let mut out = vec![0x20, kind];
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(hash);
    out.extend_from_slice(&totals.0.to_be_bytes());
    out.extend_from_slice(&totals.1.to_be_bytes());
    out.extend_from_slice(&totals.2.to_be_bytes());
    out.extend_from_slice(&extra_bytes(extra));
    out
}

/// The extra data of a record that says only how the tree was chunked.
pub fn chunking_tag(tag: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![(b"chunking".to_vec(), tag.as_bytes().to_vec())]
}

/// The frame that shows items `start` up to `end` of a file's list.
pub fn file_branch_frame(items: &[Item], start: usize, end: usize) -> Vec<u8> {
    file_branch_frame_as(items.len() as u64, start as u64, &items[start..end], &{
        file_leaves(items).carried(start, end)
    })
}

/// A file-branch frame from its parts, whatever they say.
pub fn file_branch_frame_as(
    count: u64,
    start: u64,
    shown: &[Item],
    carried: &[(Node, Vec<u8>)],
) -> Vec<u8> {
    let mut out = vec![0x23];
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&start.to_be_bytes());
    out.extend_from_slice(&(shown.len() as u32).to_be_bytes());
    out.extend_from_slice(&file_list_bytes(shown));
    out.extend_from_slice(&(carried.len() as u16).to_be_bytes());
    for (node, _) in carried {
        out.extend_from_slice(&node.0);
        out.extend_from_slice(&node.1.to_be_bytes());
    }
    out
}

/// The frame that shows entries `start` up to `end` of a folder's list.
pub fn folder_branch_frame(entries: &[Entry], start: usize, end: usize) -> Vec<u8> {
    folder_branch_frame_as(
        entries.len() as u64,
        start as u64,
        &entries[start..end],
        &folder_leaves(entries).carried(start, end),
    )
}

/// A folder-branch frame from its parts, whatever they say.
pub fn folder_branch_frame_as(
    count: u64,
    start: u64,
    shown: &[Entry],
    carried: &[(Node, Vec<u8>)],
) -> Vec<u8> {
    let mut out = vec![0x24];
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&start.to_be_bytes());
    out.extend_from_slice(&(shown.len() as u32).to_be_bytes());
    out.extend_from_slice(&folder_list_bytes(shown));
    out.extend_from_slice(&(carried.len() as u16).to_be_bytes());
    for (node, name) in carried {
        out.extend_from_slice(&node.0);
        out.extend_from_slice(&node.1.to_be_bytes());
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        out.extend_from_slice(name);
    }
    out
}

/// A frame: its first byte, and its body.
pub fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    [&[tag][..], body].concat()
}
