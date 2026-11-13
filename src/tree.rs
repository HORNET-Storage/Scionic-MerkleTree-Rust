//! The classic tree over a list.
//!
//! A file is a list of pieces and a folder is a list of entries. This module
//! turns a list into the one hash that its owner is known by, shows a part of a
//! list together with the nodes that stand for the rest, and checks such a
//! showing.
//!
//! The rule, in full:
//!
//! * a leaf stands for one item of the list: the caller hashes the item, and
//!   says how many bytes of file content it holds;
//! * a fork joins two halves: its hash covers each half's hash, its size and
//!   the number of its items, and in a folder's tree the first name of its
//!   right half; its size is the two sizes added;
//! * a list of more than one item is halved at the largest power of two that
//!   is less than its length.
//!
//! So the shape of a tree follows from the number of its items alone, and the
//! hash on top covers that number: a list cannot be passed off as a longer or
//! a shorter one. Nothing is padded and nothing is repeated, and a place beyond
//! the count does not exist. Forks are hashed from a mark of their own, so a
//! fork cannot be shown as a leaf.

use crate::classic::Digest;
use crate::{Error, Result};
use sha2::{Digest as _, Sha256};

/// The most items a list may hold. It bounds how deep any walk goes.
pub const MAX_LIST_ITEMS: u64 = 1 << 40;

const FILE_FORK: u8 = 0x01;
const FOLDER_FORK: u8 = 0x03;

/// What a list is a list of.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListKind {
    /// A file's pieces, in the file's order.
    File,
    /// A folder's entries, sorted by name. Its forks record names.
    Folder,
}

/// A node of a list's tree: its hash, and the bytes of file content under it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Node {
    pub hash: Digest,
    pub size: u64,
}

/// What an empty list has in place of a tree.
pub const EMPTY_LIST: Node = Node {
    hash: [0; 32],
    size: 0,
};

/// One item of a list as its tree sees it: the item's leaf, and for a folder's
/// list the entry's name. A file's list has no names.
#[derive(Clone, Copy, Debug)]
pub struct Leaf<'a> {
    pub node: Node,
    pub name: &'a [u8],
}

/// A node sent in place of the items under it. In a folder's tree it comes
/// with the first name under it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Carried {
    pub node: Node,
    pub first_name: Vec<u8>,
}

/// What an opening shows, once it is rebuilt: the node on top of the list, to
/// hold against the hash and size the list is known by, and how many bytes of
/// file content come before the first opened item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Shown {
    pub top: Node,
    pub offset: u64,
}

fn invalid(detail: &str) -> Error {
    Error::InvalidData {
        detail: detail.to_owned(),
    }
}

/// Where a list of `width` items is halved: the largest power of two below it.
fn split(width: u64) -> u64 {
    debug_assert!(width >= 2);
    1 << (63 - (width - 1).leading_zeros())
}

/// Joins two halves. `left_items` and `right_items` say how many items of the
/// list are under each.
fn fork(
    kind: ListKind,
    left: Node,
    left_items: u64,
    right: Node,
    right_items: u64,
    right_first_name: &[u8],
) -> Result<Node> {
    let size = left
        .size
        .checked_add(right.size)
        .ok_or(Error::SizeOverflow { field: "list size" })?;
    let mut hasher = Sha256::new();
    hasher.update([match kind {
        ListKind::File => FILE_FORK,
        ListKind::Folder => FOLDER_FORK,
    }]);
    hasher.update(left.hash);
    hasher.update(left.size.to_be_bytes());
    hasher.update(left_items.to_be_bytes());
    hasher.update(right.hash);
    hasher.update(right.size.to_be_bytes());
    hasher.update(right_items.to_be_bytes());
    if kind == ListKind::Folder {
        hasher.update(right_first_name);
    }
    Ok(Node {
        hash: hasher.finalize().into(),
        size,
    })
}

/// A whole list has to be short enough, and a folder's has to be sorted by
/// name with no name twice.
fn check_list(kind: ListKind, leaves: &[Leaf<'_>]) -> Result<()> {
    if leaves.len() as u64 > MAX_LIST_ITEMS {
        return Err(invalid("a list holds more items than the format allows"));
    }
    if kind == ListKind::Folder && !names_ascend(leaves) {
        return Err(invalid(
            "a folder's entries are not sorted by name, or a name is there twice",
        ));
    }
    Ok(())
}

fn names_ascend(leaves: &[Leaf<'_>]) -> bool {
    leaves.windows(2).all(|pair| pair[0].name < pair[1].name)
}

/// The node on top of a whole list. An empty list gives [`EMPTY_LIST`].
pub fn top_of(kind: ListKind, leaves: &[Leaf<'_>]) -> Result<Node> {
    check_list(kind, leaves)?;
    top_unchecked(kind, leaves)
}

fn top_unchecked(kind: ListKind, leaves: &[Leaf<'_>]) -> Result<Node> {
    // Two whole trees of one width are joined as soon as they stand side by
    // side, so the stack holds one tree for each 1 bit of the count so far.
    // Each is kept with the place of its first item and its width.
    let mut stack: Vec<(Node, usize, usize)> = Vec::new();
    for (index, leaf) in leaves.iter().enumerate() {
        let mut right = (leaf.node, index, 1_usize);
        while let Some(&(left, left_first, left_width)) = stack.last() {
            if left_width != right.2 {
                break;
            }
            stack.pop();
            let name = leaves[right.1].name;
            right = (
                fork(kind, left, left_width as u64, right.0, right.2 as u64, name)?,
                left_first,
                left_width * 2,
            );
        }
        stack.push(right);
    }
    // What is left joins from the right: each is the left half of all after it.
    let Some(mut top) = stack.pop() else {
        return Ok(EMPTY_LIST);
    };
    while let Some((left, left_first, left_width)) = stack.pop() {
        let name = leaves[top.1].name;
        top = (
            fork(kind, left, left_width as u64, top.0, top.2 as u64, name)?,
            left_first,
            left_width + top.2,
        );
    }
    Ok(top.0)
}

/// A list's tree kept whole, for showing parts of it.
pub struct ListTree<'a> {
    kind: ListKind,
    leaves: &'a [Leaf<'a>],
    /// `levels[j]` holds, in order, the nodes over `2^(j + 1)` items each.
    levels: Vec<Vec<Node>>,
}

impl<'a> ListTree<'a> {
    pub fn build(kind: ListKind, leaves: &'a [Leaf<'a>]) -> Result<Self> {
        check_list(kind, leaves)?;
        Self::build_unchecked(kind, leaves)
    }

    fn build_unchecked(kind: ListKind, leaves: &'a [Leaf<'a>]) -> Result<Self> {
        let mut levels: Vec<Vec<Node>> = Vec::new();
        let mut below_width = 1_usize;
        loop {
            let below_len = levels.last().map_or(leaves.len(), Vec::len);
            if below_len < 2 {
                break;
            }
            let mut level = Vec::with_capacity(below_len / 2);
            for pair in 0..below_len / 2 {
                let (left, right) = match levels.last() {
                    None => (leaves[pair * 2].node, leaves[pair * 2 + 1].node),
                    Some(below) => (below[pair * 2], below[pair * 2 + 1]),
                };
                let name = leaves[(pair * 2 + 1) * below_width].name;
                let items = below_width as u64;
                level.push(fork(kind, left, items, right, items, name)?);
            }
            levels.push(level);
            below_width *= 2;
        }
        Ok(Self {
            kind,
            leaves,
            levels,
        })
    }

    /// How many items the list holds.
    pub fn count(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// The node on top of the list.
    pub fn top(&self) -> Result<Node> {
        if self.leaves.is_empty() {
            return Ok(EMPTY_LIST);
        }
        self.node(0, self.leaves.len())
    }

    /// The node over the `width` items that start at `offset`. Every node a
    /// walk from the top asks for either has a width that is a power of two
    /// and starts at a multiple of it, and is kept, or it lies on the list's
    /// right edge and is joined from such nodes.
    fn node(&self, offset: usize, width: usize) -> Result<Node> {
        if width.is_power_of_two() {
            debug_assert_eq!(offset % width, 0);
            let level = width.trailing_zeros() as usize;
            return Ok(if level == 0 {
                self.leaves[offset].node
            } else {
                self.levels[level - 1][offset >> level]
            });
        }
        let left_width = split(width as u64) as usize;
        let left = self.node(offset, left_width)?;
        let right = self.node(offset + left_width, width - left_width)?;
        fork(
            self.kind,
            left,
            left_width as u64,
            right,
            (width - left_width) as u64,
            self.leaves[offset + left_width].name,
        )
    }

    /// The nodes to send with items `start` up to, not including, `end`: one
    /// for each run of items that is left out, in the order a checker meets
    /// them.
    pub fn open(&self, start: u64, end: u64) -> Result<Vec<Carried>> {
        if start >= end || end > self.count() {
            return Err(invalid("the items to open are outside the list"));
        }
        let mut carried = Vec::new();
        self.collect(
            0,
            self.leaves.len(),
            start as usize,
            end as usize,
            &mut carried,
        )?;
        Ok(carried)
    }

    fn collect(
        &self,
        offset: usize,
        width: usize,
        start: usize,
        end: usize,
        carried: &mut Vec<Carried>,
    ) -> Result<()> {
        let after = offset + width;
        if after <= start || end <= offset {
            carried.push(Carried {
                node: self.node(offset, width)?,
                first_name: match self.kind {
                    ListKind::File => Vec::new(),
                    ListKind::Folder => self.leaves[offset].name.to_vec(),
                },
            });
            return Ok(());
        }
        if start <= offset && after <= end {
            return Ok(());
        }
        let left_width = split(width as u64) as usize;
        self.collect(offset, left_width, start, end, carried)?;
        self.collect(offset + left_width, width - left_width, start, end, carried)
    }
}

/// Rebuilds the top of a list of `count` items from the `opened` items, which
/// start at item `start`, and the nodes `carried` for the rest.
///
/// The caller holds the result against the hash and the size that the list is
/// known by. In a folder's list every opened entry must also be where the fork
/// names send its name, so that an entry is never shown at a place where a
/// search for its name would not find it.
pub fn check_opening(
    kind: ListKind,
    count: u64,
    start: u64,
    opened: &[Leaf<'_>],
    carried: &[Carried],
) -> Result<Shown> {
    Walk::run(kind, count, start, opened, carried, None)
}

/// Rebuilds the top of a folder's list from the one entry at the place where
/// `name` can be, and says whether that entry has the name. Each fork sends
/// the name left when it sorts before the fork's name and right otherwise, so
/// for one folder and one name there is one place, and one answer.
pub fn check_lookup(
    count: u64,
    index: u64,
    entry: Leaf<'_>,
    name: &[u8],
    carried: &[Carried],
) -> Result<(Shown, bool)> {
    let opened = [entry];
    let shown = Walk::run(ListKind::Folder, count, index, &opened, carried, Some(name))?;
    Ok((shown, entry.name == name))
}

struct Walk<'a> {
    kind: ListKind,
    start: u64,
    end: u64,
    opened: &'a [Leaf<'a>],
    carried: std::slice::Iter<'a, Carried>,
    before: u64,
    lookup: Option<&'a [u8]>,
}

impl<'a> Walk<'a> {
    fn run(
        kind: ListKind,
        count: u64,
        start: u64,
        opened: &'a [Leaf<'a>],
        carried: &'a [Carried],
        lookup: Option<&'a [u8]>,
    ) -> Result<Shown> {
        if count > MAX_LIST_ITEMS {
            return Err(invalid("a list holds more items than the format allows"));
        }
        let length = opened.len() as u64;
        let end = start
            .checked_add(length)
            .filter(|end| length > 0 && *end <= count)
            .ok_or_else(|| invalid("the opened items are outside the list"))?;
        match kind {
            ListKind::File => {
                if carried.iter().any(|node| !node.first_name.is_empty()) {
                    return Err(invalid("a node of a file's tree carries a name"));
                }
            }
            ListKind::Folder => {
                if !names_ascend(opened) {
                    return Err(invalid(
                        "opened entries are not sorted by name, or a name is there twice",
                    ));
                }
            }
        }
        let mut walk = Self {
            kind,
            start,
            end,
            opened,
            carried: carried.iter(),
            before: 0,
            lookup,
        };
        let (top, _) = walk.node(0, count)?;
        if walk.carried.next().is_some() {
            return Err(invalid("an opening carries more nodes than it needs"));
        }
        Ok(Shown {
            top,
            offset: walk.before,
        })
    }

    fn item(&self, index: u64) -> &Leaf<'a> {
        &self.opened[(index - self.start) as usize]
    }

    /// The node over the `width` items that start at `offset`, and the first
    /// name under it. No more than 41 calls are ever nested, because the list
    /// holds at most 2^40 items.
    fn node(&mut self, offset: u64, width: u64) -> Result<(Node, &'a [u8])> {
        let after = offset + width;
        if after <= self.start || self.end <= offset {
            let carried = self
                .carried
                .next()
                .ok_or_else(|| invalid("an opening carries fewer nodes than it needs"))?;
            if after <= self.start {
                self.before = self
                    .before
                    .checked_add(carried.node.size)
                    .ok_or(Error::SizeOverflow { field: "list size" })?;
            }
            return Ok((carried.node, carried.first_name.as_slice()));
        }
        if width == 1 {
            let leaf = self.item(offset);
            return Ok((leaf.node, leaf.name));
        }
        let middle = offset + split(width);
        let (left, first_name) = self.node(offset, middle - offset)?;
        let (right, fork_name) = self.node(middle, after - middle)?;
        if self.kind == ListKind::Folder {
            self.check_names(offset, middle, after, fork_name)?;
        }
        let node = fork(
            self.kind,
            left,
            middle - offset,
            right,
            after - middle,
            fork_name,
        )?;
        Ok((node, first_name))
    }

    /// At a fork of a folder's tree: every opened entry on its left sorts
    /// before the fork's name, and every opened entry on its right sorts after
    /// it, except the right half's own first entry, which has that name. A
    /// name that is looked up takes the same turn as the entry it is shown.
    fn check_names(&self, offset: u64, middle: u64, after: u64, fork_name: &[u8]) -> Result<()> {
        let left_end = self.end.min(middle);
        if self.start.max(offset) < left_end && self.item(left_end - 1).name >= fork_name {
            return Err(invalid(
                "an entry is left of a fork whose name it does not sort before",
            ));
        }
        let right_start = self.start.max(middle);
        if right_start > middle
            && right_start < self.end.min(after)
            && self.item(right_start).name <= fork_name
        {
            return Err(invalid(
                "an entry is right of a fork whose name it does not sort after",
            ));
        }
        if let Some(name) = self.lookup {
            let name_goes_left = name < fork_name;
            let entry_is_left = self.start < middle;
            if name_goes_left != entry_is_left {
                return Err(invalid("the opened entry is not where the name would be"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::sha256;

    /// A list for tests: each item's leaf, and its name.
    type Owned = Vec<(Node, Vec<u8>)>;

    fn leaf_node(seed: usize) -> Node {
        Node {
            hash: sha256(&(seed as u64).to_be_bytes()),
            size: (seed as u64 % 7) + 1,
        }
    }

    fn file_list(count: usize) -> Owned {
        (0..count)
            .map(|index| (leaf_node(index), Vec::new()))
            .collect()
    }

    fn folder_list(names: &[&str]) -> Owned {
        names
            .iter()
            .enumerate()
            .map(|(index, name)| (leaf_node(index), name.as_bytes().to_vec()))
            .collect()
    }

    fn sorted_folder(count: usize) -> Owned {
        (0..count)
            .map(|index| (leaf_node(index), format!("name-{index:04}").into_bytes()))
            .collect()
    }

    fn leaves(owned: &Owned) -> Vec<Leaf<'_>> {
        owned
            .iter()
            .map(|(node, name)| Leaf { node: *node, name })
            .collect()
    }

    /// The rule as it is written, with no stack and no kept levels.
    fn by_the_rule(kind: ListKind, leaves: &[Leaf<'_>], offset: usize, width: usize) -> Node {
        if width == 1 {
            return leaves[offset].node;
        }
        let mut left_width = 1;
        while left_width * 2 < width {
            left_width *= 2;
        }
        let left = by_the_rule(kind, leaves, offset, left_width);
        let right = by_the_rule(kind, leaves, offset + left_width, width - left_width);
        fork(
            kind,
            left,
            left_width as u64,
            right,
            (width - left_width) as u64,
            leaves[offset + left_width].name,
        )
        .unwrap()
    }

    /// A small generator of numbers that repeats from run to run.
    struct Numbers(u64);

    impl Numbers {
        fn next(&mut self, below: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % below as u64) as usize
        }
    }

    #[test]
    fn a_list_is_halved_at_the_largest_power_of_two_below_its_length() {
        for (width, left) in [(2, 1), (3, 2), (4, 2), (5, 4), (6, 4), (8, 4), (9, 8)] {
            assert_eq!(split(width), left, "a list of {width}");
        }
        assert_eq!(split(MAX_LIST_ITEMS), MAX_LIST_ITEMS / 2);
        assert_eq!(split(MAX_LIST_ITEMS + 1), MAX_LIST_ITEMS);
    }

    #[test]
    fn a_fork_hashes_exactly_the_bytes_the_format_names() {
        let left = leaf_node(1);
        let right = leaf_node(2);
        let mut bytes = vec![0x01];
        bytes.extend_from_slice(&left.hash);
        bytes.extend_from_slice(&left.size.to_be_bytes());
        bytes.extend_from_slice(&4_u64.to_be_bytes());
        bytes.extend_from_slice(&right.hash);
        bytes.extend_from_slice(&right.size.to_be_bytes());
        bytes.extend_from_slice(&3_u64.to_be_bytes());
        assert_eq!(bytes.len(), 97);
        let file = fork(ListKind::File, left, 4, right, 3, b"ignored").unwrap();
        assert_eq!(file.hash, sha256(&bytes));
        assert_eq!(file.size, left.size + right.size);
        // The same two halves over another number of items are another fork.
        let other = fork(ListKind::File, left, 4, right, 2, b"ignored").unwrap();
        assert_ne!(other.hash, file.hash);

        bytes[0] = 0x03;
        bytes.extend_from_slice(b"right-half");
        let folder = fork(ListKind::Folder, left, 4, right, 3, b"right-half").unwrap();
        assert_eq!(folder.hash, sha256(&bytes));
        assert_ne!(folder.hash, file.hash);
    }

    #[test]
    fn the_top_of_a_list_follows_the_rule_at_every_length() {
        assert_eq!(top_of(ListKind::File, &[]).unwrap(), EMPTY_LIST);
        assert_eq!(top_of(ListKind::Folder, &[]).unwrap(), EMPTY_LIST);
        for count in 1..=70 {
            for (kind, owned) in [
                (ListKind::File, file_list(count)),
                (ListKind::Folder, sorted_folder(count)),
            ] {
                let leaves = leaves(&owned);
                let expected = by_the_rule(kind, &leaves, 0, count);
                assert_eq!(
                    top_of(kind, &leaves).unwrap(),
                    expected,
                    "{kind:?} of {count}"
                );
                let tree = ListTree::build(kind, &leaves).unwrap();
                assert_eq!(tree.top().unwrap(), expected, "kept {kind:?} of {count}");
            }
        }
    }

    #[test]
    fn a_list_of_one_is_its_leaf_and_a_longer_list_is_never_one_of_its_leaves() {
        let owned = file_list(3);
        let leaves = leaves(&owned);
        assert_eq!(
            top_of(ListKind::File, &leaves[..1]).unwrap(),
            leaves[0].node
        );
        let top = top_of(ListKind::File, &leaves).unwrap();
        assert!(leaves.iter().all(|leaf| leaf.node.hash != top.hash));
        assert_eq!(
            top.size,
            leaves.iter().map(|leaf| leaf.node.size).sum::<u64>()
        );
    }

    #[test]
    fn the_same_items_in_another_order_or_number_give_another_top() {
        let owned = file_list(6);
        let mut leaves = leaves(&owned);
        let top = top_of(ListKind::File, &leaves).unwrap();
        // A last item that is listed twice is a longer list, not the same one.
        let mut repeated = leaves.clone();
        repeated.push(leaves[5]);
        assert_ne!(top_of(ListKind::File, &repeated).unwrap().hash, top.hash);
        assert_ne!(top_of(ListKind::File, &leaves[..5]).unwrap().hash, top.hash);
        leaves.swap(1, 2);
        assert_ne!(top_of(ListKind::File, &leaves).unwrap().hash, top.hash);
    }

    #[test]
    fn a_folder_list_out_of_order_or_with_a_name_twice_has_no_hash() {
        for names in [&["b", "a"][..], &["a", "a"], &["a", "c", "b"]] {
            let owned = folder_list(names);
            let leaves = leaves(&owned);
            assert!(top_of(ListKind::Folder, &leaves).is_err(), "{names:?}");
            assert!(
                ListTree::build(ListKind::Folder, &leaves).is_err(),
                "{names:?}"
            );
        }
    }

    #[test]
    fn every_run_of_every_list_opens_and_rebuilds_to_the_top() {
        for count in 1..=33_usize {
            for (kind, owned) in [
                (ListKind::File, file_list(count)),
                (ListKind::Folder, sorted_folder(count)),
            ] {
                let leaves = leaves(&owned);
                let tree = ListTree::build(kind, &leaves).unwrap();
                let top = tree.top().unwrap();
                for start in 0..count {
                    for end in start + 1..=count {
                        let carried = tree.open(start as u64, end as u64).unwrap();
                        let shown = check_opening(
                            kind,
                            count as u64,
                            start as u64,
                            &leaves[start..end],
                            &carried,
                        )
                        .unwrap_or_else(|error| {
                            panic!("{kind:?} of {count}, {start}..{end}: {error}")
                        });
                        assert_eq!(shown.top, top, "{kind:?} of {count}, {start}..{end}");
                        let before: u64 = leaves[..start].iter().map(|leaf| leaf.node.size).sum();
                        assert_eq!(shown.offset, before, "{kind:?} of {count}, {start}..{end}");
                        // An opening carries a node for each run it leaves
                        // out, and never more than two for a level.
                        assert!(carried.len() <= 2 * 6, "{} nodes", carried.len());
                        if start == 0 && end == count {
                            assert!(carried.is_empty());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn an_opening_that_is_changed_does_not_rebuild_to_the_top() {
        let owned = file_list(11);
        let leaves = leaves(&owned);
        let tree = ListTree::build(ListKind::File, &leaves).unwrap();
        let top = tree.top().unwrap();
        let carried = tree.open(4, 6).unwrap();
        let rebuilt = |start: u64, opened: &[Leaf<'_>], carried: &[Carried]| {
            check_opening(ListKind::File, 11, start, opened, carried).map(|shown| shown.top)
        };
        assert_eq!(rebuilt(4, &leaves[4..6], &carried).unwrap(), top);

        // Another item in an opened place, and the same items one place on.
        assert_ne!(
            rebuilt(4, &[leaves[4], leaves[7]], &carried).ok(),
            Some(top)
        );
        assert_ne!(rebuilt(5, &leaves[4..6], &carried).ok(), Some(top));
        // The same item with another size.
        let mut resized = leaves[4];
        resized.node.size += 1;
        assert_ne!(rebuilt(4, &[resized, leaves[5]], &carried).ok(), Some(top));
        // A carried node with another size, two carried nodes changed about,
        // one too few and one too many.
        let mut wrong_size = carried.clone();
        wrong_size[0].node.size += 1;
        assert_ne!(rebuilt(4, &leaves[4..6], &wrong_size).ok(), Some(top));
        let mut swapped = carried.clone();
        swapped.swap(0, 1);
        assert_ne!(rebuilt(4, &leaves[4..6], &swapped).ok(), Some(top));
        assert!(rebuilt(4, &leaves[4..6], &carried[1..]).is_err());
        let mut extra = carried.clone();
        extra.push(carried[0].clone());
        assert!(rebuilt(4, &leaves[4..6], &extra).is_err());
        // A list that is said to be longer or shorter.
        for count in [10, 12] {
            let result = check_opening(ListKind::File, count, 4, &leaves[4..6], &carried);
            assert_ne!(
                result.map(|shown| shown.top).ok(),
                Some(top),
                "as {count} items"
            );
        }
        // Items outside the list, and none at all.
        assert!(rebuilt(10, &leaves[4..6], &carried).is_err());
        assert!(rebuilt(4, &[], &carried).is_err());
        assert!(rebuilt(u64::MAX, &leaves[4..6], &carried).is_err());
    }

    #[test]
    fn no_place_exists_beyond_the_count() {
        // Trees that fill a level by repeating their last item let that item be
        // shown again at the place after it. Here the place is not there.
        for count in [1_usize, 3, 5, 7] {
            let owned = file_list(count);
            let leaves = leaves(&owned);
            let tree = ListTree::build(ListKind::File, &leaves).unwrap();
            let carried = tree.open(count as u64 - 1, count as u64).unwrap();
            let last = &leaves[count - 1..];
            assert!(
                check_opening(ListKind::File, count as u64, count as u64, last, &carried).is_err()
            );
            assert!(tree.open(count as u64, count as u64 + 1).is_err());
        }
    }

    #[test]
    fn sizes_that_do_not_fit_are_an_error() {
        let mut owned = file_list(2);
        owned[0].0.size = u64::MAX;
        let leaves = leaves(&owned);
        assert!(top_of(ListKind::File, &leaves).is_err());
        assert!(ListTree::build(ListKind::File, &leaves).is_err());
    }

    #[test]
    fn a_name_in_a_sorted_folder_is_found_at_its_one_place_or_shown_missing() {
        for count in 1..=20_usize {
            let owned = sorted_folder(count);
            let leaves = leaves(&owned);
            let tree = ListTree::build(ListKind::Folder, &leaves).unwrap();
            let top = tree.top().unwrap();
            let verdict = |name: &[u8], index: usize| {
                let carried = tree.open(index as u64, index as u64 + 1).unwrap();
                check_lookup(count as u64, index as u64, leaves[index], name, &carried)
                    .ok()
                    .filter(|(shown, _)| shown.top == top)
                    .map(|(_, present)| present)
            };
            for (place, leaf) in leaves.iter().enumerate() {
                // The name itself: there, at its own place and nowhere else.
                for index in 0..count {
                    let expected = (index == place).then_some(true);
                    assert_eq!(
                        verdict(leaf.name, index),
                        expected,
                        "{count}: {place} at {index}"
                    );
                }
                // A name just after it: missing, shown by the entry before
                // it, and by no other entry.
                let mut later = leaf.name.to_vec();
                later.push(b'!');
                for index in 0..count {
                    let expected = (index == place).then_some(false);
                    assert_eq!(
                        verdict(&later, index),
                        expected,
                        "{count}: after {place} at {index}"
                    );
                }
            }
            // A name before every entry: missing, shown by the first entry.
            for index in 0..count {
                let expected = (index == 0).then_some(false);
                assert_eq!(
                    verdict(b"a", index),
                    expected,
                    "{count}: before all at {index}"
                );
            }
        }
    }

    #[test]
    fn a_folder_built_out_of_order_cannot_show_one_name_at_two_places() {
        // An author is free to hash any list. Whatever it hashed, a name has
        // one place, and an entry anywhere else cannot be shown at all.
        let mut numbers = Numbers(0x5c10_71c5_eed5_eed5);
        let alphabet = ["a", "b", "c", "d", "e", "f"];
        for _ in 0..400 {
            let count = 2 + numbers.next(16);
            let names: Vec<&str> = (0..count)
                .map(|_| alphabet[numbers.next(alphabet.len())])
                .collect();
            let owned = folder_list(&names);
            let leaves = leaves(&owned);
            let tree = ListTree::build_unchecked(ListKind::Folder, &leaves).unwrap();
            let top = tree.top().unwrap();
            for name in alphabet {
                let mut answers = Vec::new();
                for (index, entry) in leaves.iter().copied().enumerate() {
                    let carried = tree.open(index as u64, index as u64 + 1).unwrap();
                    if let Ok((shown, present)) =
                        check_lookup(count as u64, index as u64, entry, name.as_bytes(), &carried)
                    {
                        if shown.top == top {
                            answers.push((index, present));
                        }
                    }
                    // An entry with this name that is shown as a plain opening
                    // passes only at the place a search would reach.
                    if entry.name == name.as_bytes() {
                        let plain = check_opening(
                            ListKind::Folder,
                            count as u64,
                            index as u64,
                            &[entry],
                            &carried,
                        );
                        let found_here = answers.last() == Some(&(index, true));
                        assert_eq!(
                            plain.is_ok_and(|shown| shown.top == top),
                            found_here,
                            "{names:?}: {name} at {index}"
                        );
                    }
                }
                assert!(
                    answers.len() <= 1,
                    "{names:?}: {name} answered at {answers:?}"
                );
            }
        }
    }

    #[test]
    fn runs_of_a_folder_built_out_of_order_open_only_where_a_search_agrees() {
        // "c" sits left of a fork named "b": it cannot be shown, alone or in a
        // run, and a search for it is sent to "b", which says it is missing.
        let owned = folder_list(&["a", "c", "b", "d"]);
        let leaves = leaves(&owned);
        let tree = ListTree::build_unchecked(ListKind::Folder, &leaves).unwrap();
        let top = tree.top().unwrap();
        let opens = |start: usize, end: usize| {
            let carried = tree.open(start as u64, end as u64).unwrap();
            check_opening(
                ListKind::Folder,
                4,
                start as u64,
                &leaves[start..end],
                &carried,
            )
            .is_ok_and(|shown| shown.top == top)
        };
        assert!(opens(0, 1), "a");
        assert!(!opens(1, 2), "c, alone");
        assert!(!opens(0, 2), "a and c");
        assert!(!opens(1, 3), "c and b");
        assert!(opens(2, 3), "b");
        assert!(opens(2, 4), "b and d");
        assert!(!opens(0, 4), "the whole list");

        let carried = tree.open(2, 3).unwrap();
        let (shown, present) = check_lookup(4, 2, leaves[2], b"c", &carried).unwrap();
        assert_eq!((shown.top, present), (top, false));
    }

    #[test]
    fn a_carried_name_is_held_to_the_fork_it_enters() {
        // The first name under a carried right half is part of the fork above
        // it. Another name there gives another top.
        let owned = sorted_folder(8);
        let leaves = leaves(&owned);
        let tree = ListTree::build(ListKind::Folder, &leaves).unwrap();
        let top = tree.top().unwrap();
        let mut carried = tree.open(1, 2).unwrap();
        let honest = check_opening(ListKind::Folder, 8, 1, &leaves[1..2], &carried).unwrap();
        assert_eq!(honest.top, top);
        let last = carried.len() - 1;
        carried[last].first_name = b"name-9999".to_vec();
        let forged = check_opening(ListKind::Folder, 8, 1, &leaves[1..2], &carried);
        assert_ne!(forged.map(|shown| shown.top).ok(), Some(top));
    }

    #[test]
    fn a_files_tree_carries_no_names() {
        let owned = file_list(4);
        let leaves = leaves(&owned);
        let tree = ListTree::build(ListKind::File, &leaves).unwrap();
        let mut carried = tree.open(0, 1).unwrap();
        carried[0].first_name = b"x".to_vec();
        assert!(check_opening(ListKind::File, 4, 0, &leaves[..1], &carried).is_err());
    }
}
