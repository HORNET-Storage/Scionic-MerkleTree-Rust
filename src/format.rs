//! The things a tree is made of, and their exact bytes.
//!
//! * A **piece** is a run of a file's bytes. Its hash is the SHA-256 of those
//!   bytes, and nothing else.
//! * A **file** is the list of its pieces, in the file's order.
//! * A **folder** is the list of its entries, sorted by name. An entry holds a
//!   name, and the file or folder under it.
//! * The **record** says what a tree's root stands for.
//!
//! A thing's hash covers what the thing is, and its parent's hash covers where
//! it sits. So a file has no name of its own and a piece has no number of its
//! own: the name is in the folder, and the number is the piece's place in the
//! file's list.
//!
//! A value of one of these types is always well formed. It is checked when it
//! is made and when it is read from bytes, and reading is strict: bytes that
//! could be written in two ways are read in one way only.

use crate::fastcdc::{FASTCDC_MAX_SIZE, FASTCDC_MIN_SIZE};
use crate::hash::{Hash, Root};
use crate::tree::{
    check_lookup, check_opening, top_of, Carried, Leaf, ListKind, ListTree, Node, EMPTY_LIST,
    MAX_LIST_ITEMS,
};
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::sync::Arc;

/// The most bytes a piece may hold: 8 MiB.
pub const MAX_PIECE_BYTES: usize = FASTCDC_MAX_SIZE;
/// How many bytes one item of a file's list takes: a hash and a length.
pub const LIST_ITEM_BYTES: usize = 36;
/// The most bytes a name may hold.
pub const MAX_NAME_BYTES: usize = 255;
/// The most values a set of extra data may hold.
pub const MAX_EXTRA_VALUES: usize = 32;
/// The most bytes the name of an extra value may hold.
pub const MAX_EXTRA_NAME_BYTES: usize = 64;
/// The most bytes an extra value may hold.
pub const MAX_EXTRA_VALUE_BYTES: usize = 1024;
/// The most folders that may sit inside one another, the top one counted.
pub const MAX_FOLDER_DEPTH: usize = 128;
/// The most nodes an opening may carry: 40 on each side of what it shows.
pub const MAX_CARRIED_NODES: usize = 80;
/// The most bytes a set of extra data may take: how many values it has, and
/// 32 values that are as long as they can be.
pub const MAX_EXTRA_BYTES: usize =
    2 + MAX_EXTRA_VALUES * (4 + MAX_EXTRA_NAME_BYTES + MAX_EXTRA_VALUE_BYTES);
/// The most bytes a record may take: its fixed part, and extra data that is
/// as full as it can be.
pub const MAX_RECORD_BYTES: usize = 66 + MAX_EXTRA_BYTES;
/// The most bytes a folder's entry may take: its fixed part, the longest
/// name, and extra data that is as full as it can be.
pub const MAX_ENTRY_BYTES: usize = 43 + MAX_NAME_BYTES + MAX_EXTRA_BYTES;
/// The extra value of a record that says how the tree's files were cut.
pub const CUTTING_KEY: &str = "chunking";
/// The extra value of a record that says when the tree was built.
pub const TIMESTAMP_KEY: &str = "timestamp";
/// How a tree says that its files were cut by content.
pub const CUTTING_FASTCDC_V1: &str = "fastcdc-v1";
const CUTTING_FIXED_PREFIX: &str = "fixed-";

const FILE_LEAF_MARK: u8 = 0x00;
const FOLDER_LEAF_MARK: u8 = 0x02;
const FILE_MARK: u8 = 0x10;
const FOLDER_MARK: u8 = 0x11;
pub(crate) const RECORD_MARK: u8 = 0x20;
const KIND_FILE: u8 = 1;
const KIND_FOLDER: u8 = 2;

fn invalid(detail: impl Into<String>) -> Error {
    Error::InvalidData {
        detail: detail.into(),
    }
}

/// Reads numbers and runs of bytes off the front of a slice.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8], what: &'static str) -> Self {
        Self { bytes, what }
    }

    pub(crate) fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        if self.bytes.len() < count {
            return Err(invalid(format!("{} is cut short", self.what)));
        }
        let (head, tail) = self.bytes.split_at(count);
        self.bytes = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut array = [0_u8; N];
        array.copy_from_slice(self.take(N)?);
        Ok(array)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn hash(&mut self) -> Result<Hash> {
        Ok(Hash::from_bytes(self.array()?))
    }

    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Everything must have been read.
    pub(crate) fn finish(self) -> Result<()> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(invalid(format!("{} has bytes after its end", self.what)))
        }
    }
}

/// Whether an entry is a file or a folder.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Kind {
    File,
    Folder,
}

impl Kind {
    fn byte(self) -> u8 {
        match self {
            Self::File => KIND_FILE,
            Self::Folder => KIND_FOLDER,
        }
    }

    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            KIND_FILE => Ok(Self::File),
            KIND_FOLDER => Ok(Self::Folder),
            _ => Err(invalid("an entry is neither a file nor a folder")),
        }
    }
}

/// A file or a folder as the thing above it names it: its kind, its hash, and
/// how many bytes of file content it holds.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Target {
    pub kind: Kind,
    pub hash: Hash,
    pub size: u64,
}

impl Target {
    pub(crate) fn require(&self, kind: Kind) -> Result<()> {
        if self.kind == kind {
            Ok(())
        } else {
            Err(invalid(match kind {
                Kind::File => "a folder was given where a file is needed",
                Kind::Folder => "a file was given where a folder is needed",
            }))
        }
    }
}

/// Checks a name: 1 to 255 bytes, no `/`, no zero byte, and not `.` or `..`.
pub fn check_name(name: &str) -> Result<()> {
    let reason = if name.is_empty() {
        "it is empty"
    } else if name.len() > MAX_NAME_BYTES {
        "it is longer than 255 bytes"
    } else if name == "." || name == ".." {
        "it is a dot name"
    } else if name.contains('/') {
        "it holds a slash"
    } else if name.contains('\0') {
        "it holds a zero byte"
    } else {
        return Ok(());
    };
    Err(Error::InvalidName {
        name: name.chars().take(80).collect(),
        reason,
    })
}

/// A small set of named values, kept beside a name in a folder or in a tree's
/// record. It holds at most 32 values. A value's name is 1 to 64 bytes, and a
/// value is at most 1,024 bytes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExtraData {
    values: BTreeMap<String, Vec<u8>>,
}

impl ExtraData {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a value, in place of any value of the same name.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Result<()> {
        let name = name.into();
        let value = value.into();
        if name.is_empty() || name.len() > MAX_EXTRA_NAME_BYTES {
            return Err(invalid("the name of an extra value is not 1 to 64 bytes"));
        }
        if value.len() > MAX_EXTRA_VALUE_BYTES {
            return Err(invalid("an extra value is longer than 1,024 bytes"));
        }
        if !self.values.contains_key(&name) && self.values.len() >= MAX_EXTRA_VALUES {
            return Err(invalid("extra data holds more than 32 values"));
        }
        self.values.insert(name, value);
        Ok(())
    }

    /// The same set with one more value.
    pub fn with(mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Result<Self> {
        self.insert(name, value)?;
        Ok(self)
    }

    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.values.get(name).map(Vec::as_slice)
    }

    /// A value as text, when it is UTF-8.
    pub fn text(&self, name: &str) -> Option<&str> {
        self.get(name)
            .and_then(|value| std::str::from_utf8(value).ok())
    }

    pub fn remove(&mut self, name: &str) -> Option<Vec<u8>> {
        self.values.remove(name)
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// The values, in the order of their names' bytes.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.values
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice()))
    }

    pub(crate) fn encoded_len(&self) -> usize {
        2 + self
            .values
            .iter()
            .map(|(name, value)| 4 + name.len() + value.len())
            .sum::<usize>()
    }

    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.values.len() as u16).to_be_bytes());
        for (name, value) in &self.values {
            out.extend_from_slice(&(name.len() as u16).to_be_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            out.extend_from_slice(value);
        }
    }

    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let count = usize::from(reader.u16()?);
        if count > MAX_EXTRA_VALUES {
            return Err(invalid("extra data holds more than 32 values"));
        }
        let mut values = BTreeMap::new();
        let mut previous: Option<&[u8]> = None;
        for _ in 0..count {
            let name_len = usize::from(reader.u16()?);
            if name_len == 0 || name_len > MAX_EXTRA_NAME_BYTES {
                return Err(invalid("the name of an extra value is not 1 to 64 bytes"));
            }
            let name = reader.take(name_len)?;
            if previous.is_some_and(|previous| previous >= name) {
                return Err(invalid(
                    "extra values are not in the order of their names, or a name is there twice",
                ));
            }
            previous = Some(name);
            let name = std::str::from_utf8(name)
                .map_err(|_| invalid("the name of an extra value is not UTF-8"))?;
            let value_len = usize::from(reader.u16()?);
            if value_len > MAX_EXTRA_VALUE_BYTES {
                return Err(invalid("an extra value is longer than 1,024 bytes"));
            }
            values.insert(name.to_owned(), reader.take(value_len)?.to_vec());
        }
        Ok(Self { values })
    }
}

/// One item of a file's list: a piece's hash, and how many bytes it holds.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PieceRef {
    pub hash: Hash,
    pub length: u32,
}

impl PieceRef {
    /// The item for a piece with these bytes. A piece holds 1 byte to 8 MiB.
    pub fn of(bytes: &[u8]) -> Result<Self> {
        let item = Self {
            hash: Hash::of(bytes),
            length: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        };
        item.check()?;
        Ok(item)
    }

    fn check(&self) -> Result<()> {
        if self.length == 0 || self.length as usize > MAX_PIECE_BYTES {
            return Err(invalid("a piece does not hold 1 byte to 8 MiB"));
        }
        Ok(())
    }

    /// Whether `bytes` are the piece this item names: of its length, and
    /// with its hash.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        bytes.len() as u64 == u64::from(self.length) && Hash::of(bytes) == self.hash
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.hash.as_bytes());
        out.extend_from_slice(&self.length.to_be_bytes());
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let item = Self {
            hash: reader.hash()?,
            length: reader.u32()?,
        };
        item.check()?;
        Ok(item)
    }

    /// The item's leaf in its file's tree.
    pub(crate) fn leaf(&self) -> Node {
        let mut bytes = [0_u8; 1 + LIST_ITEM_BYTES];
        bytes[0] = FILE_LEAF_MARK;
        bytes[1..33].copy_from_slice(self.hash.as_bytes());
        bytes[33..].copy_from_slice(&self.length.to_be_bytes());
        Node {
            hash: Hash::of(&bytes),
            size: u64::from(self.length),
        }
    }
}

/// One entry of a folder: a name, the file or folder under it, and extra data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    name: String,
    target: Target,
    extra: ExtraData,
}

impl Entry {
    pub fn new(name: impl Into<String>, target: Target, extra: ExtraData) -> Result<Self> {
        let name = name.into();
        check_name(&name)?;
        Ok(Self {
            name,
            target,
            extra,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> Kind {
        self.target.kind
    }

    /// How many bytes of file content are under this entry.
    pub fn size(&self) -> u64 {
        self.target.size
    }

    pub fn hash(&self) -> &Hash {
        &self.target.hash
    }

    /// The file or folder under this entry.
    pub fn target(&self) -> Target {
        self.target
    }

    pub fn extra(&self) -> &ExtraData {
        &self.extra
    }

    /// How many bytes the entry takes in its folder's list.
    pub fn encoded_len(&self) -> usize {
        1 + 8 + 32 + 2 + self.name.len() + self.extra.encoded_len()
    }

    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.target.kind.byte());
        out.extend_from_slice(&self.target.size.to_be_bytes());
        out.extend_from_slice(self.target.hash.as_bytes());
        out.extend_from_slice(&(self.name.len() as u16).to_be_bytes());
        out.extend_from_slice(self.name.as_bytes());
        self.extra.encode_into(out);
    }

    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let kind = Kind::from_byte(reader.u8()?)?;
        let size = reader.u64()?;
        let hash = reader.hash()?;
        let name_len = usize::from(reader.u16()?);
        let name = std::str::from_utf8(reader.take(name_len)?)
            .map_err(|_| invalid("a name is not UTF-8"))?;
        check_name(name)?;
        let extra = ExtraData::decode(reader)?;
        Ok(Self {
            name: name.to_owned(),
            target: Target { kind, hash, size },
            extra,
        })
    }

    /// The entry's leaf in its folder's tree.
    pub(crate) fn leaf(&self) -> Node {
        let mut bytes = Vec::with_capacity(1 + self.encoded_len());
        bytes.push(FOLDER_LEAF_MARK);
        self.encode_into(&mut bytes);
        Node {
            hash: Hash::of(&bytes),
            size: self.target.size,
        }
    }
}

fn owner_hash(mark: u8, count: u64, size: u64, list: &Hash) -> Hash {
    let mut bytes = [0_u8; 49];
    bytes[0] = mark;
    bytes[1..9].copy_from_slice(&count.to_be_bytes());
    bytes[9..17].copy_from_slice(&size.to_be_bytes());
    bytes[17..].copy_from_slice(list.as_bytes());
    Hash::of(&bytes)
}

/// The hash of a file with `count` pieces and `size` bytes, whose list's tree
/// has `list` on top.
pub fn file_hash(count: u64, size: u64, list: &Hash) -> Hash {
    owner_hash(FILE_MARK, count, size, list)
}

/// The hash of a folder with `count` entries and `size` bytes of file content,
/// whose list's tree has `list` on top.
pub fn folder_hash(count: u64, size: u64, list: &Hash) -> Hash {
    owner_hash(FOLDER_MARK, count, size, list)
}

/// Holds a rebuilt top against the file or folder it should be the top of.
fn confirm(target: &Target, count: u64, top: Node) -> Result<()> {
    let (what, hash) = match target.kind {
        Kind::File => ("a file's list", file_hash(count, top.size, &top.hash)),
        Kind::Folder => ("a folder's list", folder_hash(count, top.size, &top.hash)),
    };
    if top.size != target.size {
        return Err(Error::SizeMismatch {
            what,
            expected: target.size,
            actual: top.size,
        });
    }
    if hash != target.hash {
        return Err(Error::HashMismatch { what });
    }
    Ok(())
}

/// How a tree's files are cut into pieces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cutting {
    /// By content: pieces of more than 512 KiB, about 2 MiB on average, and
    /// 8 MiB at most. Only a file's last piece may be smaller.
    FastCdcV1,
    /// Every piece but a file's last holds exactly this many bytes. For tests.
    Fixed(NonZeroU32),
}

impl Cutting {
    /// Cutting at a fixed size, of 1 byte to 8 MiB.
    pub fn fixed(size: u32) -> Result<Self> {
        NonZeroU32::new(size)
            .filter(|size| size.get() as usize <= MAX_PIECE_BYTES)
            .map(Self::Fixed)
            .ok_or_else(|| invalid("a fixed piece size is not 1 byte to 8 MiB"))
    }

    /// How a record says this: `fastcdc-v1`, or `fixed-` and the size.
    pub fn tag(self) -> String {
        match self {
            Self::FastCdcV1 => CUTTING_FASTCDC_V1.to_owned(),
            Self::Fixed(size) => format!("{CUTTING_FIXED_PREFIX}{size}"),
        }
    }

    /// Reads what a record says. A size is written in digits with no zero in
    /// front, so each way of cutting has one spelling.
    pub fn from_tag(tag: &[u8]) -> Result<Self> {
        let unknown = || invalid("a record names a way of cutting that is not known");
        if tag == CUTTING_FASTCDC_V1.as_bytes() {
            return Ok(Self::FastCdcV1);
        }
        let digits = tag
            .strip_prefix(CUTTING_FIXED_PREFIX.as_bytes())
            .ok_or_else(unknown)?;
        if digits.is_empty()
            || digits.len() > 7
            || digits[0] == b'0'
            || !digits.iter().all(u8::is_ascii_digit)
        {
            return Err(unknown());
        }
        let size = digits
            .iter()
            .fold(0_u32, |size, digit| size * 10 + u32::from(digit - b'0'));
        Self::fixed(size).map_err(|_| unknown())
    }

    /// Whether a piece of `length` bytes fits, as a file's last piece or as
    /// one before it.
    pub fn check_length(self, length: u32, is_last: bool) -> Result<()> {
        let length = length as usize;
        let fits = match self {
            Self::FastCdcV1 => {
                (1..=FASTCDC_MAX_SIZE).contains(&length) && (is_last || length > FASTCDC_MIN_SIZE)
            }
            Self::Fixed(size) => {
                let size = size.get() as usize;
                if is_last {
                    (1..=size).contains(&length)
                } else {
                    length == size
                }
            }
        };
        if fits {
            Ok(())
        } else {
            Err(invalid(
                "a piece has a length that the tree's way of cutting does not give",
            ))
        }
    }

    /// The fewest and the most pieces that a file of `size` bytes can have.
    pub fn count_bounds(self, size: u64) -> (u64, u64) {
        if size == 0 {
            return (0, 0);
        }
        match self {
            Self::FastCdcV1 => (
                size.div_ceil(FASTCDC_MAX_SIZE as u64),
                (size - 1) / (FASTCDC_MIN_SIZE as u64 + 1) + 1,
            ),
            Self::Fixed(piece) => {
                let count = size.div_ceil(u64::from(piece.get()));
                (count, count)
            }
        }
    }

    /// Whether a file of `size` bytes can have `count` pieces.
    pub fn check_count(self, size: u64, count: u64) -> Result<()> {
        let (fewest, most) = self.count_bounds(size);
        if (fewest..=most).contains(&count) {
            Ok(())
        } else {
            Err(invalid(
                "a file has a number of pieces that its size does not allow",
            ))
        }
    }
}

/// A file: the list of its pieces, in the file's order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileList {
    items: Vec<PieceRef>,
    size: u64,
    hash: Hash,
}

impl FileList {
    /// The file with these pieces, in this order. A piece that occurs twice
    /// is listed twice. No pieces at all is the empty file.
    pub fn new(items: Vec<PieceRef>) -> Result<Self> {
        let mut leaves = Vec::with_capacity(items.len());
        for item in &items {
            item.check()?;
            leaves.push(Leaf {
                node: item.leaf(),
                name: &[],
            });
        }
        let top = top_of(ListKind::File, &leaves)?;
        Ok(Self {
            hash: file_hash(items.len() as u64, top.size, &top.hash),
            size: top.size,
            items,
        })
    }

    /// Reads the items of a whole list: 36 bytes for each piece.
    fn items_of(bytes: &[u8]) -> Result<Vec<PieceRef>> {
        if bytes.len() % LIST_ITEM_BYTES != 0 {
            return Err(invalid("a file's list is not a whole number of items"));
        }
        let mut reader = Reader::new(bytes, "a file's list");
        let mut items = Vec::with_capacity(bytes.len() / LIST_ITEM_BYTES);
        while !reader.is_empty() {
            items.push(PieceRef::decode(&mut reader)?);
        }
        Ok(items)
    }

    /// Reads a whole list: 36 bytes for each piece.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::new(Self::items_of(bytes)?)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.items.len() * LIST_ITEM_BYTES);
        for item in &self.items {
            item.encode_into(&mut out);
        }
        out
    }

    pub fn items(&self) -> &[PieceRef] {
        &self.items
    }

    /// How many pieces the file has.
    pub fn count(&self) -> u64 {
        self.items.len() as u64
    }

    /// How many bytes the file holds.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The file's hash. It covers the pieces, their order, how many there
    /// are and the size, and nothing about where the file sits.
    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    pub fn target(&self) -> Target {
        Target {
            kind: Kind::File,
            hash: self.hash,
            size: self.size,
        }
    }

    /// How many bytes the list takes.
    pub fn encoded_len(&self) -> u64 {
        self.items.len() as u64 * LIST_ITEM_BYTES as u64
    }

    /// Whether every piece has a length that `cutting` gives.
    pub fn check_cutting(&self, cutting: Cutting) -> Result<()> {
        cutting.check_count(self.size, self.count())?;
        let last = self.items.len().saturating_sub(1);
        for (index, item) in self.items.iter().enumerate() {
            cutting.check_length(item.length, index == last)?;
        }
        Ok(())
    }

    fn leaves(&self) -> Vec<Leaf<'static>> {
        self.items
            .iter()
            .map(|item| Leaf {
                node: item.leaf(),
                name: &[],
            })
            .collect()
    }

    /// Shows pieces `start` up to, not including, `end`. This hashes the
    /// whole list each time: keep an [`OpenFile`] to show many parts.
    pub fn open(&self, start: u64, end: u64) -> Result<FileRun> {
        let tree = ListTree::build(ListKind::File, &self.leaves())?;
        self.open_with(&tree, start, end)
    }

    fn open_with(&self, tree: &ListTree, start: u64, end: u64) -> Result<FileRun> {
        let carried = tree.open(start, end)?;
        Ok(FileRun {
            count: self.count(),
            start,
            items: self.items[start as usize..end as usize].to_vec(),
            carried,
        })
    }
}

/// A file's list with its tree kept, for showing many parts of it, and for
/// finding the pieces that hold a stretch of bytes.
#[derive(Clone, Debug)]
pub struct OpenFile {
    list: Arc<FileList>,
    tree: ListTree,
    /// Where each piece starts, and after the last one the file's size.
    starts: Vec<u64>,
}

impl OpenFile {
    pub fn new(list: FileList) -> Result<Self> {
        Self::shared(Arc::new(list))
    }

    /// As [`OpenFile::new`], for a list that others hold too.
    pub fn shared(list: Arc<FileList>) -> Result<Self> {
        let tree = ListTree::build(ListKind::File, &list.leaves())?;
        Ok(Self::with_tree(list, tree))
    }

    /// Reads a whole list as [`FileList::decode`] does, and keeps its tree.
    /// The list is hashed once for both.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let items = FileList::items_of(bytes)?;
        let leaves: Vec<Leaf<'static>> = items
            .iter()
            .map(|item| Leaf {
                node: item.leaf(),
                name: &[],
            })
            .collect();
        let tree = ListTree::build(ListKind::File, &leaves)?;
        let top = tree.top()?;
        let list = FileList {
            hash: file_hash(items.len() as u64, top.size, &top.hash),
            size: top.size,
            items,
        };
        Ok(Self::with_tree(Arc::new(list), tree))
    }

    fn with_tree(list: Arc<FileList>, tree: ListTree) -> Self {
        let mut starts = Vec::with_capacity(list.items.len() + 1);
        let mut at = 0_u64;
        for item in &list.items {
            starts.push(at);
            at += u64::from(item.length);
        }
        starts.push(at);
        Self { list, tree, starts }
    }

    pub fn list(&self) -> &FileList {
        &self.list
    }

    /// The list, to hold beside this.
    pub fn shared_list(&self) -> Arc<FileList> {
        Arc::clone(&self.list)
    }

    /// The byte at which piece `index` starts. The count gives the size.
    pub fn start_of(&self, index: u64) -> Option<u64> {
        self.starts.get(usize::try_from(index).ok()?).copied()
    }

    /// The pieces that hold the `length` bytes from `offset`: the first one's
    /// number, and the number after the last one. The stretch must lie
    /// inside the file and hold at least one byte.
    pub fn pieces_for(&self, offset: u64, length: u64) -> Result<(u64, u64)> {
        let end = offset
            .checked_add(length)
            .filter(|end| length > 0 && *end <= self.list.size)
            .ok_or_else(|| invalid("a stretch of bytes is outside the file"))?;
        // Every piece holds a byte, so the starts ascend and each is found.
        let first = self.starts.partition_point(|start| *start <= offset) - 1;
        let after = self.starts.partition_point(|start| *start < end);
        Ok((first as u64, after as u64))
    }

    /// Shows pieces `start` up to, not including, `end`.
    pub fn open(&self, start: u64, end: u64) -> Result<FileRun> {
        self.list.open_with(&self.tree, start, end)
    }

    /// Shows the pieces that hold the `length` bytes from `offset`.
    pub fn open_bytes(&self, offset: u64, length: u64) -> Result<FileRun> {
        let (start, end) = self.pieces_for(offset, length)?;
        self.open(start, end)
    }
}

/// A run of a file's list, with the nodes that stand for the rest of it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileRun {
    count: u64,
    start: u64,
    items: Vec<PieceRef>,
    carried: Vec<Carried>,
}

impl FileRun {
    /// How many pieces the whole file is said to have.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The number of the first piece shown.
    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn items(&self) -> &[PieceRef] {
        &self.items
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(22 + self.items.len() * LIST_ITEM_BYTES + self.carried.len() * 40);
        out.extend_from_slice(&self.count.to_be_bytes());
        out.extend_from_slice(&self.start.to_be_bytes());
        out.extend_from_slice(&(self.items.len() as u32).to_be_bytes());
        for item in &self.items {
            item.encode_into(&mut out);
        }
        out.extend_from_slice(&(self.carried.len() as u16).to_be_bytes());
        for carried in &self.carried {
            out.extend_from_slice(carried.node.hash.as_bytes());
            out.extend_from_slice(&carried.node.size.to_be_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes, "a run of a file's list");
        let (count, start, shown) = run_header(&mut reader)?;
        if shown == 0 || reader.remaining() / LIST_ITEM_BYTES < shown {
            return Err(invalid(
                "a run of a file's list is cut short, or shows nothing",
            ));
        }
        let mut items = Vec::with_capacity(shown);
        for _ in 0..shown {
            items.push(PieceRef::decode(&mut reader)?);
        }
        let mut carried = Vec::new();
        for _ in 0..carried_count(&mut reader)? {
            carried.push(Carried {
                node: Node {
                    hash: reader.hash()?,
                    size: reader.u64()?,
                },
                first_name: Vec::new(),
            });
        }
        reader.finish()?;
        Ok(Self {
            count,
            start,
            items,
            carried,
        })
    }

    /// Checks the run against the file it is said to be a part of, and gives
    /// the byte of the file at which the run starts. With a way of cutting,
    /// the pieces' lengths are held to it too.
    pub fn check(&self, file: &Target, cutting: Option<Cutting>) -> Result<u64> {
        file.require(Kind::File)?;
        if let Some(cutting) = cutting {
            cutting.check_count(file.size, self.count)?;
            for (place, item) in (self.start..).zip(&self.items) {
                cutting.check_length(item.length, place + 1 == self.count)?;
            }
        }
        let leaves: Vec<Leaf<'_>> = self
            .items
            .iter()
            .map(|item| Leaf {
                node: item.leaf(),
                name: &[],
            })
            .collect();
        let shown = check_opening(
            ListKind::File,
            self.count,
            self.start,
            &leaves,
            &self.carried,
        )?;
        confirm(file, self.count, shown.top)?;
        Ok(shown.offset)
    }
}

/// What every run starts with: how many items the whole list has, the place
/// of the first one shown, and how many are shown.
fn run_header(reader: &mut Reader<'_>) -> Result<(u64, u64, usize)> {
    let count = reader.u64()?;
    let start = reader.u64()?;
    let shown = reader.u32()?;
    let inside = start
        .checked_add(u64::from(shown))
        .is_some_and(|end| end <= count);
    if count > MAX_LIST_ITEMS || !inside {
        return Err(invalid("a run lies outside its list"));
    }
    Ok((count, start, shown as usize))
}

fn carried_count(reader: &mut Reader<'_>) -> Result<usize> {
    let count = usize::from(reader.u16()?);
    if count > MAX_CARRIED_NODES {
        return Err(invalid("a run carries more nodes than any list needs"));
    }
    Ok(count)
}

/// A folder: the list of its entries, sorted by name, with no name twice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FolderList {
    entries: Vec<Entry>,
    size: u64,
    hash: Hash,
    encoded_len: u64,
}

impl FolderList {
    /// The folder with these entries. They must be in the order of their
    /// names' bytes, with no name twice. No entries is the empty folder.
    pub fn new(entries: Vec<Entry>) -> Result<Self> {
        let leaves: Vec<Leaf<'_>> = entries
            .iter()
            .map(|entry| Leaf {
                node: entry.leaf(),
                name: entry.name.as_bytes(),
            })
            .collect();
        let top = top_of(ListKind::Folder, &leaves)?;
        let encoded_len = entries.iter().map(|entry| entry.encoded_len() as u64).sum();
        Ok(Self {
            hash: folder_hash(entries.len() as u64, top.size, &top.hash),
            size: top.size,
            encoded_len,
            entries,
        })
    }

    /// Reads the entries of a whole list, one after another.
    fn entries_of(bytes: &[u8]) -> Result<Vec<Entry>> {
        let mut reader = Reader::new(bytes, "a folder's list");
        let mut entries = Vec::new();
        while !reader.is_empty() {
            entries.push(Entry::decode(&mut reader)?);
        }
        Ok(entries)
    }

    /// Reads a whole list: its entries, one after another.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::new(Self::entries_of(bytes)?)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len as usize);
        for entry in &self.entries {
            entry.encode_into(&mut out);
        }
        out
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// How many entries the folder has.
    pub fn count(&self) -> u64 {
        self.entries.len() as u64
    }

    /// How many bytes of file content are under the folder.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The folder's hash. It covers every entry: its name, its kind, its
    /// size, its hash and its extra data. It does not cover a name for the
    /// folder itself.
    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    pub fn target(&self) -> Target {
        Target {
            kind: Kind::Folder,
            hash: self.hash,
            size: self.size,
        }
    }

    /// How many bytes the list takes.
    pub fn encoded_len(&self) -> u64 {
        self.encoded_len
    }

    /// The entry with this name.
    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.entries
            .binary_search_by(|entry| entry.name.as_str().cmp(name))
            .ok()
            .map(|index| &self.entries[index])
    }

    /// The one place where `name` can be: that of the last entry whose name
    /// does not sort after it, or the first place. An empty folder has none.
    pub fn place_of(&self, name: &str) -> Option<u64> {
        if self.entries.is_empty() {
            return None;
        }
        let not_after = self
            .entries
            .partition_point(|entry| entry.name.as_str() <= name);
        Some(not_after.saturating_sub(1) as u64)
    }

    fn leaves(&self) -> Vec<Leaf<'_>> {
        self.entries
            .iter()
            .map(|entry| Leaf {
                node: entry.leaf(),
                name: entry.name.as_bytes(),
            })
            .collect()
    }

    /// Shows entries `start` up to, not including, `end`. This hashes the
    /// whole list each time: keep an [`OpenFolder`] to show many parts.
    pub fn open(&self, start: u64, end: u64) -> Result<FolderRun> {
        let tree = ListTree::build(ListKind::Folder, &self.leaves())?;
        self.open_with(&tree, start, end)
    }

    /// Shows the entry at the one place where `name` can be. It answers
    /// whether the folder has the name, whichever way the answer falls.
    pub fn open_name(&self, name: &str) -> Result<FolderRun> {
        let tree = ListTree::build(ListKind::Folder, &self.leaves())?;
        self.open_name_with(&tree, name)
    }

    fn open_with(&self, tree: &ListTree, start: u64, end: u64) -> Result<FolderRun> {
        let carried = tree.open(start, end)?;
        Ok(FolderRun {
            count: self.count(),
            start,
            entries: self.entries[start as usize..end as usize].to_vec(),
            carried,
        })
    }

    fn open_name_with(&self, tree: &ListTree, name: &str) -> Result<FolderRun> {
        check_name(name)?;
        match self.place_of(name) {
            Some(place) => self.open_with(tree, place, place + 1),
            None => Ok(FolderRun {
                count: 0,
                start: 0,
                entries: Vec::new(),
                carried: Vec::new(),
            }),
        }
    }
}

/// A folder's list with its tree kept, for showing many parts of it.
#[derive(Clone, Debug)]
pub struct OpenFolder {
    list: FolderList,
    tree: ListTree,
}

impl OpenFolder {
    pub fn new(list: FolderList) -> Result<Self> {
        let tree = ListTree::build(ListKind::Folder, &list.leaves())?;
        Ok(Self { list, tree })
    }

    /// Reads a whole list as [`FolderList::decode`] does, and keeps its tree.
    /// The list is hashed once for both.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let entries = FolderList::entries_of(bytes)?;
        let leaves: Vec<Leaf<'_>> = entries
            .iter()
            .map(|entry| Leaf {
                node: entry.leaf(),
                name: entry.name.as_bytes(),
            })
            .collect();
        let tree = ListTree::build(ListKind::Folder, &leaves)?;
        let top = tree.top()?;
        drop(leaves);
        let encoded_len = entries.iter().map(|entry| entry.encoded_len() as u64).sum();
        let list = FolderList {
            hash: folder_hash(entries.len() as u64, top.size, &top.hash),
            size: top.size,
            encoded_len,
            entries,
        };
        Ok(Self { list, tree })
    }

    pub fn list(&self) -> &FolderList {
        &self.list
    }

    /// Shows entries `start` up to, not including, `end`.
    pub fn open(&self, start: u64, end: u64) -> Result<FolderRun> {
        self.list.open_with(&self.tree, start, end)
    }

    /// Shows the entry at the one place where `name` can be.
    pub fn open_name(&self, name: &str) -> Result<FolderRun> {
        self.list.open_name_with(&self.tree, name)
    }
}

/// A run of a folder's list, with the nodes that stand for the rest of it.
/// A run of an empty folder shows nothing, and carries nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FolderRun {
    count: u64,
    start: u64,
    entries: Vec<Entry>,
    carried: Vec<Carried>,
}

impl FolderRun {
    /// The run of an empty folder: it shows nothing, and carries nothing.
    pub(crate) fn empty() -> Self {
        Self {
            count: 0,
            start: 0,
            entries: Vec::new(),
            carried: Vec::new(),
        }
    }

    /// How many entries the whole folder is said to have.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The place of the first entry shown.
    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.count.to_be_bytes());
        out.extend_from_slice(&self.start.to_be_bytes());
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for entry in &self.entries {
            entry.encode_into(&mut out);
        }
        out.extend_from_slice(&(self.carried.len() as u16).to_be_bytes());
        for carried in &self.carried {
            out.extend_from_slice(carried.node.hash.as_bytes());
            out.extend_from_slice(&carried.node.size.to_be_bytes());
            out.extend_from_slice(&(carried.first_name.len() as u16).to_be_bytes());
            out.extend_from_slice(&carried.first_name);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes, "a run of a folder's list");
        let (count, start, shown) = run_header(&mut reader)?;
        if (shown == 0) != (count == 0) {
            return Err(invalid("a run of a folder's list shows nothing"));
        }
        // An entry takes 45 bytes at least, so a count is held to the bytes.
        if reader.remaining() / 45 < shown {
            return Err(invalid("a run of a folder's list is cut short"));
        }
        let mut entries = Vec::with_capacity(shown);
        for _ in 0..shown {
            entries.push(Entry::decode(&mut reader)?);
        }
        let mut carried = Vec::new();
        for index in 0..carried_count(&mut reader)? {
            let node = Node {
                hash: reader.hash()?,
                size: reader.u64()?,
            };
            let name_len = usize::from(reader.u16()?);
            // The first carried node of a run that does not start the list
            // is the node that begins the list. No fork hashes a name for
            // it, so it comes with none. Every other one comes with a name.
            let begins_the_list = index == 0 && start > 0;
            if begins_the_list != (name_len == 0) {
                return Err(invalid(if begins_the_list {
                    "the carried node that begins a folder's list has a name"
                } else {
                    "a carried node of a folder's list has no name"
                }));
            }
            if name_len > MAX_NAME_BYTES {
                return Err(invalid("a carried name is longer than 255 bytes"));
            }
            carried.push(Carried {
                node,
                first_name: reader.take(name_len)?.to_vec(),
            });
        }
        reader.finish()?;
        if count == 0 && !carried.is_empty() {
            return Err(invalid("a run of an empty folder carries nodes"));
        }
        Ok(Self {
            count,
            start,
            entries,
            carried,
        })
    }

    fn leaves(&self) -> Vec<Leaf<'_>> {
        self.entries
            .iter()
            .map(|entry| Leaf {
                node: entry.leaf(),
                name: entry.name.as_bytes(),
            })
            .collect()
    }

    /// Checks the run against the folder it is said to be a part of. Every
    /// entry shown is then an entry of that folder, at the place where a
    /// search for its name ends.
    pub fn check(&self, folder: &Target) -> Result<()> {
        folder.require(Kind::Folder)?;
        if self.count == 0 {
            if !self.entries.is_empty() || !self.carried.is_empty() || self.start != 0 {
                return Err(invalid("a run of an empty folder shows something"));
            }
            return confirm(folder, 0, EMPTY_LIST);
        }
        let shown = check_opening(
            ListKind::Folder,
            self.count,
            self.start,
            &self.leaves(),
            &self.carried,
        )?;
        confirm(folder, self.count, shown.top)
    }

    /// Checks the run as the answer to "what is under `name` in this
    /// folder". It gives the entry, or nothing when the folder has no entry
    /// of that name. Either answer is proven: the run must show the one place
    /// where the name can be.
    pub fn check_name(&self, folder: &Target, name: &str) -> Result<Option<&Entry>> {
        check_name(name)?;
        folder.require(Kind::Folder)?;
        if self.count == 0 {
            self.check(folder)?;
            return Ok(None);
        }
        let [entry] = self.entries.as_slice() else {
            return Err(invalid("a name is answered by one entry, and no more"));
        };
        let leaf = Leaf {
            node: entry.leaf(),
            name: entry.name.as_bytes(),
        };
        let (shown, present) =
            check_lookup(self.count, self.start, leaf, name.as_bytes(), &self.carried)?;
        confirm(folder, self.count, shown.top)?;
        Ok(present.then_some(entry))
    }
}

/// What a tree says about itself as a whole: how much a store has to keep
/// for it. Each counts a thing once, however often the tree uses it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Totals {
    /// How many different pieces the tree has.
    pub pieces: u64,
    /// How many bytes those pieces hold.
    pub piece_bytes: u64,
    /// How many bytes the lists of its different files and folders take.
    pub list_bytes: u64,
}

/// A tree's record: the file or folder on top, the tree's totals, and its
/// extra data. The hash of the record is the tree's root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    top: Target,
    totals: Totals,
    extra: ExtraData,
    cutting: Cutting,
}

impl Record {
    /// The record of a tree with `top` on top. How the tree was cut is
    /// written into the extra data, in place of anything the caller put under
    /// that name.
    pub fn new(
        top: Target,
        totals: Totals,
        cutting: Cutting,
        mut extra: ExtraData,
    ) -> Result<Self> {
        extra.remove(CUTTING_KEY);
        extra.insert(CUTTING_KEY, cutting.tag())?;
        check_totals(&top, &totals)?;
        Ok(Self {
            top,
            totals,
            extra,
            cutting,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes, "a record");
        if reader.u8()? != RECORD_MARK {
            return Err(invalid("a record does not start with its mark"));
        }
        let kind = Kind::from_byte(reader.u8()?)?;
        let size = reader.u64()?;
        let hash = reader.hash()?;
        let totals = Totals {
            pieces: reader.u64()?,
            piece_bytes: reader.u64()?,
            list_bytes: reader.u64()?,
        };
        let extra = ExtraData::decode(&mut reader)?;
        reader.finish()?;
        let cutting = Cutting::from_tag(
            extra
                .get(CUTTING_KEY)
                .ok_or_else(|| invalid("a record does not say how the tree was cut"))?,
        )?;
        let top = Target { kind, hash, size };
        check_totals(&top, &totals)?;
        Ok(Self {
            top,
            totals,
            extra,
            cutting,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(66 + self.extra.encoded_len());
        out.push(RECORD_MARK);
        out.push(self.top.kind.byte());
        out.extend_from_slice(&self.top.size.to_be_bytes());
        out.extend_from_slice(self.top.hash.as_bytes());
        out.extend_from_slice(&self.totals.pieces.to_be_bytes());
        out.extend_from_slice(&self.totals.piece_bytes.to_be_bytes());
        out.extend_from_slice(&self.totals.list_bytes.to_be_bytes());
        self.extra.encode_into(&mut out);
        out
    }

    /// The tree's root: the hash of the record.
    pub fn root(&self) -> Root {
        Root::of_record(&self.encode())
    }

    /// The file or folder on top of the tree.
    pub fn top(&self) -> Target {
        self.top
    }

    pub fn totals(&self) -> Totals {
        self.totals
    }

    pub fn extra(&self) -> &ExtraData {
        &self.extra
    }

    /// How the tree's files were cut.
    pub fn cutting(&self) -> Cutting {
        self.cutting
    }
}

/// What must hold between a record's numbers in any tree. Whether the totals
/// are right is checked against the whole tree.
fn check_totals(top: &Target, totals: &Totals) -> Result<()> {
    let fits = totals.pieces <= totals.piece_bytes
        && totals.piece_bytes <= top.size
        && totals
            .pieces
            .checked_mul(MAX_PIECE_BYTES as u64)
            .is_none_or(|most| totals.piece_bytes <= most)
        && totals
            .pieces
            .checked_mul(LIST_ITEM_BYTES as u64)
            .is_some_and(|least| totals.list_bytes >= least)
        && (top.kind == Kind::Folder || totals.list_bytes % LIST_ITEM_BYTES as u64 == 0);
    if fits {
        Ok(())
    } else {
        Err(invalid("a record's totals cannot belong to any tree"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn piece(seed: u8, length: u32) -> PieceRef {
        PieceRef {
            hash: Hash::of(&[seed]),
            length,
        }
    }

    fn file(seed: u8) -> Target {
        FileList::new(vec![piece(seed, u32::from(seed) + 1)])
            .unwrap()
            .target()
    }

    fn entry(name: &str, target: Target) -> Entry {
        Entry::new(name, target, ExtraData::new()).unwrap()
    }

    fn folder(names: &[&str]) -> FolderList {
        FolderList::new(
            names
                .iter()
                .enumerate()
                .map(|(index, name)| entry(name, file(index as u8)))
                .collect(),
        )
        .unwrap()
    }

    fn sha(parts: &[&[u8]]) -> Hash {
        Hash::of(&parts.concat())
    }

    fn u64be(value: u64) -> [u8; 8] {
        value.to_be_bytes()
    }

    /// An entry's bytes, written by hand.
    fn entry_bytes(kind: u8, size: u64, hash: &Hash, name: &[u8], extra: &[u8]) -> Vec<u8> {
        let mut bytes = vec![kind];
        bytes.extend_from_slice(&size.to_be_bytes());
        bytes.extend_from_slice(hash.as_bytes());
        bytes.extend_from_slice(&(name.len() as u16).to_be_bytes());
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(extra);
        bytes
    }

    const NO_EXTRA: [u8; 2] = [0, 0];

    #[test]
    fn every_hash_covers_exactly_the_bytes_the_format_names() {
        // A file's list item, and its leaf.
        let first = piece(1, 5);
        let second = piece(2, 7);
        let mut item = first.hash.as_bytes().to_vec();
        item.extend_from_slice(&5_u32.to_be_bytes());
        let one = FileList::new(vec![first]).unwrap();
        assert_eq!(one.encode(), item);
        let first_leaf = sha(&[&[0x00], &item]);
        assert_eq!(
            first.leaf(),
            Node {
                hash: first_leaf,
                size: 5
            }
        );

        // A file of one piece: the leaf is the top of its list.
        assert_eq!(
            *one.hash(),
            sha(&[&[0x10], &u64be(1), &u64be(5), first_leaf.as_bytes()])
        );

        // A file of two pieces: the top is a fork over the two leaves.
        let second_leaf = second.leaf().hash;
        let top = sha(&[
            &[0x01],
            first_leaf.as_bytes(),
            &u64be(5),
            &u64be(1),
            second_leaf.as_bytes(),
            &u64be(7),
            &u64be(1),
        ]);
        let two = FileList::new(vec![first, second]).unwrap();
        assert_eq!(two.size(), 12);
        assert_eq!(
            *two.hash(),
            sha(&[&[0x10], &u64be(2), &u64be(12), top.as_bytes()])
        );

        // An entry with extra data, and its leaf.
        let extra = ExtraData::new()
            .with("mode", "644")
            .unwrap()
            .with("a", [0xff_u8])
            .unwrap();
        let named = Entry::new("b.txt", two.target(), extra).unwrap();
        let mut extra_bytes = vec![0, 2];
        extra_bytes.extend_from_slice(&[0, 1, b'a', 0, 1, 0xff]);
        extra_bytes.extend_from_slice(&[0, 4, b'm', b'o', b'd', b'e', 0, 3, b'6', b'4', b'4']);
        let named_bytes = entry_bytes(1, 12, two.hash(), b"b.txt", &extra_bytes);
        let mut encoded = Vec::new();
        named.encode_into(&mut encoded);
        assert_eq!(encoded, named_bytes);
        assert_eq!(named.encoded_len(), named_bytes.len());
        let named_leaf = sha(&[&[0x02], &named_bytes]);
        assert_eq!(
            named.leaf(),
            Node {
                hash: named_leaf,
                size: 12
            }
        );

        // A folder of an empty folder and that file.
        let empty = FolderList::new(Vec::new()).unwrap();
        assert_eq!(
            *empty.hash(),
            sha(&[&[0x11], &u64be(0), &u64be(0), &[0; 32]])
        );
        let inner = entry("a", empty.target());
        let inner_bytes = entry_bytes(2, 0, empty.hash(), b"a", &NO_EXTRA);
        let inner_leaf = sha(&[&[0x02], &inner_bytes]);
        let both = FolderList::new(vec![inner, named]).unwrap();
        assert_eq!(
            both.encode(),
            [inner_bytes.clone(), named_bytes.clone()].concat()
        );
        assert_eq!(
            both.encoded_len(),
            (inner_bytes.len() + named_bytes.len()) as u64
        );
        let folder_top = sha(&[
            &[0x03],
            inner_leaf.as_bytes(),
            &u64be(0),
            &u64be(1),
            named_leaf.as_bytes(),
            &u64be(12),
            &u64be(1),
            b"b.txt",
        ]);
        assert_eq!(
            *both.hash(),
            sha(&[&[0x11], &u64be(2), &u64be(12), folder_top.as_bytes()])
        );

        // The record, and the root.
        let totals = Totals {
            pieces: 2,
            piece_bytes: 12,
            list_bytes: 72 + both.encoded_len(),
        };
        let record = Record::new(
            both.target(),
            totals,
            Cutting::fixed(5).unwrap(),
            ExtraData::new(),
        )
        .unwrap();
        let mut record_bytes = vec![0x20, 2];
        record_bytes.extend_from_slice(&u64be(12));
        record_bytes.extend_from_slice(both.hash().as_bytes());
        record_bytes.extend_from_slice(&u64be(2));
        record_bytes.extend_from_slice(&u64be(12));
        record_bytes.extend_from_slice(&u64be(totals.list_bytes));
        record_bytes.extend_from_slice(&[0, 1, 0, 8]);
        record_bytes.extend_from_slice(b"chunking");
        record_bytes.extend_from_slice(&[0, 7]);
        record_bytes.extend_from_slice(b"fixed-5");
        assert_eq!(record.encode(), record_bytes);
        assert_eq!(*record.root().as_hash(), Hash::of(&record_bytes));
        assert_eq!(Record::decode(&record_bytes).unwrap(), record);
    }

    #[test]
    fn the_same_thing_has_the_same_hash_wherever_it_is() {
        // A file's hash covers its pieces, and nothing about where it sits.
        let list = FileList::new(vec![piece(1, 5), piece(2, 7), piece(1, 5)]).unwrap();
        let here = FolderList::new(vec![entry("a.bin", list.target())]).unwrap();
        let there = FolderList::new(vec![
            entry("other", file(9)),
            entry("renamed.bin", list.target()),
        ])
        .unwrap();
        assert_eq!(here.entries()[0].hash(), there.entries()[1].hash());
        assert_ne!(here.hash(), there.hash());

        // A folder's hash covers its entries, and no name for itself.
        let outer = FolderList::new(vec![
            entry("one", here.target()),
            entry("two", here.target()),
        ])
        .unwrap();
        assert_eq!(outer.entries()[0].hash(), outer.entries()[1].hash());
        assert_eq!(outer.size(), 2 * here.size());

        // Every empty file is one file, and it is not the empty folder.
        let empty_file = FileList::new(Vec::new()).unwrap();
        assert_eq!(*empty_file.hash(), file_hash(0, 0, &Hash::ZERO));
        assert_eq!(empty_file, FileList::decode(&[]).unwrap());
        let empty_folder = FolderList::decode(&[]).unwrap();
        assert_eq!(*empty_folder.hash(), folder_hash(0, 0, &Hash::ZERO));
        assert_ne!(empty_file.hash(), empty_folder.hash());

        // The pieces' order, their number and their lengths are all covered.
        let other_order = FileList::new(vec![piece(2, 7), piece(1, 5), piece(1, 5)]).unwrap();
        let one_less = FileList::new(vec![piece(1, 5), piece(2, 7)]).unwrap();
        let other_length = FileList::new(vec![piece(1, 5), piece(2, 6), piece(1, 6)]).unwrap();
        assert_eq!(other_length.size(), list.size());
        for other in [&other_order, &one_less, &other_length] {
            assert_ne!(other.hash(), list.hash());
        }
    }

    #[test]
    fn an_entry_differs_with_its_name_kind_size_hash_and_extra_data() {
        let target = file(1);
        let base = FolderList::new(vec![entry("a", target)]).unwrap();
        let renamed = FolderList::new(vec![entry("b", target)]).unwrap();
        let as_folder = FolderList::new(vec![entry(
            "a",
            Target {
                kind: Kind::Folder,
                ..target
            },
        )])
        .unwrap();
        let resized = FolderList::new(vec![entry(
            "a",
            Target {
                size: target.size + 1,
                ..target
            },
        )])
        .unwrap();
        let other_file = FolderList::new(vec![entry("a", file(2))]).unwrap();
        let with_extra = FolderList::new(vec![Entry::new(
            "a",
            target,
            ExtraData::new().with("mode", "755").unwrap(),
        )
        .unwrap()])
        .unwrap();
        for other in [&renamed, &as_folder, &resized, &other_file, &with_extra] {
            assert_ne!(other.hash(), base.hash());
        }
    }

    #[test]
    fn names_are_held_to_the_rules() {
        let long = "x".repeat(255);
        for name in [
            "a",
            "A",
            ".a",
            "...",
            "a b",
            "a\\b",
            "\u{e9}t\u{e9}",
            long.as_str(),
        ] {
            assert!(check_name(name).is_ok(), "{name:?}");
        }
        let too_long = "x".repeat(256);
        for name in ["", ".", "..", "a/b", "/", "a\0b", too_long.as_str()] {
            assert!(check_name(name).is_err(), "{name:?}");
            assert!(
                Entry::new(name, file(1), ExtraData::new()).is_err(),
                "{name:?}"
            );
        }
        // Names are compared as bytes: these are two names.
        assert!(FolderList::new(vec![entry("File", file(1)), entry("file", file(2))]).is_ok());
    }

    #[test]
    fn a_folder_list_is_sorted_by_its_names_bytes_with_no_name_twice() {
        assert!(FolderList::new(vec![entry("b", file(1)), entry("a", file(2))]).is_err());
        assert!(FolderList::new(vec![entry("a", file(1)), entry("a", file(1))]).is_err());
        // Bytes, not letters: "Z" sorts before "a", and "a" before "a0".
        let list = folder(&["Z", "a", "a0", "b"]);
        assert_eq!(list.get("a0").unwrap().name(), "a0");
        assert!(list.get("a1").is_none());
        let unsorted = [list.encode(), folder(&["B"]).encode()].concat();
        assert!(FolderList::decode(&unsorted).is_err());
        let twice = [folder(&["a"]).encode(), folder(&["a"]).encode()].concat();
        assert!(FolderList::decode(&twice).is_err());
    }

    #[test]
    fn extra_data_is_held_to_its_limits_and_read_in_one_way_only() {
        let mut extra = ExtraData::new();
        assert!(extra.insert("", "x").is_err());
        assert!(extra.insert("n".repeat(65), "x").is_err());
        assert!(extra.insert("n".repeat(64), vec![0_u8; 1024]).is_ok());
        assert!(extra.insert("big", vec![0_u8; 1025]).is_err());
        for index in 0..31 {
            extra.insert(format!("k{index:02}"), "v").unwrap();
        }
        assert_eq!(extra.len(), 32);
        assert!(extra.insert("one-more", "v").is_err());
        assert!(
            extra.insert("k00", "again").is_ok(),
            "a name that is there is set again"
        );
        assert_eq!(extra.text("k00"), Some("again"));

        let read = |bytes: &[u8]| {
            let mut reader = Reader::new(bytes, "extra data");
            ExtraData::decode(&mut reader).and_then(|extra| reader.finish().map(|()| extra))
        };
        let mut written = Vec::new();
        extra.encode_into(&mut written);
        assert_eq!(written.len(), extra.encoded_len());
        assert_eq!(read(&written).unwrap(), extra);

        assert!(read(&[0, 0]).unwrap().is_empty());
        let good = [0, 2, 0, 1, b'a', 0, 1, 1, 0, 1, b'b', 0, 0];
        assert_eq!(read(&good).unwrap().len(), 2);
        let out_of_order = [0, 2, 0, 1, b'b', 0, 0, 0, 1, b'a', 0, 0];
        let name_twice = [0, 2, 0, 1, b'a', 0, 0, 0, 1, b'a', 0, 0];
        let empty_name = [0, 1, 0, 0, 0, 0];
        let not_utf8 = [0, 1, 0, 1, 0xff, 0, 0];
        let cut_short = [0, 1, 0, 1, b'a', 0, 5, 1];
        let count_too_high = [0, 2, 0, 1, b'a', 0, 0];
        let trailing = [0, 0, 0];
        for bad in [
            &out_of_order[..],
            &name_twice,
            &empty_name,
            &not_utf8,
            &cut_short,
            &count_too_high,
            &trailing,
            &[0, 33],
            &[],
        ] {
            assert!(read(bad).is_err(), "{bad:?}");
        }
        let mut long_name = vec![0, 1, 0, 65];
        long_name.extend_from_slice(&[b'n'; 65]);
        long_name.extend_from_slice(&[0, 0]);
        assert!(read(&long_name).is_err());
        let mut long_value = vec![0, 1, 0, 1, b'a', 0x04, 0x01];
        long_value.extend_from_slice(&[0; 1025]);
        assert!(read(&long_value).is_err());
    }

    #[test]
    fn lists_are_read_strictly() {
        let hash = Hash::of(b"x");
        // A file's list: whole items, and pieces of 1 byte to 8 MiB.
        let item = |length: u32| [hash.as_bytes().as_slice(), &length.to_be_bytes()].concat();
        assert!(FileList::decode(&item(1)).is_ok());
        assert!(FileList::decode(&item(MAX_PIECE_BYTES as u32)).is_ok());
        assert!(FileList::decode(&item(0)).is_err());
        assert!(FileList::decode(&item(MAX_PIECE_BYTES as u32 + 1)).is_err());
        assert!(FileList::decode(&item(1)[..35]).is_err());
        assert!(FileList::decode(&[item(1), vec![0]].concat()).is_err());
        assert!(PieceRef::of(&[]).is_err());
        assert_eq!(PieceRef::of(b"x").unwrap(), PieceRef { hash, length: 1 });

        // A folder's list: every entry whole, of a known kind, validly named.
        assert!(FolderList::decode(&entry_bytes(1, 3, &hash, b"a", &NO_EXTRA)).is_ok());
        assert!(FolderList::decode(&entry_bytes(2, 3, &hash, b"a", &NO_EXTRA)).is_ok());
        for kind in [0, 3, 0xff] {
            assert!(FolderList::decode(&entry_bytes(kind, 3, &hash, b"a", &NO_EXTRA)).is_err());
        }
        for name in [
            &b""[..],
            b".",
            b"..",
            b"a/b",
            b"a\0",
            &[0xff, 0xfe],
            &[b'x'; 256],
        ] {
            let bytes = entry_bytes(1, 3, &hash, name, &NO_EXTRA);
            assert!(FolderList::decode(&bytes).is_err(), "{name:?}");
        }
        let whole = entry_bytes(1, 3, &hash, b"a", &NO_EXTRA);
        for cut in 1..whole.len() {
            assert!(FolderList::decode(&whole[..cut]).is_err(), "cut at {cut}");
        }
        assert!(FolderList::decode(&[whole.clone(), vec![0]].concat()).is_err());
        // A list's sizes are added up, and a sum that does not fit is refused.
        let huge = [
            entry_bytes(1, u64::MAX, &hash, b"a", &NO_EXTRA),
            entry_bytes(1, 1, &hash, b"b", &NO_EXTRA),
        ]
        .concat();
        assert!(matches!(
            FolderList::decode(&huge),
            Err(Error::SizeOverflow { .. })
        ));
    }

    #[test]
    fn a_record_is_read_strictly() {
        let top = folder(&["a", "b"]).target();
        let totals = Totals {
            pieces: 2,
            piece_bytes: 3,
            list_bytes: 200,
        };
        let extra = ExtraData::new()
            .with(CUTTING_KEY, "a caller cannot set this")
            .unwrap()
            .with(TIMESTAMP_KEY, "2026-11-12T00:00:00Z")
            .unwrap();
        let record = Record::new(top, totals, Cutting::FastCdcV1, extra).unwrap();
        assert_eq!(record.extra().text(CUTTING_KEY), Some("fastcdc-v1"));
        assert_eq!(record.cutting(), Cutting::FastCdcV1);
        assert_eq!(record.top(), top);
        assert_eq!(record.totals(), totals);
        let bytes = record.encode();
        assert_eq!(Record::decode(&bytes).unwrap(), record);
        assert_eq!(record.root(), Root::of_record(&bytes));

        for cut in 0..bytes.len() {
            assert!(Record::decode(&bytes[..cut]).is_err(), "cut at {cut}");
        }
        assert!(Record::decode(&[bytes.clone(), vec![0]].concat()).is_err());
        let mut other_mark = bytes.clone();
        other_mark[0] = 0x21;
        assert!(Record::decode(&other_mark).is_err());
        let mut other_kind = bytes.clone();
        other_kind[1] = 3;
        assert!(Record::decode(&other_kind).is_err());

        // A record that does not say how its tree was cut is no record.
        let mut untagged = bytes[..66].to_vec();
        untagged.extend_from_slice(&NO_EXTRA);
        assert!(Record::decode(&untagged).is_err());
        let mut unknown = bytes[..66].to_vec();
        unknown.extend_from_slice(&[0, 1, 0, 8]);
        unknown.extend_from_slice(b"chunking");
        unknown.extend_from_slice(&[0, 8]);
        unknown.extend_from_slice(b"fixed-2m");
        assert!(Record::decode(&unknown).is_err());

        // Totals that no tree can have.
        let bad_totals = [
            (3, 2, 200),            // more pieces than piece bytes
            (1, top.size + 1, 200), // more piece bytes than the tree holds
            (2, 3, 71),             // lists too short to name the pieces
            (0, 1, 0),              // bytes without pieces
        ];
        for (pieces, piece_bytes, list_bytes) in bad_totals {
            let totals = Totals {
                pieces,
                piece_bytes,
                list_bytes,
            };
            let made = Record::new(top, totals, Cutting::FastCdcV1, ExtraData::new());
            assert!(made.is_err(), "{totals:?}");
        }
        let file_top = FileList::new(vec![piece(1, 5)]).unwrap().target();
        let uneven = Totals {
            pieces: 1,
            piece_bytes: 5,
            list_bytes: 37,
        };
        assert!(Record::new(file_top, uneven, Cutting::FastCdcV1, ExtraData::new()).is_err());
    }

    #[test]
    fn a_way_of_cutting_has_one_spelling_and_holds_pieces_to_its_lengths() {
        assert_eq!(Cutting::FastCdcV1.tag(), "fastcdc-v1");
        assert_eq!(Cutting::fixed(16).unwrap().tag(), "fixed-16");
        for cutting in [
            Cutting::FastCdcV1,
            Cutting::fixed(1).unwrap(),
            Cutting::fixed(16).unwrap(),
            Cutting::fixed(MAX_PIECE_BYTES as u32).unwrap(),
        ] {
            assert_eq!(
                Cutting::from_tag(cutting.tag().as_bytes()).unwrap(),
                cutting
            );
        }
        for tag in [
            "",
            "fastcdc-v2",
            "FASTCDC-V1",
            "fastcdc-v1 ",
            "fixed-",
            "fixed-0",
            "fixed-016",
            "fixed-+16",
            "fixed-16 ",
            "fixed-2m",
            "fixed-8388609",
            "fixed-99999999",
            "fixed-4294967297",
        ] {
            assert!(Cutting::from_tag(tag.as_bytes()).is_err(), "{tag:?}");
        }

        let content = Cutting::FastCdcV1;
        let min = FASTCDC_MIN_SIZE as u32;
        let max = FASTCDC_MAX_SIZE as u32;
        assert!(content.check_length(min + 1, false).is_ok());
        assert!(content.check_length(max, false).is_ok());
        assert!(
            content.check_length(min, false).is_err(),
            "the cutter never stops there"
        );
        assert!(content.check_length(1, false).is_err());
        assert!(content.check_length(1, true).is_ok());
        assert!(content.check_length(max, true).is_ok());
        assert!(content.check_length(max + 1, true).is_err());
        assert!(content.check_length(0, true).is_err());

        let fixed = Cutting::fixed(16).unwrap();
        assert!(fixed.check_length(16, false).is_ok());
        assert!(fixed.check_length(15, false).is_err());
        assert!(fixed.check_length(17, false).is_err());
        assert!(fixed.check_length(1, true).is_ok());
        assert!(fixed.check_length(16, true).is_ok());
        assert!(fixed.check_length(17, true).is_err());
        assert!(fixed.check_length(0, true).is_err());
    }

    #[test]
    fn a_files_size_bounds_how_many_pieces_it_can_have() {
        let step = FASTCDC_MIN_SIZE as u64 + 1;
        let max = FASTCDC_MAX_SIZE as u64;
        let content = Cutting::FastCdcV1;
        assert_eq!(content.count_bounds(0), (0, 0));
        assert_eq!(content.count_bounds(1), (1, 1));
        assert_eq!(content.count_bounds(step), (1, 1));
        assert_eq!(content.count_bounds(step + 1), (1, 2));
        assert_eq!(content.count_bounds(max), (1, 16));
        assert_eq!(content.count_bounds(max + 1), (2, 16));
        assert_eq!(content.count_bounds(2 * step + 1), (1, 3));
        // A terabyte: at most about two million pieces, never a billion. The
        // most is 2,097,148 pieces of 524,289 bytes, and a last one of 4.
        let (fewest, most) = content.count_bounds(1 << 40);
        assert_eq!(fewest, 131_072);
        assert_eq!(most, 2_097_149);
        assert_eq!(2_097_148 * step + 4, 1 << 40);
        assert!(content.check_count(1 << 40, 500_000).is_ok());
        assert!(content.check_count(1 << 40, most + 1).is_err());
        assert!(content.check_count(1 << 40, fewest - 1).is_err());
        assert!(content.check_count(0, 1).is_err());

        // What the bounds say is what lists of fitting pieces can add up to.
        let fixed = Cutting::fixed(4).unwrap();
        for size in 0..40_u64 {
            let pieces = fixed.cut(&vec![0_u8; size as usize]).len() as u64;
            assert_eq!(fixed.count_bounds(size), (pieces, pieces), "size {size}");
        }
        let list = FileList::new(vec![piece(1, 4), piece(2, 4), piece(3, 3)]).unwrap();
        assert!(list.check_cutting(fixed).is_ok());
        assert!(list.check_cutting(Cutting::fixed(5).unwrap()).is_err());
        assert!(list.check_cutting(content).is_err());
        let short_in_the_middle =
            FileList::new(vec![piece(1, 4), piece(2, 3), piece(3, 4)]).unwrap();
        assert!(short_in_the_middle.check_cutting(fixed).is_err());
        assert!(FileList::new(Vec::new())
            .unwrap()
            .check_cutting(content)
            .is_ok());
    }

    #[test]
    fn every_run_of_a_file_checks_and_gives_the_byte_it_starts_at() {
        for count in 1..=17_u8 {
            let items: Vec<PieceRef> = (0..count)
                .map(|index| piece(index, u32::from(index % 5) + 1))
                .collect();
            let list = FileList::new(items.clone()).unwrap();
            let open = OpenFile::new(list.clone()).unwrap();
            let target = list.target();
            for start in 0..u64::from(count) {
                for end in start + 1..=u64::from(count) {
                    let run = open.open(start, end).unwrap();
                    assert_eq!(run, list.open(start, end).unwrap());
                    assert_eq!(FileRun::decode(&run.encode()).unwrap(), run);
                    let before: u64 = items[..start as usize]
                        .iter()
                        .map(|item| u64::from(item.length))
                        .sum();
                    assert_eq!(run.check(&target, None).unwrap(), before);
                    assert_eq!(open.start_of(start), Some(before));
                    assert_eq!(run.items(), &items[start as usize..end as usize]);
                }
            }
            assert_eq!(open.start_of(u64::from(count)), Some(list.size()));
            assert_eq!(open.start_of(u64::from(count) + 1), None);
        }
    }

    #[test]
    fn a_run_of_a_file_is_refused_for_any_other_file_count_or_place() {
        let items: Vec<PieceRef> = (0..9).map(|index| piece(index, 4)).collect();
        let list = FileList::new(items).unwrap();
        let target = list.target();
        let run = list.open(3, 5).unwrap();
        assert_eq!(run.check(&target, None).unwrap(), 12);

        // Another file, another size, and a folder.
        assert!(matches!(
            run.check(&file(1), None),
            Err(Error::SizeMismatch { .. })
        ));
        let other_hash = Target {
            hash: Hash::of(b"other"),
            ..target
        };
        assert!(matches!(
            run.check(&other_hash, None),
            Err(Error::HashMismatch { .. })
        ));
        let other_size = Target {
            size: target.size + 1,
            ..target
        };
        assert!(matches!(
            run.check(&other_size, None),
            Err(Error::SizeMismatch { .. })
        ));
        let as_folder = Target {
            kind: Kind::Folder,
            ..target
        };
        assert!(run.check(&as_folder, None).is_err());

        // The same bytes with another count, another place, or one item less.
        let bytes = run.encode();
        let with = |at: usize, value: u8| {
            let mut changed = bytes.clone();
            changed[at] = value;
            FileRun::decode(&changed).and_then(|run| run.check(&target, None))
        };
        assert!(with(7, 10).is_err(), "as a file of 10 pieces");
        assert!(with(7, 8).is_err(), "as a file of 8 pieces");
        assert!(with(15, 4).is_err(), "one place on");
        assert!(with(15, 2).is_err(), "one place back");
        assert!(with(19, 1).is_err(), "one item less");
        assert!(with(19, 0).is_err(), "no items");
        assert!(with(20, 0).is_err(), "another piece");
        let last = bytes.len() - 1;
        assert!(
            with(last, bytes[last] ^ 1).is_err(),
            "another size for a carried node"
        );
        for cut in 0..bytes.len() {
            assert!(FileRun::decode(&bytes[..cut]).is_err(), "cut at {cut}");
        }
        assert!(FileRun::decode(&[bytes.clone(), vec![0]].concat()).is_err());

        // The pieces' lengths are held to the way of cutting, when one is given.
        assert!(run.check(&target, Some(Cutting::fixed(4).unwrap())).is_ok());
        assert!(run
            .check(&target, Some(Cutting::fixed(5).unwrap()))
            .is_err());
        assert!(run.check(&target, Some(Cutting::FastCdcV1)).is_err());

        // A run that claims more carried nodes than any list needs.
        let mut crowded = bytes[..20 + 2 * LIST_ITEM_BYTES].to_vec();
        crowded.extend_from_slice(&81_u16.to_be_bytes());
        crowded.extend_from_slice(&[0; 81 * 40]);
        assert!(FileRun::decode(&crowded).is_err());
        // A run that claims more items than it has bytes for.
        let mut hollow = bytes[..16].to_vec();
        hollow.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(FileRun::decode(&hollow).is_err());
    }

    #[test]
    fn the_pieces_that_hold_a_stretch_of_bytes_are_found() {
        let lengths = [3_u32, 1, 4, 1, 5, 9, 2, 6];
        let items: Vec<PieceRef> = lengths
            .iter()
            .enumerate()
            .map(|(index, length)| piece(index as u8, *length))
            .collect();
        let list = FileList::new(items).unwrap();
        let open = OpenFile::new(list.clone()).unwrap();
        let size = list.size();
        assert_eq!(size, 31);
        // Which piece holds each byte, worked out the long way.
        let mut holder = Vec::new();
        for (index, length) in lengths.iter().enumerate() {
            holder.extend(std::iter::repeat_n(index as u64, *length as usize));
        }
        for offset in 0..size {
            for length in 1..=size - offset {
                let (first, after) = open.pieces_for(offset, length).unwrap();
                assert_eq!(first, holder[offset as usize], "{offset}+{length}");
                assert_eq!(
                    after,
                    holder[(offset + length - 1) as usize] + 1,
                    "{offset}+{length}"
                );
                let run = open.open_bytes(offset, length).unwrap();
                let starts_at = run.check(&list.target(), None).unwrap();
                assert!(starts_at <= offset);
                let shown: u64 = run.items().iter().map(|item| u64::from(item.length)).sum();
                assert!(starts_at + shown >= offset + length);
            }
        }
        assert!(open.pieces_for(0, 0).is_err());
        assert!(open.pieces_for(size, 1).is_err());
        assert!(open.pieces_for(size - 1, 2).is_err());
        assert!(open.pieces_for(u64::MAX, 2).is_err());
        assert!(OpenFile::new(FileList::new(Vec::new()).unwrap())
            .unwrap()
            .pieces_for(0, 1)
            .is_err());
    }

    #[test]
    fn every_run_of_a_folder_checks_and_reads_back() {
        let names: Vec<String> = (0..13).map(|index| format!("n{index:02}")).collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        for count in 1..=names.len() {
            let list = folder(&names[..count]);
            let open = OpenFolder::new(list.clone()).unwrap();
            let target = list.target();
            for start in 0..count as u64 {
                for end in start + 1..=count as u64 {
                    let run = open.open(start, end).unwrap();
                    assert_eq!(run, list.open(start, end).unwrap());
                    assert_eq!(FolderRun::decode(&run.encode()).unwrap(), run);
                    run.check(&target).unwrap();
                    assert_eq!(run.entries(), &list.entries()[start as usize..end as usize]);
                    assert!(run.check(&folder(&["other"]).target()).is_err());
                    let as_file = Target {
                        kind: Kind::File,
                        ..target
                    };
                    assert!(run.check(&as_file).is_err());
                }
            }
        }
    }

    #[test]
    fn a_name_is_shown_to_be_there_or_not_there_by_its_one_place() {
        let names = ["b", "d", "f", "h", "j", "l", "n"];
        let asked = [
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "b0", "B",
        ];
        for count in 1..=names.len() {
            let list = folder(&names[..count]);
            let target = list.target();
            for name in asked {
                let place = list.place_of(name).unwrap();
                let truth = list.get(name);
                // The answer the folder gives.
                let answer = list.open_name(name).unwrap();
                assert_eq!(FolderRun::decode(&answer.encode()).unwrap(), answer);
                assert_eq!(answer.check_name(&target, name).unwrap(), truth);
                // Any other entry shown in its place is refused, so there is
                // one answer, and it is the true one.
                for other in 0..count as u64 {
                    let shown = list.open(other, other + 1).unwrap();
                    let verdict = shown.check_name(&target, name);
                    if other == place {
                        assert_eq!(verdict.unwrap(), truth, "{count}: {name} at {other}");
                    } else {
                        assert!(verdict.is_err(), "{count}: {name} at {other}");
                    }
                }
                // A run of two entries is no answer for one name.
                if count >= 2 {
                    let two = list.open(0, 2).unwrap();
                    assert!(two.check_name(&target, name).is_err());
                }
            }
            assert!(list.open_name("a/b").is_err());
            let any = list.open(0, 1).unwrap();
            assert!(any.check_name(&target, "").is_err());
        }
    }

    #[test]
    fn an_empty_folder_shows_that_it_holds_no_name() {
        let empty = FolderList::new(Vec::new()).unwrap();
        assert_eq!(empty.place_of("a"), None);
        let answer = empty.open_name("a").unwrap();
        assert_eq!(FolderRun::decode(&answer.encode()).unwrap(), answer);
        assert_eq!(answer.check_name(&empty.target(), "a").unwrap(), None);
        answer.check(&empty.target()).unwrap();
        // The same answer for a folder that is not empty is refused.
        let full = folder(&["a"]);
        assert!(answer.check_name(&full.target(), "a").is_err());
        assert!(answer.check(&full.target()).is_err());
        // And a run that shows nothing of a folder with entries is no run.
        let mut nothing = 3_u64.to_be_bytes().to_vec();
        nothing.extend_from_slice(&[0; 8 + 4 + 2]);
        assert!(FolderRun::decode(&nothing).is_err());
        let mut carrying = 0_u64.to_be_bytes().to_vec();
        carrying.extend_from_slice(&[0; 8 + 4]);
        carrying.extend_from_slice(&[0, 1]);
        carrying.extend_from_slice(&[0; 40]);
        carrying.extend_from_slice(&[0, 1, b'a']);
        assert!(FolderRun::decode(&carrying).is_err());
    }
}
