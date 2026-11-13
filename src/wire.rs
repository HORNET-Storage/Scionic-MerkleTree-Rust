//! What a receiver asks, and the frames that answer it.
//!
//! A receiver asks from the top down: for the record of a root, for a folder's
//! entries, for a file's list, and for chunks. It asks for chunks by the
//! file's hash and their numbers in it, or for one chunk by its hash.
//!
//! An answer is one frame, or for chunks one frame for each chunk. A frame
//! never says which hash it belongs under: the receiver works the hash out
//! from the frame's bytes, and holds it against a hash it already trusts.
//!
//! A request and a frame each start with one byte that says what they are.
//! Numbers are big-endian.

use crate::format::{
    check_name, FileBranch, FolderBranch, Reader, MAX_CHUNK_BYTES, MAX_NAME_BYTES, RECORD_MARK,
};
use crate::hash::{Hash, Root};
use crate::tree::MAX_LIST_ITEMS;
use crate::{Error, Result};
use std::io::{ErrorKind, Read, Write};

/// A tree's record. The frame is the record itself, whose first byte this is.
pub const FRAME_RECORD: u8 = RECORD_MARK;
/// A file's whole list.
pub const FRAME_FILE_LIST: u8 = 0x21;
/// A folder's whole list.
pub const FRAME_FOLDER_LIST: u8 = 0x22;
/// A branch of a file's list, with the nodes that stand for the rest.
pub const FRAME_FILE_BRANCH: u8 = 0x23;
/// A branch of a folder's list, with the nodes that stand for the rest.
pub const FRAME_FOLDER_BRANCH: u8 = 0x24;
/// A chunk's bytes.
pub const FRAME_CHUNK: u8 = 0x25;
/// Which chunks of a file a peer holds.
pub const FRAME_HAVE: u8 = 0x26;
/// The peer does not answer, and why.
pub const FRAME_REFUSED: u8 = 0x27;

const ASK_RECORD: u8 = 0x30;
const ASK_FOLDER: u8 = 0x31;
const ASK_FOLDER_BRANCH: u8 = 0x32;
const ASK_FOLDER_NAME: u8 = 0x33;
const ASK_FILE: u8 = 0x34;
const ASK_FILE_BRANCH: u8 = 0x35;
const ASK_FILE_BYTES: u8 = 0x36;
const ASK_CHUNKS: u8 = 0x37;
const ASK_CHUNK: u8 = 0x38;
const ASK_HAVE: u8 = 0x39;

/// What starts a bundle: a tree written out as one stream of frames.
pub const BUNDLE_MAGIC: [u8; 8] = *b"SCIONIC\x01";

/// The most bytes a request may take. The longest one asks for a name in a
/// folder: its first byte, the folder's hash, and the longest name with its
/// length.
pub const MAX_REQUEST_BYTES: usize = 35 + MAX_NAME_BYTES;

/// The most bytes that are set aside for a frame before they have come. A
/// stream that claims a long frame and then sends nothing costs its reader
/// no more than this.
const READ_STEP_BYTES: usize = 1 << 20;

fn invalid(detail: &str) -> Error {
    Error::InvalidData {
        detail: detail.to_owned(),
    }
}

/// What a receiver asks a peer for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    /// The record of a root.
    Record(Root),
    /// All of a folder's entries.
    Folder(Hash),
    /// `count` of a folder's entries, from place `start`.
    FolderBranch {
        folder: Hash,
        start: u64,
        count: u32,
    },
    /// What is under one name in a folder, or that the name is not there.
    FolderName { folder: Hash, name: String },
    /// All of a file's list.
    File(Hash),
    /// `count` items of a file's list, from chunk number `start`.
    FileBranch { file: Hash, start: u64, count: u32 },
    /// The items of a file's list that hold `length` bytes from `offset`.
    FileBytes {
        file: Hash,
        offset: u64,
        length: u64,
    },
    /// `count` chunks of a file, from chunk number `start`.
    Chunks { file: Hash, start: u64, count: u32 },
    /// One chunk, by its hash.
    Chunk(Hash),
    /// Which chunks of a file the peer holds.
    Have(Hash),
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(49);
        let ranged = |out: &mut Vec<u8>, tag: u8, hash: &Hash, start: u64, count: u32| {
            out.push(tag);
            out.extend_from_slice(hash.as_bytes());
            out.extend_from_slice(&start.to_be_bytes());
            out.extend_from_slice(&count.to_be_bytes());
        };
        let one = |out: &mut Vec<u8>, tag: u8, hash: &Hash| {
            out.push(tag);
            out.extend_from_slice(hash.as_bytes());
        };
        match self {
            Self::Record(root) => one(&mut out, ASK_RECORD, root.as_hash()),
            Self::Folder(folder) => one(&mut out, ASK_FOLDER, folder),
            Self::FolderBranch {
                folder,
                start,
                count,
            } => ranged(&mut out, ASK_FOLDER_BRANCH, folder, *start, *count),
            Self::FolderName { folder, name } => {
                one(&mut out, ASK_FOLDER_NAME, folder);
                out.extend_from_slice(&(name.len() as u16).to_be_bytes());
                out.extend_from_slice(name.as_bytes());
            }
            Self::File(file) => one(&mut out, ASK_FILE, file),
            Self::FileBranch { file, start, count } => {
                ranged(&mut out, ASK_FILE_BRANCH, file, *start, *count);
            }
            Self::FileBytes {
                file,
                offset,
                length,
            } => {
                one(&mut out, ASK_FILE_BYTES, file);
                out.extend_from_slice(&offset.to_be_bytes());
                out.extend_from_slice(&length.to_be_bytes());
            }
            Self::Chunks { file, start, count } => {
                ranged(&mut out, ASK_CHUNKS, file, *start, *count);
            }
            Self::Chunk(chunk) => one(&mut out, ASK_CHUNK, chunk),
            Self::Have(file) => one(&mut out, ASK_HAVE, file),
        }
        out
    }

    /// Reads a request. One that asks for nothing, or for a name that no
    /// folder can hold, is refused here.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes, "a request");
        let tag = reader.u8()?;
        let hash = reader.hash()?;
        let request = match tag {
            ASK_RECORD => Self::Record(Root::from_hash(hash)),
            ASK_FOLDER => Self::Folder(hash),
            ASK_FILE => Self::File(hash),
            ASK_CHUNK => Self::Chunk(hash),
            ASK_HAVE => Self::Have(hash),
            ASK_FOLDER_BRANCH | ASK_FILE_BRANCH | ASK_CHUNKS => {
                let start = reader.u64()?;
                let count = reader.u32()?;
                if count == 0 || start >= MAX_LIST_ITEMS {
                    return Err(invalid("a request asks for nothing, or beyond any list"));
                }
                match tag {
                    ASK_FOLDER_BRANCH => Self::FolderBranch {
                        folder: hash,
                        start,
                        count,
                    },
                    ASK_FILE_BRANCH => Self::FileBranch {
                        file: hash,
                        start,
                        count,
                    },
                    _ => Self::Chunks {
                        file: hash,
                        start,
                        count,
                    },
                }
            }
            ASK_FOLDER_NAME => {
                let length = usize::from(reader.u16()?);
                let name = std::str::from_utf8(reader.take(length)?)
                    .map_err(|_| invalid("a name is not UTF-8"))?;
                check_name(name)?;
                Self::FolderName {
                    folder: hash,
                    name: name.to_owned(),
                }
            }
            ASK_FILE_BYTES => {
                let offset = reader.u64()?;
                let length = reader.u64()?;
                if length == 0 || offset.checked_add(length).is_none() {
                    return Err(invalid("a request asks for no bytes, or beyond any file"));
                }
                Self::FileBytes {
                    file: hash,
                    offset,
                    length,
                }
            }
            _ => return Err(invalid("a request of an unknown kind")),
        };
        reader.finish()?;
        Ok(request)
    }
}

/// Why a peer does not answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// It does not hold what was asked for.
    NotHeld,
    /// What was asked for lies outside the list or the file.
    OutOfRange,
}

impl Refusal {
    fn byte(self) -> u8 {
        match self {
            Self::NotHeld => 1,
            Self::OutOfRange => 2,
        }
    }
}

/// Which chunks of a file a peer holds: one bit a chunk, in the file's
/// order. A peer says this about itself, and nothing proves it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HaveMap {
    count: u64,
    bits: Vec<u8>,
}

impl HaveMap {
    /// A map for a file of `count` chunks, with none held.
    pub fn new(count: u64) -> Result<Self> {
        if count > MAX_LIST_ITEMS {
            return Err(invalid("a map for more chunks than a file can have"));
        }
        let length = count.div_ceil(8) as usize;
        let mut bits = Vec::new();
        bits.try_reserve_exact(length)
            .map_err(|_| Error::AllocationFailed {
                resource: "a map of held chunks",
                requested: length as u64,
            })?;
        bits.resize(length, 0);
        Ok(Self { count, bits })
    }

    /// How many chunks the file has.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Whether chunk `index` is held. A chunk beyond the count is not.
    pub fn get(&self, index: u64) -> bool {
        index < self.count && self.bits[(index / 8) as usize] & (0x80 >> (index % 8)) != 0
    }

    /// Marks chunk `index` as held.
    pub fn set(&mut self, index: u64) -> Result<()> {
        if index >= self.count {
            return Err(invalid("a chunk beyond the end of the file"));
        }
        self.bits[(index / 8) as usize] |= 0x80 >> (index % 8);
        Ok(())
    }

    /// How many chunks are held.
    pub fn held(&self) -> u64 {
        self.bits
            .iter()
            .map(|byte| u64::from(byte.count_ones()))
            .sum()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.bits.len());
        out.extend_from_slice(&self.count.to_be_bytes());
        out.extend_from_slice(&self.bits);
        out
    }

    /// Reads a map. It has one bit for each chunk and no more, and the bits
    /// left over in its last byte are zero.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes, "a map of held chunks");
        let count = reader.u64()?;
        if count > MAX_LIST_ITEMS || reader.remaining() as u64 != count.div_ceil(8) {
            return Err(invalid("a map of held chunks does not fit its count"));
        }
        let bits = reader.take(reader.remaining())?.to_vec();
        let spare = (8 - count % 8) % 8;
        if bits
            .last()
            .is_some_and(|last| last & ((1_u8 << spare) - 1) != 0)
        {
            return Err(invalid("a map of held chunks has bits past its count"));
        }
        Ok(Self { count, bits })
    }
}

/// A frame, read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Frame<'a> {
    /// A record: the whole frame.
    Record(&'a [u8]),
    /// A file's whole list.
    FileList(&'a [u8]),
    /// A folder's whole list.
    FolderList(&'a [u8]),
    FileBranch(FileBranch),
    FolderBranch(FolderBranch),
    /// A chunk's bytes.
    Chunk(&'a [u8]),
    Have(HaveMap),
    Refused(Refusal),
}

impl<'a> Frame<'a> {
    /// Reads a frame. This says what kind of frame it is and that it is well
    /// formed. It does not say that the frame is true: that is checked
    /// against a hash the receiver trusts.
    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        let (&tag, body) = bytes
            .split_first()
            .ok_or_else(|| invalid("a frame is empty"))?;
        Ok(match tag {
            FRAME_RECORD => Self::Record(bytes),
            FRAME_FILE_LIST => Self::FileList(body),
            FRAME_FOLDER_LIST => Self::FolderList(body),
            FRAME_FILE_BRANCH => Self::FileBranch(FileBranch::decode(body)?),
            FRAME_FOLDER_BRANCH => Self::FolderBranch(FolderBranch::decode(body)?),
            FRAME_CHUNK => {
                if body.is_empty() || body.len() > MAX_CHUNK_BYTES {
                    return Err(invalid("a chunk does not hold 1 byte to 8 MiB"));
                }
                Self::Chunk(body)
            }
            FRAME_HAVE => Self::Have(HaveMap::decode(body)?),
            FRAME_REFUSED => match body {
                [1] => Self::Refused(Refusal::NotHeld),
                [2] => Self::Refused(Refusal::OutOfRange),
                _ => return Err(invalid("a refusal of an unknown kind")),
            },
            _ => return Err(invalid("a frame of an unknown kind")),
        })
    }
}

fn framed(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + body.len());
    frame.push(tag);
    frame.extend_from_slice(body);
    frame
}

/// The frame for a file's whole list.
pub fn file_list_frame(list: &[u8]) -> Vec<u8> {
    framed(FRAME_FILE_LIST, list)
}

/// The frame for a folder's whole list.
pub fn folder_list_frame(list: &[u8]) -> Vec<u8> {
    framed(FRAME_FOLDER_LIST, list)
}

pub fn file_branch_frame(branch: &FileBranch) -> Vec<u8> {
    framed(FRAME_FILE_BRANCH, &branch.encode())
}

pub fn folder_branch_frame(branch: &FolderBranch) -> Vec<u8> {
    framed(FRAME_FOLDER_BRANCH, &branch.encode())
}

/// The frame for a chunk's bytes.
pub fn chunk_frame(chunk: &[u8]) -> Vec<u8> {
    framed(FRAME_CHUNK, chunk)
}

pub fn have_frame(map: &HaveMap) -> Vec<u8> {
    framed(FRAME_HAVE, &map.encode())
}

pub fn refused_frame(why: Refusal) -> Vec<u8> {
    vec![FRAME_REFUSED, why.byte()]
}

/// Writes one frame to a stream: its length as four bytes, then the frame.
pub fn write_frame(out: &mut dyn Write, frame: &[u8]) -> Result<()> {
    let length = u32::try_from(frame.len()).map_err(|_| Error::LimitExceeded {
        what: "a frame",
        limit: u64::from(u32::MAX),
        requested: frame.len() as u64,
    })?;
    let failed = |source| Error::Stream {
        operation: "write a frame",
        source,
    };
    out.write_all(&length.to_be_bytes()).map_err(failed)?;
    out.write_all(frame).map_err(failed)
}

/// What comes next on a stream of frames.
pub(crate) enum Next {
    Frame(Vec<u8>),
    /// A length of zero. Where answers are sent, it ends one answer.
    End,
    /// The stream has ended, between two frames.
    Closed,
}

/// Writes a length of zero to a stream: the end of an answer.
pub(crate) fn write_end(out: &mut dyn Write) -> Result<()> {
    out.write_all(&[0; 4]).map_err(|source| Error::Stream {
        operation: "write a frame",
        source,
    })
}

/// Reads what comes next on a stream. A frame longer than `limit` is refused
/// before any of it is read, and a stream that ends inside a frame is an
/// error. A frame's bytes are set aside as they come, a megabyte at a time.
pub(crate) fn read_next(input: &mut dyn Read, limit: usize) -> Result<Next> {
    let failed = |source| Error::Stream {
        operation: "read a frame",
        source,
    };
    let cut_short = |error: std::io::Error| {
        if error.kind() == ErrorKind::UnexpectedEof {
            invalid("a stream ends inside a frame")
        } else {
            failed(error)
        }
    };
    let mut header = [0_u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        match input.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Ok(Next::Closed),
            Ok(0) => return Err(invalid("a stream ends inside a frame")),
            Ok(count) => filled += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(failed(error)),
        }
    }
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Ok(Next::End);
    }
    if length > limit {
        return Err(Error::LimitExceeded {
            what: "a frame",
            limit: limit as u64,
            requested: length as u64,
        });
    }
    let mut frame = Vec::new();
    while frame.len() < length {
        let held = frame.len();
        let more = (length - held).min(READ_STEP_BYTES);
        frame
            .try_reserve(more)
            .map_err(|_| Error::AllocationFailed {
                resource: "a frame",
                requested: length as u64,
            })?;
        frame.resize(held + more, 0);
        input.read_exact(&mut frame[held..]).map_err(cut_short)?;
    }
    Ok(Next::Frame(frame))
}

/// Reads one frame from a stream, or nothing when the stream has ended. A
/// frame longer than `limit` is refused before any of it is read, and a
/// stream that ends inside a frame is an error.
pub fn read_frame(input: &mut dyn Read, limit: usize) -> Result<Option<Vec<u8>>> {
    match read_next(input, limit)? {
        Next::Frame(frame) => Ok(Some(frame)),
        Next::End => Err(invalid("a frame is empty")),
        Next::Closed => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_request() -> Vec<Request> {
        let hash = Hash::of(b"x");
        vec![
            Request::Record(Root::from_hash(hash)),
            Request::Folder(hash),
            Request::FolderBranch {
                folder: hash,
                start: 3,
                count: 9,
            },
            Request::FolderName {
                folder: hash,
                name: "model.safetensors".to_owned(),
            },
            Request::File(hash),
            Request::FileBranch {
                file: hash,
                start: 100,
                count: 100,
            },
            Request::FileBytes {
                file: hash,
                offset: 500 << 30,
                length: 1 << 30,
            },
            Request::Chunks {
                file: hash,
                start: 100,
                count: 101,
            },
            Request::Chunk(hash),
            Request::Have(hash),
        ]
    }

    #[test]
    fn every_request_reads_back_and_is_read_in_one_way_only() {
        for request in every_request() {
            let bytes = request.encode();
            assert_eq!(Request::decode(&bytes).unwrap(), request);
            for cut in 0..bytes.len() {
                assert!(
                    Request::decode(&bytes[..cut]).is_err(),
                    "{request:?} cut at {cut}"
                );
            }
            assert!(Request::decode(&[bytes.clone(), vec![0]].concat()).is_err());
        }
        let mut tags: Vec<u8> = every_request()
            .iter()
            .map(|request| request.encode()[0])
            .collect();
        tags.dedup();
        assert_eq!(tags, (0x30..=0x39).collect::<Vec<u8>>());
        // "Chunks 100 to 200 of this file" is 45 bytes, whatever the file.
        assert_eq!(every_request()[7].encode().len(), 45);
    }

    #[test]
    fn a_request_for_nothing_or_for_a_name_no_folder_holds_is_refused() {
        let hash = Hash::of(b"x");
        let ranged = |tag: u8, start: u64, count: u32| {
            let mut bytes = vec![tag];
            bytes.extend_from_slice(hash.as_bytes());
            bytes.extend_from_slice(&start.to_be_bytes());
            bytes.extend_from_slice(&count.to_be_bytes());
            Request::decode(&bytes)
        };
        for tag in [0x32, 0x35, 0x37] {
            assert!(ranged(tag, 0, 1).is_ok());
            assert!(ranged(tag, 0, 0).is_err());
            assert!(ranged(tag, MAX_LIST_ITEMS, 1).is_err());
        }
        let named = |name: &[u8]| {
            let mut bytes = vec![0x33];
            bytes.extend_from_slice(hash.as_bytes());
            bytes.extend_from_slice(&(name.len() as u16).to_be_bytes());
            bytes.extend_from_slice(name);
            Request::decode(&bytes)
        };
        assert!(named(b"a").is_ok());
        for name in [&b""[..], b".", b"..", b"a/b", b"a\0", &[0xff]] {
            assert!(named(name).is_err(), "{name:?}");
        }
        let stretch = |offset: u64, length: u64| {
            let mut bytes = vec![0x36];
            bytes.extend_from_slice(hash.as_bytes());
            bytes.extend_from_slice(&offset.to_be_bytes());
            bytes.extend_from_slice(&length.to_be_bytes());
            Request::decode(&bytes)
        };
        assert!(stretch(0, 1).is_ok());
        assert!(stretch(0, 0).is_err());
        assert!(stretch(u64::MAX, 1).is_err());
        let mut unknown = vec![0x3a];
        unknown.extend_from_slice(hash.as_bytes());
        assert!(Request::decode(&unknown).is_err());
    }

    #[test]
    fn a_map_of_held_chunks_has_one_bit_a_chunk() {
        let mut map = HaveMap::new(11).unwrap();
        assert_eq!(map.encode().len(), 8 + 2);
        for index in [0, 3, 10] {
            map.set(index).unwrap();
        }
        assert!(map.set(11).is_err());
        assert_eq!(map.held(), 3);
        let held: Vec<u64> = (0..16).filter(|index| map.get(*index)).collect();
        assert_eq!(held, [0, 3, 10]);
        let bytes = map.encode();
        assert_eq!(&bytes[8..], [0b1001_0000, 0b0010_0000]);
        assert_eq!(HaveMap::decode(&bytes).unwrap(), map);

        // A bit past the count, a byte too many and a byte too few.
        let mut past = bytes.clone();
        past[9] |= 0b0001_0000;
        assert!(HaveMap::decode(&past).is_err());
        assert!(HaveMap::decode(&[bytes.clone(), vec![0]].concat()).is_err());
        assert!(HaveMap::decode(&bytes[..9]).is_err());
        // A terabyte file's map is about 60 KB.
        let big = HaveMap::new(500_000).unwrap();
        assert_eq!(big.encode().len(), 8 + 62_500);
        assert_eq!(
            HaveMap::decode(&HaveMap::new(0).unwrap().encode())
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            HaveMap::decode(&HaveMap::new(8).unwrap().encode())
                .unwrap()
                .count(),
            8
        );
    }

    #[test]
    fn frames_are_told_apart_by_their_first_byte() {
        assert_eq!(
            Frame::decode(&chunk_frame(b"abc")).unwrap(),
            Frame::Chunk(b"abc")
        );
        assert_eq!(
            Frame::decode(&file_list_frame(&[7; 36])).unwrap(),
            Frame::FileList(&[7; 36])
        );
        assert_eq!(
            Frame::decode(&folder_list_frame(&[])).unwrap(),
            Frame::FolderList(&[])
        );
        assert_eq!(
            Frame::decode(&refused_frame(Refusal::NotHeld)).unwrap(),
            Frame::Refused(Refusal::NotHeld)
        );
        assert_eq!(
            Frame::decode(&refused_frame(Refusal::OutOfRange)).unwrap(),
            Frame::Refused(Refusal::OutOfRange)
        );
        let map = HaveMap::new(3).unwrap();
        assert_eq!(Frame::decode(&have_frame(&map)).unwrap(), Frame::Have(map));
        assert_eq!(
            Frame::decode(&[0x20, 1]).unwrap(),
            Frame::Record(&[0x20, 1])
        );
        for bad in [
            &[][..],
            &[0x25],
            &[0x27],
            &[0x27, 0],
            &[0x27, 3],
            &[0x27, 1, 1],
            &[0x28],
            &[0x1f],
        ] {
            assert!(Frame::decode(bad).is_err(), "{bad:?}");
        }
        let too_long = chunk_frame(&vec![0; MAX_CHUNK_BYTES + 1]);
        assert!(Frame::decode(&too_long).is_err());
        assert!(Frame::decode(&chunk_frame(&vec![0; MAX_CHUNK_BYTES])).is_ok());
    }

    #[test]
    fn frames_go_through_a_stream_whole_or_not_at_all() {
        let mut stream = Vec::new();
        write_frame(&mut stream, b"one").unwrap();
        write_frame(&mut stream, b"three").unwrap();
        let mut input = stream.as_slice();
        assert_eq!(read_frame(&mut input, 16).unwrap().unwrap(), b"one");
        assert_eq!(read_frame(&mut input, 16).unwrap().unwrap(), b"three");
        assert!(read_frame(&mut input, 16).unwrap().is_none());

        // A frame over the limit is refused before it is read.
        let mut input = stream.as_slice();
        assert!(matches!(
            read_frame(&mut input, 2),
            Err(Error::LimitExceeded { .. })
        ));
        // A stream that ends inside a length or inside a frame.
        for cut in [1, 3, 5, 6] {
            let mut input = &stream[..cut];
            assert!(read_frame(&mut input, 16).is_err(), "cut at {cut}");
        }
        let mut empty = &[0_u8, 0, 0, 0][..];
        assert!(read_frame(&mut empty, 16).is_err());
    }
}
