//! A hash, and the root that a tree is known by.

use crate::encoding::{base32_lower, base32_lower_decode, hex_lower, hex_lower_decode, sha256};
use crate::{Error, Result};
use std::fmt;
use std::str::FromStr;

/// A SHA-256 hash: of a chunk's bytes, or of the bytes that describe a file,
/// a folder or a tree.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Hash([u8; 32]);

impl Hash {
    /// What an empty list has in place of a hash.
    pub const ZERO: Self = Self([0; 32]);

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The SHA-256 of `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        Self(sha256(bytes))
    }

    /// Reads a hash from exactly 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        <[u8; 32]>::try_from(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidData {
                detail: "a hash is not 32 bytes".to_owned(),
            })
    }

    /// The hash as 64 lowercase hex digits.
    pub fn to_hex(&self) -> String {
        hex_lower(&self.0)
    }

    /// Reads 64 lowercase hex digits.
    pub fn from_hex(text: &str) -> Result<Self> {
        let mut bytes = [0_u8; 32];
        hex_lower_decode(text, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// What a root's text form starts with, before the hash: CID version 1, raw
/// content, SHA-256, 32 bytes.
const ROOT_PREFIX: [u8; 4] = [0x01, 0x55, 0x12, 0x20];

/// The root of a tree: the hash of its record. It is what a tree is known by.
///
/// Written out, a root is a CID that begins `bafkrei`.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Root(Hash);

impl Root {
    pub const fn from_hash(hash: Hash) -> Self {
        Self(hash)
    }

    pub const fn as_hash(&self) -> &Hash {
        &self.0
    }

    /// The root of the tree whose record is `record`.
    pub fn of_record(record: &[u8]) -> Self {
        Self(Hash::of(record))
    }

    /// The root as text.
    pub fn to_text(&self) -> String {
        let mut bytes = [0_u8; 36];
        bytes[..4].copy_from_slice(&ROOT_PREFIX);
        bytes[4..].copy_from_slice(self.0.as_bytes());
        let mut text = String::with_capacity(59);
        text.push('b');
        text.push_str(&base32_lower(&bytes));
        text
    }

    /// Reads a root from its text. Only the one way of writing a root is
    /// read: any other spelling of the same bytes is refused.
    pub fn parse(text: &str) -> Result<Self> {
        let invalid = || Error::InvalidRoot {
            value: text.chars().take(80).collect(),
        };
        let body = text.strip_prefix('b').ok_or_else(invalid)?;
        let bytes = base32_lower_decode(body).map_err(|_| invalid())?;
        if bytes.len() != 36 || bytes[..4] != ROOT_PREFIX {
            return Err(invalid());
        }
        let root = Self(Hash::from_slice(&bytes[4..])?);
        if root.to_text() != text {
            return Err(invalid());
        }
        Ok(root)
    }
}

impl fmt::Display for Root {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl fmt::Debug for Root {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Root({})", self.to_text())
    }
}

impl FromStr for Root {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        Self::parse(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hash_is_the_sha_256_of_the_bytes() {
        assert_eq!(
            Hash::of(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            Hash::of(b"").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn a_hash_reads_back_from_its_hex() {
        let hash = Hash::of(b"abc");
        assert_eq!(Hash::from_hex(&hash.to_hex()).unwrap(), hash);
        assert_eq!(format!("{hash}"), hash.to_hex());
        assert!(Hash::from_hex(&hash.to_hex().to_uppercase()).is_err());
        assert!(Hash::from_hex(&hash.to_hex()[..63]).is_err());
        assert!(Hash::from_slice(&[0; 31]).is_err());
    }

    #[test]
    fn a_root_is_written_as_a_cid_that_begins_bafkrei() {
        let root = Root::of_record(b"abc");
        let text = root.to_text();
        assert_eq!(text.len(), 59);
        assert!(text.starts_with("bafkrei"), "{text}");
        // The CID of the raw bytes "abc", as other tools write it.
        assert_eq!(
            text,
            "bafkreif2pall7dybz7vecqka3zo24irdwabwdi4wc55jznaq75q7eaavvu"
        );
        assert_eq!(Root::parse(&text).unwrap(), root);
        assert_eq!(text.parse::<Root>().unwrap(), root);
    }

    #[test]
    fn only_the_one_spelling_of_a_root_is_read() {
        let text = Root::of_record(b"abc").to_text();
        let old_layout = text.replacen("bafkrei", "bafirei", 1);
        let mut longer = text.clone();
        longer.push('a');
        for other in [
            text.to_uppercase(),
            text[1..].to_owned(),
            text[..58].to_owned(),
            longer,
            old_layout,
            format!("{text}="),
            String::new(),
        ] {
            assert!(Root::parse(&other).is_err(), "{other:?}");
        }
        // The last letter carries two bits that must be zero.
        let mut bytes = text.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'b' { b'c' } else { b'b' };
        let changed = String::from_utf8(bytes).unwrap();
        assert!(Root::parse(&changed).is_err(), "{changed:?}");
    }
}
