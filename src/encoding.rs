use crate::{Error, Result};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;

#[cfg(test)]
mod wire_map_ordering_tests {
    use super::{cbor_encode, sorted_cbor_map, CborValue};

    /// Pins the wire map comparator across all three ports.
    ///
    /// Every map key the spec-vector corpus exercises is a CID of uniform length,
    /// where length-first and plain-lexicographic ordering coincide -- so the
    /// corpus cannot tell the two apart. AdditionalData is the one wire map with
    /// arbitrary, mixed-length keys, and it is empty in every corpus case.
    ///
    /// This vector is the only thing standing between the three ports and a silent
    /// divergence on that axis. The identical bytes are asserted in Go
    /// (dag/sortedmap_test.go) and Swift (WireMapOrderingTests.swift).
    ///
    /// Keys sort length-first, then bytewise: mm, zz, aaaaaa -- carrying values
    /// 2, 1, 3 respectively. Plain lexicographic would give aaaaaa, mm, zz.
    const EXPECTED: &str = "a3626d6d6132627a7a6131666161616161616133";

    #[test]
    fn wire_maps_sort_length_first_then_bytewise() {
        let encoded = cbor_encode(&sorted_cbor_map(vec![
            ("zz".to_owned(), CborValue::Text("1".to_owned())),
            ("aaaaaa".to_owned(), CborValue::Text("3".to_owned())),
            ("mm".to_owned(), CborValue::Text("2".to_owned())),
        ]));
        let hex: String = encoded.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, EXPECTED,
            "wire map ordering drifted from the bytes Go and Swift pin"
        );
    }

    #[test]
    fn wire_map_ordering_is_independent_of_insertion_order() {
        let forward = cbor_encode(&sorted_cbor_map(vec![
            ("mm".to_owned(), CborValue::Text("2".to_owned())),
            ("zz".to_owned(), CborValue::Text("1".to_owned())),
            ("aaaaaa".to_owned(), CborValue::Text("3".to_owned())),
        ]));
        let reverse = cbor_encode(&sorted_cbor_map(vec![
            ("aaaaaa".to_owned(), CborValue::Text("3".to_owned())),
            ("zz".to_owned(), CborValue::Text("1".to_owned())),
            ("mm".to_owned(), CborValue::Text("2".to_owned())),
        ]));
        assert_eq!(forward, reverse);
    }
}

const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CborNegative {
    argument: u64,
}

impl CborNegative {
    pub const fn argument(self) -> u64 {
        self.argument
    }
}

impl TryFrom<i64> for CborNegative {
    type Error = Error;

    fn try_from(value: i64) -> Result<Self> {
        if value >= 0 {
            return Err(Error::InvalidCborNegative { value });
        }
        Ok(Self {
            argument: (-1_i128 - i128::from(value)) as u64,
        })
    }
}

#[derive(Clone, Debug)]
// Adding a variant to a public enum silently breaks every downstream exhaustive
// `match` -- which is exactly what `SharedBytes` did before this attribute was
// here. Callers now carry a wildcard arm, so the next representation change is
// theirs to ignore rather than theirs to recompile.
#[non_exhaustive]
pub enum CborValue {
    Unsigned(u64),
    Negative(CborNegative),
    Bytes(Vec<u8>),
    /// Bytes the encoder reads from a shared owner instead of copying.
    ///
    /// Encoded byte-for-byte identically to [`CborValue::Bytes`]: this is a
    /// representation choice, never a wire choice. It exists because leaf
    /// content already lives behind an `Arc`, and wrapping it in `Bytes` meant
    /// copying the whole payload into the value tree and then copying it again
    /// into the output buffer -- two passes over every byte where Go's encoder
    /// makes one.
    ///
    /// The decoder produces this variant too, for the mirror-image reason: it
    /// allocates each byte string once while reading, and handing that same
    /// allocation to the leaf avoids a second copy on the way in.
    ///
    /// `Bytes` and `SharedBytes` are the same CBOR value and compare equal, so
    /// which one a tree happens to hold is not observable through `==`.
    SharedBytes(Arc<Vec<u8>>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(String, CborValue)>),
    Null,
    Bool(bool),
}

/// Equality is by CBOR value, not by representation.
///
/// `Bytes` and `SharedBytes` encode to identical wire bytes, so treating them as
/// different would make `cbor_decode(cbor_encode(x)) == x` fail purely because
/// ownership changed. Comparing the bytes keeps `Eq` honest -- it stays
/// reflexive, symmetric and transitive, because it reduces to comparing `[u8]`.
impl PartialEq for CborValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unsigned(left), Self::Unsigned(right)) => left == right,
            (Self::Negative(left), Self::Negative(right)) => left == right,
            (Self::Bytes(left), Self::Bytes(right)) => left == right,
            (Self::SharedBytes(left), Self::SharedBytes(right)) => left == right,
            (Self::Bytes(owned), Self::SharedBytes(shared))
            | (Self::SharedBytes(shared), Self::Bytes(owned)) => owned == shared.as_ref(),
            (Self::Text(left), Self::Text(right)) => left == right,
            (Self::Array(left), Self::Array(right)) => left == right,
            (Self::Map(left), Self::Map(right)) => left == right,
            (Self::Null, Self::Null) => true,
            (Self::Bool(left), Self::Bool(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for CborValue {}

impl CborValue {
    pub fn negative(value: i64) -> Result<Self> {
        CborNegative::try_from(value).map(Self::Negative)
    }
}

pub fn cbor_encode(value: &CborValue) -> Vec<u8> {
    // Size the buffer exactly before writing. Growing a `Vec::new()` to hold a
    // multi-megabyte DAG costs roughly two dozen reallocations, and every one of
    // them copies everything written so far -- more memory traffic than the
    // encode itself performs.
    let expected = encoded_len(value);
    let mut output = Vec::with_capacity(expected);
    encode_value(value, &mut output);
    debug_assert_eq!(
        output.len(),
        expected,
        "encoded_len must predict the encoder exactly; a drift here silently\
         reintroduces reallocation"
    );
    output
}

/// Builds a CBOR map whose keys are in RFC 8949 core-deterministic order.
///
/// This is deliberately applied PER MAP, at the few sites that build a genuinely
/// dynamic map, rather than as a blanket pass over the whole encoded tree. The
/// distinction is not cosmetic -- it is the difference between two wire formats:
///
/// * Go's wire types are structs with map FIELDS. fxamacker emits struct fields
///   in declaration order and only randomizes map iteration, so only the maps
///   were ever nondeterministic. Sorting everything reorders the struct fields
///   too, which silently rewrites the shape deployed v2.2.6 peers produce.
/// * Rust has no such distinction at the CBOR layer: a struct and a map are both
///   `CborValue::Map`. So the scoping Go gets from its type system has to be
///   expressed here by choosing which maps to sort.
///
/// The blanket version of this function shipped briefly and was caught by the
/// Swift port's CrossCompatWireTests, which pins the packet key order against
/// golden bytes captured from a real deployed build:
///
/// ```text
/// expected [Leaves, Relationships, PacketIndex, TotalPackets]  (declaration)
/// got      [Leaves, PacketIndex, TotalPackets, Relationships]  (sorted)
/// ```
///
/// The five maps that DO need this -- `Leafs`, `AdditionalData`, `stored_proofs`,
/// `proofs`, `Relationships` -- are exactly the five map fields on Go's wire
/// structs, so the ports agree map for map.
///
/// RFC 8949 orders map keys by their ENCODED bytes, bytewise. For text keys that
/// reduces to length-first, then bytewise on the UTF-8 -- and it reduces exactly,
/// at every boundary, because the encoded head grows monotonically with length:
/// a key shorter than 24 bytes starts with `0x60 + len` (at most `0x77`), a key of
/// 24..=255 bytes starts with `0x78`, and one of 256..=65535 starts with `0x79`.
/// A shorter key therefore always has a smaller leading byte, so comparing
/// `(len, bytes)` and comparing the encoded forms never disagree.
pub(crate) fn sorted_cbor_map(mut pairs: Vec<(String, CborValue)>) -> CborValue {
    pairs.sort_by(|(left, _), (right, _)| {
        left.len()
            .cmp(&right.len())
            .then_with(|| left.as_bytes().cmp(right.as_bytes()))
    });
    CborValue::Map(pairs)
}

/// Byte width of one CBOR head, mirroring [`encode_argument`] exactly.
const fn argument_len(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=255 => 2,
        256..=65_535 => 3,
        65_536..=4_294_967_295 => 5,
        _ => 9,
    }
}

/// Exact encoded size of `value`, used to preallocate the output buffer.
///
/// This walks the tree without allocating, so it is cheap next to the copying it
/// avoids. It must agree with [`encode_value`] byte for byte; the `debug_assert`
/// in [`cbor_encode`] enforces that on every debug run rather than trusting it.
fn encoded_len(value: &CborValue) -> usize {
    match value {
        CborValue::Unsigned(value) => argument_len(*value),
        CborValue::Negative(value) => argument_len(value.argument()),
        CborValue::Bytes(bytes) => argument_len(bytes.len() as u64) + bytes.len(),
        CborValue::SharedBytes(bytes) => argument_len(bytes.len() as u64) + bytes.len(),
        CborValue::Text(text) => argument_len(text.len() as u64) + text.len(),
        CborValue::Array(values) => {
            argument_len(values.len() as u64) + values.iter().map(encoded_len).sum::<usize>()
        }
        CborValue::Map(pairs) => {
            argument_len(pairs.len() as u64)
                + pairs
                    .iter()
                    .map(|(key, value)| {
                        argument_len(key.len() as u64) + key.len() + encoded_len(value)
                    })
                    .sum::<usize>()
        }
        CborValue::Null | CborValue::Bool(_) => 1,
    }
}

/// Decodes the strict CBOR subset used by this crate.
///
/// Maps must have unique text keys, nesting is bounded, unsupported simple and
/// floating-point values are rejected, and the entire input must be consumed.
///
/// Byte strings come back as [`CborValue::Bytes`]. The reader itself produces
/// [`CborValue::SharedBytes`] so leaf decoding can adopt that allocation instead
/// of copying it, but that is an internal representation choice: letting it out
/// through the public entry point would change the variant every downstream
/// `match` has always seen, in exchange for a copy only the crate's own decode
/// path is positioned to skip.
pub fn cbor_decode(input: &[u8]) -> Result<CborValue> {
    Ok(own_shared_bytes(cbor_decode_shared(input)?))
}

/// [`cbor_decode`], keeping the reader's shared byte strings.
///
/// Crate-internal on purpose: the only callers are the ones that hand the
/// allocation straight to a leaf, which is the entire reason it exists.
pub(crate) fn cbor_decode_shared(input: &[u8]) -> Result<CborValue> {
    let mut reader = CborReader { input, cursor: 0 };
    let value = reader.read_value(0)?;
    if reader.cursor != input.len() {
        return Err(Error::InvalidCbor {
            detail: "trailing bytes after the top-level value",
        });
    }
    Ok(value)
}

/// Rewrites a freshly decoded tree so every byte string is owned.
///
/// This copies nothing for its intended caller: the tree was built by the line
/// directly above, so every `Arc` is uniquely owned and `try_unwrap` moves the
/// `Vec` out rather than duplicating it. The clone arm is unreachable from
/// there and exists only so the function is total.
fn own_shared_bytes(value: CborValue) -> CborValue {
    match value {
        CborValue::SharedBytes(bytes) => CborValue::Bytes(match Arc::try_unwrap(bytes) {
            Ok(owned) => owned,
            Err(shared) => shared.as_ref().clone(),
        }),
        CborValue::Array(values) => {
            CborValue::Array(values.into_iter().map(own_shared_bytes).collect())
        }
        CborValue::Map(pairs) => CborValue::Map(
            pairs
                .into_iter()
                .map(|(key, value)| (key, own_shared_bytes(value)))
                .collect(),
        ),
        other => other,
    }
}

struct CborReader<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl CborReader<'_> {
    fn read_value(&mut self, depth: usize) -> Result<CborValue> {
        if depth > 256 {
            return Err(Error::InvalidCbor {
                detail: "maximum nesting depth exceeded",
            });
        }
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 => Ok(CborValue::Unsigned(self.read_argument(additional)?)),
            1 => Ok(CborValue::Negative(CborNegative {
                argument: self.read_argument(additional)?,
            })),
            2 => {
                let length = self.read_length(additional)?;
                // Shared, not owned: this allocation is handed straight to the
                // leaf, so a decoded payload is copied once rather than twice.
                Ok(CborValue::SharedBytes(Arc::new(
                    self.read_exact(length)?.to_vec(),
                )))
            }
            3 => {
                let length = self.read_length(additional)?;
                let bytes = self.read_exact(length)?;
                let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidCbor {
                    detail: "text string is not valid UTF-8",
                })?;
                Ok(CborValue::Text(text.to_owned()))
            }
            4 => {
                let length = self.read_length(additional)?;
                let mut values = Vec::new();
                values
                    .try_reserve_exact(length)
                    .map_err(|_| Error::AllocationFailed {
                        resource: "CBOR array",
                        requested: length as u64,
                    })?;
                for _ in 0..length {
                    values.push(self.read_value(depth + 1)?);
                }
                Ok(CborValue::Array(values))
            }
            5 => {
                let length = self.read_length(additional)?;
                let mut pairs = Vec::new();
                pairs
                    .try_reserve_exact(length)
                    .map_err(|_| Error::AllocationFailed {
                        resource: "CBOR map",
                        requested: length as u64,
                    })?;
                let mut keys = BTreeSet::new();
                for _ in 0..length {
                    let key = match self.read_value(depth + 1)? {
                        CborValue::Text(key) => key,
                        _ => {
                            return Err(Error::InvalidCbor {
                                detail: "map key is not a text string",
                            });
                        }
                    };
                    if !keys.insert(key.clone()) {
                        return Err(Error::DuplicateKey { key });
                    }
                    let value = self.read_value(depth + 1)?;
                    pairs.push((key, value));
                }
                Ok(CborValue::Map(pairs))
            }
            7 => match additional {
                20 => Ok(CborValue::Bool(false)),
                21 => Ok(CborValue::Bool(true)),
                22 => Ok(CborValue::Null),
                _ => Err(Error::InvalidCbor {
                    detail: "unsupported simple or floating-point value",
                }),
            },
            _ => Err(Error::InvalidCbor {
                detail: "unsupported CBOR major type",
            }),
        }
    }

    fn read_argument(&mut self, additional: u8) -> Result<u64> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => Ok(u64::from(self.read_byte()?)),
            25 => {
                let bytes: [u8; 2] = self.read_exact(2)?.try_into().expect("two bytes");
                Ok(u64::from(u16::from_be_bytes(bytes)))
            }
            26 => {
                let bytes: [u8; 4] = self.read_exact(4)?.try_into().expect("four bytes");
                Ok(u64::from(u32::from_be_bytes(bytes)))
            }
            27 => {
                let bytes: [u8; 8] = self.read_exact(8)?.try_into().expect("eight bytes");
                Ok(u64::from_be_bytes(bytes))
            }
            _ => Err(Error::InvalidCbor {
                detail: "indefinite or reserved argument encoding",
            }),
        }
    }

    fn read_length(&mut self, additional: u8) -> Result<usize> {
        let length = self.read_argument(additional)?;
        usize::try_from(length).map_err(|_| Error::InvalidCbor {
            detail: "collection length exceeds usize",
        })
    }

    fn read_byte(&mut self) -> Result<u8> {
        let byte = self.input.get(self.cursor).copied().ok_or(Error::InvalidCbor {
            detail: "truncated input",
        })?;
        self.cursor += 1;
        Ok(byte)
    }

    fn read_exact(&mut self, length: usize) -> Result<&[u8]> {
        let end = self.cursor.checked_add(length).ok_or(Error::InvalidCbor {
            detail: "length overflow",
        })?;
        let bytes = self.input.get(self.cursor..end).ok_or(Error::InvalidCbor {
            detail: "declared length exceeds input",
        })?;
        self.cursor = end;
        Ok(bytes)
    }
}

fn encode_value(value: &CborValue, output: &mut Vec<u8>) {
    match value {
        CborValue::Unsigned(value) => encode_argument(0, *value, output),
        CborValue::Negative(value) => encode_argument(1, value.argument(), output),
        CborValue::Bytes(bytes) => {
            encode_argument(2, bytes.len() as u64, output);
            output.extend_from_slice(bytes);
        }
        // Same major type and same bytes as `Bytes`; only the ownership of the
        // source differs, so the wire output is identical either way.
        CborValue::SharedBytes(bytes) => {
            encode_argument(2, bytes.len() as u64, output);
            output.extend_from_slice(bytes);
        }
        CborValue::Text(text) => {
            encode_argument(3, text.len() as u64, output);
            output.extend_from_slice(text.as_bytes());
        }
        CborValue::Array(values) => {
            encode_argument(4, values.len() as u64, output);
            for value in values {
                encode_value(value, output);
            }
        }
        CborValue::Map(pairs) => {
            encode_argument(5, pairs.len() as u64, output);
            for (key, value) in pairs {
                // Written in place on purpose. Wrapping the key in a temporary
                // `CborValue::Text` clones the String once per key, per map, per
                // encode -- thousands of pointless allocations for bytes that are
                // already sitting right here.
                encode_argument(3, key.len() as u64, output);
                output.extend_from_slice(key.as_bytes());
                encode_value(value, output);
            }
        }
        CborValue::Null => output.push(0xf6),
        CborValue::Bool(false) => output.push(0xf4),
        CborValue::Bool(true) => output.push(0xf5),
    }
}

fn encode_argument(major: u8, value: u64, output: &mut Vec<u8>) {
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | value as u8),
        24..=255 => {
            output.push(prefix | 24);
            output.push(value as u8);
        }
        256..=65_535 => {
            output.push(prefix | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        65_536..=4_294_967_295 => {
            output.push(prefix | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(prefix | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

pub fn base32_lower(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    let mut output = String::with_capacity((input.len() * 8).div_ceil(5));
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for &byte in input {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((accumulator >> bits) & 0x1f) as usize;
            output.push(BASE32_ALPHABET[index] as char);
        }
    }
    if bits != 0 {
        let index = ((accumulator << (5 - bits)) & 0x1f) as usize;
        output.push(BASE32_ALPHABET[index] as char);
    }
    output
}

pub(crate) fn base32_lower_decode(input: &str) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len() * 5 / 8);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in input.bytes() {
        let value = match byte {
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(Error::InvalidBase32),
        };
        accumulator = (accumulator << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push(((accumulator >> bits) & 0xff) as u8);
            accumulator &= if bits == 0 { 0 } else { (1_u32 << bits) - 1 };
        }
    }
    if bits != 0 && accumulator != 0 {
        return Err(Error::InvalidBase32);
    }
    Ok(output)
}

pub(crate) fn base64_standard(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}

pub(crate) fn base64_standard_decode(input: &str) -> Result<Vec<u8>> {
    if input.len() % 4 != 0 {
        return Err(Error::InvalidBase64);
    }
    let mut output = Vec::with_capacity(input.len() / 4 * 3);
    let bytes = input.as_bytes();
    for (quartet_index, quartet) in bytes.chunks_exact(4).enumerate() {
        let last = quartet_index + 1 == bytes.len() / 4;
        let a = base64_value(quartet[0])?;
        let b = base64_value(quartet[1])?;
        let c = if quartet[2] == b'=' {
            64
        } else {
            base64_value(quartet[2])?
        };
        let d = if quartet[3] == b'=' {
            64
        } else {
            base64_value(quartet[3])?
        };
        if a == 64
            || b == 64
            || c == 64 && d != 64
            || d == 64 && !last
            || c == 64 && b & 0x0f != 0
            || d == 64 && c != 64 && c & 0x03 != 0
        {
            return Err(Error::InvalidBase64);
        }
        output.push((a << 2) | (b >> 4));
        if c != 64 {
            output.push((b << 4) | (c >> 2));
        }
        if d != 64 {
            output.push((c << 6) | d);
        }
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Result<u8> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(Error::InvalidBase64),
    }
}

pub fn base58_btc(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    let leading_zeroes = input.iter().take_while(|&&byte| byte == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in &input[leading_zeroes..] {
        let mut carry = u32::from(byte);
        for digit in &mut digits {
            let value = u32::from(*digit) * 256 + carry;
            *digit = (value % 58) as u8;
            carry = value / 58;
        }
        while carry != 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut output = String::with_capacity(leading_zeroes + digits.len());
    output.extend(std::iter::repeat_n('1', leading_zeroes));
    for digit in digits.iter().rev() {
        output.push(BASE58_ALPHABET[*digit as usize] as char);
    }
    output
}

pub fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut output = Vec::with_capacity(10);
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
    output
}

pub fn decode_varint(input: &[u8]) -> Result<(u64, usize)> {
    let mut value = 0_u64;
    for (index, &byte) in input.iter().enumerate() {
        if index == 9 && (byte & 0xfe) != 0 {
            return Err(Error::VarintOverflow);
        }
        let shift = (index * 7) as u32;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
        if index == 9 {
            return Err(Error::VarintOverflow);
        }
    }
    Err(Error::TruncatedVarint)
}

pub fn sha256(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

pub(crate) fn cid_bytes_for_cbor(input: &[u8]) -> [u8; 36] {
    let digest = sha256(input);
    let mut bytes = [0_u8; 36];
    bytes[..4].copy_from_slice(&[0x01, 0x51, 0x12, 0x20]);
    bytes[4..].copy_from_slice(&digest);
    bytes
}

pub(crate) fn cid_text(bytes: &[u8; 36]) -> String {
    let mut output = String::with_capacity(59);
    output.push('b');
    output.push_str(&base32_lower(bytes));
    output
}
