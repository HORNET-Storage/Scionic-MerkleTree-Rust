//! SHA-256, and the two ways a hash is written as text: base32 for a root,
//! and hex.

use crate::{Error, Result};
use sha2::{Digest as _, Sha256};

const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const HEX_ALPHABET: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn sha256(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

/// Lowercase base32 with no padding.
pub(crate) fn base32_lower(input: &[u8]) -> String {
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

/// Reads lowercase base32 with no padding. A letter outside the alphabet is an
/// error, and so are bits left over that are not zero.
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

pub(crate) fn hex_lower(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len() * 2);
    for &byte in input {
        output.push(HEX_ALPHABET[usize::from(byte >> 4)] as char);
        output.push(HEX_ALPHABET[usize::from(byte & 0x0f)] as char);
    }
    output
}

/// Reads lowercase hex into `output`, which it must fill exactly.
pub(crate) fn hex_lower_decode(input: &str, output: &mut [u8]) -> Result<()> {
    let input = input.as_bytes();
    if input.len() != output.len() * 2 {
        return Err(Error::InvalidHex);
    }
    for (slot, pair) in output.iter_mut().zip(input.chunks_exact(2)) {
        *slot = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Ok(())
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(Error::InvalidHex),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_reads_back_what_it_writes_at_every_length() {
        let bytes: Vec<u8> = (0_u16..64).map(|value| (value * 37 % 251) as u8).collect();
        for length in 0..bytes.len() {
            let text = base32_lower(&bytes[..length]);
            assert_eq!(base32_lower_decode(&text).unwrap(), &bytes[..length]);
        }
        assert_eq!(base32_lower(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn base32_refuses_other_letters_and_leftover_bits() {
        for text in ["MZXW6", "mzxw1", "mzxw=", "mz xw", "mzxw6ytbo1"] {
            assert!(base32_lower_decode(text).is_err(), "{text:?}");
        }
        // "my" is one byte and two bits that are zero; "mz" leaves a bit set.
        assert_eq!(base32_lower_decode("my").unwrap(), [0x66]);
        assert_eq!(base32_lower(&[0x66]), "my");
        assert!(base32_lower_decode("mz").is_err());
    }

    #[test]
    fn hex_reads_back_what_it_writes_and_refuses_the_rest() {
        let bytes = [0x00, 0x01, 0x7f, 0x80, 0xab, 0xff];
        let text = hex_lower(&bytes);
        assert_eq!(text, "00017f80abff");
        let mut back = [0_u8; 6];
        hex_lower_decode(&text, &mut back).unwrap();
        assert_eq!(back, bytes);
        for text in [
            "00017F80ABFF",
            "00017f80abf",
            "00017f80abfff",
            "00017f80abfg",
        ] {
            assert!(hex_lower_decode(text, &mut back).is_err(), "{text:?}");
        }
    }
}
