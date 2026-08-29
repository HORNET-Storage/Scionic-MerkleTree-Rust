use scionic_merkletree::encoding::{
    base32_lower, base58_btc, cbor_decode, cbor_encode, decode_varint, encode_varint, CborValue,
};
use scionic_merkletree::{Cid, Error};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn cbor_reference_table_is_byte_exact() {
    let cases = vec![
        (CborValue::Unsigned(0), "00"),
        (CborValue::Unsigned(23), "17"),
        (CborValue::Unsigned(24), "1818"),
        (CborValue::Unsigned(42), "182a"),
        (CborValue::Unsigned(255), "18ff"),
        (CborValue::Unsigned(256), "190100"),
        (CborValue::Unsigned(1_000), "1903e8"),
        (CborValue::Unsigned(65_535), "19ffff"),
        (CborValue::Unsigned(65_536), "1a00010000"),
        (CborValue::Unsigned(1_000_000), "1a000f4240"),
        (CborValue::negative(-1).unwrap(), "20"),
        (CborValue::negative(-10).unwrap(), "29"),
        (CborValue::negative(-100).unwrap(), "3863"),
        (CborValue::negative(i64::MIN).unwrap(), "3b7fffffffffffffff"),
        (CborValue::Bytes(Vec::new()), "40"),
        (CborValue::Bytes(vec![1, 2, 3, 4]), "4401020304"),
        (CborValue::Text(String::new()), "60"),
        (CborValue::Text("hello".to_owned()), "6568656c6c6f"),
        (CborValue::Text("file".to_owned()), "6466696c65"),
        (CborValue::Array(Vec::new()), "80"),
        (
            CborValue::Array(vec![
                CborValue::Unsigned(1),
                CborValue::Unsigned(2),
                CborValue::Unsigned(3),
            ]),
            "83010203",
        ),
        (CborValue::Map(Vec::new()), "a0"),
        (CborValue::Null, "f6"),
        (CborValue::Bool(false), "f4"),
        (CborValue::Bool(true), "f5"),
    ];
    for (value, expected) in cases {
        assert_eq!(hex(&cbor_encode(&value)), expected);
    }
}

#[test]
fn cbor_negative_constructor_rejects_zero_and_positive_values() {
    for value in [0, 1, i64::MAX] {
        assert!(matches!(
            CborValue::negative(value),
            Err(Error::InvalidCborNegative { value: rejected }) if rejected == value
        ));
    }
}

#[test]
fn cbor_preserves_map_order_and_nil_empty_states() {
    let ba = CborValue::Map(vec![
        ("B".to_owned(), CborValue::Unsigned(1)),
        ("A".to_owned(), CborValue::Unsigned(2)),
    ]);
    let ab = CborValue::Map(vec![
        ("A".to_owned(), CborValue::Unsigned(2)),
        ("B".to_owned(), CborValue::Unsigned(1)),
    ]);
    assert_eq!(hex(&cbor_encode(&ba)), "a2614201614102");
    assert_eq!(hex(&cbor_encode(&ab)), "a2614102614201");
    assert_ne!(cbor_encode(&ba), cbor_encode(&ab));
    assert_eq!(hex(&cbor_encode(&CborValue::Null)), "f6");
    assert_eq!(hex(&cbor_encode(&CborValue::Bytes(Vec::new()))), "40");
    assert_eq!(hex(&cbor_encode(&CborValue::Array(Vec::new()))), "80");
    assert_eq!(hex(&cbor_encode(&CborValue::Map(Vec::new()))), "a0");
}

#[test]
fn public_cbor_decode_round_trips_supported_values_and_rejects_malformed_input() {
    let value = CborValue::Map(vec![
        ("unsigned".to_owned(), CborValue::Unsigned(42)),
        ("negative".to_owned(), CborValue::negative(-7).unwrap()),
        ("bytes".to_owned(), CborValue::Bytes(vec![0, 1, 255])),
        ("text".to_owned(), CborValue::Text("snow 雪".to_owned())),
        (
            "array".to_owned(),
            CborValue::Array(vec![CborValue::Null, CborValue::Bool(true)]),
        ),
        ("false".to_owned(), CborValue::Bool(false)),
    ]);
    assert_eq!(cbor_decode(&cbor_encode(&value)).unwrap(), value);

    assert!(matches!(
        cbor_decode(&[0xa2, 0x61, b'a', 0x00, 0x61, b'a', 0x01]),
        Err(Error::DuplicateKey { key }) if key == "a"
    ));
    for malformed in [
        vec![0x00, 0x00],
        vec![0xa1, 0x00, 0x00],
        vec![0x58, 0x02, 0x00],
        vec![0xf7],
    ] {
        assert!(matches!(
            cbor_decode(&malformed),
            Err(Error::InvalidCbor { .. })
        ));
    }
    let mut too_deep = vec![0x81; 257];
    too_deep.push(0x00);
    assert!(matches!(
        cbor_decode(&too_deep),
        Err(Error::InvalidCbor {
            detail: "maximum nesting depth exceeded"
        })
    ));
}

/// `cbor_decode` is public, so *which variant* it returns is part of the API.
///
/// The reader allocates byte strings behind an `Arc` so leaf decoding can adopt
/// them instead of copying; that is a representation choice, and letting it out
/// through the public decoder breaks every downstream
/// `matches!(value, CborValue::Bytes(_))` while looking like a pure speedup in
/// review. It shipped exactly that way once.
///
/// The round-trip test above cannot catch it. `PartialEq` compares CBOR values
/// rather than representations -- `Bytes == SharedBytes` on purpose, so that
/// `decode(encode(x)) == x` does not fail over ownership -- which leaves the
/// variant itself as the one thing `==` is blind to. Hence a separate test that
/// asserts nothing but the variant.
#[test]
fn public_cbor_decode_returns_owned_bytes_at_every_depth() {
    fn assert_owned(value: &CborValue) {
        match value {
            CborValue::Array(values) => values.iter().for_each(assert_owned),
            CborValue::Map(pairs) => pairs.iter().for_each(|(_, value)| assert_owned(value)),
            other => assert!(
                !matches!(other, CborValue::SharedBytes(_)),
                "public cbor_decode leaked the crate-internal shared byte representation"
            ),
        }
    }

    let value = CborValue::Map(vec![
        ("top".to_owned(), CborValue::Bytes(vec![1, 2, 3])),
        ("empty".to_owned(), CborValue::Bytes(Vec::new())),
        (
            "nested".to_owned(),
            CborValue::Array(vec![
                CborValue::Bytes(vec![4]),
                CborValue::Map(vec![("deep".to_owned(), CborValue::Bytes(vec![5, 6]))]),
            ]),
        ),
    ]);

    let decoded = cbor_decode(&cbor_encode(&value)).unwrap();
    assert_owned(&decoded);
    // Value equality still has to hold; the point is that it is not sufficient.
    assert_eq!(decoded, value);
}

#[test]
fn base32lower_reference_table_is_exact() {
    let cases = [
        ("f", "my"),
        ("fo", "mzxq"),
        ("foo", "mzxw6"),
        ("foob", "mzxw6yq"),
        ("fooba", "mzxw6ytb"),
        ("foobar", "mzxw6ytboi"),
    ];
    for (input, expected) in cases {
        assert_eq!(base32_lower(input.as_bytes()), expected);
    }
    assert_eq!(base32_lower(&[]), "");
}

#[test]
fn base58btc_reference_table_is_exact() {
    assert_eq!(base58_btc(b"Hello World!"), "2NEpo7TZRRrLZSi2U");
    // The Go arithmetic and passing Swift test use 0000287fb4cd; the extra 87 in
    // the prose table is a documented typo rather than a protocol behavior.
    assert_eq!(base58_btc(&[0, 0, 0x28, 0x7f, 0xb4, 0xcd]), "11233QC4");
    assert_eq!(base58_btc(&[0]), "1");
    assert_eq!(base58_btc(&[0, 0]), "11");
    assert_eq!(base58_btc(&[]), "");
}

#[test]
fn unsigned_varint_reference_table_round_trips() {
    let cases = [
        (0, "00"),
        (1, "01"),
        (18, "12"),
        (32, "20"),
        (81, "51"),
        (113, "71"),
        (127, "7f"),
        (128, "8001"),
        (300, "ac02"),
    ];
    for (value, expected) in cases {
        let encoded = encode_varint(value);
        assert_eq!(hex(&encoded), expected);
        assert_eq!(decode_varint(&encoded).unwrap(), (value, encoded.len()));
    }
    assert!(decode_varint(&[0x80]).is_err());
    assert!(decode_varint(&[0xff; 10]).is_err());
}

#[test]
fn generated_cid_uses_plain_cbor_codec_and_fixed_sha256_frame() {
    let cid = Cid::from_cbor(b"layer-one-cid");
    assert_eq!(cid.as_bytes().len(), 36);
    assert_eq!(&cid.as_bytes()[..4], &[0x01, 0x51, 0x12, 0x20]);
    assert_eq!(cid.as_str().len(), 59);
    assert!(cid.as_str().starts_with("bafirei"));
    assert_eq!(cid.as_str(), format!("b{}", base32_lower(cid.as_bytes())));
    let mut wrong_codec = *cid.as_bytes();
    wrong_codec[1] = 0x71;
    let wrong_text = format!("b{}", base32_lower(&wrong_codec));
    assert!(wrong_text.starts_with("bafyrei"));
    assert_ne!(wrong_text, cid.as_str());
}
