//! fastcdc-v1 — content-defined chunking (FastCDC, Xia et al. 2016), the
//! DEFAULT chunking mode for all new trees. The normative specification is
//! this repository's `docs/fastcdc-v1.md`; this implementation and the
//! committed conformance vectors define its frozen byte contract.
//!
//! Fixed-size chunking ([`Chunking::Fixed`] / [`Chunking::Disabled`]) remains
//! available as an explicit current mode; the committed spec-vector corpus and
//! callers pin it explicitly. Verification is chunking-agnostic — no verifier
//! re-chunks — so trees cut by either mode verify identically everywhere.
//!
//! Every constant in this file is NORMATIVE and frozen as fastcdc-v1. Any
//! change — a size, a mask, a gear entry, an off-by-one in the boundary
//! loop — is a NEW chunking version tag, never a mutation: producers only
//! dedup against each other when every SDK cuts bit-identical boundaries,
//! and a divergent implementation produces valid-looking trees that never
//! dedup, detectable only by the conformance vectors under
//! `spec/fastcdc-vectors`.

use crate::dag::{Chunking, MAX_IN_MEMORY_LEAF_BYTES};
use crate::{io_error, Result};
use std::io::Read;
use std::path::Path;

/// Cut-point skipping floor: no boundary test runs inside the first
/// `FASTCDC_MIN_SIZE` bytes of a chunk, and those bytes are not hashed at
/// all. Interior chunks are therefore at least `FASTCDC_MIN_SIZE + 1` bytes;
/// only a final tail chunk may be smaller.
pub const FASTCDC_MIN_SIZE: usize = 512 * 1024;

/// Normalization switch: the strict mask judges positions before it, the
/// loose mask after it, squeezing the chunk-size distribution toward the
/// target. It matches the fixed-mode default (`DEFAULT_CHUNK_SIZE`), so
/// leaf counts and stats stay in the same ballpark across the mode change.
pub const FASTCDC_TARGET_SIZE: usize = 2048 * 1024;

/// Forced-cut ceiling. It exists to bound worst-case chunk size (record
/// framing, transport batching), not as a size anyone chooses: with
/// normalized chunking a forced cut is rare, degenerate-content territory.
pub const FASTCDC_MAX_SIZE: usize = 8192 * 1024;

/// Selects the top 23 bits of the rolling hash (boundary ⇔ h < 2^41).
/// Used for positions before `FASTCDC_TARGET_SIZE`.
pub const FASTCDC_STRICT_MASK: u64 = 0xFFFF_FE00_0000_0000;

/// Selects the top 19 bits (boundary ⇔ h < 2^45). Used for positions at or
/// after `FASTCDC_TARGET_SIZE`. The loose mask is a subset of the strict.
pub const FASTCDC_LOOSE_MASK: u64 = 0xFFFF_E000_0000_0000;

/// Frozen derivation seed for the gear table below:
///
/// ```text
/// G[i] = u64be(SHA-256(FASTCDC_GEAR_SEED_PREFIX ++ byte(i))[0:8])
/// ```
///
/// where `byte(i)` is the single raw byte with value `i`. The regeneration
/// test re-derives every entry and fails on drift.
pub const FASTCDC_GEAR_SEED_PREFIX: &str = "scionic-fastcdc-v1:gear:";

/// AdditionalData key carrying the chunking tag on root leaves. The tag
/// informs producers and delta tooling only; verification MUST NOT re-chunk
/// and verifiers ignore it entirely.
pub const CHUNKING_TAG_KEY: &str = "chunking";

/// Tags roots cut with fastcdc-v1.
pub const CHUNKING_FASTCDC_V1: &str = "fastcdc-v1";

/// The implied value when the tag is absent: every pre-fastcdc tree was cut
/// fixed-size. Producers never stamp it.
pub const CHUNKING_FIXED_2M: &str = "fixed-2m";

// A forced-cut chunk must always fit the crate's in-memory leaf budget.
const _: () = assert!(FASTCDC_MAX_SIZE <= MAX_IN_MEMORY_LEAF_BYTES);

/// The frozen fastcdc-v1 gear table, derived exactly from
/// [`FASTCDC_GEAR_SEED_PREFIX`]. It is committed as literals so the runtime
/// needs no hashing; the seed-derivation unit test is the regeneration check.
#[rustfmt::skip]
pub(crate) static FASTCDC_GEAR: [u64; 256] = [
    0x947e4e1b8bedab5d, 0xd7d7f340329c706e, 0x24b4933c9d4b8dbc, 0x55c3cff8b195ba49,
    0xa36a40a32a15eb96, 0x8897e6f568db999a, 0x947a231bb313926d, 0xe7e926bd79e72444,
    0x64ca6fd402ccab41, 0x22380ac762595371, 0xa1027491350cae72, 0xf3538e28c8606995,
    0x35340c7c2bbf517c, 0xf4673c048041926c, 0x619d36e34045ed48, 0x62f7eea257e5fa53,
    0xf6592b0a28cbfe72, 0x57dbf4bc9c6b6c13, 0x4570eda97a46bcd7, 0xe700b4d777b13368,
    0xfeaa0ed12db1fb1e, 0x5eaaa35f803749c5, 0x98d4aaf60762ce22, 0x57e5c72e8ca35383,
    0xfa73cdf93e8a0aa2, 0x5ff08d8005821eaf, 0x22bfbfb0909e5a97, 0xaf640461642bc5ec,
    0xf52f62b326a87782, 0x0b48fe2026c4d431, 0xe32da4ee6ee83556, 0xf6fb7c97d1347f1e,
    0xd8db48db0fc909b1, 0x61a094811e1147be, 0x55212f91cebc2fd7, 0x3cc046faa63bd6b6,
    0x6e58acaa5d253fc2, 0xdabaafb8773dd9df, 0x97e17884746879ba, 0xba04b1babdf2b315,
    0xebbba32ca84e54d4, 0xf5e823b31a74a250, 0x3a53c93b59c25ac1, 0xbbeef3c363a99a40,
    0xa43fee0764787596, 0x13afe9712464954f, 0xfb8c8b920ee55c9e, 0xd4d7bf30b1a6a5ad,
    0x0389222afdca4fd5, 0xe9ab9fb7f5155a62, 0x9f77717172866e25, 0xd2ad3637f74249a5,
    0x50bbdad70cdcd17c, 0xec8f7f90e393a183, 0x1446de505ccf5c72, 0xe6e78a5e4b304fb6,
    0x0bbe404684ecdad1, 0x532bcb63c95a255d, 0xd887c18de16cf115, 0xf513ad7d0f7d3d50,
    0x849baac5ecdefbdb, 0x94a4f2fbbcca6083, 0x1b3c9424f9385894, 0xe11e8a43c22fabcb,
    0x9b4b010fc51f21dc, 0x6acd6dbfdf0d9580, 0x7ff7afdb56a0cabf, 0x2ca318014a93f66f,
    0x903803b30226b845, 0xd706e07a902ffcf4, 0x1e43989c9177836a, 0x1450b82ebfeb59be,
    0x0317972865643dc9, 0x20d89fae677a1a46, 0x13afa6f5de7d8bc7, 0x1365198f21449085,
    0xaf159551b9609008, 0xc77a9ae105ce78ce, 0x5f6c8e2d03eb54dc, 0x276ff2550d88ac9f,
    0xa9a03f05b8ca6378, 0x2ee9d93e36176ace, 0x96f94afebcb129f1, 0x8a180b184c6c0c2c,
    0xfa8c5698643f71e4, 0x6dae6ffbcc920ed9, 0xb51d5e1420ac4477, 0xf96f4bda00bebd4b,
    0x835c221df076b64f, 0x6f1d8cb095611348, 0x519baf5ef53f2ccc, 0xf1756553b94e6fd7,
    0x794c84868fdfa25d, 0x5bb0477715cb330d, 0xc0480a057f24d19a, 0xb49ff580892d857f,
    0x4390cbc9493cd65e, 0x4501cfd187cdfaa1, 0xffa17ec6bed4ece5, 0x974516ddd0070b5d,
    0x6e2e1d0829952e10, 0xaf09891926e64ecc, 0xec238b26dd8650f4, 0x003af629de3d5d67,
    0x5f650eb277966586, 0x5acee337d875e529, 0xb768d8c2fd5074de, 0xf7ed06da4a4e2ee7,
    0xfaf4f98b5e203cce, 0xec9aea5b69f1c7c6, 0x210077754e20fa0f, 0x0beb1e323cb5510d,
    0x0e53d51183d4fe31, 0x006474795bf9118a, 0xd4b6d7c83ce5f2db, 0x42284ffa1d364d86,
    0x059c41476b5a023e, 0xdce31ea609858492, 0xd5bb4b3f8fb4c91d, 0x497195b5e4a4edc8,
    0x7d18c40f80f16a55, 0x9e4759761b570c17, 0x6fe3fb1dad1caf51, 0xd4f2b14506aae434,
    0xf2aaedad0a75b8f9, 0x8800c63677d46e91, 0x3669e9c07cdd7731, 0x396b68f5f4a95f57,
    0xaa52f9224a19c939, 0x74d1d3ad35a47f39, 0xd02dead3f0370ad1, 0x6f6f5e39506d8dd3,
    0xdd91c64473a67fad, 0x912c5a1ea387c83c, 0x0f1aef548e375e08, 0x5915126ae7ef44e5,
    0x4020e3d9b310f006, 0x57d3f19162586ae5, 0x0ec8f9bf9db952df, 0x234b45cf1ad3dece,
    0xc3439843e92ae994, 0xd6a5719e68c9f484, 0xb4c1920d525d8342, 0xb27eb38f9bbe448d,
    0x9be1ce0459d5c299, 0x4aa52d6a2dbf8342, 0x9851857f62521d37, 0x457947691df8e1fa,
    0x123ef433bc6ae855, 0x45437f1d09980d29, 0x83d6c5a9df253dac, 0xe0d309d01910481c,
    0xf5c31ed8759b25f3, 0x771c0d3936a0d986, 0x487038360bcb3235, 0x8b21d49aed2642e6,
    0xefaaeca49be99218, 0xa463929852ae6bcc, 0x9cfecd6e80346297, 0xdcb4fb0875840689,
    0x37c021d3c8e21186, 0x497f8574675b0d6a, 0x63ff7e7711d33f63, 0x27ceee2fcc031a44,
    0x77b6ec906259e727, 0xaa6454644dccc7dc, 0xa97809bb81de4c81, 0xa92caa6f12da83e6,
    0x419ba0ced90afe95, 0xc1a53002045d97de, 0xb656c2ff7d936018, 0xce49ab8e335c711b,
    0xb6f7f1f1faef85be, 0xc7fc1e0121f1f24e, 0x207f2299674cc436, 0x88ae73e046435d4a,
    0xda8b37dfd93f6cf2, 0xf8bed85aeb4de430, 0x91a05c5a842d2d3e, 0xba4acf82afc1adab,
    0x6604af724f5a2613, 0xe7487d9966306e33, 0xc8f25c01a080b6f8, 0x2579070bb841d4ea,
    0x9d0436b67a346b82, 0xddf70ae38d392e1d, 0x82fc34556533ef4e, 0xc1666e597f289225,
    0x292f47b7b03c0ad8, 0xe917418a9c71a420, 0x2512d2de56ee6abc, 0xaee5398dbcefd1a9,
    0xfd22f9171720f863, 0xdaa15260adf7ee0c, 0x8ac4120e5fca515b, 0x50c57f96eac726cb,
    0x6a8204b4b79797af, 0x7466e7a4f5d03674, 0x5cb8d6f12355cad5, 0x8120ce60387b354c,
    0x35a581514dba45d5, 0x2943845f6f208780, 0x6b5dcf7ec3a3f226, 0xbdcb9125a6c569ce,
    0x48cf3a90e9f40ca0, 0xdc147857a9b243ab, 0xcf02699bfa87d53e, 0x5f764f21da6ebd9e,
    0xa33c8b10a66ad086, 0x67a21420306440f6, 0x3227f62c1550edf1, 0xf075bc356a5a6c19,
    0x692445ed785b7fee, 0xbdc8aac2413c5869, 0x9ba4cb61288e442e, 0xd595279bb31b949e,
    0x128284fde7e3c4f9, 0x1f78bc1a35436eb8, 0xd78586033f026e98, 0xff65419e1caad205,
    0x2121853fca84902d, 0x1f509792e8676c6f, 0x071efae5e5c7cdba, 0xdf9fbe86bb672b62,
    0x2a48e13feb8155d1, 0x362d3079f581cc21, 0x82d1d37ef9fed7d7, 0xfeb8fcbf0d0f56a8,
    0x1cd4673b1aa2e903, 0x7361c495b3516d42, 0x72b341a59b0beec5, 0xc87496bf153d4294,
    0xb180301df83ddd18, 0xc26006a95f083463, 0x140390533647c3c7, 0xc617932041cccb0e,
    0x7afb61832b5a47f6, 0x982f9e423b8ec593, 0xcd3da2d1fb9f4b32, 0x9cf5b507ed12f70a,
    0xafeea67eb17c3ecb, 0x29bde8df040ac225, 0xec8826f6677ae75c, 0xf3ee4e78d7ec22ad,
    0x73c39d59142cf6be, 0x79ad4c76a58450e1, 0xfeb76f05f4b5266d, 0x5c661848895afeb6,
    0xa3d419256671c19e, 0xfeab6e3349a9aee8, 0x8947c9860ea0a859, 0x88d04b136b03be5d,
    0x6d3315241ab6bea2, 0x9574ce7f94a7374d, 0xf9f0bc62e740e03b, 0x628f935ad9cce8d5,
];

/// Returns the length of the next chunk cut from `data`. The caller
/// guarantees `data` is either at least [`FASTCDC_MAX_SIZE`] bytes long or
/// ends at EOF — under that contract the decision is final: a boundary can
/// never depend on bytes past the forced maximum.
///
/// This loop IS the normative fastcdc-v1 boundary definition. The rolling
/// hash starts at zero for every chunk, bytes `[0, FASTCDC_MIN_SIZE)` are
/// skipped without hashing, arithmetic is wrapping u64, and a match on byte
/// index `i` cuts AFTER that byte (length `i + 1`).
pub(crate) fn fastcdc_boundary(data: &[u8]) -> usize {
    let n = data.len();
    if n <= FASTCDC_MIN_SIZE {
        return n;
    }
    let limit = n.min(FASTCDC_MAX_SIZE);
    let normal = FASTCDC_TARGET_SIZE.min(limit);
    let mut h: u64 = 0;
    for i in FASTCDC_MIN_SIZE..normal {
        h = (h << 1).wrapping_add(FASTCDC_GEAR[data[i] as usize]);
        if h & FASTCDC_STRICT_MASK == 0 {
            return i + 1;
        }
    }
    for i in normal..limit {
        h = (h << 1).wrapping_add(FASTCDC_GEAR[data[i] as usize]);
        if h & FASTCDC_LOOSE_MASK == 0 {
            return i + 1;
        }
    }
    limit
}

impl Chunking {
    /// Splits `data` into chunks under this chunking mode. The returned
    /// chunks are subslices of `data` (no copies). Empty input returns an
    /// empty vector.
    ///
    /// This is the public cutter for producers that hold content in memory:
    /// cutting through the library keeps every producer slicing identical
    /// content into identical chunks. Per-workload chunking would silently
    /// break cross-context dedup.
    pub fn cut(self, data: &[u8]) -> Vec<&[u8]> {
        if data.is_empty() {
            return Vec::new();
        }
        match self {
            Chunking::Disabled => vec![data],
            Chunking::Fixed(chunk_size) => {
                let chunk_size = chunk_size.get();
                if data.len() <= chunk_size {
                    return vec![data];
                }
                data.chunks(chunk_size).collect()
            }
            Chunking::FastCdcV1 => {
                let mut chunks = Vec::with_capacity(data.len() / FASTCDC_TARGET_SIZE + 1);
                let mut offset = 0;
                while offset < data.len() {
                    let cut = fastcdc_boundary(&data[offset..]);
                    chunks.push(&data[offset..offset + cut]);
                    offset += cut;
                }
                chunks
            }
        }
    }
}

/// Streams `reader` and emits fastcdc-v1 chunks in order. Each emitted chunk
/// is an exact-size allocation owned by the callback — leaves retain chunk
/// content, so chunks must never alias the reusable window. Transient memory
/// is one [`FASTCDC_MAX_SIZE`] window per concurrent call.
///
/// Windowing rule (normative): a boundary decision is final if and only if
/// the window holds [`FASTCDC_MAX_SIZE`] bytes or the input is exhausted —
/// which is what makes streaming equal whole-buffer cutting, byte for byte.
pub(crate) fn stream_fastcdc_chunks(
    reader: &mut dyn Read,
    path: &Path,
    mut on_chunk: impl FnMut(Vec<u8>, usize) -> Result<()>,
) -> Result<()> {
    let mut window = vec![0_u8; FASTCDC_MAX_SIZE];
    let mut filled = 0_usize;
    let mut index = 0_usize;
    let mut eof = false;
    loop {
        while filled < window.len() && !eof {
            let read = reader
                .read(&mut window[filled..])
                .map_err(|error| io_error("read file chunk", path, error))?;
            if read == 0 {
                eof = true;
            } else {
                filled += read;
            }
        }
        if filled == 0 {
            return Ok(());
        }
        while filled == window.len() || (eof && filled > 0) {
            let cut = fastcdc_boundary(&window[..filled]);
            on_chunk(window[..cut].to_vec(), index)?;
            index += 1;
            window.copy_within(cut..filled, 0);
            filled -= cut;
            if !eof {
                break; // refill the window before judging the next boundary
            }
        }
        if eof && filled == 0 {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::sha256;
    use std::collections::BTreeSet;
    use std::num::NonZeroUsize;

    /// The deterministic corpus generator shared with the conformance
    /// vectors: block `k` of the stream is `SHA-256(seed ++ u64be(k))`;
    /// blocks are concatenated and truncated to `length`.
    fn corpus_bytes(seed: &str, length: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(length + 32);
        let mut block: u64 = 0;
        while out.len() < length {
            let mut message = Vec::with_capacity(seed.len() + 8);
            message.extend_from_slice(seed.as_bytes());
            message.extend_from_slice(&block.to_be_bytes());
            out.extend_from_slice(&sha256(&message));
            block += 1;
        }
        out.truncate(length);
        out
    }

    #[test]
    fn gear_table_matches_seed_derivation() {
        for (i, &frozen) in FASTCDC_GEAR.iter().enumerate() {
            let mut message = FASTCDC_GEAR_SEED_PREFIX.as_bytes().to_vec();
            message.push(i as u8);
            let digest = sha256(&message);
            let expected = u64::from_be_bytes(digest[..8].try_into().unwrap());
            assert_eq!(
                frozen, expected,
                "fastCDCGear[{i}] drifted from the fastcdc-v1 seed derivation"
            );
        }
    }

    #[test]
    fn gear_table_eyeball_anchors_match_the_spec() {
        assert_eq!(FASTCDC_GEAR[0], 0x947e4e1b8bedab5d);
        assert_eq!(FASTCDC_GEAR[1], 0xd7d7f340329c706e);
    }

    #[test]
    fn constants_are_frozen() {
        assert_eq!(FASTCDC_MIN_SIZE, 512 * 1024);
        assert_eq!(FASTCDC_TARGET_SIZE, 2048 * 1024);
        assert_eq!(FASTCDC_MAX_SIZE, 8192 * 1024);
        let all_ones = !0_u64;
        assert_eq!(
            FASTCDC_STRICT_MASK,
            all_ones << 41,
            "strict mask must be the top 23 bits"
        );
        assert_eq!(
            FASTCDC_LOOSE_MASK,
            all_ones << 45,
            "loose mask must be the top 19 bits"
        );
        assert_eq!(FASTCDC_STRICT_MASK.count_ones(), 23);
        assert_eq!(FASTCDC_LOOSE_MASK.count_ones(), 19);
        assert_eq!(
            FASTCDC_STRICT_MASK & FASTCDC_LOOSE_MASK,
            FASTCDC_LOOSE_MASK,
            "the loose mask must be a subset of the strict mask"
        );
    }

    #[test]
    fn cut_bounds_and_determinism() {
        let data = corpus_bytes("scionic-fastcdc-v1:test:bounds", 40 << 20);
        let first = Chunking::FastCdcV1.cut(&data);
        let second = Chunking::FastCdcV1.cut(&data);
        assert_eq!(first, second, "two cuts of identical data must agree");
        assert!(!first.is_empty());
        let mut total = 0_usize;
        for (index, chunk) in first.iter().enumerate() {
            if index < first.len() - 1 {
                assert!(
                    chunk.len() > FASTCDC_MIN_SIZE,
                    "interior chunk {index} is {} bytes; interior chunks must exceed the min",
                    chunk.len()
                );
            }
            assert!(
                chunk.len() <= FASTCDC_MAX_SIZE,
                "chunk {index} exceeds the max"
            );
            total += chunk.len();
        }
        assert_eq!(total, data.len(), "chunks must cover the input exactly");
        let mean = total / first.len();
        assert!(
            (1 << 20..=4 << 20).contains(&mean),
            "mean chunk size {mean} is outside the [1MiB, 4MiB] sanity band"
        );
    }

    /// Returns data in awkward partial reads to exercise every refill path
    /// of the streaming cutter.
    struct StutterReader {
        data: Vec<u8>,
        offset: usize,
        step: usize,
    }

    impl Read for StutterReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.offset >= self.data.len() {
                return Ok(0);
            }
            let take = self
                .step
                .min(buffer.len())
                .min(self.data.len() - self.offset);
            buffer[..take].copy_from_slice(&self.data[self.offset..self.offset + take]);
            self.offset += take;
            Ok(take)
        }
    }

    #[test]
    fn streaming_matches_slice_cutting() {
        let lengths = [
            0,
            100,
            FASTCDC_MIN_SIZE,
            FASTCDC_MIN_SIZE + 1,
            FASTCDC_TARGET_SIZE,
            FASTCDC_MAX_SIZE,
            FASTCDC_MAX_SIZE + 1,
            3 << 20,
            20 << 20,
        ];
        for length in lengths {
            let data = corpus_bytes("scionic-fastcdc-v1:test:stream", length);
            let expected: Vec<Vec<u8>> = Chunking::FastCdcV1
                .cut(&data)
                .into_iter()
                .map(<[u8]>::to_vec)
                .collect();
            let mut streamed: Vec<Vec<u8>> = Vec::new();
            let mut reader = StutterReader {
                data: data.clone(),
                offset: 0,
                step: 64 * 1024 + 17,
            };
            stream_fastcdc_chunks(&mut reader, Path::new("stutter"), |chunk, index| {
                assert_eq!(index, streamed.len(), "length {length}: chunk order");
                streamed.push(chunk);
                Ok(())
            })
            .unwrap();
            assert_eq!(
                streamed, expected,
                "length {length}: streaming vs slice cutting"
            );
        }
    }

    #[test]
    fn small_inputs_are_single_chunks() {
        for length in [1, 100, FASTCDC_MIN_SIZE - 1, FASTCDC_MIN_SIZE] {
            let data = corpus_bytes("scionic-fastcdc-v1:test:small", length);
            let chunks = Chunking::FastCdcV1.cut(&data);
            assert_eq!(chunks.len(), 1, "length {length} must be a single chunk");
            assert_eq!(chunks[0], &data[..]);
        }
        assert!(Chunking::FastCdcV1.cut(&[]).is_empty());
    }

    #[test]
    fn constant_bytes_stay_bounded() {
        // 20 MiB of zeros never matches either mask: every chunk is a forced
        // cut at the max, with the remainder as the tail. The committed
        // conformance corpus pins zeros_20mib as 8 MiB + 8 MiB + 4 MiB.
        let zeros = vec![0_u8; 20 << 20];
        let cuts: Vec<usize> = Chunking::FastCdcV1
            .cut(&zeros)
            .iter()
            .map(|c| c.len())
            .collect();
        assert_eq!(cuts, [8 << 20, 8 << 20, 4 << 20]);
        let letters = vec![b'a'; 20 << 20];
        let mut total = 0_usize;
        let letter_chunks = Chunking::FastCdcV1.cut(&letters);
        for (index, chunk) in letter_chunks.iter().enumerate() {
            assert!(chunk.len() <= FASTCDC_MAX_SIZE);
            if index < letter_chunks.len() - 1 {
                assert!(chunk.len() > FASTCDC_MIN_SIZE);
            }
            total += chunk.len();
        }
        assert_eq!(total, letters.len());
    }

    #[test]
    fn insert_reuses_most_chunk_content() {
        let base = corpus_bytes("scionic-fastcdc-v1:test:reuse", 32 << 20);
        let payload = corpus_bytes("scionic-fastcdc-v1:test:reuse-payload", 4096);
        let mut edited = Vec::with_capacity(base.len() + payload.len());
        edited.extend_from_slice(&base[..16 << 20]);
        edited.extend_from_slice(&payload);
        edited.extend_from_slice(&base[16 << 20..]);
        let base_hashes: BTreeSet<[u8; 32]> = Chunking::FastCdcV1
            .cut(&base)
            .iter()
            .map(|chunk| sha256(chunk))
            .collect();
        let edited_chunks = Chunking::FastCdcV1.cut(&edited);
        let fresh = edited_chunks
            .iter()
            .filter(|chunk| !base_hashes.contains(&sha256(chunk)))
            .count();
        assert!(fresh >= 1, "an insert must produce at least one new chunk");
        assert!(
            fresh <= 3,
            "a 4 KiB insert produced {fresh} of {} unseen chunks; content-defined \\
             chunking should confine an edit to ~1-2 chunks plus resettling",
            edited_chunks.len()
        );
    }

    #[test]
    fn mode_cut_semantics_are_canonical() {
        let data: Vec<u8> = (0_u8..10).collect();
        assert!(Chunking::Disabled.cut(&[]).is_empty());
        assert!(Chunking::Fixed(NonZeroUsize::new(4).unwrap())
            .cut(&[])
            .is_empty());
        assert_eq!(Chunking::Disabled.cut(&data), vec![&data[..]]);
        assert_eq!(
            Chunking::Fixed(NonZeroUsize::new(4).unwrap()).cut(&data),
            vec![&data[0..4], &data[4..8], &data[8..10]]
        );
        assert_eq!(
            Chunking::Fixed(NonZeroUsize::new(16).unwrap()).cut(&data),
            vec![&data[..]]
        );
        assert_eq!(Chunking::FastCdcV1.cut(&data), vec![&data[..]]);
    }
}
