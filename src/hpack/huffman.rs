//! The Huffman code of HPACK string literals (RFC 7541 section 5.2 and
//! Appendix B).
//!
//! Decoding reads the longest code (30 bits) at a time: one table lookup
//! for codes of up to 8 bits (every printable ASCII symbol but a few), and
//! otherwise a walk over the code lengths, which works because the code is
//! canonical (checked by this module's tests). The padding at the end must
//! be shorter than 8 bits and all ones, and the EOS symbol must not appear;
//! anything else is refused.
//!
//! # Examples
//!
//! ```
//! use h2_net::hpack::huffman;
//!
//! let mut wire = Vec::new();
//! huffman::encode(b"www.example.com", &mut wire);
//! // RFC 7541 C.4.1.
//! assert_eq!(wire, [0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]);
//! assert_eq!(huffman::encoded_len(b"www.example.com"), wire.len());
//!
//! let mut text = Vec::new();
//! huffman::decode(&wire, &mut text)?;
//! assert_eq!(text, b"www.example.com");
//! # Ok::<(), h2_net::HpackError>(())
//! ```

use alloc::vec::Vec;

use super::HpackError;
use super::tables::{CODES, LENGTHS};

const EOS: u16 = 256;
const MAX_LEN: u32 = 30;

/// For each code length: the first code of that length, the number of codes
/// of that length, and where its symbols start in `SORTED`.
struct Canonical {
    first: [u32; 31],
    count: [u32; 31],
    offset: [u16; 31],
    sorted: [u16; 257],
}

// Evaluated at compile time only (it initializes a static): an index out
// of range fails the build, so none of these can panic at run time.
#[allow(clippy::indexing_slicing)]
const fn canonical() -> Canonical {
    let mut c = Canonical {
        first: [0; 31],
        count: [0; 31],
        offset: [0; 31],
        sorted: [0; 257],
    };
    // Symbols in code order: by length, then by code value (which, for a
    // canonical code, is symbol order within a length).
    let mut n = 0usize;
    let mut len = 1usize;
    while len <= 30 {
        c.offset[len] = n as u16;
        let mut sym = 0usize;
        let mut first = u32::MAX;
        while sym < 257 {
            if LENGTHS[sym] as usize == len {
                if first == u32::MAX {
                    first = CODES[sym];
                }
                c.sorted[n] = sym as u16;
                n += 1;
                c.count[len] += 1;
            }
            sym += 1;
        }
        c.first[len] = if first == u32::MAX { 0 } else { first };
        len += 1;
    }
    c
}

static CANON: Canonical = canonical();

/// For each value of the next 8 bits: the symbol and its code length when
/// the code is 8 bits or shorter; length 0 otherwise.
// Evaluated at compile time only (it initializes a static): an index out
// of range fails the build, so none of these can panic at run time.
#[allow(clippy::indexing_slicing)]
const fn short_table() -> [(u8, u8); 256] {
    let mut t = [(0u8, 0u8); 256];
    let mut sym = 0usize;
    while sym < 256 {
        let len = LENGTHS[sym] as u32;
        if len <= 8 {
            let base = (CODES[sym] << (8 - len)) as usize;
            let mut fill = 0usize;
            while fill < (1usize << (8 - len)) {
                t[base + fill] = (sym as u8, len as u8);
                fill += 1;
            }
        }
        sym += 1;
    }
    t
}

static SHORT: [(u8, u8); 256] = short_table();

/// The length of `src` once encoded.
#[must_use]
pub fn encoded_len(src: &[u8]) -> usize {
    let bits: u64 = src
        .iter()
        .map(|&b| u64::from(LENGTHS.get(usize::from(b)).copied().unwrap_or(30)))
        .sum();
    usize::try_from(bits.div_ceil(8)).unwrap_or(usize::MAX)
}

/// Appends the encoding of `src` to `out`, padded with the most
/// significant bits of EOS (ones).
pub fn encode(src: &[u8], out: &mut Vec<u8>) {
    out.reserve(encoded_len(src));
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;
    for &b in src {
        let (code, len) = (
            CODES.get(usize::from(b)).copied().unwrap_or(0),
            u32::from(LENGTHS.get(usize::from(b)).copied().unwrap_or(0)),
        );
        acc = (acc << len) | u64::from(code);
        bits += len;
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        // Keep only the bits not yet written.
        acc &= (1u64 << bits) - 1;
    }
    if bits > 0 {
        let pad = 8 - bits;
        out.push(((acc << pad) | ((1u64 << pad) - 1)) as u8);
    }
}

/// Appends the decoding of `src` to `out`.
///
/// # Errors
///
/// [`HpackError::Huffman`] when `src` contains EOS, padding of 8 bits or
/// more, or padding that is not all ones. `out` may then hold part of the
/// string.
pub fn decode(src: &[u8], out: &mut Vec<u8>) -> Result<(), HpackError> {
    // Each symbol takes at least 5 bits.
    out.reserve(src.len().saturating_mul(8) / 5);
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;
    let mut input = src.iter();
    loop {
        // Keep at least 30 bits when the input has them.
        while bits <= 56 - 8 {
            match input.next() {
                Some(&b) => {
                    acc = (acc << 8) | u64::from(b);
                    bits += 8;
                }
                None => break,
            }
        }
        if bits == 0 {
            return Ok(());
        }
        // The next 8 bits, ones-filled past the end.
        let top8 = if bits >= 8 {
            (acc >> (bits - 8)) as u8
        } else {
            ((acc << (8 - bits)) | ((1u64 << (8 - bits)) - 1)) as u8
        };
        if let Some(&(sym, len)) = SHORT.get(usize::from(top8)) {
            let len = u32::from(len);
            if len != 0 && len <= bits {
                out.push(sym);
                bits -= len;
                acc &= (1u64 << bits) - 1;
                continue;
            }
        }
        // A longer code, or the padding.
        let mut len = 9;
        let mut found = None;
        while len <= MAX_LEN.min(bits) {
            let code = (acc >> (bits - len)) as u32;
            let i = len as usize;
            let first = CANON.first.get(i).copied().unwrap_or(0);
            let count = CANON.count.get(i).copied().unwrap_or(0);
            if code >= first && code - first < count {
                let at = usize::from(CANON.offset.get(i).copied().unwrap_or(0))
                    + (code - first) as usize;
                found = Some((CANON.sorted.get(at).copied().unwrap_or(EOS), len));
                break;
            }
            len += 1;
        }
        match found {
            Some((sym, len)) if sym != EOS => {
                out.push(sym as u8);
                bits -= len;
                acc &= (1u64 << bits) - 1;
            }
            Some(_) => return Err(HpackError::Huffman),
            None => {
                // No code fits in what is left: it must be padding, under
                // 8 bits of ones (RFC 7541 section 5.2).
                let ones = (1u64 << bits) - 1;
                if bits < 8 && acc == ones {
                    return Ok(());
                }
                return Err(HpackError::Huffman);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn test_the_code_is_canonical_and_prefix_free() {
        // Within a length, codes are consecutive in symbol order, and each
        // length starts where the previous one ended, shifted left.
        let mut next: u32 = 0;
        let mut seen = 0u32;
        for len in 1..=30usize {
            let count = CANON.count[len];
            if count > 0 {
                assert_eq!(CANON.first[len], next, "length {len}");
                for k in 0..count {
                    let sym =
                        usize::from(CANON.sorted[usize::from(CANON.offset[len]) + k as usize]);
                    assert_eq!(CODES[sym], next + k);
                    assert_eq!(usize::from(LENGTHS[sym]), len);
                }
                seen += count;
            }
            next = (next + count) << 1;
        }
        assert_eq!(seen, 257);
        // Kraft equality: the code is complete.
        let kraft: u64 = LENGTHS.iter().map(|&l| 1u64 << (30 - u32::from(l))).sum();
        assert_eq!(kraft, 1 << 30);
        assert_eq!(CODES[256], 0x3fff_ffff);
        assert_eq!(LENGTHS[256], 30);
        assert_eq!(LENGTHS.iter().copied().min(), Some(5));
    }

    #[test]
    fn test_every_symbol_round_trips_alone_and_together() {
        for b in 0..=255u8 {
            let mut wire = vec![];
            encode(&[b], &mut wire);
            let mut back = vec![];
            decode(&wire, &mut back).unwrap();
            assert_eq!(back, [b]);
        }
        let all: Vec<u8> = (0..=255u8).chain((0..=255u8).rev()).collect();
        let mut wire = vec![];
        encode(&all, &mut wire);
        assert_eq!(wire.len(), encoded_len(&all));
        let mut back = vec![];
        decode(&wire, &mut back).unwrap();
        assert_eq!(back, all);
    }

    #[test]
    fn test_padding_rules() {
        // "a" is 00011 (5 bits); three ones of padding.
        let mut out = vec![];
        decode(&[0b0001_1111], &mut out).unwrap();
        assert_eq!(out, b"a");
        // Padding that is not all ones.
        assert_eq!(
            decode(&[0b0001_1110], &mut vec![]),
            Err(HpackError::Huffman)
        );
        // 8 bits of padding (a whole byte of ones after the symbol).
        assert_eq!(
            decode(&[0b0001_1111, 0xff], &mut vec![]),
            Err(HpackError::Huffman)
        );
        // Only padding: a whole byte of ones is already too much.
        assert_eq!(decode(&[0xff], &mut vec![]), Err(HpackError::Huffman));
        // EOS itself, padded to 32 bits.
        assert_eq!(
            decode(&[0xff, 0xff, 0xff, 0xff], &mut vec![]),
            Err(HpackError::Huffman)
        );
        // The empty string.
        decode(&[], &mut out).unwrap();
    }

    #[test]
    fn test_rfc_7541_c4_and_c6_strings() {
        for (text, hex) in [
            (&b"no-cache"[..], &[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf][..]),
            (
                b"custom-key",
                &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f],
            ),
            (
                b"custom-value",
                &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf],
            ),
            (b"302", &[0x64, 0x02]),
            (b"private", &[0xae, 0xc3, 0x77, 0x1a, 0x4b]),
        ] {
            let mut wire = vec![];
            encode(text, &mut wire);
            assert_eq!(wire, hex, "{text:?}");
            let mut back = vec![];
            decode(hex, &mut back).unwrap();
            assert_eq!(back, text);
        }
    }
}
