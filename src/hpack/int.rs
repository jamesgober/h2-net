//! Prefix integers (RFC 7541 section 5.1).

use alloc::vec::Vec;

use super::HpackError;

/// At most this many continuation bytes: 7 * 4 = 28 bits past the prefix,
/// more than any budget here allows, and a bound on overlong encodings.
const MAX_CONTINUATION: u32 = 4;

/// Reads an integer with an `n`-bit prefix from `input[*pos..]`, advancing
/// `pos`. The bits above the prefix in the first byte are the caller's.
pub(crate) fn decode(input: &[u8], pos: &mut usize, n: u8) -> Result<usize, HpackError> {
    let mask = (1u16 << n) - 1;
    let first = *input.get(*pos).ok_or(HpackError::Truncated)?;
    *pos += 1;
    let prefix = u16::from(first) & mask;
    if prefix < mask {
        return Ok(usize::from(prefix));
    }
    let mut value = u64::from(mask);
    let mut shift = 0u32;
    loop {
        let b = *input.get(*pos).ok_or(HpackError::Truncated)?;
        *pos += 1;
        value += u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 7 * MAX_CONTINUATION {
            return Err(HpackError::IntegerOverflow);
        }
    }
    u32::try_from(value)
        .ok()
        .and_then(|v| usize::try_from(v).ok())
        .ok_or(HpackError::IntegerOverflow)
}

/// Appends `value` with an `n`-bit prefix; `flags` holds the bits above the
/// prefix in the first byte.
pub(crate) fn encode(value: usize, n: u8, flags: u8, out: &mut Vec<u8>) {
    let mask = (1usize << n) - 1;
    if value < mask {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | mask as u8);
    let mut rest = value - mask;
    while rest >= 0x80 {
        out.push((rest & 0x7f) as u8 | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn read(bytes: &[u8], n: u8) -> Result<(usize, usize), HpackError> {
        let mut pos = 0;
        decode(bytes, &mut pos, n).map(|v| (v, pos))
    }

    #[test]
    fn test_rfc_7541_c1_examples() {
        // C.1.1: 10 with a 5-bit prefix.
        let mut out = vec![];
        encode(10, 5, 0, &mut out);
        assert_eq!(out, [0b0000_1010]);
        assert_eq!(read(&out, 5), Ok((10, 1)));
        // C.1.2: 1337 with a 5-bit prefix.
        out.clear();
        encode(1337, 5, 0, &mut out);
        assert_eq!(out, [0b0001_1111, 0b1001_1010, 0b0000_1010]);
        assert_eq!(read(&out, 5), Ok((1337, 3)));
        // C.1.3: 42 at an octet boundary.
        out.clear();
        encode(42, 8, 0, &mut out);
        assert_eq!(out, [42]);
        assert_eq!(read(&out, 8), Ok((42, 1)));
    }

    #[test]
    fn test_round_trip_at_every_prefix() {
        for n in 1..=8u8 {
            // Four continuation bytes carry 28 bits past the prefix.
            for v in [
                0usize,
                1,
                30,
                31,
                126,
                127,
                128,
                255,
                256,
                16_383,
                1 << 20,
                (1 << 28) - 1,
            ] {
                let mut out = vec![];
                encode(v, n, 0, &mut out);
                assert_eq!(read(&out, n), Ok((v, out.len())), "{v} with {n} bits");
            }
        }
    }

    #[test]
    fn test_the_caller_bits_are_ignored() {
        assert_eq!(read(&[0b1110_0011], 5), Ok((3, 1)));
    }

    #[test]
    fn test_truncated_and_overflowing() {
        assert_eq!(read(&[], 5), Err(HpackError::Truncated));
        assert_eq!(read(&[0x1f], 5), Err(HpackError::Truncated));
        assert_eq!(read(&[0x1f, 0x80], 5), Err(HpackError::Truncated));
        // Five continuation bytes: longer than anything that fits a budget.
        assert_eq!(
            read(&[0x1f, 0x80, 0x80, 0x80, 0x80, 0x01], 5),
            Err(HpackError::IntegerOverflow)
        );
        // Over 32 bits in four continuation bytes.
        assert_eq!(
            read(&[0x1f, 0xff, 0xff, 0xff, 0xff, 0x7f], 5),
            Err(HpackError::IntegerOverflow)
        );
        // Overlong but within four continuation bytes: still the value.
        assert_eq!(read(&[0x1f, 0x80, 0x80, 0x80, 0x00], 5), Ok((31, 5)));
    }
}
