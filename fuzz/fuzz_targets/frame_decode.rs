//! Frames read from arbitrary bytes, one after another, as a connection
//! would. Oracles: `decode` never panics; an incomplete frame asks for more
//! than it was given, and never for more than its header and the maximum
//! payload; every frame it reads encodes back to the bytes it was read from,
//! less undefined flags, the reserved bit, and padding contents, which
//! decode back to the same frame.

#![no_main]

use h2_net::frame::{self, Decoded, HEADER_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&pick, mut rest)) = data.split_first() else {
        return;
    };
    // A small maximum makes the size check bite; the default is the usual.
    let max = if pick & 1 == 0 {
        frame::DEFAULT_MAX_FRAME_SIZE
    } else {
        u32::from(pick)
    };
    loop {
        match frame::decode(rest, max) {
            Ok(Decoded::Incomplete { needed }) => {
                assert!(needed > rest.len());
                assert!(needed <= HEADER_LEN + max as usize);
                return;
            }
            Ok(Decoded::Frame { frame: f, len }) => {
                assert!(len >= HEADER_LEN && len <= rest.len());
                let mut out = Vec::new();
                frame::encode(&f, max, &mut out).expect("a decoded frame encodes");
                assert_eq!(out.len(), len, "{f:?}");
                match frame::decode(&out, max) {
                    Ok(Decoded::Frame { frame: back, len: n }) => {
                        assert_eq!(back, f);
                        assert_eq!(n, out.len());
                    }
                    other => panic!("{f:?} read back as {other:?}"),
                }
                rest = &rest[len..];
            }
            Ok(Decoded::StreamError { len, error, stream }) => {
                assert!(!stream.is_zero(), "{error:?}");
                assert!(len >= HEADER_LEN && len <= rest.len());
                rest = &rest[len..];
            }
            Err(_) => return,
        }
    }
});
