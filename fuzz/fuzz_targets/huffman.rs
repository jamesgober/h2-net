//! The Huffman code. Oracles: any input decodes or is refused without a
//! panic, and never decodes to more than 8/5 of its length; a decoded
//! string encodes back to the same bytes when the input had canonical
//! padding (the encoder pads with ones, the shortest padding); every string
//! encodes to `encoded_len` bytes and decodes back to itself.

#![no_main]

use h2_net::hpack::huffman;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut text = Vec::new();
    if huffman::decode(data, &mut text).is_ok() {
        assert!(text.len() <= data.len() * 8 / 5);
        let mut again = Vec::new();
        huffman::encode(&text, &mut again);
        // The only freedom a valid encoding has is none: padding is under 8
        // bits of ones, so the bytes must match.
        assert_eq!(again, data);
    }

    let mut wire = Vec::new();
    huffman::encode(data, &mut wire);
    assert_eq!(wire.len(), huffman::encoded_len(data));
    let mut back = Vec::new();
    huffman::decode(&wire, &mut back).expect("an encoded string decodes");
    assert_eq!(back, data);
});
