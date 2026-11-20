//! The RFC 9218 priority field. Oracles: no panic; `parse` is `try_parse`
//! with the defaults on failure; the urgency is always 0 to 7; a value that
//! parses keeps parsing to the same thing with spaces around it.

#![no_main]

use h2_net::conn::PriorityParams;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let tried = PriorityParams::try_parse(data);
    let parsed = PriorityParams::parse(data);
    assert_eq!(parsed, tried.unwrap_or_default());
    assert!(parsed.urgency <= 7);
    if let Some(p) = tried {
        let mut spaced = b" ".to_vec();
        spaced.extend_from_slice(data);
        spaced.extend_from_slice(b"  ");
        if !data.is_empty() {
            assert_eq!(PriorityParams::try_parse(&spaced), Some(p));
        }
    }
});
