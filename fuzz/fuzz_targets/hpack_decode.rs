//! Arbitrary field blocks through one decoder, as a connection would feed
//! them, with the table maximum lowered and raised in between. Oracles: no
//! panic; the fields stored never exceed the list's budget; the decoder's
//! table never exceeds its maximum; an oversized list still leaves a decoder
//! that takes the next block.

#![no_main]

use arbitrary::Arbitrary;
use h2_net::hpack::{Decoder, HeaderList};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    max: u16,
    budget: u16,
    steps: Vec<Step>,
}

#[derive(Arbitrary, Debug)]
enum Step {
    Block(Vec<u8>),
    SetMax(u16),
}

fuzz_target!(|input: Input| {
    let mut decoder = Decoder::new(usize::from(input.max));
    let mut list = HeaderList::new(usize::from(input.budget));
    for step in input.steps.iter().take(32) {
        match step {
            Step::Block(block) => {
                if decoder.decode(block, &mut list).is_err() {
                    // A connection error: the connection would end here.
                    return;
                }
                let stored: usize = list.iter().map(|f| f.size()).sum();
                assert!(stored <= list.budget(), "{stored} over {}", list.budget());
                assert!(list.size() >= stored);
                assert_eq!(list.is_oversized(), list.size() > list.budget());
                assert!(decoder.table_size() <= decoder.table_max());
            }
            Step::SetMax(m) => decoder.set_max_size(usize::from(*m)),
        }
    }
});
