//! Arbitrary field lists encoded by one encoder and decoded by one decoder,
//! across blocks and across changes to the table size the decoder allows
//! (applied the way SETTINGS would apply them: the encoder hears of a
//! change, then the decoder, before the next block). Oracles: every block
//! decodes; the decoded fields are the fields sent, in order, with the
//! never-indexed mark kept; both tables agree in size after every block.

#![no_main]

use arbitrary::Arbitrary;
use h2_net::hpack::{Decoder, Encoder, HeaderField, HeaderList};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    limit: u16,
    steps: Vec<Step>,
}

#[derive(Arbitrary, Debug)]
enum Step {
    Block(Vec<(Vec<u8>, Vec<u8>, bool)>),
    PeerMax(u16),
}

fuzz_target!(|input: Input| {
    let mut encoder = Encoder::new(usize::from(input.limit));
    let mut decoder = Decoder::new(4096);
    let mut list = HeaderList::new(1 << 20);
    let mut block = Vec::new();
    for step in input.steps.iter().take(32) {
        match step {
            Step::Block(fields) => {
                let fields = &fields[..fields.len().min(16)];
                block.clear();
                encoder.encode(
                    fields.iter().map(|(n, v, s)| HeaderField {
                        name: n,
                        value: v,
                        sensitive: *s,
                    }),
                    &mut block,
                );
                decoder.decode(&block, &mut list).expect("an encoded block decodes");
                assert!(!list.is_oversized());
                let got: Vec<_> = list.iter().map(|f| (f.name.to_vec(), f.value.to_vec())).collect();
                let want: Vec<_> = fields.iter().map(|(n, v, _)| (n.clone(), v.clone())).collect();
                assert_eq!(got, want);
                for (f, (_, _, sensitive)) in list.iter().zip(fields) {
                    if *sensitive {
                        assert!(f.sensitive, "a sensitive field lost its mark");
                    }
                }
                assert_eq!(encoder.table_size(), decoder.table_size());
            }
            Step::PeerMax(m) => {
                encoder.set_peer_max_size(usize::from(*m));
                decoder.set_max_size(usize::from(*m));
            }
        }
    }
});
