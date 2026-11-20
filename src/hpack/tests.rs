use alloc::vec;
use alloc::vec::Vec;

use super::rfc_vectors::{C2, C3, C4, C5, C6, Example};
use super::*;

fn fields(list: &HeaderList) -> Vec<(Vec<u8>, Vec<u8>)> {
    list.iter()
        .map(|f| (f.name.to_vec(), f.value.to_vec()))
        .collect()
}

fn want(e: &Example) -> Vec<(Vec<u8>, Vec<u8>)> {
    e.headers
        .iter()
        .map(|(n, v)| (n.to_vec(), v.to_vec()))
        .collect()
}

fn table_of(d: &Decoder) -> Vec<(Vec<u8>, Vec<u8>)> {
    (0..d.table().len())
        .map(|i| {
            let (n, v) = d.table().get(62 + i).unwrap();
            (n.to_vec(), v.to_vec())
        })
        .collect()
}

/// Decodes each example in order with one decoder, checking the fields and
/// the dynamic table after each.
fn run_sequence(examples: &[Example], max: usize) {
    let mut d = Decoder::new(max);
    let mut list = HeaderList::new(64 * 1024);
    for e in examples {
        d.decode(e.wire, &mut list).unwrap();
        assert_eq!(fields(&list), want(e), "{}", e.id);
        let table: Vec<_> = e
            .table
            .iter()
            .map(|(n, v)| (n.to_vec(), v.to_vec()))
            .collect();
        assert_eq!(table_of(&d), table, "{}", e.id);
        assert_eq!(d.table_size(), e.table_size, "{}", e.id);
    }
}

#[test]
fn test_rfc_7541_c2_independent_examples() {
    for e in C2 {
        run_sequence(core::slice::from_ref(e), 4096);
    }
    // C.2.3 is never indexed, and says so.
    let mut list = HeaderList::new(4096);
    Decoder::new(4096).decode(C2[2].wire, &mut list).unwrap();
    assert!(list.iter().next().unwrap().sensitive);
}

#[test]
fn test_rfc_7541_c3_to_c6_sequences() {
    run_sequence(C3, 4096);
    run_sequence(C4, 4096);
    // C.5 and C.6 run with a 256-byte table, so entries are evicted.
    run_sequence(C5, 256);
    run_sequence(C6, 256);
}

/// The RFC's examples index every field the way this encoder does not, so
/// the byte-for-byte check is on the decoder; the encoder's output must
/// decode back to the same fields through the same sequence.
#[test]
fn test_encoder_output_decodes_back_through_the_rfc_sequences() {
    for (examples, max) in [(C3, 4096), (C5, 256)] {
        let mut enc = Encoder::new(max);
        enc.set_peer_max_size(max);
        let mut dec = Decoder::new(max);
        let mut list = HeaderList::new(64 * 1024);
        for e in examples {
            let mut block = vec![];
            enc.encode(
                e.headers.iter().map(|(n, v)| HeaderField::new(n, v)),
                &mut block,
            );
            dec.decode(&block, &mut list).unwrap();
            assert_eq!(fields(&list), want(e), "{}", e.id);
            assert_eq!(enc.table_size(), dec.table_size(), "{}", e.id);
        }
    }
}

#[test]
fn test_hpack_bomb_stops_at_the_budget() {
    // One 4,000-byte entry, then the same one-byte index 1,000 times: 4 MB
    // decoded from a 1 KB block if nothing stops it.
    let mut d = Decoder::new(4096);
    let mut list = HeaderList::new(16 * 1024);
    let mut block = vec![0x40, 0x01, b'x'];
    int::encode(3960, 7, 0, &mut block);
    block.resize(block.len() + 3960, b'v');
    d.decode(&block, &mut list).unwrap();
    assert!(!list.is_oversized());
    let bomb = vec![0xbe; 1000];
    d.decode(&bomb, &mut list).unwrap();
    assert!(list.is_oversized());
    // Stored at most the budget; counted all of it.
    let stored: usize = list.iter().map(|f| f.size()).sum();
    assert!(stored <= 16 * 1024, "{stored}");
    assert_eq!(list.len(), 4);
    assert_eq!(list.size(), 1000 * (1 + 3960 + 32));
    // The table is still in step: the next block decodes.
    d.decode(b"\x82", &mut list).unwrap();
    assert_eq!(list.get(":method"), Some(&b"GET"[..]));
}

#[test]
fn test_oversized_block_still_updates_the_table() {
    let mut d = Decoder::new(4096);
    let mut tiny = HeaderList::new(10);
    // C.3.1 adds ":authority: www.example.com" to the table.
    d.decode(C3[0].wire, &mut tiny).unwrap();
    assert!(tiny.is_oversized());
    assert_eq!(d.table_size(), 57);
    // C.3.2 depends on that entry.
    let mut list = HeaderList::new(4096);
    d.decode(C3[1].wire, &mut list).unwrap();
    assert_eq!(fields(&list), want(&C3[1]));
}

#[test]
fn test_bad_indexes() {
    let mut list = HeaderList::new(4096);
    let mut d = Decoder::new(4096);
    assert_eq!(
        d.decode(b"\x80", &mut list),
        Err(HpackError::BadIndex { index: 0 })
    );
    assert_eq!(
        d.decode(b"\xbe", &mut list),
        Err(HpackError::BadIndex { index: 62 })
    );
    // A literal naming entry 62 of an empty table.
    assert_eq!(
        d.decode(b"\x7e\x01v", &mut list),
        Err(HpackError::BadIndex { index: 62 })
    );
    assert_eq!(
        d.decode(b"\x0f\x2f\x01v", &mut list),
        Err(HpackError::BadIndex { index: 62 })
    );
}

#[test]
fn test_truncated_blocks() {
    let mut d = Decoder::new(4096);
    let mut list = HeaderList::new(4096);
    for cut in 1..C3[0].wire.len() {
        let r = Decoder::new(4096).decode(&C3[0].wire[..cut], &mut list);
        // A cut between whole fields decodes; a cut inside one does not.
        if [1, 2, 3].contains(&cut) {
            assert!(r.is_ok(), "{cut}");
        } else {
            assert_eq!(r, Err(HpackError::Truncated), "{cut}");
        }
    }
    // A string length running past the end.
    assert_eq!(
        d.decode(b"\x40\x7f\x00", &mut list),
        Err(HpackError::Truncated)
    );
}

#[test]
fn test_huffman_errors_in_a_block() {
    let mut list = HeaderList::new(4096);
    // A Huffman value of one byte of ones: padding of 8 bits.
    assert_eq!(
        Decoder::new(4096).decode(b"\x04\x81\xff", &mut list),
        Err(HpackError::Huffman)
    );
}

#[test]
fn test_size_update_rules() {
    let mut list = HeaderList::new(4096);
    // Over the advertised maximum.
    assert_eq!(
        Decoder::new(100).decode(b"\x3f\x46", &mut list),
        Err(HpackError::SizeUpdateTooLarge {
            size: 101,
            max: 100
        })
    );
    // After a field.
    assert_eq!(
        Decoder::new(4096).decode(b"\x82\x20", &mut list),
        Err(HpackError::SizeUpdateMisplaced)
    );
    // At the start, twice: allowed.
    let mut d = Decoder::new(4096);
    d.decode(b"\x20\x3f\xe1\x1f\x82", &mut list).unwrap();
    assert_eq!(d.table_max(), 4096);
    // Lowered maximum: the next block must start with an update under it.
    let mut d = Decoder::new(4096);
    d.decode(b"\x40\x01k\x01v", &mut list).unwrap();
    d.set_max_size(0);
    assert_eq!(
        d.decode(b"\x82", &mut list),
        Err(HpackError::SizeUpdateMissing)
    );
    let mut d = Decoder::new(4096);
    d.set_max_size(1000);
    assert_eq!(
        d.decode(b"\x3f\xe1\x1f\x82", &mut list),
        Err(HpackError::SizeUpdateTooLarge {
            size: 4096,
            max: 1000
        })
    );
    let mut d = Decoder::new(4096);
    d.set_max_size(1000);
    d.decode(b"\x20\x82", &mut list).unwrap();
    assert_eq!(d.table_max(), 0);
    // An empty block leaves the requirement for the next one.
    let mut d = Decoder::new(4096);
    d.set_max_size(0);
    d.decode(b"", &mut list).unwrap();
    assert_eq!(
        d.decode(b"\x82", &mut list),
        Err(HpackError::SizeUpdateMissing)
    );
}

#[test]
fn test_indexed_name_from_the_dynamic_table_survives_its_eviction() {
    // A 64-byte table holding one 40-byte entry; a literal that names it and
    // is indexed evicts it on insert (RFC 7541 section 4.4).
    let mut d = Decoder::new(64);
    let mut list = HeaderList::new(4096);
    d.decode(b"\x40\x04name\x04abcd", &mut list).unwrap();
    d.decode(b"\x7e\x04wxyz", &mut list).unwrap();
    assert_eq!(fields(&list), [(b"name".to_vec(), b"wxyz".to_vec())]);
    assert_eq!(table_of(&d), [(b"name".to_vec(), b"wxyz".to_vec())]);
}

#[test]
fn test_encoder_never_indexes_credentials() {
    let mut enc = Encoder::new(4096);
    let mut block = vec![];
    enc.encode(
        [
            HeaderField::new(b"authorization", b"Bearer abc"),
            HeaderField::new(b"cookie", b"id=1"),
            HeaderField::sensitive(b"x-secret", b"1"),
        ],
        &mut block,
    );
    assert_eq!(enc.table_size(), 0);
    let mut list = HeaderList::new(4096);
    Decoder::new(4096).decode(&block, &mut list).unwrap();
    assert!(list.iter().all(|f| f.sensitive));
    // Twice the same: still a literal, never an index.
    let mut again = vec![];
    enc.encode(
        [HeaderField::new(b"authorization", b"Bearer abc")],
        &mut again,
    );
    assert_ne!(again.first().map(|b| b & 0x80), Some(0x80));
}

#[test]
fn test_encoder_signals_table_size_changes() {
    let mut enc = Encoder::new(4096);
    let mut dec = Decoder::new(4096);
    let mut list = HeaderList::new(4096);
    let mut block = vec![];
    enc.encode([HeaderField::new(b"x-a", b"1")], &mut block);
    dec.decode(&block, &mut list).unwrap();
    assert_eq!(dec.table_size(), 36);
    // The peer lowers its table to 0, then raises it to 100, before the
    // next block: both are signalled, smallest first.
    enc.set_peer_max_size(0);
    enc.set_peer_max_size(100);
    dec.set_max_size(100);
    block.clear();
    enc.encode([HeaderField::new(b"x-b", b"2")], &mut block);
    assert_eq!(&block[..2], b"\x20\x3f");
    dec.decode(&block, &mut list).unwrap();
    assert_eq!(dec.table_max(), 100);
    assert_eq!(dec.table_size(), enc.table_size());
    // A limit of 0 never uses the table, and says so before the first field.
    let mut enc = Encoder::new(0);
    block.clear();
    enc.encode([HeaderField::new(b"x-a", b"1")], &mut block);
    assert_eq!(block[0], 0x20);
    let mut dec = Decoder::new(4096);
    dec.decode(&block, &mut list).unwrap();
    assert_eq!(dec.table_max(), 0);
}

#[test]
fn test_header_list_wipe_and_debug() {
    let mut list = HeaderList::new(4096);
    Decoder::new(4096)
        .decode(b"\x10\x08password\x06secret", &mut list)
        .unwrap();
    let shown = alloc::format!("{list:?}");
    assert!(!shown.contains("secret"), "{shown}");
    assert!(shown.contains("password"));
    list.wipe();
    assert!(list.is_empty());
    assert!(list.bytes.iter().all(|&b| b == 0));
}
