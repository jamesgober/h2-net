//! The HPACK encoder (RFC 7541 sections 4, 6, and 7).

use alloc::vec::Vec;

use super::table::Table;
use super::{HeaderField, huffman, int};

/// Names whose values are never put in a dynamic table, whatever the
/// caller says: credentials, which a compression side channel could guess
/// a byte at a time (RFC 7541 section 7.1.3).
const NEVER_INDEXED: [&[u8]; 4] = [
    b"authorization",
    b"proxy-authorization",
    b"cookie",
    b"set-cookie",
];

/// Names whose values rarely repeat; indexing them only evicts entries that
/// would have been reused.
const NOT_WORTH_INDEXING: [&[u8]; 11] = [
    b":path",
    b"content-length",
    b"content-range",
    b"date",
    b"etag",
    b"last-modified",
    b"age",
    b"expires",
    b"location",
    b"if-modified-since",
    b"if-none-match",
];

/// An HPACK encoder: one per connection, used for every field block this
/// side sends, in order.
///
/// `limit` is the largest dynamic table this side is willing to keep; the
/// table used is the smaller of that and the peer's
/// `SETTINGS_HEADER_TABLE_SIZE` (4096 until the peer says otherwise). A
/// limit of 0 sends every field without the dynamic table.
///
/// Fields are sent as an index when the static or dynamic table holds them,
/// otherwise as a literal with incremental indexing unless they are
/// sensitive, a credential, larger than half the table, or of a kind that
/// rarely repeats. Strings are Huffman coded when that is shorter.
///
/// # Examples
///
/// ```
/// use h2_net::hpack::{Encoder, HeaderField};
///
/// let mut encoder = Encoder::new(4096);
/// let mut block = Vec::new();
/// encoder.encode([HeaderField::new(b":method", b"GET")], &mut block);
/// assert_eq!(block, [0x82]); // static index 2
/// ```
#[derive(Clone, Debug)]
pub struct Encoder {
    table: Table,
    limit: usize,
    peer_max: usize,
    /// Size updates to send at the start of the next block: the smallest
    /// size the table had since the last block, and the size it has now.
    pending: Option<(usize, usize)>,
}

impl Encoder {
    /// An encoder that keeps a dynamic table of at most `limit` bytes.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        let peer_max = 4096;
        let size = limit.min(peer_max);
        Self {
            table: Table::new(size),
            limit,
            peer_max,
            // The peer's decoder starts at 4096; tell it about a smaller
            // table before the first field.
            pending: (size != peer_max).then_some((size, size)),
        }
    }

    /// The dynamic table's current size, as RFC 7541 counts it.
    #[must_use]
    pub const fn table_size(&self) -> usize {
        self.table.size()
    }

    /// The dynamic table's maximum: the smaller of the limit and the peer's
    /// setting.
    #[must_use]
    pub const fn table_max(&self) -> usize {
        self.table.max()
    }

    /// Applies the peer's `SETTINGS_HEADER_TABLE_SIZE`. The change is
    /// signalled at the start of the next block.
    pub fn set_peer_max_size(&mut self, peer_max: usize) {
        self.peer_max = peer_max;
        let size = self.limit.min(peer_max);
        if size == self.table.max() {
            return;
        }
        self.table.set_max(size);
        self.pending = Some(match self.pending {
            Some((low, _)) => (low.min(size), size),
            None => (size, size),
        });
    }

    /// Appends the field block for `fields` to `out`.
    pub fn encode<'f>(
        &mut self,
        fields: impl IntoIterator<Item = HeaderField<'f>>,
        out: &mut Vec<u8>,
    ) {
        if let Some((low, now)) = self.pending.take() {
            int::encode(low, 5, 0x20, out);
            if now != low {
                int::encode(now, 5, 0x20, out);
            }
        }
        for field in fields {
            self.field(field, out);
        }
    }

    fn field(&mut self, field: HeaderField<'_>, out: &mut Vec<u8>) {
        let never = field.sensitive || NEVER_INDEXED.contains(&field.name);
        let found = self.table.find(field.name, field.value);
        if let Some((index, true)) = found {
            if !never {
                int::encode(index, 7, 0x80, out);
                return;
            }
        }
        let name_index = found.map_or(0, |(i, _)| i);
        let index_it = !never
            && self.table.max() > 0
            && field.size() <= self.table.max() / 2
            && !NOT_WORTH_INDEXING.contains(&field.name);
        if index_it {
            int::encode(name_index, 6, 0x40, out);
        } else if never {
            int::encode(name_index, 4, 0x10, out);
        } else {
            int::encode(name_index, 4, 0x00, out);
        }
        if name_index == 0 {
            string(field.name, out);
        }
        string(field.value, out);
        if index_it {
            self.table.insert(field.name, field.value);
        }
    }
}

/// Appends a string literal, Huffman coded when that is shorter.
fn string(s: &[u8], out: &mut Vec<u8>) {
    let coded = huffman::encoded_len(s);
    if coded < s.len() {
        int::encode(coded, 7, 0x80, out);
        huffman::encode(s, out);
    } else {
        int::encode(s.len(), 7, 0x00, out);
        out.extend_from_slice(s);
    }
}
