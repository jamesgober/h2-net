//! The HPACK decoder (RFC 7541 sections 3, 4, and 6).

use alloc::vec::Vec;
use core::ops::Range;

use super::table::{STATIC_LEN, Table};
use super::tables::STATIC;
use super::{HeaderField, HeaderList, HpackError, huffman, int};

/// Where a decoded string's bytes are.
#[derive(Clone)]
enum Src {
    /// In the block (a literal sent without Huffman coding).
    Block(Range<usize>),
    /// In the decoder's scratch buffer (a Huffman string, or a dynamic
    /// table name copied out before the table changes).
    Scratch(Range<usize>),
    /// A static table name.
    Static(&'static [u8]),
    /// A dynamic table name, used only when the table does not change.
    Table(usize),
}

/// An HPACK decoder: one per connection, fed every field block the peer
/// sends, in order.
///
/// `max_size` is the `SETTINGS_HEADER_TABLE_SIZE` this side advertised: the
/// largest dynamic table the peer's encoder may ask for. The table starts
/// at that size, as RFC 7541 says.
///
/// # Examples
///
/// ```
/// use h2_net::hpack::{Decoder, HeaderList};
///
/// let mut decoder = Decoder::new(256);
/// let mut list = HeaderList::new(4096);
/// // RFC 7541 C.2.1: a literal field with incremental indexing.
/// decoder.decode(b"\x40\x0acustom-key\x0dcustom-header", &mut list)?;
/// assert_eq!(list.get("custom-key"), Some(&b"custom-header"[..]));
/// assert_eq!(decoder.table_size(), 55);
/// // Index 62 is now that entry.
/// decoder.decode(b"\xbe", &mut list)?;
/// assert_eq!(list.get("custom-key"), Some(&b"custom-header"[..]));
/// # Ok::<(), h2_net::HpackError>(())
/// ```
#[derive(Clone, Debug)]
pub struct Decoder {
    table: Table,
    max_size: usize,
    /// After the maximum was lowered: the next block must start with a size
    /// update at or under this.
    must_shrink_to: Option<usize>,
    scratch: Vec<u8>,
}

impl Decoder {
    /// A decoder whose peer may use a dynamic table of up to `max_size`
    /// bytes.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            table: Table::new(max_size),
            max_size,
            must_shrink_to: None,
            scratch: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) const fn table(&self) -> &Table {
        &self.table
    }

    /// The largest table the peer may use.
    #[must_use]
    pub const fn max_size(&self) -> usize {
        self.max_size
    }

    /// The dynamic table's current size, as RFC 7541 counts it.
    #[must_use]
    pub const fn table_size(&self) -> usize {
        self.table.size()
    }

    /// The dynamic table's current maximum, the last size the peer chose.
    #[must_use]
    pub const fn table_max(&self) -> usize {
        self.table.max()
    }

    /// Changes the largest table the peer may use, once the peer has
    /// acknowledged the `SETTINGS` that carried the new value. When the
    /// value is lower than the table's current maximum, the next block must
    /// start with a size update at or under it (RFC 9113 section 4.3.1).
    pub fn set_max_size(&mut self, max_size: usize) {
        if max_size < self.table.max() {
            self.must_shrink_to = Some(self.must_shrink_to.map_or(max_size, |m| m.min(max_size)));
        }
        self.max_size = max_size;
    }

    /// Decodes one whole field block (every `HEADERS` or `PUSH_PROMISE`
    /// fragment and its `CONTINUATION` fragments, joined) into `list`,
    /// which is cleared first.
    ///
    /// # Errors
    ///
    /// An [`HpackError`], always a connection error: the table may have
    /// changed part way. A list over its budget is not an error; see
    /// [`HeaderList::is_oversized`].
    pub fn decode(&mut self, block: &[u8], list: &mut HeaderList) -> Result<(), HpackError> {
        list.clear();
        let mut pos = 0;
        let mut at_start = true;
        while let Some(&first) = block.get(pos) {
            if first & 0xe0 == 0x20 {
                // Dynamic table size update (section 6.3).
                if !at_start {
                    return Err(HpackError::SizeUpdateMisplaced);
                }
                let size = int::decode(block, &mut pos, 5)?;
                if size > self.max_size {
                    return Err(HpackError::SizeUpdateTooLarge {
                        size,
                        max: self.max_size,
                    });
                }
                if self.must_shrink_to.is_some_and(|limit| size <= limit) {
                    self.must_shrink_to = None;
                }
                self.table.set_max(size);
                continue;
            }
            if at_start && self.must_shrink_to.is_some() {
                return Err(HpackError::SizeUpdateMissing);
            }
            at_start = false;
            self.scratch.clear();
            if first & 0x80 != 0 {
                // Indexed field (section 6.1).
                let index = int::decode(block, &mut pos, 7)?;
                let (name, value) = self
                    .table
                    .get(index)
                    .ok_or(HpackError::BadIndex { index })?;
                let _ = list.push(HeaderField::new(name, value));
                continue;
            }
            // A literal (section 6.2): with incremental indexing (01), never
            // indexed (0001), or without indexing (0000).
            let (prefix, index_it, sensitive) = match first & 0xf0 {
                0x40..=0x70 => (6, true, false),
                0x10 => (4, false, true),
                _ => (4, false, false),
            };
            let name_index = int::decode(block, &mut pos, prefix)?;
            let name = if name_index == 0 {
                self.string(block, &mut pos)?
            } else if let Some(&(n, _)) = STATIC.get(name_index - 1) {
                Src::Static(n)
            } else if name_index - 1 - STATIC_LEN < self.table.len() {
                if index_it {
                    // The insert may evict this entry; copy the name first.
                    let (n, _) = self
                        .table
                        .get(name_index)
                        .ok_or(HpackError::BadIndex { index: name_index })?;
                    let start = self.scratch.len();
                    self.scratch.extend_from_slice(n);
                    Src::Scratch(start..self.scratch.len())
                } else {
                    Src::Table(name_index)
                }
            } else {
                return Err(HpackError::BadIndex { index: name_index });
            };
            let value = self.string(block, &mut pos)?;
            let Self { table, scratch, .. } = self;
            let _ = list.push(HeaderField {
                name: resolve(block, scratch, Some(table), &name),
                value: resolve(block, scratch, Some(table), &value),
                sensitive,
            });
            if index_it {
                // The name was copied out of the table above, so neither
                // slice borrows the table while it changes.
                table.insert(
                    resolve(block, scratch, None, &name),
                    resolve(block, scratch, None, &value),
                );
            }
        }
        self.scratch.clear();
        Ok(())
    }

    /// Reads a string literal (section 5.2).
    fn string(&mut self, block: &[u8], pos: &mut usize) -> Result<Src, HpackError> {
        let huffman = block.get(*pos).ok_or(HpackError::Truncated)? & 0x80 != 0;
        let len = int::decode(block, pos, 7)?;
        let end = pos.checked_add(len).ok_or(HpackError::Truncated)?;
        let raw = block.get(*pos..end).ok_or(HpackError::Truncated)?;
        let src = if huffman {
            let start = self.scratch.len();
            huffman::decode(raw, &mut self.scratch)?;
            Src::Scratch(start..self.scratch.len())
        } else {
            Src::Block(*pos..end)
        };
        *pos = end;
        Ok(src)
    }
}

/// The bytes of a decoded string. `table` is `None` while the table is
/// about to change; a name that is still in it was copied to the scratch
/// buffer by then.
fn resolve<'a>(
    block: &'a [u8],
    scratch: &'a [u8],
    table: Option<&'a Table>,
    src: &Src,
) -> &'a [u8] {
    match src {
        Src::Block(r) => block.get(r.clone()).unwrap_or_default(),
        Src::Scratch(r) => scratch.get(r.clone()).unwrap_or_default(),
        Src::Static(s) => s,
        Src::Table(i) => table.and_then(|t| t.get(*i)).map_or(&[][..], |(n, _)| n),
    }
}
