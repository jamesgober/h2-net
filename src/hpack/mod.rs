//! HPACK field section compression (RFC 7541).
//!
//! [`Decoder`] turns a field block into a [`HeaderList`]; [`Encoder`] does
//! the reverse. Each keeps its own dynamic table, bounded by a maximum size
//! that only `SETTINGS` can change.
//!
//! ## Budgets
//!
//! A field block is small on the wire but can decode to much more: an
//! indexed field is one byte that names a table entry of up to the table's
//! size, and a block can name it thousands of times (an "HPACK bomb"). The
//! [`HeaderList`] has a budget in RFC 9113's terms (each field's name and
//! value plus 32 bytes, as `SETTINGS_MAX_HEADER_LIST_SIZE` counts), and
//! each field is checked against it before its bytes are copied. A block
//! over the budget is still decoded to the end, so the dynamic table stays
//! in step with the peer's, but nothing past the budget is stored: the list
//! reports [`is_oversized`](HeaderList::is_oversized) and the request can be
//! refused with 431 without ending the connection. The work a block costs
//! is linear in its length; the memory it costs is the budget.
//!
//! # Examples
//!
//! ```
//! use h2_net::hpack::{Decoder, Encoder, HeaderField, HeaderList};
//!
//! let mut encoder = Encoder::new(4096);
//! let mut block = Vec::new();
//! encoder.encode(
//!     [
//!         HeaderField::new(b":status", b"200"),
//!         HeaderField::new(b"content-type", b"text/html"),
//!         HeaderField::sensitive(b"x-token", b"s3cret"),
//!     ],
//!     &mut block,
//! );
//!
//! let mut decoder = Decoder::new(4096);
//! let mut list = HeaderList::new(8 * 1024);
//! decoder.decode(&block, &mut list)?;
//! assert_eq!(list.get(":status"), Some(&b"200"[..]));
//! assert_eq!(list.get("x-token"), Some(&b"s3cret"[..]));
//! assert!(list.iter().any(|f| f.name == b"x-token" && f.sensitive));
//! # Ok::<(), h2_net::HpackError>(())
//! ```

mod decoder;
mod encoder;
pub mod huffman;
mod int;
#[cfg(test)]
mod rfc_vectors;
mod table;
mod tables;

use alloc::vec::Vec;
use core::fmt;

pub use decoder::Decoder;
pub use encoder::Encoder;

use crate::error::ErrorCode;

/// The size RFC 7541 and RFC 9113 count for each field on top of its name
/// and value.
pub const FIELD_OVERHEAD: usize = table::ENTRY_OVERHEAD;

/// A field block the decoder refused. Every one is a connection error of
/// type `COMPRESSION_ERROR` (RFC 9113 section 4.3): the decoder's dynamic
/// table can no longer be trusted to match the peer's.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HpackError {
    /// The block ends inside a field representation.
    Truncated,
    /// An integer over 2^32 - 1, or with more than four continuation bytes.
    IntegerOverflow,
    /// A Huffman string with EOS in it, or with bad padding.
    Huffman,
    /// An index of 0, or past the end of the dynamic table.
    BadIndex {
        /// The index.
        index: usize,
    },
    /// A dynamic table size update over the maximum the decoder allowed.
    SizeUpdateTooLarge {
        /// The size asked for.
        size: usize,
        /// The maximum.
        max: usize,
    },
    /// A dynamic table size update after the first field of a block.
    SizeUpdateMisplaced,
    /// The first block after the decoder's maximum was lowered did not
    /// start with a size update at or under the new maximum.
    SizeUpdateMissing,
}

impl HpackError {
    /// The error code for this refusal: always `COMPRESSION_ERROR`.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        ErrorCode::COMPRESSION_ERROR
    }
}

impl fmt::Display for HpackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("field block ends inside a field"),
            Self::IntegerOverflow => f.write_str("integer too large"),
            Self::Huffman => f.write_str("invalid Huffman string"),
            Self::BadIndex { index } => write!(f, "no table entry at index {index}"),
            Self::SizeUpdateTooLarge { size, max } => {
                write!(
                    f,
                    "table size update to {size} is over the maximum of {max}"
                )
            }
            Self::SizeUpdateMisplaced => f.write_str("table size update after a field"),
            Self::SizeUpdateMissing => {
                f.write_str("no table size update after the maximum was lowered")
            }
        }
    }
}

impl core::error::Error for HpackError {}

/// One field: a name, a value, and whether it must never be put in a
/// dynamic table (the never-indexed representation, RFC 7541 section
/// 6.2.3, which a proxy must keep when it forwards the field).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HeaderField<'a> {
    /// The name, as sent (HTTP/2 requires lowercase; the connection checks).
    pub name: &'a [u8],
    /// The value.
    pub value: &'a [u8],
    /// Never indexed.
    pub sensitive: bool,
}

impl<'a> HeaderField<'a> {
    /// A field that may be indexed.
    #[must_use]
    pub const fn new(name: &'a [u8], value: &'a [u8]) -> Self {
        Self {
            name,
            value,
            sensitive: false,
        }
    }

    /// A field that must never be indexed.
    #[must_use]
    pub const fn sensitive(name: &'a [u8], value: &'a [u8]) -> Self {
        Self {
            name,
            value,
            sensitive: true,
        }
    }

    /// The size RFC 9113 counts for this field: name, value, and 32.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.name.len() + self.value.len() + FIELD_OVERHEAD
    }
}

impl fmt::Debug for HeaderField<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Values can be credentials; only their length is printed.
        write!(
            f,
            "{}: <{} bytes>{}",
            alloc::string::String::from_utf8_lossy(self.name),
            self.value.len(),
            if self.sensitive {
                " (never indexed)"
            } else {
                ""
            }
        )
    }
}

#[derive(Clone, Copy, Debug)]
struct Stored {
    at: usize,
    name: usize,
    value: usize,
    sensitive: bool,
}

/// A decoded field section, with a budget on its size.
///
/// The size is RFC 9113's: each field's name and value plus 32 bytes. A
/// field that would take the list over its budget is not stored, and the
/// list is marked [`oversized`](Self::is_oversized); fields after it are
/// counted but not stored either. `Debug` prints names and value lengths,
/// never values.
///
/// # Examples
///
/// ```
/// use h2_net::hpack::{Decoder, HeaderList};
///
/// // ":method: GET" twice is 2 * (7 + 3 + 32) = 84 bytes.
/// let mut list = HeaderList::new(83);
/// Decoder::new(4096).decode(b"\x82\x82", &mut list)?;
/// assert!(list.is_oversized());
/// assert_eq!(list.size(), 84);
/// assert_eq!(list.len(), 1);
/// # Ok::<(), h2_net::HpackError>(())
/// ```
#[derive(Clone)]
pub struct HeaderList {
    bytes: Vec<u8>,
    fields: Vec<Stored>,
    budget: usize,
    size: usize,
    oversized: bool,
}

impl HeaderList {
    /// An empty list that stores at most `budget` bytes of fields.
    #[must_use]
    pub const fn new(budget: usize) -> Self {
        Self {
            bytes: Vec::new(),
            fields: Vec::new(),
            budget,
            size: 0,
            oversized: false,
        }
    }

    /// The budget.
    #[must_use]
    pub const fn budget(&self) -> usize {
        self.budget
    }

    /// Changes the budget for the next field section.
    pub const fn set_budget(&mut self, budget: usize) {
        self.budget = budget;
    }

    /// Empties the list, keeping its allocations.
    pub fn clear(&mut self) {
        self.bytes.clear();
        self.fields.clear();
        self.size = 0;
        self.oversized = false;
    }

    /// Empties the list and zeroes the bytes it held, including spare
    /// capacity, so a credential does not linger in memory that is reused.
    pub fn wipe(&mut self) {
        let capacity = self.bytes.capacity();
        self.bytes.clear();
        self.bytes.resize(capacity, 0);
        for b in &mut self.bytes {
            // A volatile write is not available without unsafe code; the
            // read-back through `black_box` keeps the stores from being
            // dropped as dead.
            *b = core::hint::black_box(0);
        }
        self.clear();
    }

    /// The number of fields stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether no field is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// The size of every field decoded, stored or not.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Whether a field went over the budget. The section must then be
    /// refused (431 for a request); the connection can go on.
    #[must_use]
    pub const fn is_oversized(&self) -> bool {
        self.oversized
    }

    /// The fields stored, in order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = HeaderField<'_>> + '_ {
        self.fields.iter().map(|s| self.field(s))
    }

    fn field(&self, s: &Stored) -> HeaderField<'_> {
        let name = self.bytes.get(s.at..s.at + s.name).unwrap_or_default();
        let value = self
            .bytes
            .get(s.at + s.name..s.at + s.name + s.value)
            .unwrap_or_default();
        HeaderField {
            name,
            value,
            sensitive: s.sensitive,
        }
    }

    /// The value of the first field named `name` (compared exactly; HTTP/2
    /// names are lowercase).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.iter()
            .find(|f| f.name == name.as_bytes())
            .map(|f| f.value)
    }

    /// Adds a field if it fits the budget; returns whether it was stored.
    pub(crate) fn push(&mut self, field: HeaderField<'_>) -> bool {
        self.size = self.size.saturating_add(field.size());
        if self.oversized || self.size > self.budget {
            self.oversized = true;
            return false;
        }
        let at = self.bytes.len();
        self.bytes.extend_from_slice(field.name);
        self.bytes.extend_from_slice(field.value);
        self.fields.push(Stored {
            at,
            name: field.name.len(),
            value: field.value.len(),
            sensitive: field.sensitive,
        });
        true
    }
}

impl fmt::Debug for HeaderList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderList")
            .field("fields", &DebugFields(self))
            .field("size", &self.size)
            .field("budget", &self.budget)
            .field("oversized", &self.oversized)
            .finish()
    }
}

struct DebugFields<'a>(&'a HeaderList);

impl fmt::Debug for DebugFields<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.iter()).finish()
    }
}

#[cfg(test)]
mod tests;
