//! The HPACK dynamic table (RFC 7541 section 2.3.2 and 4).
//!
//! Entries live back to back in one byte buffer, oldest first; evicting
//! moves the start forward. When an insert would run past twice the table's
//! maximum size, the live entries move to the front, so the buffer never
//! grows past that and an insert never allocates once the buffer has
//! reached it. Each move copies at most the maximum size and happens at most
//! once per maximum size of inserted bytes: at most one byte moved per byte
//! inserted.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::tables::STATIC;

/// The size RFC 7541 counts for each entry on top of its name and value.
pub(crate) const ENTRY_OVERHEAD: usize = 32;

/// The number of static table entries.
pub(crate) const STATIC_LEN: usize = STATIC.len();

#[derive(Clone, Copy, Debug)]
struct Entry {
    /// Where the name starts in `bytes`, before `base` is subtracted.
    at: usize,
    name: usize,
    value: usize,
}

impl Entry {
    const fn size(&self) -> usize {
        self.name + self.value + ENTRY_OVERHEAD
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Table {
    bytes: Vec<u8>,
    /// Entries, newest first.
    entries: VecDeque<Entry>,
    /// What `Entry::at` values are offset by: bytes dropped from the front
    /// of `bytes` since the offsets were taken.
    base: usize,
    size: usize,
    max: usize,
}

impl Table {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            max,
            ..Self::default()
        }
    }

    pub(crate) const fn size(&self) -> usize {
        self.size
    }

    pub(crate) const fn max(&self) -> usize {
        self.max
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// The entry at HPACK index `index` (1-based, static entries first).
    pub(crate) fn get(&self, index: usize) -> Option<(&[u8], &[u8])> {
        if index == 0 {
            return None;
        }
        if let Some(&(n, v)) = STATIC.get(index - 1) {
            return Some((n, v));
        }
        let e = self.entries.get(index - 1 - STATIC_LEN)?;
        let at = e.at - self.base;
        let name = self.bytes.get(at..at + e.name)?;
        let value = self.bytes.get(at + e.name..at + e.name + e.value)?;
        Some((name, value))
    }

    /// Changes the maximum size, evicting until the table fits.
    pub(crate) fn set_max(&mut self, max: usize) {
        self.max = max;
        self.evict_to(max);
    }

    fn evict_to(&mut self, limit: usize) {
        while self.size > limit {
            match self.entries.pop_back() {
                Some(e) => self.size -= e.size(),
                None => {
                    self.size = 0;
                    break;
                }
            }
        }
        if self.entries.is_empty() {
            self.bytes.clear();
            self.base = 0;
        }
    }

    /// Adds an entry, evicting the oldest ones to make room. An entry larger
    /// than the maximum empties the table and is not added (section 4.4).
    pub(crate) fn insert(&mut self, name: &[u8], value: &[u8]) {
        let size = name.len() + value.len() + ENTRY_OVERHEAD;
        if size > self.max {
            self.evict_to(0);
            return;
        }
        self.evict_to(self.max - size);
        let len = name.len() + value.len();
        if self.bytes.len() + len > self.max.saturating_mul(2) {
            self.compact();
        }
        let at = self.base + self.bytes.len();
        self.bytes.extend_from_slice(name);
        self.bytes.extend_from_slice(value);
        self.entries.push_front(Entry {
            at,
            name: name.len(),
            value: value.len(),
        });
        self.size += size;
    }

    /// Moves the live entries to the front of the buffer.
    fn compact(&mut self) {
        let Some(oldest) = self.entries.back() else {
            self.bytes.clear();
            self.base = 0;
            return;
        };
        let start = oldest.at - self.base;
        let _ = self.bytes.drain(..start);
        self.base += start;
    }

    /// Finds an entry: `(index, true)` for an exact match, `(index, false)`
    /// for a name match. Static entries are preferred for a name match, and
    /// exact matches anywhere over a name match.
    pub(crate) fn find(&self, name: &[u8], value: &[u8]) -> Option<(usize, bool)> {
        let mut by_name = None;
        for (i, &(n, v)) in STATIC.iter().enumerate() {
            if n == name {
                if v == value {
                    return Some((i + 1, true));
                }
                by_name = by_name.or(Some(i + 1));
            }
        }
        for i in 0..self.entries.len() {
            let index = STATIC_LEN + 1 + i;
            if let Some((n, v)) = self.get(index) {
                if n == name {
                    if v == value {
                        return Some((index, true));
                    }
                    by_name = by_name.or(Some(index));
                }
            }
        }
        by_name.map(|i| (i, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_table_spot_checks() {
        let t = Table::new(4096);
        assert_eq!(t.get(1), Some((&b":authority"[..], &b""[..])));
        assert_eq!(t.get(2), Some((&b":method"[..], &b"GET"[..])));
        assert_eq!(t.get(61), Some((&b"www-authenticate"[..], &b""[..])));
        assert_eq!(t.get(0), None);
        assert_eq!(t.get(62), None);
    }

    #[test]
    fn test_insert_evicts_oldest_first() {
        let mut t = Table::new(100);
        t.insert(b"aaaa", b"1111"); // 40
        t.insert(b"bbbb", b"2222"); // 80
        assert_eq!(t.get(62), Some((&b"bbbb"[..], &b"2222"[..])));
        assert_eq!(t.get(63), Some((&b"aaaa"[..], &b"1111"[..])));
        t.insert(b"cccc", b"3333"); // evicts aaaa
        assert_eq!(t.size(), 80);
        assert_eq!(t.len(), 2);
        assert_eq!(t.get(63), Some((&b"bbbb"[..], &b"2222"[..])));
        assert_eq!(t.get(64), None);
    }

    #[test]
    fn test_an_entry_larger_than_the_table_empties_it() {
        let mut t = Table::new(64);
        t.insert(b"a", b"b");
        t.insert(&[b'x'; 40], b"");
        assert_eq!(t.len(), 0);
        assert_eq!(t.size(), 0);
        // Exactly the maximum fits.
        t.insert(&[b'x'; 32], b"");
        assert_eq!(t.size(), 64);
    }

    #[test]
    fn test_buffer_stays_bounded_over_many_inserts() {
        let mut t = Table::new(256);
        for i in 0..10_000u32 {
            let v = i.to_be_bytes();
            t.insert(b"name", &v[..(i % 4) as usize + 1]);
            assert!(t.bytes.len() <= 512, "{}", t.bytes.len());
            assert!(t.size() <= 256);
            let (n, value) = t.get(62).unwrap();
            assert_eq!(n, b"name");
            assert_eq!(value, &v[..(i % 4) as usize + 1]);
        }
    }

    #[test]
    fn test_set_max_evicts() {
        let mut t = Table::new(4096);
        for _ in 0..10 {
            t.insert(b"k", b"v");
        }
        t.set_max(70);
        assert_eq!(t.len(), 2);
        t.set_max(0);
        assert_eq!(t.len(), 0);
        assert!(t.bytes.is_empty());
    }

    #[test]
    fn test_find_prefers_exact_matches() {
        let mut t = Table::new(4096);
        assert_eq!(t.find(b":method", b"GET"), Some((2, true)));
        assert_eq!(t.find(b":method", b"PUT"), Some((2, false)));
        assert_eq!(t.find(b"x-new", b"1"), None);
        t.insert(b":method", b"PUT");
        assert_eq!(t.find(b":method", b"PUT"), Some((62, true)));
        t.insert(b"x-new", b"1");
        assert_eq!(t.find(b"x-new", b"2"), Some((62, false)));
    }
}
