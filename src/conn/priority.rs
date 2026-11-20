//! Extensible priorities (RFC 9218): the `priority` field and the
//! `PRIORITY_UPDATE` frame, both a Structured Field dictionary (RFC 8941).
//!
//! The connection reads the signals and passes them on; which response
//! gets the next window is the scheduler's decision, and the scheduler is
//! the driver's.

/// A request's priority (RFC 9218 section 4): urgency `0` (highest) to `7`
/// (lowest), default `3`, and whether the response can be delivered
/// incrementally, default no.
///
/// # Examples
///
/// ```
/// use h2_net::conn::PriorityParams;
///
/// assert_eq!(PriorityParams::parse(b"u=1, i"), PriorityParams { urgency: 1, incremental: true });
/// assert_eq!(PriorityParams::parse(b"i=?0"), PriorityParams::default());
/// // Not a dictionary: the defaults.
/// assert_eq!(PriorityParams::parse(b"u=1,,"), PriorityParams::default());
/// // An urgency out of range is ignored; the rest still applies.
/// assert_eq!(PriorityParams::parse(b"u=9, i"), PriorityParams { urgency: 3, incremental: true });
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PriorityParams {
    /// `u`: 0 (highest) to 7 (lowest).
    pub urgency: u8,
    /// `i`: the response is useful in pieces.
    pub incremental: bool,
}

impl Default for PriorityParams {
    fn default() -> Self {
        Self {
            urgency: 3,
            incremental: false,
        }
    }
}

impl PriorityParams {
    /// Parses a Priority Field Value. A value that is not a valid
    /// dictionary gives the defaults (RFC 8941 says to ignore a field that
    /// fails to parse); a member of the wrong type or out of range is
    /// ignored and its default kept (RFC 9218 section 4); unknown members
    /// are ignored.
    #[must_use]
    pub fn parse(value: &[u8]) -> Self {
        Self::try_parse(value).unwrap_or_default()
    }

    /// As [`parse`](Self::parse), but `None` when the value is not a
    /// dictionary (a `PRIORITY_UPDATE` with such a value is ignored).
    #[must_use]
    pub fn try_parse(value: &[u8]) -> Option<Self> {
        let mut p = Self::default();
        let mut s = Scan { b: value, at: 0 };
        s.skip_sp();
        if s.done() {
            return Some(p);
        }
        loop {
            let key = s.key()?;
            let item = if s.eat(b'=') {
                s.bare_item()?
            } else {
                Item::Bool(true)
            };
            s.params()?;
            match (key, item) {
                (b"u", Item::Int(u)) if (0..=7).contains(&u) => p.urgency = u as u8,
                (b"i", Item::Bool(i)) => p.incremental = i,
                // Wrong type or out of range: ignored (RFC 9218 section 4).
                (b"u", _) | (b"i", _) => {}
                _ => {}
            }
            s.skip_ows();
            if s.done() {
                return Some(p);
            }
            if !s.eat(b',') {
                return None;
            }
            s.skip_ows();
            if s.done() {
                // A trailing comma.
                return None;
            }
        }
    }
}

enum Item {
    Int(i64),
    Bool(bool),
    Other,
}

struct Scan<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Scan<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.at).copied()
    }

    fn done(&self) -> bool {
        self.at >= self.b.len()
    }

    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn skip_sp(&mut self) {
        while self.peek() == Some(b' ') {
            self.at += 1;
        }
    }

    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.at += 1;
        }
    }

    fn take_while(&mut self, f: impl Fn(u8) -> bool) -> &'a [u8] {
        let start = self.at;
        while self.peek().is_some_and(&f) {
            self.at += 1;
        }
        self.b.get(start..self.at).unwrap_or_default()
    }

    /// `key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )`
    fn key(&mut self) -> Option<&'a [u8]> {
        if !matches!(self.peek(), Some(b'a'..=b'z' | b'*')) {
            return None;
        }
        Some(
            self.take_while(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'*')),
        )
    }

    /// `;key[=bare-item]` parameters, read and dropped.
    fn params(&mut self) -> Option<()> {
        while self.eat(b';') {
            self.skip_sp();
            let _ = self.key()?;
            if self.eat(b'=') {
                let _ = self.bare_item()?;
            }
        }
        Some(())
    }

    fn bare_item(&mut self) -> Option<Item> {
        match self.peek()? {
            b'-' | b'0'..=b'9' => self.number(),
            b'?' => {
                self.at += 1;
                match self.peek()? {
                    b'0' => {
                        self.at += 1;
                        Some(Item::Bool(false))
                    }
                    b'1' => {
                        self.at += 1;
                        Some(Item::Bool(true))
                    }
                    _ => None,
                }
            }
            b'"' => {
                self.at += 1;
                loop {
                    match self.peek()? {
                        b'"' => {
                            self.at += 1;
                            return Some(Item::Other);
                        }
                        b'\\' => {
                            self.at += 1;
                            if !matches!(self.peek()?, b'"' | b'\\') {
                                return None;
                            }
                            self.at += 1;
                        }
                        0x20..=0x7e => self.at += 1,
                        _ => return None,
                    }
                }
            }
            b':' => {
                self.at += 1;
                let _ = self
                    .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'='));
                self.eat(b':').then_some(Item::Other)
            }
            b'A'..=b'Z' | b'a'..=b'z' | b'*' => {
                let _ = self.take_while(|c| {
                    c.is_ascii_alphanumeric()
                        || matches!(
                            c,
                            b'!' | b'#'
                                | b'$'
                                | b'%'
                                | b'&'
                                | b'\''
                                | b'*'
                                | b'+'
                                | b'-'
                                | b'.'
                                | b'^'
                                | b'_'
                                | b'`'
                                | b'|'
                                | b'~'
                                | b':'
                                | b'/'
                        )
                });
                Some(Item::Other)
            }
            _ => None,
        }
    }

    /// An integer (at most 15 digits) or a decimal (at most 12 digits, a
    /// dot, and 1 to 3 more).
    fn number(&mut self) -> Option<Item> {
        let negative = self.eat(b'-');
        let int = self.take_while(|c| c.is_ascii_digit());
        if int.is_empty() {
            return None;
        }
        if self.eat(b'.') {
            let frac = self.take_while(|c| c.is_ascii_digit());
            if int.len() > 12 || frac.is_empty() || frac.len() > 3 {
                return None;
            }
            return Some(Item::Other);
        }
        if int.len() > 15 {
            return None;
        }
        let mut v: i64 = 0;
        for d in int {
            v = v * 10 + i64::from(d - b'0');
        }
        Some(Item::Int(if negative { -v } else { v }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(u: u8, i: bool) -> PriorityParams {
        PriorityParams {
            urgency: u,
            incremental: i,
        }
    }

    #[test]
    fn test_rfc_9218_examples() {
        assert_eq!(PriorityParams::parse(b"u=5"), p(5, false));
        assert_eq!(PriorityParams::parse(b"u=5, i"), p(5, true));
        assert_eq!(PriorityParams::parse(b"i"), p(3, true));
        assert_eq!(PriorityParams::parse(b""), p(3, false));
        assert_eq!(PriorityParams::parse(b"u=0"), p(0, false));
    }

    #[test]
    fn test_dictionary_details() {
        // Last value wins; unknown members and parameters are skipped.
        assert_eq!(PriorityParams::parse(b"u=1, u=2"), p(2, false));
        assert_eq!(
            PriorityParams::parse(b"x=\"a,b\", u=4;q=1.5, y=:aGk=:, z=tok/en, i=?1"),
            p(4, true)
        );
        assert_eq!(PriorityParams::parse(b"  u=6,\ti"), p(6, true));
        // Wrong types: ignored.
        assert_eq!(PriorityParams::parse(b"u=?1, i=3"), p(3, false));
        assert_eq!(PriorityParams::parse(b"u=-1"), p(3, false));
        assert_eq!(PriorityParams::parse(b"u=2.5"), p(3, false));
        // Not a dictionary at all: defaults, and `try_parse` says so.
        for bad in [
            &b"U=1"[..],
            b"u=1,",
            b"u=",
            b"u=1 i",
            b",u=1",
            b"u=\"x",
            b"u=1234567890123456",
            b"u=?2",
        ] {
            assert_eq!(PriorityParams::try_parse(bad), None, "{bad:?}");
            assert_eq!(PriorityParams::parse(bad), p(3, false));
        }
    }
}
