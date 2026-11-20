//! The HTTP layer of HTTP/2 (RFC 9113 section 8): checking a decoded field
//! section, and mapping a request onto http-net's types.
//!
//! A request is written out as the HTTP/1.1 head a translating proxy would
//! send (`:method :path HTTP/1.1`, `host` from `:authority`, the `cookie`
//! fields joined with "; " as section 8.2.3 says, and `transfer-encoding:
//! chunked` when a body follows without `content-length`) and parsed by
//! http-net, so an HTTP/2 request gets the same accessors, the same type,
//! and the same strictness as an HTTP/1.1 one. The head's framing then
//! tells the truth about the body.

use alloc::vec::Vec;

use http_net::{FieldSpan, Limits, OwnedRequestHead, Parsed, parse_request_head};

use super::error::Malformed;
use crate::hpack::{HeaderField, HeaderList};

/// Fields RFC 9113 section 8.2.2 forbids in HTTP/2.
const CONNECTION_SPECIFIC: [&[u8]; 5] = [
    b"connection",
    b"keep-alive",
    b"proxy-connection",
    b"transfer-encoding",
    b"upgrade",
];

/// The request's scheme.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// `http` (cleartext HTTP/2, behind a trusted proxy only).
    Http,
    /// `https`.
    Https,
}

impl Scheme {
    /// The scheme's name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// A request head, checked and mapped.
pub(crate) struct Mapped {
    pub(crate) head: OwnedRequestHead,
    pub(crate) scheme: Option<Scheme>,
    pub(crate) content_length: Option<u64>,
    pub(crate) is_head: bool,
}

const fn is_tchar_lower(b: u8) -> bool {
    matches!(b,
        b'a'..=b'z' | b'0'..=b'9'
        | b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_'
        | b'`' | b'|' | b'~')
}

/// A regular field name: a token of lowercase characters.
pub(crate) fn check_name(name: &[u8]) -> Result<(), Malformed> {
    if !name.is_empty() && name.iter().all(|&b| is_tchar_lower(b)) {
        Ok(())
    } else {
        Err(Malformed::FieldName)
    }
}

/// A field value: no NUL, CR, or LF, and no whitespace at either end
/// (section 8.2.1). http-net refuses other control bytes afterwards.
pub(crate) fn check_value(value: &[u8]) -> Result<(), Malformed> {
    let ws = |b: &u8| *b == b' ' || *b == b'\t';
    if value.iter().any(|&b| b == 0 || b == b'\r' || b == b'\n')
        || value.first().is_some_and(ws)
        || value.last().is_some_and(ws)
    {
        Err(Malformed::FieldValue)
    } else {
        Ok(())
    }
}

/// The checks every regular field gets, in a request, its trailers, and a
/// response.
pub(crate) fn check_regular(f: &HeaderField<'_>) -> Result<(), Malformed> {
    check_name(f.name)?;
    check_value(f.value)?;
    if CONNECTION_SPECIFIC.contains(&f.name) {
        return Err(Malformed::ConnectionSpecific);
    }
    if f.name == b"te" && !f.value.eq_ignore_ascii_case(b"trailers") {
        return Err(Malformed::Te);
    }
    Ok(())
}

/// Checks trailers: regular fields only.
pub(crate) fn check_trailers(list: &HeaderList) -> Result<(), Malformed> {
    for f in list.iter() {
        if f.name.first() == Some(&b':') {
            return Err(Malformed::PseudoInTrailers);
        }
        check_regular(&f)?;
    }
    Ok(())
}

#[derive(Default)]
struct Pseudo<'a> {
    method: Option<&'a [u8]>,
    scheme: Option<&'a [u8]>,
    authority: Option<&'a [u8]>,
    path: Option<&'a [u8]>,
}

/// Checks a request's field section and maps it onto http-net's head.
/// `synth` is scratch space for the HTTP/1.1 rendering; `slots` holds
/// http-net's field records.
pub(crate) fn map_request(
    list: &HeaderList,
    end_stream: bool,
    limits: &Limits,
    synth: &mut Vec<u8>,
    slots: &mut Vec<FieldSpan>,
) -> Result<Mapped, Malformed> {
    let mut p = Pseudo::default();
    let mut regular = false;
    let mut host = None;
    let mut content_length = None::<&[u8]>;
    for f in list.iter() {
        if let Some(rest) = f.name.strip_prefix(b":") {
            if regular {
                return Err(Malformed::PseudoOrder);
            }
            let slot = match rest {
                b"method" => &mut p.method,
                b"scheme" => &mut p.scheme,
                b"authority" => &mut p.authority,
                b"path" => &mut p.path,
                _ => return Err(Malformed::UnknownPseudo),
            };
            if slot.replace(f.value).is_some() {
                return Err(Malformed::PseudoOrder);
            }
            check_value(f.value)?;
            continue;
        }
        regular = true;
        check_regular(&f)?;
        if f.name == b"host" && host.replace(f.value).is_some() {
            // http-net refuses a repeated host too; refuse it here so the
            // authority check below sees one value.
            return Err(Malformed::Authority);
        }
        if f.name == b"content-length" {
            content_length = Some(f.value);
        }
    }
    let method = p.method.ok_or(Malformed::MissingPseudo)?;
    let connect = method == b"CONNECT";
    let scheme = if connect {
        if p.scheme.is_some() || p.path.is_some() || p.authority.is_none() {
            return Err(Malformed::MissingPseudo);
        }
        None
    } else {
        match p.scheme.ok_or(Malformed::MissingPseudo)? {
            b"https" => Some(Scheme::Https),
            b"http" => Some(Scheme::Http),
            _ => return Err(Malformed::Scheme),
        }
    };
    let target = if connect {
        p.authority.unwrap_or_default()
    } else {
        let path = p.path.ok_or(Malformed::MissingPseudo)?;
        let ok = path.first() == Some(&b'/') || (path == b"*" && method == b"OPTIONS");
        if !ok {
            return Err(Malformed::Path);
        }
        path
    };
    let authority = match (p.authority, host) {
        (Some(a), Some(h)) if !a.eq_ignore_ascii_case(h) => return Err(Malformed::Authority),
        (Some(a), _) => Some(a),
        (None, h) => h,
    };
    if authority.is_some_and(|a| a.contains(&b'@')) {
        return Err(Malformed::Authority);
    }
    if end_stream && content_length.is_some_and(|v| v != b"0") {
        // A body was announced but the stream ended with the head. http-net
        // checks the digits; a value other than "0" here is either a length
        // that can never be met or not a length.
        return Err(Malformed::ContentLength);
    }

    // The HTTP/1.1 rendering.
    synth.clear();
    synth.extend_from_slice(method);
    synth.push(b' ');
    synth.extend_from_slice(target);
    synth.extend_from_slice(b" HTTP/1.1\r\n");
    if let Some(a) = authority {
        synth.extend_from_slice(b"host: ");
        synth.extend_from_slice(a);
        synth.extend_from_slice(b"\r\n");
    }
    let mut cookies = 0usize;
    for f in list.iter() {
        if f.name.first() == Some(&b':') || f.name == b"host" {
            continue;
        }
        if f.name == b"cookie" {
            cookies += 1;
            continue;
        }
        synth.extend_from_slice(f.name);
        synth.extend_from_slice(b": ");
        synth.extend_from_slice(f.value);
        synth.extend_from_slice(b"\r\n");
    }
    if cookies > 0 {
        synth.extend_from_slice(b"cookie: ");
        let mut first = true;
        for f in list.iter().filter(|f| f.name == b"cookie") {
            if !first {
                synth.extend_from_slice(b"; ");
            }
            first = false;
            synth.extend_from_slice(f.value);
        }
        synth.extend_from_slice(b"\r\n");
    }
    if !end_stream && content_length.is_none() {
        synth.extend_from_slice(b"transfer-encoding: chunked\r\n");
    }
    synth.extend_from_slice(b"\r\n");

    slots.clear();
    slots.resize(list.len() + 2, FieldSpan::default());
    let parsed = match parse_request_head(synth, limits, slots) {
        Ok(Parsed::Complete { head, .. }) => head,
        Ok(_) => return Err(Malformed::Http(http_net::HttpError::InvalidState("head"))),
        Err(e) => return Err(Malformed::Http(e)),
    };
    let view = parsed.view();
    let content_length = view.content_length();
    let head = view.to_owned();
    Ok(Mapped {
        head,
        scheme,
        content_length,
        is_head: method == b"HEAD",
    })
}

/// Whether a response field is one this side drops when it maps an
/// HTTP/1.1 response onto HTTP/2 (section 8.2.2: an intermediary removes
/// them).
pub(crate) fn is_connection_specific(name: &[u8]) -> bool {
    CONNECTION_SPECIFIC
        .iter()
        .any(|c| c.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::hpack::{Decoder, Encoder};

    fn list(fields: &[(&[u8], &[u8])]) -> HeaderList {
        let mut block = vec![];
        Encoder::new(0).encode(
            fields.iter().map(|(n, v)| HeaderField::new(n, v)),
            &mut block,
        );
        let mut l = HeaderList::new(64 * 1024);
        Decoder::new(4096).decode(&block, &mut l).unwrap();
        l
    }

    fn map(fields: &[(&[u8], &[u8])], end: bool) -> Result<Mapped, Malformed> {
        map_request(&list(fields), end, &Limits::new(), &mut vec![], &mut vec![])
    }

    const BASE: [(&[u8], &[u8]); 4] = [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"example.com"),
        (b":path", b"/a?b=c"),
    ];

    fn with(extra: &[(&'static [u8], &'static [u8])]) -> Vec<(&'static [u8], &'static [u8])> {
        let mut v = BASE.to_vec();
        v.extend_from_slice(extra);
        v
    }

    #[test]
    fn test_a_plain_request_maps_to_http_net() {
        let m = map(&with(&[(b"accept", b"*/*")]), true).unwrap();
        let h = m.head.view();
        assert_eq!(h.method_str(), "GET");
        assert_eq!(h.path(), "/a");
        assert_eq!(h.query(), Some("b=c"));
        assert_eq!(h.host(), Some("example.com"));
        assert_eq!(h.header_str("accept"), Some("*/*"));
        assert_eq!(h.framing(), http_net::BodyFraming::None);
        assert_eq!(m.scheme, Some(Scheme::Https));
        assert!(!m.is_head);
    }

    #[test]
    fn test_body_framing_is_truthful() {
        let m = map(&with(&[]), false).unwrap();
        assert_eq!(m.head.view().framing(), http_net::BodyFraming::Chunked);
        let m = map(&with(&[(b"content-length", b"5")]), false).unwrap();
        assert_eq!(m.head.view().framing(), http_net::BodyFraming::Length(5));
        assert_eq!(m.content_length, Some(5));
        assert_eq!(
            map(&with(&[(b"content-length", b"5")]), true).err(),
            Some(Malformed::ContentLength)
        );
        assert!(map(&with(&[(b"content-length", b"0")]), true).is_ok());
    }

    #[test]
    fn test_cookies_are_joined() {
        let m = map(
            &with(&[(b"cookie", b"a=1"), (b"x", b"y"), (b"cookie", b"b=2")]),
            true,
        )
        .unwrap();
        assert_eq!(m.head.view().header_str("cookie"), Some("a=1; b=2"));
    }

    #[test]
    fn test_malformed_requests() {
        type Fields = &'static [(&'static [u8], &'static [u8])];
        let cases: &[(Fields, Malformed)] = &[
            (
                &[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":path", b"/"),
                    (b"Accept", b"x"),
                ],
                Malformed::FieldName,
            ),
            (
                &[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":path", b"/"),
                    (b"a", b" x"),
                ],
                Malformed::FieldValue,
            ),
            (
                &[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":path", b"/"),
                    (b"a", b"x\ny"),
                ],
                Malformed::FieldValue,
            ),
            (
                &[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":path", b"/"),
                    (b"connection", b"close"),
                ],
                Malformed::ConnectionSpecific,
            ),
            (
                &[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":path", b"/"),
                    (b"transfer-encoding", b"chunked"),
                ],
                Malformed::ConnectionSpecific,
            ),
            (
                &[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":path", b"/"),
                    (b"te", b"gzip"),
                ],
                Malformed::Te,
            ),
            (
                &[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":path", b"/"),
                    (b":protocol", b"websocket"),
                ],
                Malformed::UnknownPseudo,
            ),
            (
                &[
                    (b":method", b"GET"),
                    (b"a", b"b"),
                    (b":scheme", b"https"),
                    (b":path", b"/"),
                ],
                Malformed::PseudoOrder,
            ),
            (
                &[
                    (b":method", b"GET"),
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":path", b"/"),
                ],
                Malformed::PseudoOrder,
            ),
            (
                &[(b":method", b"GET"), (b":scheme", b"https")],
                Malformed::MissingPseudo,
            ),
            (
                &[(b":scheme", b"https"), (b":path", b"/")],
                Malformed::MissingPseudo,
            ),
            (
                &[(b":method", b"GET"), (b":scheme", b"ftp"), (b":path", b"/")],
                Malformed::Scheme,
            ),
            (
                &[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":path", b""),
                ],
                Malformed::Path,
            ),
            (
                &[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":path", b"http://evil/"),
                ],
                Malformed::Path,
            ),
            (
                &[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":path", b"*"),
                ],
                Malformed::Path,
            ),
            (
                &[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"u@a"),
                    (b":path", b"/"),
                ],
                Malformed::Authority,
            ),
            (
                &[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"a"),
                    (b":path", b"/"),
                    (b"host", b"b"),
                ],
                Malformed::Authority,
            ),
            (
                &[
                    (b":method", b"CONNECT"),
                    (b":scheme", b"https"),
                    (b":authority", b"a:443"),
                ],
                Malformed::MissingPseudo,
            ),
        ];
        for (fields, want) in cases {
            assert_eq!(map(fields, true).err(), Some(*want), "{fields:?}");
        }
    }

    #[test]
    fn test_accepted_shapes() {
        assert!(
            map(
                &[
                    (b":method", b"OPTIONS"),
                    (b":scheme", b"https"),
                    (b":authority", b"a"),
                    (b":path", b"*")
                ],
                true
            )
            .is_ok()
        );
        let m = map(
            &[(b":method", b"CONNECT"), (b":authority", b"a.example:443")],
            false,
        )
        .unwrap();
        assert_eq!(m.head.view().method_str(), "CONNECT");
        assert_eq!(m.scheme, None);
        // host alone, no :authority.
        let m = map(
            &[
                (b":method", b"HEAD"),
                (b":scheme", b"http"),
                (b":path", b"/"),
                (b"host", b"h"),
            ],
            true,
        )
        .unwrap();
        assert_eq!(m.head.view().host(), Some("h"));
        assert!(m.is_head);
        // te: trailers is allowed.
        assert!(map(&with(&[(b"te", b"trailers")]), true).is_ok());
        // A matching host is allowed, and appears once.
        let m = map(&with(&[(b"host", b"EXAMPLE.com")]), true).unwrap();
        assert_eq!(m.head.view().header_all("host").count(), 1);
    }

    #[test]
    fn test_http_net_strictness_applies() {
        // A control byte other than NUL, CR, and LF in a value.
        assert!(matches!(
            map(&with(&[(b"a", b"x\x01y")]), true),
            Err(Malformed::Http(_))
        ));
        // A bad content-length.
        assert!(matches!(
            map(&with(&[(b"content-length", b"x")]), false),
            Err(Malformed::Http(_))
        ));
        // Two content-lengths.
        assert!(matches!(
            map(
                &with(&[(b"content-length", b"1"), (b"content-length", b"1")]),
                false
            ),
            Err(Malformed::Http(_))
        ));
    }

    #[test]
    fn test_trailers() {
        assert!(check_trailers(&list(&[(b"x-sum", b"1")])).is_ok());
        assert_eq!(
            check_trailers(&list(&[(b":path", b"/")])),
            Err(Malformed::PseudoInTrailers)
        );
        assert_eq!(
            check_trailers(&list(&[(b"X", b"1")])),
            Err(Malformed::FieldName)
        );
    }
}
