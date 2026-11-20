//! What the connection refuses: connection errors, requests it rejects on
//! its own, and calls the application makes out of turn.

use core::fmt;

use crate::error::{ErrorCode, FrameError};
use crate::frame::{FrameType, StreamId};
use crate::hpack::HpackError;

/// The connection ended. A `GOAWAY` carrying [`code`](Self::code) has been
/// written to the output; flush it and close the socket.
///
/// [`is_abuse`](Self::is_abuse) says whether a budget was crossed (rapid
/// reset, a `CONTINUATION` flood, a control frame flood, a peer that sends
/// but does not read): what a connection gate should count against the
/// address. Every other refusal is a protocol violation, which no correct
/// peer commits either; a gate may count those too.
///
/// # Examples
///
/// ```
/// use h2_net::ErrorCode;
/// use h2_net::conn::{Config, ConnErrorKind, ServerConn};
///
/// let mut conn = ServerConn::new(Config::new());
/// let _ = conn.feed(b"GET / HTTP/1.1\r\n\r\n");
/// let error = conn.poll().unwrap_err();
/// assert_eq!(*error.kind(), ConnErrorKind::Preface);
/// assert_eq!(error.code(), ErrorCode::PROTOCOL_ERROR);
/// assert!(!error.is_abuse());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnError {
    kind: ConnErrorKind,
}

impl ConnError {
    pub(crate) const fn new(kind: ConnErrorKind) -> Self {
        Self { kind }
    }

    /// What went wrong.
    #[must_use]
    pub const fn kind(&self) -> &ConnErrorKind {
        &self.kind
    }

    /// The error code sent in the `GOAWAY`.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match &self.kind {
            ConnErrorKind::Frame(e) => e.code(),
            ConnErrorKind::Hpack(e) => e.code(),
            ConnErrorKind::FlowControl => ErrorCode::FLOW_CONTROL_ERROR,
            ConnErrorKind::StreamClosed { .. } => ErrorCode::STREAM_CLOSED,
            ConnErrorKind::RapidReset
            | ConnErrorKind::ContinuationFlood
            | ConnErrorKind::HeaderBlockTooLarge
            | ConnErrorKind::ControlFlood
            | ConnErrorKind::OutputBacklog => ErrorCode::ENHANCE_YOUR_CALM,
            ConnErrorKind::Closed { code } => *code,
            ConnErrorKind::Preface | ConnErrorKind::Protocol(_) => ErrorCode::PROTOCOL_ERROR,
        }
    }

    /// Whether a budget was crossed.
    #[must_use]
    pub const fn is_abuse(&self) -> bool {
        matches!(
            self.kind,
            ConnErrorKind::RapidReset
                | ConnErrorKind::ContinuationFlood
                | ConnErrorKind::HeaderBlockTooLarge
                | ConnErrorKind::ControlFlood
                | ConnErrorKind::OutputBacklog
        )
    }
}

impl fmt::Display for ConnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ConnErrorKind::Preface => f.write_str("the client did not send the HTTP/2 preface"),
            ConnErrorKind::Frame(e) => fmt::Display::fmt(e, f),
            ConnErrorKind::Hpack(e) => fmt::Display::fmt(e, f),
            ConnErrorKind::Protocol(v) => fmt::Display::fmt(v, f),
            ConnErrorKind::FlowControl => f.write_str("the peer broke flow control"),
            ConnErrorKind::StreamClosed { stream } => {
                write!(f, "a frame on closed stream {}", stream.value())
            }
            ConnErrorKind::RapidReset => f.write_str("too many streams reset for the work done"),
            ConnErrorKind::ContinuationFlood => {
                f.write_str("too many CONTINUATION frames in one block")
            }
            ConnErrorKind::HeaderBlockTooLarge => f.write_str("field block over its byte budget"),
            ConnErrorKind::ControlFlood => f.write_str("too many control frames for the work done"),
            ConnErrorKind::OutputBacklog => {
                f.write_str("the peer sends frames that need answers but does not read them")
            }
            ConnErrorKind::Closed { code } => write!(f, "closed by the application ({code})"),
        }
    }
}

impl core::error::Error for ConnError {}

/// Why the connection ended. `#[non_exhaustive]`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnErrorKind {
    /// The first 24 bytes were not the client preface.
    Preface,
    /// A frame the frame layer refused.
    Frame(FrameError),
    /// A field block the HPACK decoder refused.
    Hpack(HpackError),
    /// A frame not allowed where it arrived.
    Protocol(Violation),
    /// A flow-control window went below zero or over 2^31 - 1.
    FlowControl,
    /// `DATA` or `HEADERS` on a stream that had closed.
    StreamClosed {
        /// The stream.
        stream: StreamId,
    },
    /// Budget: streams reset (by the peer, or by this side for the peer's
    /// errors) outnumber the responses completed (CVE-2023-44487 and the
    /// resets a peer provokes with bad frames).
    RapidReset,
    /// Budget: more `CONTINUATION` frames in one field block than allowed.
    ContinuationFlood,
    /// Budget: a field block's bytes over the block budget.
    HeaderBlockTooLarge,
    /// Budget: `SETTINGS`, `PING`, priority, empty `DATA`, unknown, and
    /// similar frames outnumber the useful work done.
    ControlFlood,
    /// Budget: answers to the peer's frames (`PING` and `SETTINGS`
    /// acknowledgments, resets) piled up unread in the output.
    OutputBacklog,
    /// The application closed the connection with this code.
    Closed {
        /// The code sent.
        code: ErrorCode,
    },
}

/// A frame that is valid by itself but not where it arrived.
/// `#[non_exhaustive]`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    /// The first frame was not `SETTINGS`.
    SettingsFirst,
    /// A frame other than `CONTINUATION` for the same stream inside a field
    /// block.
    ContinuationExpected,
    /// A `CONTINUATION` outside a field block.
    UnexpectedContinuation,
    /// A frame that needs an open stream, on a stream that was never opened.
    IdleStream {
        /// The frame's type.
        kind: FrameType,
        /// The stream.
        stream: StreamId,
    },
    /// A client opened a stream with an even identifier, or one lower than
    /// a stream it already opened.
    BadStreamId {
        /// The stream.
        stream: StreamId,
    },
    /// A client sent `PUSH_PROMISE`.
    PushPromise,
    /// A `SETTINGS` acknowledgment with none outstanding.
    UnsolicitedSettingsAck,
    /// A server sent `PRIORITY_UPDATE` (RFC 9218 section 7.1).
    PriorityUpdate,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SettingsFirst => f.write_str("the first frame was not SETTINGS"),
            Self::ContinuationExpected => f.write_str("a field block was interrupted"),
            Self::UnexpectedContinuation => f.write_str("CONTINUATION outside a field block"),
            Self::IdleStream { kind, stream } => {
                write!(f, "{kind} on idle stream {}", stream.value())
            }
            Self::BadStreamId { stream } => {
                write!(
                    f,
                    "stream {} cannot be opened by the client",
                    stream.value()
                )
            }
            Self::PushPromise => f.write_str("a client sent PUSH_PROMISE"),
            Self::UnsolicitedSettingsAck => f.write_str("SETTINGS acknowledged without being sent"),
            Self::PriorityUpdate => f.write_str("a server sent PRIORITY_UPDATE"),
        }
    }
}

/// A request the connection answered on its own, without the application:
/// the stream was reset, or answered with a status, before any
/// [`Event::Request`](super::Event::Request).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// The request was malformed (RFC 9113 section 8.1.1): reset with
    /// `PROTOCOL_ERROR`.
    Malformed(Malformed),
    /// The field section was over `SETTINGS_MAX_HEADER_LIST_SIZE`: answered
    /// `431`.
    HeadersTooLarge,
    /// Over `SETTINGS_MAX_CONCURRENT_STREAMS`: reset with `REFUSED_STREAM`.
    TooManyStreams,
}

/// What made a request or its trailers malformed. `#[non_exhaustive]`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed {
    /// A field name with an uppercase letter or a byte that is not a token
    /// character.
    FieldName,
    /// A field value with NUL, CR, or LF, or with whitespace at either end.
    FieldValue,
    /// `connection`, `keep-alive`, `proxy-connection`, `transfer-encoding`,
    /// or `upgrade`.
    ConnectionSpecific,
    /// `te` with a value other than `trailers`.
    Te,
    /// A pseudo-header this crate does not accept (`:protocol` included,
    /// since extended CONNECT is not offered).
    UnknownPseudo,
    /// A pseudo-header after a regular field, or repeated.
    PseudoOrder,
    /// `:method`, or for a request other than `CONNECT` `:scheme` or
    /// `:path`, is missing; or `CONNECT` carries `:scheme` or `:path`.
    MissingPseudo,
    /// A `:scheme` other than `http` or `https`.
    Scheme,
    /// A `:path` that is empty or does not start with `/` (`*` is allowed
    /// for `OPTIONS`).
    Path,
    /// An `:authority` with userinfo, or a `host` that names another
    /// authority.
    Authority,
    /// Pseudo-headers in trailers.
    PseudoInTrailers,
    /// A second field section without `END_STREAM`.
    TrailersWithoutEnd,
    /// The body's length differs from `content-length`.
    ContentLength,
    /// The head, written as HTTP/1.1, was refused by http-net.
    Http(http_net::HttpError),
    /// A response without one `:status` of three digits, `101`, or an
    /// informational head that ends the stream.
    Status,
}
