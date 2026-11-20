//! HTTP/2 frames (RFC 9113 section 4 and 6, and `PRIORITY_UPDATE` from
//! RFC 9218): the 9-byte header, every frame type, and the checks RFC 9113
//! puts on each one.
//!
//! [`decode`] reads one frame from the front of a buffer as a borrowed view;
//! [`encode`] writes one. The encoder refuses every frame the decoder would
//! refuse, so `decode(encode(f)) == f` for every frame `encode` accepts.
//!
//! The frame layer checks what a frame says about itself: its length, its
//! stream identifier, its padding, its setting values. Whether a frame is
//! allowed in the connection's current state (a `CONTINUATION` without a
//! `HEADERS` before it, `DATA` on a closed stream) is the connection's job.
//!
//! # Examples
//!
//! ```
//! use h2_net::frame::{self, Decoded, Frame, StreamId};
//!
//! let stream = StreamId::new(1).unwrap();
//! let mut wire = Vec::new();
//! let data = Frame::Data { stream, end_stream: true, data: b"hello", padding: None };
//! frame::encode(&data, frame::DEFAULT_MAX_FRAME_SIZE, &mut wire)?;
//! assert_eq!(wire.len(), 9 + 5);
//!
//! match frame::decode(&wire, frame::DEFAULT_MAX_FRAME_SIZE)? {
//!     Decoded::Frame { frame, len } => {
//!         assert_eq!(frame, data);
//!         assert_eq!(len, wire.len());
//!     }
//!     other => panic!("{other:?}"),
//! }
//! # Ok::<(), h2_net::FrameError>(())
//! ```

mod settings;

use alloc::vec::Vec;
use core::fmt;

pub use settings::{SettingId, SettingValues, Settings, SettingsIter, settings_frame};

use crate::error::{ErrorCode, FrameError};

/// The length of a frame header.
pub const HEADER_LEN: usize = 9;

/// The initial `SETTINGS_MAX_FRAME_SIZE` of every connection, and the
/// smallest value the setting may take.
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;

/// The largest value `SETTINGS_MAX_FRAME_SIZE` may take, 2^24 - 1.
pub const MAX_FRAME_SIZE_LIMIT: u32 = 16_777_215;

/// The largest flow-control window and window increment, 2^31 - 1.
pub const MAX_WINDOW: u32 = 0x7fff_ffff;

/// The 24 bytes a client sends before its first frame (RFC 9113 section
/// 3.4).
pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Frame flags (RFC 9113 section 6). A flag a frame type does not define is
/// ignored when read and never written.
pub mod flags {
    /// `END_STREAM` on `DATA` and `HEADERS`.
    pub const END_STREAM: u8 = 0x1;
    /// `ACK` on `SETTINGS` and `PING`.
    pub const ACK: u8 = 0x1;
    /// `END_HEADERS` on `HEADERS`, `PUSH_PROMISE`, and `CONTINUATION`.
    pub const END_HEADERS: u8 = 0x4;
    /// `PADDED` on `DATA`, `HEADERS`, and `PUSH_PROMISE`.
    pub const PADDED: u8 = 0x8;
    /// `PRIORITY` on `HEADERS`.
    pub const PRIORITY: u8 = 0x20;
}

/// A frame type. Types RFC 9113 and RFC 9218 do not define are kept as
/// they arrived and read as [`Frame::Unknown`].
///
/// # Examples
///
/// ```
/// use h2_net::frame::FrameType;
///
/// assert_eq!(FrameType::HEADERS.value(), 0x1);
/// assert_eq!(FrameType::new(0x1).to_string(), "HEADERS");
/// assert_eq!(FrameType::new(0xfa).to_string(), "frame type 0xfa");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameType(u8);

impl FrameType {
    /// `DATA`.
    pub const DATA: Self = Self(0x0);
    /// `HEADERS`.
    pub const HEADERS: Self = Self(0x1);
    /// `PRIORITY` (its signal is deprecated; the frame is still read).
    pub const PRIORITY: Self = Self(0x2);
    /// `RST_STREAM`.
    pub const RST_STREAM: Self = Self(0x3);
    /// `SETTINGS`.
    pub const SETTINGS: Self = Self(0x4);
    /// `PUSH_PROMISE`.
    pub const PUSH_PROMISE: Self = Self(0x5);
    /// `PING`.
    pub const PING: Self = Self(0x6);
    /// `GOAWAY`.
    pub const GOAWAY: Self = Self(0x7);
    /// `WINDOW_UPDATE`.
    pub const WINDOW_UPDATE: Self = Self(0x8);
    /// `CONTINUATION`.
    pub const CONTINUATION: Self = Self(0x9);
    /// `PRIORITY_UPDATE` (RFC 9218).
    pub const PRIORITY_UPDATE: Self = Self(0x10);

    /// The type with this value.
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// The type's value on the wire.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    /// The type's name, or `None` for a type this crate does not define.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self.0 {
            0x0 => "DATA",
            0x1 => "HEADERS",
            0x2 => "PRIORITY",
            0x3 => "RST_STREAM",
            0x4 => "SETTINGS",
            0x5 => "PUSH_PROMISE",
            0x6 => "PING",
            0x7 => "GOAWAY",
            0x8 => "WINDOW_UPDATE",
            0x9 => "CONTINUATION",
            0x10 => "PRIORITY_UPDATE",
            _ => return None,
        })
    }
}

impl fmt::Debug for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "frame type {:#x}", self.0),
        }
    }
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// A stream identifier: 31 bits, 0 for the connection itself.
///
/// # Examples
///
/// ```
/// use h2_net::frame::StreamId;
///
/// let s = StreamId::new(3).unwrap();
/// assert!(s.is_client_initiated());
/// assert!(StreamId::new(1 << 31).is_none());
/// assert!(StreamId::ZERO.is_zero());
/// ```
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(u32);

impl StreamId {
    /// Stream 0: the connection.
    pub const ZERO: Self = Self(0);
    /// The largest stream identifier, 2^31 - 1.
    pub const MAX: Self = Self(0x7fff_ffff);

    /// The identifier with this value, or `None` above 2^31 - 1.
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        if value > Self::MAX.0 {
            None
        } else {
            Some(Self(value))
        }
    }

    /// The low 31 bits of `value`, the reserved bit dropped as RFC 9113
    /// says a receiver must.
    #[must_use]
    pub const fn masked(value: u32) -> Self {
        Self(value & Self::MAX.0)
    }

    /// The identifier's value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }

    /// Whether this is stream 0, the connection.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Whether a client opens streams with this identifier (odd ones).
    #[must_use]
    pub const fn is_client_initiated(self) -> bool {
        self.0 % 2 == 1
    }
}

impl fmt::Debug for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StreamId({})", self.0)
    }
}

/// A frame header (RFC 9113 section 4.1).
///
/// # Examples
///
/// ```
/// use h2_net::frame::{FrameHeader, FrameType};
///
/// let h = FrameHeader::parse(&[0, 0, 5, 0x0, 0x1, 0x80, 0, 0, 1]).unwrap();
/// assert_eq!(h.len, 5);
/// assert_eq!(h.kind, FrameType::DATA);
/// assert_eq!(h.flags, 0x1);
/// assert_eq!(h.stream.value(), 1); // the reserved bit is dropped
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// The payload length.
    pub len: u32,
    /// The frame type.
    pub kind: FrameType,
    /// The flags, as sent.
    pub flags: u8,
    /// The stream.
    pub stream: StreamId,
}

impl FrameHeader {
    /// Reads a header from the first 9 bytes of `bytes`; `None` when there
    /// are fewer.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let h: &[u8; HEADER_LEN] = bytes.get(..HEADER_LEN)?.try_into().ok()?;
        Some(Self {
            len: u32::from_be_bytes([0, h[0], h[1], h[2]]),
            kind: FrameType(h[3]),
            flags: h[4],
            stream: StreamId::masked(u32::from_be_bytes([h[5], h[6], h[7], h[8]])),
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        let len = self.len.to_be_bytes();
        out.extend_from_slice(&[len[1], len[2], len[3], self.kind.0, self.flags]);
        out.extend_from_slice(&self.stream.0.to_be_bytes());
    }
}

/// A priority signal from RFC 7540 (in `HEADERS` and `PRIORITY` frames).
/// RFC 9113 deprecates the scheme; the fields are read so a stream that
/// depends on itself is refused, and otherwise ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Priority {
    /// The exclusive flag.
    pub exclusive: bool,
    /// The stream this one depends on.
    pub depends_on: StreamId,
    /// The weight minus one, as sent (0 means a weight of 1).
    pub weight: u8,
}

impl Priority {
    fn parse(b: &[u8; 5]) -> Self {
        let dep = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        Self {
            exclusive: dep & 0x8000_0000 != 0,
            depends_on: StreamId::masked(dep),
            weight: b[4],
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        let dep = self.depends_on.0 | if self.exclusive { 0x8000_0000 } else { 0 };
        out.extend_from_slice(&dep.to_be_bytes());
        out.push(self.weight);
    }
}

/// One frame, borrowed from the buffer it was read from.
///
/// Padding is kept as its length (`Some(n)` when the `PADDED` flag was set,
/// with `n` bytes of padding), so a frame's flow-controlled length is
/// [`flow_len`](Self::flow_len) and an encoded frame reads back the same.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    /// `DATA`.
    Data {
        /// The stream.
        stream: StreamId,
        /// The last frame of the stream from this side.
        end_stream: bool,
        /// The data, without padding.
        data: &'a [u8],
        /// The padding length, when the frame is padded.
        padding: Option<u8>,
    },
    /// `HEADERS`.
    Headers {
        /// The stream.
        stream: StreamId,
        /// The last frame of the stream from this side.
        end_stream: bool,
        /// The field block is complete (no `CONTINUATION` follows).
        end_headers: bool,
        /// The deprecated priority signal, when present.
        priority: Option<Priority>,
        /// The field block fragment, without padding.
        fragment: &'a [u8],
        /// The padding length, when the frame is padded.
        padding: Option<u8>,
    },
    /// `PRIORITY` (deprecated by RFC 9113; read and ignored).
    Priority {
        /// The stream.
        stream: StreamId,
        /// The signal.
        priority: Priority,
    },
    /// `RST_STREAM`.
    RstStream {
        /// The stream.
        stream: StreamId,
        /// Why the stream ends.
        code: ErrorCode,
    },
    /// `SETTINGS`.
    Settings(Settings<'a>),
    /// `PUSH_PROMISE` (a server refuses every one it receives).
    PushPromise {
        /// The stream the promise is made on.
        stream: StreamId,
        /// The field block is complete.
        end_headers: bool,
        /// The promised stream.
        promised: StreamId,
        /// The field block fragment, without padding.
        fragment: &'a [u8],
        /// The padding length, when the frame is padded.
        padding: Option<u8>,
    },
    /// `PING`.
    Ping {
        /// An answer to a `PING`.
        ack: bool,
        /// The opaque data an answer echoes.
        payload: [u8; 8],
    },
    /// `GOAWAY`.
    GoAway {
        /// The last stream the sender may have processed.
        last_stream: StreamId,
        /// Why the connection ends.
        code: ErrorCode,
        /// Diagnostic data (opaque; never interpreted).
        debug: &'a [u8],
    },
    /// `WINDOW_UPDATE`.
    WindowUpdate {
        /// The stream, or 0 for the connection window.
        stream: StreamId,
        /// The increment, 1 to 2^31 - 1.
        increment: u32,
    },
    /// `CONTINUATION`.
    Continuation {
        /// The stream.
        stream: StreamId,
        /// The field block is complete.
        end_headers: bool,
        /// The field block fragment.
        fragment: &'a [u8],
    },
    /// `PRIORITY_UPDATE` (RFC 9218).
    PriorityUpdate {
        /// The stream the signal is for.
        prioritized: StreamId,
        /// The Priority Field Value (a Structured Field dictionary), not
        /// interpreted here.
        field: &'a [u8],
    },
    /// A frame of a type this crate does not define. RFC 9113 says to
    /// ignore it, except in the middle of a field block.
    Unknown {
        /// The type.
        kind: FrameType,
        /// The flags, as sent.
        flags: u8,
        /// The stream.
        stream: StreamId,
        /// The payload.
        payload: &'a [u8],
    },
}

impl Frame<'_> {
    /// The frame's type.
    #[must_use]
    pub const fn kind(&self) -> FrameType {
        match self {
            Self::Data { .. } => FrameType::DATA,
            Self::Headers { .. } => FrameType::HEADERS,
            Self::Priority { .. } => FrameType::PRIORITY,
            Self::RstStream { .. } => FrameType::RST_STREAM,
            Self::Settings(_) => FrameType::SETTINGS,
            Self::PushPromise { .. } => FrameType::PUSH_PROMISE,
            Self::Ping { .. } => FrameType::PING,
            Self::GoAway { .. } => FrameType::GOAWAY,
            Self::WindowUpdate { .. } => FrameType::WINDOW_UPDATE,
            Self::Continuation { .. } => FrameType::CONTINUATION,
            Self::PriorityUpdate { .. } => FrameType::PRIORITY_UPDATE,
            Self::Unknown { kind, .. } => *kind,
        }
    }

    /// The stream the frame is on (0 for connection frames).
    #[must_use]
    pub const fn stream(&self) -> StreamId {
        match self {
            Self::Data { stream, .. }
            | Self::Headers { stream, .. }
            | Self::Priority { stream, .. }
            | Self::RstStream { stream, .. }
            | Self::PushPromise { stream, .. }
            | Self::WindowUpdate { stream, .. }
            | Self::Continuation { stream, .. }
            | Self::Unknown { stream, .. } => *stream,
            Self::Settings(_) | Self::Ping { .. } | Self::GoAway { .. } => StreamId::ZERO,
            Self::PriorityUpdate { .. } => StreamId::ZERO,
        }
    }

    /// The bytes the frame counts against flow control: a `DATA` frame's
    /// whole payload, padding included (RFC 9113 section 6.9.1); 0 for
    /// every other frame.
    ///
    /// # Examples
    ///
    /// ```
    /// use h2_net::frame::{Frame, StreamId};
    ///
    /// let f = Frame::Data {
    ///     stream: StreamId::new(1).unwrap(),
    ///     end_stream: false,
    ///     data: b"abc",
    ///     padding: Some(4),
    /// };
    /// assert_eq!(f.flow_len(), 3 + 1 + 4);
    /// ```
    #[must_use]
    pub fn flow_len(&self) -> u32 {
        match self {
            Self::Data { data, padding, .. } => {
                let pad = padding.map_or(0, |p| u32::from(p) + 1);
                u32::try_from(data.len()).map_or(u32::MAX, |d| d.saturating_add(pad))
            }
            _ => 0,
        }
    }

    /// The payload length this frame encodes to.
    fn payload_len(&self) -> usize {
        let padded = |padding: &Option<u8>| padding.map_or(0, |p| usize::from(p) + 1);
        match self {
            Self::Data { data, padding, .. } => data.len() + padded(padding),
            Self::Headers {
                priority,
                fragment,
                padding,
                ..
            } => fragment.len() + padded(padding) + if priority.is_some() { 5 } else { 0 },
            Self::Priority { .. } => 5,
            Self::RstStream { .. } | Self::WindowUpdate { .. } => 4,
            Self::Settings(s) => s.payload().len(),
            Self::PushPromise {
                fragment, padding, ..
            } => fragment.len() + padded(padding) + 4,
            Self::Ping { .. } => 8,
            Self::GoAway { debug, .. } => debug.len() + 8,
            Self::Continuation { fragment, .. } => fragment.len(),
            Self::PriorityUpdate { field, .. } => field.len() + 4,
            Self::Unknown { payload, .. } => payload.len(),
        }
    }
}

/// What [`decode`] found at the front of the buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decoded<'a> {
    /// Not a whole frame yet; `needed` is the length the buffer must reach
    /// (the header, or the header and its payload). The payload length was
    /// already checked against the maximum, so it is safe to buffer.
    Incomplete {
        /// The buffer length that holds the next frame.
        needed: usize,
    },
    /// One frame, `len` bytes long including its header.
    Frame {
        /// The frame.
        frame: Frame<'a>,
        /// The bytes it took.
        len: usize,
    },
    /// A frame RFC 9113 says to refuse as a stream error: the stream is
    /// reset with `error.code()` and the connection goes on after `len`
    /// bytes. (A `PRIORITY` frame of the wrong length, or one naming its own
    /// stream; a `WINDOW_UPDATE` of 0 on a stream.)
    StreamError {
        /// The stream to reset.
        stream: StreamId,
        /// What was wrong.
        error: FrameError,
        /// The bytes the frame took.
        len: usize,
    },
}

/// A refusal and whether it ends the stream or the connection.
enum Fault {
    Stream(FrameError),
    Connection(FrameError),
}

impl From<FrameError> for Fault {
    fn from(e: FrameError) -> Self {
        Self::Connection(e)
    }
}

/// Reads one frame from the front of `input`.
///
/// `max_frame_size` is the receiver's `SETTINGS_MAX_FRAME_SIZE`: a longer
/// frame is refused from its header alone, before its payload is waited for.
///
/// # Errors
///
/// A [`FrameError`] the connection must answer with `GOAWAY` and the
/// error's [`code`](FrameError::code). Refusals RFC 9113 scopes to a stream
/// come back as [`Decoded::StreamError`] instead.
///
/// # Examples
///
/// ```
/// use h2_net::frame::{self, Decoded, Frame};
///
/// let ping = [0, 0, 8, 0x6, 0x1, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
/// assert_eq!(
///     frame::decode(&ping[..4], 16_384)?,
///     Decoded::Incomplete { needed: 9 }
/// );
/// assert_eq!(
///     frame::decode(&ping[..12], 16_384)?,
///     Decoded::Incomplete { needed: 17 }
/// );
/// let Decoded::Frame { frame: Frame::Ping { ack, payload }, len } =
///     frame::decode(&ping, 16_384)?
/// else {
///     panic!()
/// };
/// assert!(ack);
/// assert_eq!(payload, [1, 2, 3, 4, 5, 6, 7, 8]);
/// assert_eq!(len, 17);
/// # Ok::<(), h2_net::FrameError>(())
/// ```
pub fn decode(input: &[u8], max_frame_size: u32) -> Result<Decoded<'_>, FrameError> {
    let Some(header) = FrameHeader::parse(input) else {
        return Ok(Decoded::Incomplete { needed: HEADER_LEN });
    };
    if header.len > max_frame_size {
        return Err(FrameError::TooLarge {
            len: header.len,
            max: max_frame_size,
        });
    }
    // At most 2^24 - 1 + 9, so no overflow on any target.
    let len = HEADER_LEN + header.len as usize;
    let Some(payload) = input.get(HEADER_LEN..len) else {
        return Ok(Decoded::Incomplete { needed: len });
    };
    match parse(header, payload) {
        Ok(frame) => Ok(Decoded::Frame { frame, len }),
        Err(Fault::Stream(error)) => Ok(Decoded::StreamError {
            stream: header.stream,
            error,
            len,
        }),
        Err(Fault::Connection(e)) => Err(e),
    }
}

/// Splits a padded payload into its content and padding length.
fn unpad(kind: FrameType, flags: u8, payload: &[u8]) -> Result<(&[u8], Option<u8>), FrameError> {
    if flags & flags::PADDED == 0 {
        return Ok((payload, None));
    }
    let (&pad, rest) = payload.split_first().ok_or(FrameError::Padding { kind })?;
    let content = rest
        .len()
        .checked_sub(usize::from(pad))
        .ok_or(FrameError::Padding { kind })?;
    Ok((rest.get(..content).unwrap_or_default(), Some(pad)))
}

fn need_stream(h: FrameHeader) -> Result<(), FrameError> {
    if h.stream.is_zero() {
        Err(FrameError::NeedsStream { kind: h.kind })
    } else {
        Ok(())
    }
}

fn need_connection(h: FrameHeader) -> Result<(), FrameError> {
    if h.stream.is_zero() {
        Ok(())
    } else {
        Err(FrameError::NeedsConnection {
            kind: h.kind,
            stream: h.stream,
        })
    }
}

fn bad_length(h: FrameHeader) -> FrameError {
    FrameError::BadLength {
        kind: h.kind,
        len: h.len,
    }
}

fn be32(b: &[u8]) -> u32 {
    let mut a = [0u8; 4];
    if let Some(src) = b.get(..4) {
        a.copy_from_slice(src);
    }
    u32::from_be_bytes(a)
}

fn parse(h: FrameHeader, payload: &[u8]) -> Result<Frame<'_>, Fault> {
    let flag = |f: u8| h.flags & f != 0;
    let frame = match h.kind {
        FrameType::DATA => {
            need_stream(h)?;
            let (data, padding) = unpad(h.kind, h.flags, payload)?;
            Frame::Data {
                stream: h.stream,
                end_stream: flag(flags::END_STREAM),
                data,
                padding,
            }
        }
        FrameType::HEADERS => {
            need_stream(h)?;
            let (rest, padding) = unpad(h.kind, h.flags, payload)?;
            let (priority, fragment) = if flag(flags::PRIORITY) {
                let (p, fragment) = rest.split_first_chunk::<5>().ok_or_else(|| bad_length(h))?;
                let p = Priority::parse(p);
                if p.depends_on == h.stream {
                    // A stream error by RFC 9113 section 5.3.1, but the
                    // field block must still be decoded to keep HPACK in
                    // step; refusing the connection is the simpler safe
                    // answer, and no correct peer sends this.
                    return Err(Fault::Connection(FrameError::SelfDependency {
                        stream: h.stream,
                    }));
                }
                (Some(p), fragment)
            } else {
                (None, rest)
            };
            Frame::Headers {
                stream: h.stream,
                end_stream: flag(flags::END_STREAM),
                end_headers: flag(flags::END_HEADERS),
                priority,
                fragment,
                padding,
            }
        }
        FrameType::PRIORITY => {
            need_stream(h)?;
            let p: &[u8; 5] = payload
                .try_into()
                .map_err(|_| Fault::Stream(bad_length(h)))?;
            let priority = Priority::parse(p);
            if priority.depends_on == h.stream {
                return Err(Fault::Stream(FrameError::SelfDependency {
                    stream: h.stream,
                }));
            }
            Frame::Priority {
                stream: h.stream,
                priority,
            }
        }
        FrameType::RST_STREAM => {
            need_stream(h)?;
            if payload.len() != 4 {
                return Err(bad_length(h).into());
            }
            Frame::RstStream {
                stream: h.stream,
                code: ErrorCode::new(be32(payload)),
            }
        }
        FrameType::SETTINGS => {
            need_connection(h)?;
            if flag(flags::ACK) {
                if !payload.is_empty() {
                    return Err(bad_length(h).into());
                }
                Frame::Settings(Settings::ack())
            } else {
                Frame::Settings(Settings::from_payload(payload)?)
            }
        }
        FrameType::PUSH_PROMISE => {
            need_stream(h)?;
            let (rest, padding) = unpad(h.kind, h.flags, payload)?;
            let (promised, fragment) =
                rest.split_first_chunk::<4>().ok_or_else(|| bad_length(h))?;
            Frame::PushPromise {
                stream: h.stream,
                end_headers: flag(flags::END_HEADERS),
                promised: StreamId::masked(u32::from_be_bytes(*promised)),
                fragment,
                padding,
            }
        }
        FrameType::PING => {
            need_connection(h)?;
            let payload: [u8; 8] = payload.try_into().map_err(|_| bad_length(h))?;
            Frame::Ping {
                ack: flag(flags::ACK),
                payload,
            }
        }
        FrameType::GOAWAY => {
            need_connection(h)?;
            let (head, debug) = payload
                .split_first_chunk::<8>()
                .ok_or_else(|| bad_length(h))?;
            Frame::GoAway {
                last_stream: StreamId::masked(be32(&head[..4])),
                code: ErrorCode::new(be32(&head[4..])),
                debug,
            }
        }
        FrameType::WINDOW_UPDATE => {
            if payload.len() != 4 {
                return Err(bad_length(h).into());
            }
            let increment = be32(payload) & MAX_WINDOW;
            if increment == 0 {
                return Err(if h.stream.is_zero() {
                    Fault::Connection(FrameError::ZeroIncrement)
                } else {
                    Fault::Stream(FrameError::ZeroIncrement)
                });
            }
            Frame::WindowUpdate {
                stream: h.stream,
                increment,
            }
        }
        FrameType::CONTINUATION => {
            need_stream(h)?;
            Frame::Continuation {
                stream: h.stream,
                end_headers: flag(flags::END_HEADERS),
                fragment: payload,
            }
        }
        FrameType::PRIORITY_UPDATE => {
            need_connection(h)?;
            let (id, field) = payload
                .split_first_chunk::<4>()
                .ok_or_else(|| bad_length(h))?;
            let prioritized = StreamId::masked(u32::from_be_bytes(*id));
            if prioritized.is_zero() {
                return Err(FrameError::PriorityUpdateForZero.into());
            }
            Frame::PriorityUpdate { prioritized, field }
        }
        kind => Frame::Unknown {
            kind,
            flags: h.flags,
            stream: h.stream,
            payload,
        },
    };
    Ok(frame)
}

/// Checks a frame against every rule [`decode`] applies, so nothing is
/// written that a peer would refuse.
fn check(frame: &Frame<'_>, max_frame_size: u32) -> Result<(), FrameError> {
    let kind = frame.kind();
    let stream = frame.stream();
    let on_stream = matches!(
        frame,
        Frame::Data { .. }
            | Frame::Headers { .. }
            | Frame::Priority { .. }
            | Frame::RstStream { .. }
            | Frame::PushPromise { .. }
            | Frame::Continuation { .. }
    );
    if on_stream && stream.is_zero() {
        return Err(FrameError::NeedsStream { kind });
    }
    match frame {
        Frame::Headers {
            priority: Some(p), ..
        }
        | Frame::Priority { priority: p, .. }
            if p.depends_on == stream =>
        {
            return Err(FrameError::SelfDependency { stream });
        }
        Frame::WindowUpdate { increment: 0, .. } => return Err(FrameError::ZeroIncrement),
        Frame::WindowUpdate { increment, .. } if *increment > MAX_WINDOW => {
            return Err(FrameError::IncrementTooLarge {
                increment: *increment,
            });
        }
        Frame::Unknown { kind, .. } if kind.name().is_some() => {
            return Err(FrameError::DefinedType { kind: *kind });
        }
        Frame::PriorityUpdate { prioritized, .. } if prioritized.is_zero() => {
            return Err(FrameError::PriorityUpdateForZero);
        }
        _ => {}
    }
    let len = frame.payload_len();
    match u32::try_from(len) {
        Ok(len) if len <= max_frame_size.min(MAX_FRAME_SIZE_LIMIT) => Ok(()),
        _ => Err(FrameError::TooLarge {
            len: u32::try_from(len).unwrap_or(u32::MAX),
            max: max_frame_size.min(MAX_FRAME_SIZE_LIMIT),
        }),
    }
}

/// Appends one frame to `out`. Undefined flags are never set; padding is
/// written as zeros.
///
/// `max_frame_size` is the peer's `SETTINGS_MAX_FRAME_SIZE`. Splitting a
/// field block or a body to fit is the caller's job.
///
/// # Errors
///
/// The [`FrameError`] [`decode`] would report for the frame (a stream frame
/// on stream 0, a payload over `max_frame_size`, a window increment of 0 or
/// over 2^31 - 1, a stream that depends on itself). Nothing is written.
///
/// # Examples
///
/// ```
/// use h2_net::{ErrorCode, frame::{self, Frame, StreamId}};
///
/// let mut out = Vec::new();
/// let rst = Frame::RstStream { stream: StreamId::new(5).unwrap(), code: ErrorCode::CANCEL };
/// frame::encode(&rst, 16_384, &mut out)?;
/// assert_eq!(out, [0, 0, 4, 0x3, 0, 0, 0, 0, 5, 0, 0, 0, 0x8]);
///
/// let bad = Frame::RstStream { stream: StreamId::ZERO, code: ErrorCode::CANCEL };
/// assert!(frame::encode(&bad, 16_384, &mut out).is_err());
/// # Ok::<(), h2_net::FrameError>(())
/// ```
pub fn encode(frame: &Frame<'_>, max_frame_size: u32, out: &mut Vec<u8>) -> Result<(), FrameError> {
    check(frame, max_frame_size)?;
    let mut flags = 0u8;
    let set = |flags: &mut u8, on: bool, f: u8| {
        if on {
            *flags |= f;
        }
    };
    match frame {
        Frame::Data {
            end_stream,
            padding,
            ..
        } => {
            set(&mut flags, *end_stream, flags::END_STREAM);
            set(&mut flags, padding.is_some(), flags::PADDED);
        }
        Frame::Headers {
            end_stream,
            end_headers,
            priority,
            padding,
            ..
        } => {
            set(&mut flags, *end_stream, flags::END_STREAM);
            set(&mut flags, *end_headers, flags::END_HEADERS);
            set(&mut flags, padding.is_some(), flags::PADDED);
            set(&mut flags, priority.is_some(), flags::PRIORITY);
        }
        Frame::Settings(s) => set(&mut flags, s.is_ack(), flags::ACK),
        Frame::PushPromise {
            end_headers,
            padding,
            ..
        } => {
            set(&mut flags, *end_headers, flags::END_HEADERS);
            set(&mut flags, padding.is_some(), flags::PADDED);
        }
        Frame::Ping { ack, .. } => set(&mut flags, *ack, flags::ACK),
        Frame::Continuation { end_headers, .. } => {
            set(&mut flags, *end_headers, flags::END_HEADERS);
        }
        Frame::Unknown { flags: f, .. } => flags = *f,
        _ => {}
    }
    let len = frame.payload_len();
    out.reserve(HEADER_LEN + len);
    FrameHeader {
        // Checked against the maximum above.
        len: u32::try_from(len).unwrap_or(MAX_FRAME_SIZE_LIMIT),
        kind: frame.kind(),
        flags,
        stream: frame.stream(),
    }
    .write(out);
    let pad_start = |out: &mut Vec<u8>, padding: &Option<u8>| {
        if let Some(p) = padding {
            out.push(*p);
        }
    };
    let pad_end = |out: &mut Vec<u8>, padding: &Option<u8>| {
        if let Some(p) = padding {
            out.resize(out.len() + usize::from(*p), 0);
        }
    };
    match frame {
        Frame::Data { data, padding, .. } => {
            pad_start(out, padding);
            out.extend_from_slice(data);
            pad_end(out, padding);
        }
        Frame::Headers {
            priority,
            fragment,
            padding,
            ..
        } => {
            pad_start(out, padding);
            if let Some(p) = priority {
                p.write(out);
            }
            out.extend_from_slice(fragment);
            pad_end(out, padding);
        }
        Frame::Priority { priority, .. } => priority.write(out),
        Frame::RstStream { code, .. } => out.extend_from_slice(&code.value().to_be_bytes()),
        Frame::Settings(s) => out.extend_from_slice(s.payload()),
        Frame::PushPromise {
            promised,
            fragment,
            padding,
            ..
        } => {
            pad_start(out, padding);
            out.extend_from_slice(&promised.0.to_be_bytes());
            out.extend_from_slice(fragment);
            pad_end(out, padding);
        }
        Frame::Ping { payload, .. } => out.extend_from_slice(payload),
        Frame::GoAway {
            last_stream,
            code,
            debug,
        } => {
            out.extend_from_slice(&last_stream.0.to_be_bytes());
            out.extend_from_slice(&code.value().to_be_bytes());
            out.extend_from_slice(debug);
        }
        Frame::WindowUpdate { increment, .. } => out.extend_from_slice(&increment.to_be_bytes()),
        Frame::Continuation { fragment, .. } => out.extend_from_slice(fragment),
        Frame::PriorityUpdate { prioritized, field } => {
            out.extend_from_slice(&prioritized.0.to_be_bytes());
            out.extend_from_slice(field);
        }
        Frame::Unknown { payload, .. } => out.extend_from_slice(payload),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
