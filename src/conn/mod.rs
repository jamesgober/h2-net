//! The server side of an HTTP/2 connection (RFC 9113 sections 3 to 8),
//! without I/O.
//!
//! [`ServerConn::feed`] takes bytes from the socket and [`ServerConn::poll`]
//! turns them into [`Event`]s; answers go in through
//! [`send_headers`](ServerConn::send_headers),
//! [`send_data`](ServerConn::send_data), and
//! [`send_trailers`](ServerConn::send_trailers), and every byte to write
//! comes out of [`output`](ServerConn::output). The connection answers
//! `SETTINGS`, `PING`, and flow control itself.
//!
//! Requests arrive as http-net's [`OwnedRequestHead`]:
//! the same type and accessors an HTTP/1.1 request has, built by writing the
//! HTTP/2 request out as HTTP/1.1 and parsing it with http-net, so the same
//! strictness applies to both.
//!
//! ## Budgets
//!
//! Every attack in the plan's threat table has a budget here, and none
//! needs a clock: each weighs what the peer costs against the work it asked
//! for. See [`Config`] for the defaults and what each one costs.
//!
//! # Examples
//!
//! ```
//! use h2_net::conn::{Config, Event, ServerConn};
//! use h2_net::frame::{self, Frame, StreamId};
//! use h2_net::hpack::{Encoder, HeaderField};
//!
//! // What a client sends: the preface, its SETTINGS, and one request.
//! let mut wire = frame::PREFACE.to_vec();
//! frame::settings_frame(&[], 16_384, &mut wire)?;
//! let mut block = Vec::new();
//! Encoder::new(4096).encode(
//!     [
//!         HeaderField::new(b":method", b"GET"),
//!         HeaderField::new(b":scheme", b"https"),
//!         HeaderField::new(b":authority", b"example.com"),
//!         HeaderField::new(b":path", b"/hello"),
//!     ],
//!     &mut block,
//! );
//! let stream = StreamId::new(1).unwrap();
//! frame::encode(
//!     &Frame::Headers { stream, end_stream: true, end_headers: true, priority: None, fragment: &block, padding: None },
//!     16_384,
//!     &mut wire,
//! )?;
//!
//! let mut conn = ServerConn::new(Config::new());
//! assert_eq!(conn.feed(&wire), wire.len());
//! let mut served = 0;
//! while let Some(event) = conn.poll()? {
//!     if let Event::Request { stream, head, .. } = event {
//!         assert_eq!(head.view().path(), "/hello");
//!         conn.send_headers(stream, 200, &[("content-type", b"text/plain")], false)?;
//!         conn.send_data(stream, b"hi", true)?;
//!         served += 1;
//!     }
//! }
//! assert_eq!(served, 1);
//! let out = conn.output().to_vec(); // write this to the socket
//! conn.consume_output(out.len());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod error;
mod fields;
mod priority;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

pub use error::{ConnError, ConnErrorKind, Malformed, Rejection, Violation};
pub use fields::Scheme;
use http_net::{FieldSpan, Limits, OwnedRequestHead};
pub use priority::PriorityParams;

use crate::error::{ErrorCode, FrameError};
use crate::frame::{self, Decoded, Frame, MAX_WINDOW, PREFACE, SettingId, SettingValues, StreamId};
use crate::hpack::{Decoder, Encoder, HeaderField, HeaderList};

/// The connection's limits and budgets. Every value has a secure default;
/// each setter documents what the value costs.
///
/// # Examples
///
/// ```
/// use h2_net::conn::Config;
///
/// let config = Config::new().max_concurrent_streams(50).stream_window(1 << 20);
/// assert_eq!(config.get_max_concurrent_streams(), 50);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    max_concurrent_streams: u32,
    stream_window: u32,
    connection_window: u32,
    max_frame_size: u32,
    header_table_size: u32,
    max_header_list_size: u32,
    max_header_block: u32,
    max_continuations: u32,
    encoder_table_size: u32,
    reset_floor: u32,
    reset_ratio: u32,
    control_floor: u32,
    control_ratio: u32,
    max_unread_answers: u32,
    max_output: u32,
    auto_release: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    /// The defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_concurrent_streams: 100,
            stream_window: 256 * 1024,
            connection_window: 1024 * 1024,
            max_frame_size: frame::DEFAULT_MAX_FRAME_SIZE,
            header_table_size: 4096,
            max_header_list_size: 16 * 1024,
            max_header_block: 64 * 1024,
            max_continuations: 32,
            encoder_table_size: 4096,
            reset_floor: 200,
            reset_ratio: 4,
            control_floor: 1000,
            control_ratio: 10,
            max_unread_answers: 1000,
            max_output: 256 * 1024,
            auto_release: false,
        }
    }

    /// `SETTINGS_MAX_CONCURRENT_STREAMS` (default 100). A stream holds its
    /// slot until both sides have ended it, so this also caps the requests
    /// the application holds at once. A stream over the cap is reset with
    /// `REFUSED_STREAM` (and counts as a reset).
    #[must_use]
    pub const fn max_concurrent_streams(mut self, n: u32) -> Self {
        self.max_concurrent_streams = n;
        self
    }

    /// The configured stream cap.
    #[must_use]
    pub const fn get_max_concurrent_streams(&self) -> u32 {
        self.max_concurrent_streams
    }

    /// `SETTINGS_INITIAL_WINDOW_SIZE` (default 256 KiB, at least 65,535 and
    /// at most 2^31 - 1): how much of a request body the peer may send
    /// before the application [releases](ServerConn::release) it. Memory:
    /// what the application buffers, up to this per stream.
    #[must_use]
    pub const fn stream_window(mut self, n: u32) -> Self {
        self.stream_window = clamp(n, 65_535, MAX_WINDOW);
        self
    }

    /// The connection window (default 1 MiB, at least 65,535): the request
    /// body bytes, all streams together, the peer may send before they are
    /// released.
    #[must_use]
    pub const fn connection_window(mut self, n: u32) -> Self {
        self.connection_window = clamp(n, 65_535, MAX_WINDOW);
        self
    }

    /// `SETTINGS_MAX_FRAME_SIZE` (default 16,384, the smallest allowed).
    /// The input buffer holds two frames of this size.
    #[must_use]
    pub const fn max_frame_size(mut self, n: u32) -> Self {
        self.max_frame_size = clamp(
            n,
            frame::DEFAULT_MAX_FRAME_SIZE,
            frame::MAX_FRAME_SIZE_LIMIT,
        );
        self
    }

    /// `SETTINGS_HEADER_TABLE_SIZE` (default 4096): the HPACK table the
    /// peer may make this side keep. Memory: up to twice this.
    #[must_use]
    pub const fn header_table_size(mut self, n: u32) -> Self {
        self.header_table_size = n;
        self
    }

    /// `SETTINGS_MAX_HEADER_LIST_SIZE` (default 16 KiB), in RFC 9113's
    /// terms (each field's name and value plus 32). A request over it is
    /// answered `431` and the connection goes on.
    #[must_use]
    pub const fn max_header_list_size(mut self, n: u32) -> Self {
        self.max_header_list_size = n;
        self
    }

    /// The bytes one field block may take on the wire, `HEADERS` and every
    /// `CONTINUATION` together (default 64 KiB). Over it, the connection
    /// ends (`ENHANCE_YOUR_CALM`): the bytes are refused before they are
    /// buffered.
    #[must_use]
    pub const fn max_header_block(mut self, n: u32) -> Self {
        self.max_header_block = n;
        self
    }

    /// The `CONTINUATION` frames one field block may take (default 32;
    /// browsers send none or one). Counts empty ones, which cost the
    /// receiver work and no bytes.
    #[must_use]
    pub const fn max_continuations(mut self, n: u32) -> Self {
        self.max_continuations = n;
        self
    }

    /// The largest HPACK table this side's encoder keeps (default 4096).
    #[must_use]
    pub const fn encoder_table_size(mut self, n: u32) -> Self {
        self.encoder_table_size = n;
        self
    }

    /// The reset budget (default 200 and 4): the connection ends once
    /// streams reset (by the peer before their response completed, or by
    /// this side for the peer's errors) exceed `floor` and also exceed
    /// `ratio` times the responses completed. A browser that cancels a
    /// navigation now and then stays far below; a rapid-reset client
    /// crosses it after `floor` streams. Cost: two counters.
    #[must_use]
    pub const fn reset_budget(mut self, floor: u32, ratio: u32) -> Self {
        self.reset_floor = floor;
        self.reset_ratio = ratio;
        self
    }

    /// The control frame budget (default 1000 and 10): `SETTINGS` after
    /// the first, `PING`, `PRIORITY`, `PRIORITY_UPDATE`, empty `DATA`
    /// without `END_STREAM`, frames of unknown type, and frames for closed
    /// streams. The connection ends once they exceed `floor` and also
    /// `ratio` times the requests and `DATA` frames received. Cost: two
    /// counters.
    #[must_use]
    pub const fn control_budget(mut self, floor: u32, ratio: u32) -> Self {
        self.control_floor = floor;
        self.control_ratio = ratio;
        self
    }

    /// Answers (`PING` and `SETTINGS` acknowledgments, resets) that may
    /// wait in the output unread (default 1000). A peer that sends `PING`
    /// and never reads would otherwise grow the output without bound.
    #[must_use]
    pub const fn max_unread_answers(mut self, n: u32) -> Self {
        self.max_unread_answers = n;
        self
    }

    /// The output [`send_data`](ServerConn::send_data) fills up to (default
    /// 256 KiB): a peer that opens a 2 GiB window still gets at most this
    /// much buffered. Headers and answers are not held back by it.
    #[must_use]
    pub const fn max_output(mut self, n: u32) -> Self {
        self.max_output = n;
        self
    }

    /// Releases a request body's bytes as soon as they are handed out in
    /// [`Event::Data`] (default off: the application calls
    /// [`release`](ServerConn::release) once it has dealt with them, which
    /// is what holds back a peer that sends faster than the application
    /// reads).
    #[must_use]
    pub const fn auto_release(mut self, on: bool) -> Self {
        self.auto_release = on;
        self
    }
}

const fn clamp(n: u32, lo: u32, hi: u32) -> u32 {
    if n < lo {
        lo
    } else if n > hi {
        hi
    } else {
        n
    }
}

/// What [`ServerConn::poll`] reports.
#[non_exhaustive]
#[derive(Debug)]
pub enum Event<'a> {
    /// A request head. `end_stream` means no body follows.
    Request {
        /// The stream to answer on.
        stream: StreamId,
        /// The head, as http-net's type. Its framing says whether a body
        /// follows: none, a `content-length`, or chunked (a body of unknown
        /// length; HTTP/2 itself has no chunked encoding).
        head: OwnedRequestHead,
        /// `:scheme`, or `None` for `CONNECT`.
        scheme: Option<Scheme>,
        /// The request's priority (RFC 9218): from a `PRIORITY_UPDATE`
        /// that arrived before the request, or else its `priority` field,
        /// or else the defaults.
        priority: PriorityParams,
        /// No body follows.
        end_stream: bool,
    },
    /// The peer changed a request's priority (`PRIORITY_UPDATE`, RFC
    /// 9218). The scheduling is the driver's; the connection only reports.
    Priority {
        /// The stream.
        stream: StreamId,
        /// The new priority, complete (omitted members are defaults).
        priority: PriorityParams,
    },
    /// Part of a request body. Call [`ServerConn::release`] with its length
    /// once it has been dealt with (unless [`Config::auto_release`] is on).
    Data {
        /// The stream.
        stream: StreamId,
        /// The bytes (borrowed until the next call).
        data: &'a [u8],
        /// The body is complete.
        end_stream: bool,
    },
    /// A request's trailers; the body is complete.
    Trailers {
        /// The stream.
        stream: StreamId,
        /// The fields.
        fields: &'a HeaderList,
    },
    /// A stream ended before its exchange completed: the peer reset it
    /// (`remote`), or this side did because of the peer's error. Stop
    /// working on it.
    Reset {
        /// The stream.
        stream: StreamId,
        /// The code sent or received.
        code: ErrorCode,
        /// Whether the peer sent the reset.
        remote: bool,
    },
    /// A request the connection answered on its own (reset, or `431`),
    /// before any [`Event::Request`]. For logging and connection gates.
    Rejected {
        /// The stream.
        stream: StreamId,
        /// Why.
        reason: Rejection,
    },
    /// A stream that [`send_data`](ServerConn::send_data) could not finish
    /// has window again.
    Writable {
        /// The stream.
        stream: StreamId,
    },
    /// The peer sent `GOAWAY`: it opens no more streams. On a client, every
    /// stream above the one it names was not processed, and is reported as
    /// [`Event::Reset`] with `REFUSED_STREAM` (safe to retry).
    GoAway {
        /// The code it sent.
        code: ErrorCode,
    },
    /// Client: a final response head. `fields` holds every field,
    /// `:status` first. `end_stream` means no body follows.
    Response {
        /// The stream.
        stream: StreamId,
        /// The status.
        status: u16,
        /// The fields, checked by RFC 9113 section 8.
        fields: &'a HeaderList,
        /// No body follows.
        end_stream: bool,
    },
    /// Client: an informational (`1xx`) response head; the final one follows.
    Informational {
        /// The stream.
        stream: StreamId,
        /// The status, `100` to `199` (never `101`).
        status: u16,
        /// The fields, `:status` first.
        fields: &'a HeaderList,
    },
}

/// A call the connection refused. Nothing was written.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// No open stream with this identifier (never opened, reset, or done).
    UnknownStream,
    /// The response head was already sent, or not yet.
    OutOfOrder,
    /// The stream's response already ended.
    Ended,
    /// A status outside `100..=599`, or `101` (HTTP/2 has no upgrade).
    Status,
    /// A field name or value HTTP/2 cannot carry.
    Field(Malformed),
    /// A body on a response that has none (`HEAD`, `204`, `304`), or more
    /// or less body than its `content-length`.
    Body,
    /// The connection is closed.
    Closed,
    /// Client: the peer's `SETTINGS_MAX_CONCURRENT_STREAMS` is reached; send
    /// once a stream ends.
    Busy,
    /// Client: the connection is going away (a `GOAWAY` either way); open a
    /// new one.
    GoingAway,
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::UnknownStream => "no such open stream",
            Self::OutOfOrder => "response parts out of order",
            Self::Ended => "the response already ended",
            Self::Status => "status not allowed in HTTP/2",
            Self::Field(_) => "field not allowed in HTTP/2",
            Self::Body => "body not allowed or of the wrong length",
            Self::Closed => "the connection is closed",
            Self::Busy => "the peer's stream limit is reached",
            Self::GoingAway => "the connection is going away",
        })
    }
}

impl core::error::Error for SendError {}

#[derive(Debug)]
struct Stream {
    /// The peer sent `END_STREAM`.
    peer_ended: bool,
    /// This side sent `END_STREAM`.
    local_ended: bool,
    /// The final response head was sent.
    responded: bool,
    /// The response has no body (a `HEAD` request, `204`, `304`).
    bodiless: bool,
    /// The request was `HEAD`.
    is_head: bool,
    /// The request's `content-length` and the body bytes received.
    content_length: Option<u64>,
    received: u64,
    /// The response's `content-length` and the body bytes sent.
    send_length: Option<u64>,
    sent: u64,
    /// Body bytes the peer may still send, and bytes handed out not yet
    /// released.
    recv_window: i64,
    held: u32,
    unreleased: u32,
    send_window: i64,
    wants_write: bool,
    priority: PriorityParams,
    /// Client: the final status received; `None` until the response head.
    response_status: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Waiting for the 24-byte preface.
    Preface,
    /// Waiting for the client's first `SETTINGS`.
    FirstSettings,
    Open,
    /// `GOAWAY` sent; `last` is the highest stream still served.
    Draining {
        last: u32,
        ping_acked: bool,
    },
    Closed,
}

/// A field block being collected across `CONTINUATION` frames.
#[derive(Debug)]
struct Block {
    stream: StreamId,
    end_stream: bool,
    continuations: u32,
}

/// What one frame produced.
enum Step {
    Nothing,
    Data {
        stream: StreamId,
        at: usize,
        len: usize,
        end_stream: bool,
    },
    Trailers(StreamId),
    Response {
        stream: StreamId,
        status: u16,
        end_stream: bool,
    },
    Informational {
        stream: StreamId,
        status: u16,
    },
}

const SHUTDOWN_PING: [u8; 8] = *b"h2-net\x00\x01";

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Server {}
    impl Sealed for super::Client {}
}

/// Which side of a connection this is: [`Server`] or [`Client`]. Sealed.
pub trait Role: sealed::Sealed + core::fmt::Debug + Send + Sync + 'static {
    /// Whether this side opened the connection.
    const CLIENT: bool;
}

/// The server side: it accepts streams.
#[derive(Debug)]
pub enum Server {}

/// The client side: it opens streams.
#[derive(Debug)]
pub enum Client {}

impl Role for Server {
    const CLIENT: bool = false;
}

impl Role for Client {
    const CLIENT: bool = true;
}

/// The server side of a connection: see [`Connection`].
pub type ServerConn = Connection<Server>;

/// The client side of a connection: see [`Connection`].
pub type ClientConn = Connection<Client>;

/// One HTTP/2 connection, [`ServerConn`] or [`ClientConn`]. Both sides share
/// the protocol (settings, `PING`, flow control, field blocks, `GOAWAY`) and
/// every budget; the server accepts requests and answers them with
/// [`send_headers`](Connection::send_headers), the client opens them with
/// [`send_request`](Connection::send_request).
#[derive(Debug)]
pub struct Connection<R: Role> {
    config: Config,
    state: State,
    input: Vec<u8>,
    start: usize,
    /// Bytes of the frame behind the last `Data` event, consumed on the
    /// next call.
    pending_consume: usize,
    out: Vec<u8>,
    unread_answers: u32,
    decoder: Decoder,
    encoder: Encoder,
    list: HeaderList,
    block: Vec<u8>,
    collecting: Option<Block>,
    synth: Vec<u8>,
    slots: Vec<FieldSpan>,
    limits: Limits,
    scratch_fields: Vec<u8>,
    streams: BTreeMap<u32, Stream>,
    /// Streams this side reset lately, whose late frames are ignored.
    recent_resets: VecDeque<u32>,
    last_peer_stream: u32,
    peer: SettingValues,
    settings_unacked: u32,
    settings_seen: u32,
    recv_window: i64,
    unreleased: u32,
    send_window: i64,
    resets: u32,
    completed: u32,
    control: u32,
    work: u32,
    peer_goaway: bool,
    events: VecDeque<Queued>,
    error: Option<ConnError>,
    /// `PRIORITY_UPDATE`s for streams not yet opened (at most the stream
    /// cap of them).
    pending_priority: BTreeMap<u32, PriorityParams>,
    /// The client's next stream identifier (odd, from 1).
    next_stream: u32,
    role: core::marker::PhantomData<R>,
}

#[derive(Debug)]
enum Queued {
    Request {
        stream: StreamId,
        head: OwnedRequestHead,
        scheme: Option<Scheme>,
        priority: PriorityParams,
        end_stream: bool,
    },
    Priority(StreamId, PriorityParams),
    Reset {
        stream: StreamId,
        code: ErrorCode,
        remote: bool,
    },
    Rejected {
        stream: StreamId,
        reason: Rejection,
    },
    Writable(StreamId),
    GoAway(ErrorCode),
}

type Fail = ConnErrorKind;

impl<R: Role> Connection<R> {
    /// A connection that has accepted a socket (after TLS and ALPN `h2`,
    /// or behind a trusted proxy for cleartext). Its `SETTINGS` are already
    /// in [`output`](Self::output): the server preface needs no wait.
    fn with_config(config: Config) -> Self {
        let mut conn = Self {
            config,
            state: if R::CLIENT {
                State::FirstSettings
            } else {
                State::Preface
            },
            input: Vec::new(),
            start: 0,
            pending_consume: 0,
            out: Vec::new(),
            unread_answers: 0,
            // The peer may use 4096 until it has our SETTINGS; a larger
            // table is harmless to allow at once, a smaller one waits for
            // the acknowledgment.
            decoder: Decoder::new((config.header_table_size as usize).max(4096)),
            encoder: Encoder::new(config.encoder_table_size as usize),
            list: HeaderList::new(config.max_header_list_size as usize),
            block: Vec::new(),
            collecting: None,
            synth: Vec::new(),
            slots: Vec::new(),
            limits: Limits::new()
                .with_max_start_line(config.max_header_list_size as usize + 64)
                .with_max_header_bytes(config.max_header_list_size as usize + 64)
                .with_max_field_line(config.max_header_list_size as usize + 64)
                .with_max_headers(config.max_header_list_size as usize / 32 + 2)
                .with_max_body(u64::MAX),
            scratch_fields: Vec::new(),
            streams: BTreeMap::new(),
            recent_resets: VecDeque::new(),
            last_peer_stream: 0,
            peer: SettingValues::default(),
            settings_unacked: 0,
            settings_seen: 0,
            recv_window: 65_535,
            unreleased: 0,
            send_window: 65_535,
            resets: 0,
            completed: 0,
            control: 0,
            work: 0,
            peer_goaway: false,
            events: VecDeque::new(),
            error: None,
            pending_priority: BTreeMap::new(),
            next_stream: 1,
            role: core::marker::PhantomData,
        };
        conn.send_preface();
        conn
    }

    fn send_preface(&mut self) {
        let c = self.config;
        let mut params = Vec::with_capacity(6);
        if R::CLIENT {
            // The client speaks first, and refuses server push.
            self.out.extend_from_slice(PREFACE);
            params.push((SettingId::ENABLE_PUSH, 0));
        } else {
            params.push((SettingId::MAX_CONCURRENT_STREAMS, c.max_concurrent_streams));
        }
        params.push((SettingId::MAX_HEADER_LIST_SIZE, c.max_header_list_size));
        params.push((SettingId::NO_RFC7540_PRIORITIES, 1));
        if c.stream_window != 65_535 {
            params.push((SettingId::INITIAL_WINDOW_SIZE, c.stream_window));
        }
        if c.max_frame_size != frame::DEFAULT_MAX_FRAME_SIZE {
            params.push((SettingId::MAX_FRAME_SIZE, c.max_frame_size));
        }
        if c.header_table_size != 4096 {
            params.push((SettingId::HEADER_TABLE_SIZE, c.header_table_size));
        }
        // Every value was checked by the setters.
        let _ = frame::settings_frame(&params, frame::DEFAULT_MAX_FRAME_SIZE, &mut self.out);
        self.settings_unacked += 1;
        if c.connection_window > 65_535 {
            self.write_frame(&Frame::WindowUpdate {
                stream: StreamId::ZERO,
                increment: c.connection_window - 65_535,
            });
            self.recv_window = i64::from(c.connection_window);
        }
    }

    /// Copies what fits of `bytes` into the input buffer; returns the count
    /// taken. The buffer holds two frames of the largest size this side
    /// allows; call [`poll`](Self::poll) to make room.
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.state == State::Closed {
            return 0;
        }
        self.apply_consume();
        if self.start > 0 {
            let _ = self.input.drain(..self.start);
            self.start = 0;
        }
        let cap = 2 * (frame::HEADER_LEN + self.config.max_frame_size as usize);
        let room = cap.saturating_sub(self.input.len());
        let n = room.min(bytes.len());
        self.input
            .extend_from_slice(bytes.get(..n).unwrap_or_default());
        n
    }

    /// The bytes waiting to be written to the socket.
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.out
    }

    /// Marks the first `n` bytes of [`output`](Self::output) as written.
    pub fn consume_output(&mut self, n: usize) {
        let n = n.min(self.out.len());
        let _ = self.out.drain(..n);
        if self.out.is_empty() {
            self.unread_answers = 0;
        }
    }

    /// Whether the connection is finished: closed, or drained with nothing
    /// left to serve. Write out what [`output`](Self::output) holds, then
    /// close the socket.
    #[must_use]
    pub fn is_done(&self) -> bool {
        match self.state {
            State::Closed => true,
            State::Draining { ping_acked, .. } => ping_acked && self.streams.is_empty(),
            _ => self.peer_goaway && self.streams.is_empty(),
        }
    }

    /// Whether the peer has acknowledged this side's `SETTINGS`. A driver
    /// that wants `SETTINGS_TIMEOUT` closes the connection when this stays
    /// false past its deadline.
    #[must_use]
    pub const fn settings_acked(&self) -> bool {
        self.settings_unacked == 0
    }

    /// The number of open streams.
    #[must_use]
    pub fn open_streams(&self) -> usize {
        self.streams.len()
    }

    /// The next event, or `None` when more input is needed (or nothing is
    /// left to do).
    ///
    /// # Errors
    ///
    /// A [`ConnError`] once the connection has failed; a `GOAWAY` is in
    /// the output. Every later call returns the same error.
    pub fn poll(&mut self) -> Result<Option<Event<'_>>, ConnError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        self.apply_consume();
        if let Some(q) = self.events.pop_front() {
            return Ok(Some(self.queued(q)));
        }
        loop {
            let step = match self.step() {
                Ok(Some(step)) => step,
                Ok(None) => return Ok(None),
                Err(kind) => return Err(self.fail(kind)),
            };
            // A step that hands out borrowed bytes returns them now; events
            // it queued (none do today) wait for the next call, so nothing
            // is dropped.
            match step {
                Step::Data {
                    stream,
                    at,
                    len,
                    end_stream,
                } => {
                    let data = self.input.get(at..at + len).unwrap_or_default();
                    return Ok(Some(Event::Data {
                        stream,
                        data,
                        end_stream,
                    }));
                }
                Step::Trailers(stream) => {
                    return Ok(Some(Event::Trailers {
                        stream,
                        fields: &self.list,
                    }));
                }
                Step::Response {
                    stream,
                    status,
                    end_stream,
                } => {
                    return Ok(Some(Event::Response {
                        stream,
                        status,
                        fields: &self.list,
                        end_stream,
                    }));
                }
                Step::Informational { stream, status } => {
                    return Ok(Some(Event::Informational {
                        stream,
                        status,
                        fields: &self.list,
                    }));
                }
                Step::Nothing => {}
            }
            if let Some(q) = self.events.pop_front() {
                return Ok(Some(self.queued(q)));
            }
        }
    }

    fn queued(&self, q: Queued) -> Event<'_> {
        match q {
            Queued::Request {
                stream,
                head,
                scheme,
                priority,
                end_stream,
            } => Event::Request {
                stream,
                head,
                scheme,
                priority,
                end_stream,
            },
            Queued::Priority(stream, priority) => Event::Priority { stream, priority },
            Queued::Reset {
                stream,
                code,
                remote,
            } => Event::Reset {
                stream,
                code,
                remote,
            },
            Queued::Rejected { stream, reason } => Event::Rejected { stream, reason },
            Queued::Writable(stream) => Event::Writable { stream },
            Queued::GoAway(code) => Event::GoAway { code },
        }
    }

    fn apply_consume(&mut self) {
        self.start += core::mem::take(&mut self.pending_consume);
    }

    /// Ends the connection with `kind`: a `GOAWAY` goes out and every later
    /// call reports the error.
    fn fail(&mut self, kind: ConnErrorKind) -> ConnError {
        let error = ConnError::new(kind);
        if self.state != State::Closed {
            self.write_frame(&Frame::GoAway {
                last_stream: StreamId::masked(self.last_peer_stream),
                code: error.code(),
                debug: b"",
            });
        }
        self.state = State::Closed;
        self.error = Some(error);
        self.streams.clear();
        self.events.clear();
        error
    }

    /// Ends the connection now with `code` (for a driver's timeouts, or
    /// `INTERNAL_ERROR`). A `GOAWAY` goes out; later calls report
    /// [`ConnErrorKind::Closed`].
    pub fn close(&mut self, code: ErrorCode) {
        if self.error.is_none() {
            let _ = self.fail(ConnErrorKind::Closed { code });
        }
    }

    /// Starts a graceful shutdown (RFC 9113 section 6.8): a `GOAWAY` that
    /// still admits every stream, and a `PING`; once the `PING` is
    /// answered, a second `GOAWAY` names the last stream served and later
    /// ones are ignored. [`is_done`](Self::is_done) turns true when the
    /// streams in flight have finished.
    pub fn shutdown(&mut self) {
        if matches!(self.state, State::Closed | State::Draining { .. }) {
            return;
        }
        if R::CLIENT {
            // A client accepts no streams, so one GOAWAY says it all; its own
            // streams finish.
            self.write_frame(&Frame::GoAway {
                last_stream: StreamId::ZERO,
                code: ErrorCode::NO_ERROR,
                debug: b"",
            });
            self.state = State::Draining {
                last: 0,
                ping_acked: true,
            };
            return;
        }
        self.write_frame(&Frame::GoAway {
            last_stream: StreamId::MAX,
            code: ErrorCode::NO_ERROR,
            debug: b"",
        });
        self.write_frame(&Frame::Ping {
            ack: false,
            payload: SHUTDOWN_PING,
        });
        self.state = State::Draining {
            last: StreamId::MAX.value(),
            ping_acked: false,
        };
    }

    /// Whether `id` names a stream that was never opened.
    fn is_idle(&self, id: u32) -> bool {
        if R::CLIENT {
            id % 2 == 0 || id >= self.next_stream
        } else {
            id > self.last_peer_stream
        }
    }

    fn write_frame(&mut self, f: &Frame<'_>) {
        // Every frame written here is well formed and under the peer's
        // maximum (16,384 at least); an error would be a bug, and writing
        // nothing is the safe outcome.
        let _ = frame::encode(f, self.peer.max_frame_size, &mut self.out);
    }

    /// An answer to the peer (an acknowledgment or a reset), counted
    /// against the unread-answer budget.
    fn answer(&mut self, f: &Frame<'_>) -> Result<(), Fail> {
        self.write_frame(f);
        self.unread_answers += 1;
        if self.unread_answers > self.config.max_unread_answers {
            return Err(ConnErrorKind::OutputBacklog);
        }
        Ok(())
    }

    fn charge_control(&mut self) -> Result<(), Fail> {
        self.control = self.control.saturating_add(1);
        let allowed = u64::from(self.config.control_ratio) * (u64::from(self.work) + 1);
        if self.control > self.config.control_floor && u64::from(self.control) > allowed {
            return Err(ConnErrorKind::ControlFlood);
        }
        Ok(())
    }

    fn charge_reset(&mut self) -> Result<(), Fail> {
        self.resets = self.resets.saturating_add(1);
        let allowed = u64::from(self.config.reset_ratio) * (u64::from(self.completed) + 1);
        if self.resets > self.config.reset_floor && u64::from(self.resets) > allowed {
            return Err(ConnErrorKind::RapidReset);
        }
        Ok(())
    }

    fn remember_reset(&mut self, stream: u32) {
        let cap = (self.config.max_concurrent_streams as usize * 2).max(256);
        if self.recent_resets.len() >= cap {
            let _ = self.recent_resets.pop_front();
        }
        self.recent_resets.push_back(stream);
    }

    /// Resets a stream for the peer's error, charging the reset budget.
    fn reset_for_peer(
        &mut self,
        stream: StreamId,
        code: ErrorCode,
        announce: bool,
    ) -> Result<(), Fail> {
        self.answer(&Frame::RstStream { stream, code })?;
        if let Some(s) = self.streams.remove(&stream.value()) {
            self.release_connection(s.held);
            if announce {
                self.events.push_back(Queued::Reset {
                    stream,
                    code,
                    remote: false,
                });
            }
        }
        self.remember_reset(stream.value());
        self.charge_reset()
    }

    /// Reads and handles one frame; `None` when the input holds no whole
    /// frame.
    fn step(&mut self) -> Result<Option<Step>, Fail> {
        match self.state {
            State::Closed => return Ok(None),
            State::Preface => {
                let have = self.input.get(self.start..).unwrap_or_default();
                return match http_net::is_h2_preface(have) {
                    None => Ok(None),
                    Some(false) => Err(ConnErrorKind::Preface),
                    Some(true) => {
                        self.start += PREFACE.len();
                        self.state = State::FirstSettings;
                        Ok(Some(Step::Nothing))
                    }
                };
            }
            _ => {}
        }
        // The frame borrows the input while the handler changes the rest of
        // the connection; the handler never touches the input itself.
        let input = core::mem::take(&mut self.input);
        let result = self.frame_step(&input);
        self.input = input;
        result
    }

    fn frame_step(&mut self, input: &[u8]) -> Result<Option<Step>, Fail> {
        let rest = input.get(self.start..).unwrap_or_default();
        let (frame, len) = match frame::decode(rest, self.config.max_frame_size) {
            Ok(Decoded::Incomplete { .. }) => return Ok(None),
            Ok(Decoded::Frame { frame, len }) => (frame, len),
            Ok(Decoded::StreamError { stream, error, len }) => {
                if self.collecting.is_some() {
                    return Err(ConnErrorKind::Protocol(Violation::ContinuationExpected));
                }
                self.start += len;
                if self.is_idle(stream.value()) && error == FrameError::ZeroIncrement {
                    return Err(ConnErrorKind::Protocol(Violation::IdleStream {
                        kind: frame::FrameType::WINDOW_UPDATE,
                        stream,
                    }));
                }
                self.reset_for_peer(stream, error.code(), true)?;
                return Ok(Some(Step::Nothing));
            }
            Err(e) => return Err(ConnErrorKind::Frame(e)),
        };
        let at = self.start;
        let step = self.handle(frame, at, len)?;
        if matches!(step, Step::Data { .. }) {
            self.pending_consume = len;
        } else {
            self.start += len;
        }
        Ok(Some(step))
    }

    #[allow(clippy::too_many_lines)]
    fn handle(&mut self, f: Frame<'_>, at: usize, len: usize) -> Result<Step, Fail> {
        if self.state == State::FirstSettings {
            match f {
                Frame::Settings(s) if !s.is_ack() => self.state = State::Open,
                _ => return Err(ConnErrorKind::Protocol(Violation::SettingsFirst)),
            }
        }
        if let Some(b) = &self.collecting {
            match f {
                Frame::Continuation { stream, .. } if stream == b.stream => {}
                _ => return Err(ConnErrorKind::Protocol(Violation::ContinuationExpected)),
            }
        }
        match f {
            Frame::Data {
                stream,
                end_stream,
                data,
                padding,
            } => {
                let flow = i64::from(f.flow_len());
                self.recv_window -= flow;
                if self.recv_window < 0 {
                    return Err(ConnErrorKind::FlowControl);
                }
                let pad = u32::try_from(flow)
                    .unwrap_or(0)
                    .saturating_sub(u32::try_from(data.len()).unwrap_or(u32::MAX));
                let Some(s) = self.streams.get_mut(&stream.value()) else {
                    // Not open: the whole frame goes back to the window.
                    self.release_connection(u32::try_from(flow).unwrap_or(0));
                    if self.recent_resets.contains(&stream.value()) {
                        self.charge_control()?;
                        return Ok(Step::Nothing);
                    }
                    if self.is_idle(stream.value()) {
                        return Err(ConnErrorKind::Protocol(Violation::IdleStream {
                            kind: frame::FrameType::DATA,
                            stream,
                        }));
                    }
                    return Err(ConnErrorKind::StreamClosed { stream });
                };
                if s.peer_ended {
                    self.release_connection(u32::try_from(flow).unwrap_or(0));
                    self.reset_for_peer(stream, ErrorCode::STREAM_CLOSED, true)?;
                    return Ok(Step::Nothing);
                }
                // A response body before its head, or on a response that has
                // none (to HEAD, or 204 or 304), is malformed.
                if R::CLIENT && (s.response_status.is_none() || (s.bodiless && !data.is_empty())) {
                    self.release_connection(u32::try_from(flow).unwrap_or(0));
                    self.reset_for_peer(stream, ErrorCode::PROTOCOL_ERROR, true)?;
                    return Ok(Step::Nothing);
                }
                s.recv_window -= flow;
                if s.recv_window < 0 {
                    return Err(ConnErrorKind::FlowControl);
                }
                s.received += data.len() as u64;
                s.peer_ended = end_stream;
                let length_ok = match s.content_length {
                    Some(cl) => s.received <= cl && (!end_stream || s.received == cl),
                    None => true,
                };
                if !length_ok {
                    self.release_connection(u32::try_from(flow).unwrap_or(0));
                    self.reset_for_peer(stream, ErrorCode::PROTOCOL_ERROR, true)?;
                    return Ok(Step::Nothing);
                }
                let data_len = u32::try_from(data.len()).unwrap_or(u32::MAX);
                s.held = s.held.saturating_add(data_len);
                // Padding is never handed out, so it goes back at once.
                if pad > 0 {
                    self.stream_released(stream, pad);
                    self.release_connection(pad);
                }
                if data.is_empty() && !end_stream {
                    self.charge_control()?;
                    return Ok(Step::Nothing);
                }
                self.work = self.work.saturating_add(1);
                let payload_at = at + frame::HEADER_LEN + usize::from(padding.is_some());
                if self.config.auto_release {
                    self.release(stream, data.len());
                }
                self.close_if_done(stream);
                Ok(Step::Data {
                    stream,
                    at: payload_at,
                    len: data.len(),
                    end_stream,
                })
            }
            Frame::Headers {
                stream,
                end_stream,
                end_headers,
                fragment,
                ..
            } => {
                self.block.clear();
                self.append_block(fragment)?;
                if end_headers {
                    self.field_block(stream, end_stream)
                } else {
                    self.collecting = Some(Block {
                        stream,
                        end_stream,
                        continuations: 0,
                    });
                    Ok(Step::Nothing)
                }
            }
            Frame::Continuation {
                end_headers,
                fragment,
                ..
            } => {
                let Some(b) = self.collecting.as_mut() else {
                    return Err(ConnErrorKind::Protocol(Violation::UnexpectedContinuation));
                };
                b.continuations += 1;
                if b.continuations > self.config.max_continuations {
                    return Err(ConnErrorKind::ContinuationFlood);
                }
                self.append_block(fragment)?;
                if end_headers {
                    let Some(b) = self.collecting.take() else {
                        return Ok(Step::Nothing);
                    };
                    self.field_block(b.stream, b.end_stream)
                } else {
                    Ok(Step::Nothing)
                }
            }
            Frame::PriorityUpdate { prioritized, field } => {
                self.charge_control()?;
                if R::CLIENT {
                    // RFC 9218 section 7.1: only clients send it.
                    return Err(ConnErrorKind::Protocol(Violation::PriorityUpdate));
                }
                if !prioritized.is_client_initiated() {
                    // A server never pushes, so an even stream is wrong
                    // (RFC 9218 section 7.1).
                    return Err(ConnErrorKind::Protocol(Violation::BadStreamId {
                        stream: prioritized,
                    }));
                }
                let Some(priority) = PriorityParams::try_parse(field) else {
                    return Ok(Step::Nothing);
                };
                let id = prioritized.value();
                if let Some(s) = self.streams.get_mut(&id) {
                    s.priority = priority;
                    self.events
                        .push_back(Queued::Priority(prioritized, priority));
                } else if id > self.last_peer_stream
                    && (self.pending_priority.len() < self.config.max_concurrent_streams as usize
                        || self.pending_priority.contains_key(&id))
                {
                    let _ = self.pending_priority.insert(id, priority);
                }
                Ok(Step::Nothing)
            }
            Frame::Priority { .. } | Frame::Unknown { .. } => {
                self.charge_control()?;
                Ok(Step::Nothing)
            }
            Frame::RstStream { stream, code } => {
                if self.is_idle(stream.value()) {
                    return Err(ConnErrorKind::Protocol(Violation::IdleStream {
                        kind: frame::FrameType::RST_STREAM,
                        stream,
                    }));
                }
                match self.streams.remove(&stream.value()) {
                    Some(s) => {
                        // Body bytes the application still held go back to
                        // the connection window.
                        self.release_connection(s.held);
                        if !s.local_ended && !R::CLIENT {
                            self.charge_reset()?;
                        }
                        self.events.push_back(Queued::Reset {
                            stream,
                            code,
                            remote: true,
                        });
                    }
                    None => self.charge_control()?,
                }
                Ok(Step::Nothing)
            }
            Frame::Settings(s) => {
                if s.is_ack() {
                    if self.settings_unacked == 0 {
                        return Err(ConnErrorKind::Protocol(Violation::UnsolicitedSettingsAck));
                    }
                    self.settings_unacked -= 1;
                    self.decoder
                        .set_max_size(self.config.header_table_size as usize);
                    return Ok(Step::Nothing);
                }
                self.settings_seen += 1;
                if self.settings_seen > 1 {
                    self.charge_control()?;
                }
                let before = self.peer;
                self.peer.apply(&s);
                if self.peer.header_table_size != before.header_table_size {
                    self.encoder
                        .set_peer_max_size(self.peer.header_table_size as usize);
                }
                let delta = i64::from(self.peer.initial_window_size)
                    - i64::from(before.initial_window_size);
                if delta != 0 {
                    for (id, st) in &mut self.streams {
                        st.send_window += delta;
                        if st.send_window > i64::from(MAX_WINDOW) {
                            return Err(ConnErrorKind::FlowControl);
                        }
                        if delta > 0 && st.wants_write && st.send_window > 0 {
                            st.wants_write = false;
                            self.events
                                .push_back(Queued::Writable(StreamId::masked(*id)));
                        }
                    }
                }
                self.answer(&Frame::Settings(frame::Settings::ack()))?;
                Ok(Step::Nothing)
            }
            Frame::PushPromise { .. } => Err(ConnErrorKind::Protocol(Violation::PushPromise)),
            Frame::Ping { ack, payload } => {
                if ack {
                    if payload == SHUTDOWN_PING {
                        if let State::Draining { ping_acked, .. } = &mut self.state {
                            if !*ping_acked {
                                *ping_acked = true;
                                let last = self.last_peer_stream;
                                self.state = State::Draining {
                                    last,
                                    ping_acked: true,
                                };
                                self.write_frame(&Frame::GoAway {
                                    last_stream: StreamId::masked(last),
                                    code: ErrorCode::NO_ERROR,
                                    debug: b"",
                                });
                            }
                        }
                    }
                    self.charge_control()?;
                } else {
                    self.charge_control()?;
                    self.answer(&Frame::Ping { ack: true, payload })?;
                }
                Ok(Step::Nothing)
            }
            Frame::GoAway {
                code, last_stream, ..
            } => {
                if !self.peer_goaway {
                    self.peer_goaway = true;
                    self.events.push_back(Queued::GoAway(code));
                } else {
                    self.charge_control()?;
                }
                if R::CLIENT {
                    let unprocessed: Vec<u32> = self
                        .streams
                        .range(last_stream.value().saturating_add(1)..)
                        .map(|(id, _)| *id)
                        .collect();
                    for id in unprocessed {
                        if let Some(s) = self.streams.remove(&id) {
                            self.release_connection(s.held);
                            self.events.push_back(Queued::Reset {
                                stream: StreamId::masked(id),
                                code: ErrorCode::REFUSED_STREAM,
                                remote: true,
                            });
                        }
                    }
                }
                Ok(Step::Nothing)
            }
            Frame::WindowUpdate { stream, increment } => {
                let inc = i64::from(increment);
                if stream.is_zero() {
                    self.send_window += inc;
                    if self.send_window > i64::from(MAX_WINDOW) {
                        return Err(ConnErrorKind::FlowControl);
                    }
                    let ready: Vec<u32> = self
                        .streams
                        .iter_mut()
                        .filter(|(_, s)| s.wants_write && s.send_window > 0)
                        .map(|(id, s)| {
                            s.wants_write = false;
                            *id
                        })
                        .collect();
                    for id in ready {
                        self.events
                            .push_back(Queued::Writable(StreamId::masked(id)));
                    }
                    return Ok(Step::Nothing);
                }
                if self.is_idle(stream.value()) {
                    return Err(ConnErrorKind::Protocol(Violation::IdleStream {
                        kind: frame::FrameType::WINDOW_UPDATE,
                        stream,
                    }));
                }
                let Some(s) = self.streams.get_mut(&stream.value()) else {
                    if !self.recent_resets.contains(&stream.value()) {
                        self.charge_control()?;
                    }
                    return Ok(Step::Nothing);
                };
                s.send_window += inc;
                if s.send_window > i64::from(MAX_WINDOW) {
                    self.reset_for_peer(stream, ErrorCode::FLOW_CONTROL_ERROR, true)?;
                    return Ok(Step::Nothing);
                }
                if s.wants_write && s.send_window > 0 && self.send_window > 0 {
                    s.wants_write = false;
                    self.events.push_back(Queued::Writable(stream));
                }
                Ok(Step::Nothing)
            }
            // `Frame` is non-exhaustive for callers, not for this crate.
            #[allow(unreachable_patterns)]
            _ => {
                let _ = len;
                self.charge_control()?;
                Ok(Step::Nothing)
            }
        }
    }

    fn append_block(&mut self, fragment: &[u8]) -> Result<(), Fail> {
        if self.block.len() + fragment.len() > self.config.max_header_block as usize {
            return Err(ConnErrorKind::HeaderBlockTooLarge);
        }
        self.block.extend_from_slice(fragment);
        Ok(())
    }

    /// A complete field block: a new request, or trailers.
    fn field_block(&mut self, stream: StreamId, end_stream: bool) -> Result<Step, Fail> {
        // Decode first, whatever happens to the stream: the HPACK table must
        // stay in step with the peer's.
        self.list
            .set_budget(self.config.max_header_list_size as usize);
        let block = core::mem::take(&mut self.block);
        let decoded = self.decoder.decode(&block, &mut self.list);
        self.block = block;
        decoded.map_err(ConnErrorKind::Hpack)?;
        if R::CLIENT {
            return self.response_block(stream, end_stream);
        }

        let id = stream.value();
        if self.streams.contains_key(&id) {
            return self.trailers(stream, end_stream);
        }
        if id <= self.last_peer_stream {
            if self.recent_resets.contains(&id) {
                self.charge_control()?;
                return Ok(Step::Nothing);
            }
            return Err(ConnErrorKind::StreamClosed { stream });
        }
        if !stream.is_client_initiated() {
            return Err(ConnErrorKind::Protocol(Violation::BadStreamId { stream }));
        }
        self.last_peer_stream = id;
        let pending = self.pending_priority.remove(&id);
        if self
            .pending_priority
            .first_key_value()
            .is_some_and(|(k, _)| *k <= id)
        {
            // Updates for streams that can no longer open.
            self.pending_priority = self.pending_priority.split_off(&(id + 1));
        }
        if let State::Draining { last, .. } = self.state {
            if id > last {
                // After the final GOAWAY: ignored, as RFC 9113 says.
                return Ok(Step::Nothing);
            }
        }
        if self.streams.len() >= self.config.max_concurrent_streams as usize {
            self.events.push_back(Queued::Rejected {
                stream,
                reason: Rejection::TooManyStreams,
            });
            self.reset_for_peer(stream, ErrorCode::REFUSED_STREAM, false)?;
            return Ok(Step::Nothing);
        }
        self.work = self.work.saturating_add(1);
        let mut s = Stream {
            peer_ended: end_stream,
            local_ended: false,
            responded: false,
            bodiless: false,
            is_head: false,
            content_length: None,
            received: 0,
            send_length: None,
            sent: 0,
            recv_window: i64::from(self.config.stream_window),
            held: 0,
            unreleased: 0,
            send_window: i64::from(self.peer.initial_window_size),
            wants_write: false,
            priority: PriorityParams::default(),
            response_status: None,
        };
        if self.list.is_oversized() {
            // Answered here; the application never sees it.
            let _ = self.streams.insert(id, s);
            self.events.push_back(Queued::Rejected {
                stream,
                reason: Rejection::HeadersTooLarge,
            });
            let _ = self.send_head(stream, 431, &[], true);
            if !end_stream {
                // Ask the client to stop sending the body (RFC 9113 8.1).
                self.reset_for_peer(stream, ErrorCode::NO_ERROR, false)?;
            } else {
                self.charge_reset()?;
            }
            let _ = self.streams.remove(&id);
            return Ok(Step::Nothing);
        }
        let mapped = match fields::map_request(
            &self.list,
            end_stream,
            &self.limits,
            &mut self.synth,
            &mut self.slots,
        ) {
            Ok(m) => m,
            Err(reason) => {
                self.events.push_back(Queued::Rejected {
                    stream,
                    reason: Rejection::Malformed(reason),
                });
                self.reset_for_peer(stream, ErrorCode::PROTOCOL_ERROR, false)?;
                return Ok(Step::Nothing);
            }
        };
        s.content_length = mapped.content_length;
        s.is_head = mapped.is_head;
        s.priority = pending.unwrap_or_else(|| self.field_priority());
        let priority = s.priority;
        let _ = self.streams.insert(id, s);
        self.events.push_back(Queued::Request {
            stream,
            head: mapped.head,
            scheme: mapped.scheme,
            priority,
            end_stream,
        });
        Ok(Step::Nothing)
    }

    /// Client: a field block on one of this side's streams: a response
    /// head (informational or final) or trailers.
    fn response_block(&mut self, stream: StreamId, end_stream: bool) -> Result<Step, Fail> {
        let id = stream.value();
        let Some(s) = self.streams.get(&id) else {
            if self.recent_resets.contains(&id) {
                self.charge_control()?;
                return Ok(Step::Nothing);
            }
            if self.is_idle(id) {
                return Err(ConnErrorKind::Protocol(Violation::IdleStream {
                    kind: frame::FrameType::HEADERS,
                    stream,
                }));
            }
            return Err(ConnErrorKind::StreamClosed { stream });
        };
        if s.peer_ended {
            self.reset_for_peer(stream, ErrorCode::STREAM_CLOSED, true)?;
            return Ok(Step::Nothing);
        }
        let reject = |this: &mut Self, reason: Rejection| -> Result<Step, Fail> {
            this.events.push_back(Queued::Rejected { stream, reason });
            this.reset_for_peer(stream, ErrorCode::PROTOCOL_ERROR, true)?;
            Ok(Step::Nothing)
        };
        if self.list.is_oversized() {
            return reject(self, Rejection::HeadersTooLarge);
        }
        if s.response_status.is_some() {
            // Trailers: they end the stream.
            if !end_stream {
                return reject(self, Rejection::Malformed(Malformed::TrailersWithoutEnd));
            }
            if s.content_length.is_some_and(|cl| cl != s.received) {
                return reject(self, Rejection::Malformed(Malformed::ContentLength));
            }
            if let Err(m) = fields::check_trailers(&self.list) {
                return reject(self, Rejection::Malformed(m));
            }
            if let Some(s) = self.streams.get_mut(&id) {
                s.peer_ended = true;
            }
            self.close_if_done(stream);
            return Ok(Step::Trailers(stream));
        }
        let (status, content_length) = match fields::check_response(&self.list) {
            Ok(v) => v,
            Err(m) => return reject(self, Rejection::Malformed(m)),
        };
        if status < 200 {
            if end_stream || status == 101 {
                return reject(self, Rejection::Malformed(Malformed::Status));
            }
            return Ok(Step::Informational { stream, status });
        }
        let is_head = s.is_head;
        let bodiless = is_head || status == 204 || status == 304;
        if end_stream && !bodiless && content_length.is_some_and(|n| n > 0) {
            return reject(self, Rejection::Malformed(Malformed::ContentLength));
        }
        self.work = self.work.saturating_add(1);
        if let Some(s) = self.streams.get_mut(&id) {
            s.response_status = Some(status);
            s.bodiless = bodiless;
            // A HEAD response's content-length describes a body it does not
            // carry.
            s.content_length = if bodiless { Some(0) } else { content_length };
            s.peer_ended = end_stream;
        }
        self.close_if_done(stream);
        Ok(Step::Response {
            stream,
            status,
            end_stream,
        })
    }

    /// The `priority` field of the request just decoded; several fields
    /// are one dictionary, joined with commas (RFC 8941 section 3.2).
    fn field_priority(&self) -> PriorityParams {
        let mut fields = self.list.iter().filter(|f| f.name == b"priority");
        let Some(first) = fields.next() else {
            return PriorityParams::default();
        };
        let Some(second) = fields.next() else {
            return PriorityParams::parse(first.value);
        };
        let mut joined = Vec::with_capacity(first.value.len() + second.value.len() + 16);
        joined.extend_from_slice(first.value);
        for f in core::iter::once(second).chain(fields) {
            joined.push(b',');
            joined.extend_from_slice(f.value);
        }
        PriorityParams::parse(&joined)
    }

    fn trailers(&mut self, stream: StreamId, end_stream: bool) -> Result<Step, Fail> {
        let Some(s) = self.streams.get_mut(&stream.value()) else {
            return Ok(Step::Nothing);
        };
        if s.peer_ended {
            self.reset_for_peer(stream, ErrorCode::STREAM_CLOSED, true)?;
            return Ok(Step::Nothing);
        }
        let problem = if !end_stream {
            Some(Malformed::TrailersWithoutEnd)
        } else if self.list.is_oversized() {
            Some(Malformed::FieldValue)
        } else if s.content_length.is_some_and(|cl| cl != s.received) {
            Some(Malformed::ContentLength)
        } else {
            fields::check_trailers(&self.list).err()
        };
        if problem.is_some() {
            self.reset_for_peer(stream, ErrorCode::PROTOCOL_ERROR, true)?;
            return Ok(Step::Nothing);
        }
        s.peer_ended = true;
        self.close_if_done(stream);
        Ok(Step::Trailers(stream))
    }

    fn close_if_done(&mut self, stream: StreamId) {
        if self
            .streams
            .get(&stream.value())
            .is_some_and(|s| s.peer_ended && s.local_ended)
        {
            if let Some(s) = self.streams.remove(&stream.value()) {
                self.release_connection(s.held);
            }
        }
    }

    fn release_connection(&mut self, n: u32) {
        self.unreleased = self.unreleased.saturating_add(n);
        if self.unreleased >= self.config.connection_window / 2 && self.state != State::Closed {
            let inc = core::mem::take(&mut self.unreleased);
            self.recv_window += i64::from(inc);
            self.write_frame(&Frame::WindowUpdate {
                stream: StreamId::ZERO,
                increment: inc,
            });
        }
    }

    /// Bytes of a stream's window given back; a stream `WINDOW_UPDATE` goes
    /// out once half the window has been, while the peer is still sending.
    fn stream_released(&mut self, stream: StreamId, n: u32) {
        let half = self.config.stream_window / 2;
        let Some(s) = self.streams.get_mut(&stream.value()) else {
            return;
        };
        s.unreleased = s.unreleased.saturating_add(n);
        if s.unreleased >= half && !s.peer_ended && self.state != State::Closed {
            let inc = core::mem::take(&mut s.unreleased);
            s.recv_window += i64::from(inc);
            self.write_frame(&Frame::WindowUpdate {
                stream,
                increment: inc,
            });
        }
    }

    /// Gives `n` bytes of a request body handed out in [`Event::Data`] back
    /// to the peer's windows: the application has dealt with them. Window
    /// updates go out once half a window is released. More than the stream
    /// holds is capped; a stream that has ended already gave its bytes back.
    pub fn release(&mut self, stream: StreamId, n: usize) {
        let Some(s) = self.streams.get_mut(&stream.value()) else {
            return;
        };
        let n = u32::try_from(n).unwrap_or(u32::MAX).min(s.held);
        s.held -= n;
        self.stream_released(stream, n);
        self.release_connection(n);
    }

    /// The server's response head (`send_headers`, and the connection's
    /// own `431`).
    fn send_head(
        &mut self,
        stream: StreamId,
        status: u16,
        fields: &[(&str, &[u8])],
        end_stream: bool,
    ) -> Result<(), SendError> {
        if self.state == State::Closed {
            return Err(SendError::Closed);
        }
        let s = self
            .streams
            .get(&stream.value())
            .ok_or(SendError::UnknownStream)?;
        if s.responded {
            return Err(SendError::OutOfOrder);
        }
        if !(100..=599).contains(&status) || status == 101 {
            return Err(SendError::Status);
        }
        let informational = status < 200;
        if informational && end_stream {
            return Err(SendError::Status);
        }
        let bodiless = s.is_head || status == 204 || status == 304;
        let end_stream = end_stream || (!informational && bodiless);

        // Lowercase names into scratch space and check every field before
        // anything is written.
        let mut names = core::mem::take(&mut self.scratch_fields);
        names.clear();
        let mut spans = Vec::with_capacity(fields.len());
        let mut send_length = None;
        for (name, value) in fields {
            let name = name.as_bytes();
            if fields::is_connection_specific(name) {
                continue;
            }
            let start = names.len();
            names.extend(name.iter().map(u8::to_ascii_lowercase));
            let lower = names.get(start..).unwrap_or_default();
            let field = HeaderField::new(lower, value);
            if let Err(e) = fields::check_regular(&field) {
                self.scratch_fields = names;
                return Err(SendError::Field(e));
            }
            if lower == b"content-length" {
                send_length = core::str::from_utf8(value)
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok());
                if send_length.is_none() {
                    self.scratch_fields = names;
                    return Err(SendError::Field(Malformed::FieldValue));
                }
            }
            spans.push((start, names.len(), *value));
        }
        let mut status_text = [0u8; 3];
        status_text[0] = b'0' + (status / 100) as u8;
        status_text[1] = b'0' + (status / 10 % 10) as u8;
        status_text[2] = b'0' + (status % 10) as u8;
        let mut block = core::mem::take(&mut self.block);
        block.clear();
        self.encoder.encode(
            core::iter::once(HeaderField::new(b":status", &status_text)).chain(
                spans
                    .iter()
                    .map(|(a, b, v)| HeaderField::new(names.get(*a..*b).unwrap_or_default(), v)),
            ),
            &mut block,
        );
        self.write_block(stream, &block, end_stream);
        self.block = block;
        self.scratch_fields = names;

        if let Some(s) = self.streams.get_mut(&stream.value()) {
            if !informational {
                s.responded = true;
                s.bodiless = bodiless;
                s.send_length = if bodiless { None } else { send_length };
            }
            if end_stream {
                s.local_ended = true;
                self.completed = self.completed.saturating_add(1);
            }
        }
        if end_stream {
            self.close_if_done(stream);
        }
        Ok(())
    }

    /// Writes a field block as `HEADERS` and as many `CONTINUATION` frames
    /// as the peer's maximum frame size needs.
    fn write_block(&mut self, stream: StreamId, block: &[u8], end_stream: bool) {
        let max = self.peer.max_frame_size as usize;
        let mut chunks = block.chunks(max.max(1));
        let first = chunks.next().unwrap_or_default();
        let mut rest = chunks.peekable();
        self.write_frame(&Frame::Headers {
            stream,
            end_stream,
            end_headers: rest.peek().is_none(),
            priority: None,
            fragment: first,
            padding: None,
        });
        while let Some(chunk) = rest.next() {
            self.write_frame(&Frame::Continuation {
                stream,
                end_headers: rest.peek().is_none(),
                fragment: chunk,
            });
        }
    }

    /// Sends response body bytes, as much as the flow-control windows and
    /// [`Config::max_output`] allow; returns how many were taken. When not
    /// all were, an [`Event::Writable`] follows once the peer opens its
    /// window. `end_stream` takes effect only once every byte is taken.
    ///
    /// # Errors
    ///
    /// A [`SendError`]; nothing is written.
    pub fn send_data(
        &mut self,
        stream: StreamId,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, SendError> {
        if self.state == State::Closed {
            return Err(SendError::Closed);
        }
        let max_frame = self.peer.max_frame_size as usize;
        let room = (self.config.max_output as usize).saturating_sub(self.out.len());
        let conn_window = usize::try_from(self.send_window.max(0)).unwrap_or(0);
        let s = self
            .streams
            .get_mut(&stream.value())
            .ok_or(SendError::UnknownStream)?;
        if !s.responded {
            return Err(SendError::OutOfOrder);
        }
        if s.local_ended {
            return Err(SendError::Ended);
        }
        if s.bodiless && !data.is_empty() {
            return Err(SendError::Body);
        }
        if let Some(len) = s.send_length {
            let total = s.sent + data.len() as u64;
            if total > len || (end_stream && total != len) {
                return Err(SendError::Body);
            }
        }
        let window = usize::try_from(s.send_window.max(0)).unwrap_or(0);
        let n = data.len().min(window).min(conn_window).min(room);
        let all = n == data.len();
        let taken = data.get(..n).unwrap_or_default();
        s.send_window -= n as i64;
        s.sent += n as u64;
        if !all {
            s.wants_write = true;
        }
        let end = all && end_stream;
        if end {
            s.local_ended = true;
        }
        self.send_window -= n as i64;
        if taken.is_empty() {
            if end {
                self.write_frame(&Frame::Data {
                    stream,
                    end_stream: true,
                    data: b"",
                    padding: None,
                });
            }
        } else {
            let mut chunks = taken.chunks(max_frame.max(1)).peekable();
            while let Some(chunk) = chunks.next() {
                let last = chunks.peek().is_none();
                self.write_frame(&Frame::Data {
                    stream,
                    end_stream: end && last,
                    data: chunk,
                    padding: None,
                });
            }
        }
        if end {
            self.completed = self.completed.saturating_add(1);
            self.close_if_done(stream);
        }
        Ok(n)
    }

    /// Ends a response with trailers.
    ///
    /// # Errors
    ///
    /// A [`SendError`]; nothing is written.
    pub fn send_trailers(
        &mut self,
        stream: StreamId,
        fields: &[(&str, &[u8])],
    ) -> Result<(), SendError> {
        if self.state == State::Closed {
            return Err(SendError::Closed);
        }
        let s = self
            .streams
            .get(&stream.value())
            .ok_or(SendError::UnknownStream)?;
        if !s.responded {
            return Err(SendError::OutOfOrder);
        }
        if s.local_ended {
            return Err(SendError::Ended);
        }
        if s.send_length.is_some_and(|len| len != s.sent) {
            return Err(SendError::Body);
        }
        let mut names = core::mem::take(&mut self.scratch_fields);
        names.clear();
        let mut spans = Vec::with_capacity(fields.len());
        for (name, value) in fields {
            let start = names.len();
            names.extend(name.as_bytes().iter().map(u8::to_ascii_lowercase));
            let lower = names.get(start..).unwrap_or_default();
            if let Err(e) = fields::check_regular(&HeaderField::new(lower, value)) {
                self.scratch_fields = names;
                return Err(SendError::Field(e));
            }
            spans.push((start, names.len(), *value));
        }
        let mut block = core::mem::take(&mut self.block);
        block.clear();
        self.encoder.encode(
            spans
                .iter()
                .map(|(a, b, v)| HeaderField::new(names.get(*a..*b).unwrap_or_default(), v)),
            &mut block,
        );
        self.write_block(stream, &block, true);
        self.block = block;
        self.scratch_fields = names;
        if let Some(s) = self.streams.get_mut(&stream.value()) {
            s.local_ended = true;
        }
        self.completed = self.completed.saturating_add(1);
        self.close_if_done(stream);
        Ok(())
    }

    /// Resets a stream from this side (the application gave up on it).
    /// Not counted against the peer.
    pub fn reset(&mut self, stream: StreamId, code: ErrorCode) {
        if self.state == State::Closed {
            return;
        }
        if let Some(s) = self.streams.remove(&stream.value()) {
            self.write_frame(&Frame::RstStream { stream, code });
            self.remember_reset(stream.value());
            self.release_connection(s.held);
        }
    }
}

impl Connection<Server> {
    /// A connection that has accepted a socket (after TLS and ALPN `h2`,
    /// or behind a trusted proxy for cleartext). Its `SETTINGS` are already
    /// in [`output`](Self::output): the server preface needs no wait.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self::with_config(config)
    }

    /// The current priority of an open stream.
    #[must_use]
    pub fn priority(&self, stream: StreamId) -> Option<PriorityParams> {
        self.streams.get(&stream.value()).map(|s| s.priority)
    }

    /// Sends a response head (or an informational `1xx` head, which may
    /// come more than once before the final one). `fields` are regular
    /// fields; names are lowercased, and the fields HTTP/2 forbids
    /// (`connection`, `keep-alive`, `proxy-connection`,
    /// `transfer-encoding`, `upgrade`) are dropped, so an HTTP/1.1
    /// response maps across as it is. `end_stream` means no body follows;
    /// it is forced for a `HEAD` request and for `204` and `304`.
    ///
    /// # Errors
    ///
    /// A [`SendError`]; nothing is written.
    pub fn send_headers(
        &mut self,
        stream: StreamId,
        status: u16,
        fields: &[(&str, &[u8])],
        end_stream: bool,
    ) -> Result<(), SendError> {
        self.send_head(stream, status, fields, end_stream)
    }
}

impl Connection<Client> {
    /// A connection that has just connected (after TLS and ALPN `h2`). The
    /// client preface and its `SETTINGS` (server push refused) are already
    /// in [`output`](Self::output): requests can follow at once.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self::with_config(config)
    }

    /// Opens a stream with a request head; returns its identifier. Names
    /// are lowercased; `host` and the fields HTTP/2 forbids (`connection`,
    /// `keep-alive`, `proxy-connection`, `transfer-encoding`, `upgrade`)
    /// are dropped, since `:authority` carries the host. `end_stream` means
    /// no body follows; otherwise send it with
    /// [`send_data`](Connection::send_data), whose total must match a
    /// `content-length` given here.
    ///
    /// # Errors
    ///
    /// A [`SendError`]; nothing is written. [`SendError::Busy`] at the
    /// peer's stream limit, [`SendError::GoingAway`] after a `GOAWAY`.
    pub fn send_request(
        &mut self,
        request: &RequestParts<'_>,
        end_stream: bool,
    ) -> Result<StreamId, SendError> {
        match self.state {
            State::Closed => return Err(SendError::Closed),
            State::Draining { .. } => return Err(SendError::GoingAway),
            _ if self.peer_goaway => return Err(SendError::GoingAway),
            _ => {}
        }
        let Some(stream) = StreamId::new(self.next_stream) else {
            return Err(SendError::GoingAway);
        };
        let limit = self
            .peer
            .max_concurrent_streams
            .map_or(usize::MAX, |n| n as usize);
        if self.streams.len() >= limit {
            return Err(SendError::Busy);
        }
        let method = request.method.as_bytes();
        let token = |b: &u8| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
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
                )
        };
        if method.is_empty() || !method.iter().all(token) {
            return Err(SendError::Field(Malformed::MissingPseudo));
        }
        let connect = method == b"CONNECT";
        let authority = request.authority.as_bytes();
        if authority.is_empty() || authority.contains(&b'@') {
            return Err(SendError::Field(Malformed::Authority));
        }
        fields::check_value(authority).map_err(SendError::Field)?;
        let path = request.path.as_bytes();
        let origin_form = path.first() == Some(&b'/') || (path == b"*" && method == b"OPTIONS");
        if !connect && !origin_form {
            return Err(SendError::Field(Malformed::Path));
        }
        fields::check_value(path).map_err(SendError::Field)?;

        let mut names = core::mem::take(&mut self.scratch_fields);
        names.clear();
        let mut spans = Vec::with_capacity(request.fields.len());
        let mut send_length = None;
        for (name, value) in request.fields {
            let name = name.as_bytes();
            if fields::is_connection_specific(name) || name.eq_ignore_ascii_case(b"host") {
                continue;
            }
            let start = names.len();
            names.extend(name.iter().map(u8::to_ascii_lowercase));
            let lower = names.get(start..).unwrap_or_default();
            if let Err(e) = fields::check_regular(&HeaderField::new(lower, value)) {
                self.scratch_fields = names;
                return Err(SendError::Field(e));
            }
            if lower == b"content-length" {
                send_length = core::str::from_utf8(value)
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok());
                if send_length.is_none() {
                    self.scratch_fields = names;
                    return Err(SendError::Field(Malformed::ContentLength));
                }
            }
            spans.push((start, names.len(), *value));
        }
        if end_stream && send_length.is_some_and(|n| n > 0) {
            self.scratch_fields = names;
            return Err(SendError::Body);
        }
        let scheme = request.scheme.as_str().as_bytes();
        let mut pseudo: Vec<HeaderField<'_>> = Vec::with_capacity(4);
        pseudo.push(HeaderField::new(b":method", method));
        if !connect {
            pseudo.push(HeaderField::new(b":scheme", scheme));
        }
        pseudo.push(HeaderField::new(b":authority", authority));
        if !connect {
            pseudo.push(HeaderField::new(b":path", path));
        }
        let mut block = core::mem::take(&mut self.block);
        block.clear();
        self.encoder.encode(
            pseudo.into_iter().chain(
                spans
                    .iter()
                    .map(|(a, b, v)| HeaderField::new(names.get(*a..*b).unwrap_or_default(), v)),
            ),
            &mut block,
        );
        self.write_block(stream, &block, end_stream);
        self.block = block;
        self.scratch_fields = names;
        self.next_stream = self.next_stream.saturating_add(2);
        let s = Stream {
            peer_ended: false,
            local_ended: end_stream,
            // The head left: a body may follow.
            responded: true,
            bodiless: false,
            is_head: method == b"HEAD",
            content_length: None,
            received: 0,
            send_length,
            sent: 0,
            recv_window: i64::from(self.config.stream_window),
            held: 0,
            unreleased: 0,
            send_window: i64::from(self.peer.initial_window_size),
            wants_write: false,
            priority: PriorityParams::default(),
            response_status: None,
        };
        let _ = self.streams.insert(stream.value(), s);
        Ok(stream)
    }
}

/// A request head for [`ClientConn::send_request`].
///
/// # Examples
///
/// ```
/// use h2_net::conn::{RequestParts, Scheme};
///
/// let head = RequestParts {
///     method: "GET",
///     scheme: Scheme::Https,
///     authority: "example.com",
///     path: "/index.html",
///     fields: &[("accept", b"text/html")],
/// };
/// assert_eq!(head.path, "/index.html");
/// ```
#[derive(Clone, Copy, Debug)]
pub struct RequestParts<'a> {
    /// The method (`CONNECT` sends no `:scheme` or `:path`).
    pub method: &'a str,
    /// The scheme.
    pub scheme: Scheme,
    /// The authority (`host[:port]`, no userinfo).
    pub authority: &'a str,
    /// The path and query, starting with `/` (`*` for `OPTIONS`).
    pub path: &'a str,
    /// The regular fields.
    pub fields: &'a [(&'a str, &'a [u8])],
}

#[cfg(test)]
mod client_tests;
#[cfg(test)]
mod tests;
