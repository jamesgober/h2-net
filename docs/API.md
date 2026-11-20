# h2-net &mdash; API Reference

> Every public item in `h2-net`, with examples. The examples run as tests.
> **Status: in development.** The codec (`frame`, `hpack`) and the server connection (`conn`) are built (see [`../dev/ROADMAP.md`](../dev/ROADMAP.md)).

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Table of contents

- [Crate root](#crate-root): `VERSION`, `ErrorCode`, `FrameError`, `HpackError`
- [`frame`](#frame): `decode`, `encode`, `Decoded`, `Frame`, `FrameHeader`, `FrameType`, `StreamId`, `Priority`, `Settings`, `SettingId`, `SettingValues`, `settings_frame`, `flags`, constants
- [`hpack`](#hpack): `Decoder`, `Encoder`, `HeaderList`, `HeaderField`, `huffman`, `FIELD_OVERHEAD`
- [`conn`](#conn): `ServerConn`, `Config`, `Event`, `Scheme`, `PriorityParams`, `SendError`, `ConnError`, `ConnErrorKind`, `Violation`, `Rejection`, `Malformed`

## Crate root

### `VERSION`

The crate version, as published.

```rust
println!("h2-net {}", h2_net::VERSION);
```

### `ErrorCode`

An HTTP/2 error code (RFC 9113 section 7), as carried by `RST_STREAM` and `GOAWAY`. Constants for every code RFC 9113 defines (`NO_ERROR` to `HTTP_1_1_REQUIRED`); `new(u32)`, `value()`, and `name()` (`None` for a code RFC 9113 does not define). Unknown codes are kept as they arrived.

```rust
use h2_net::ErrorCode;

assert_eq!(ErrorCode::ENHANCE_YOUR_CALM.value(), 0xb);
assert_eq!(ErrorCode::new(0x8), ErrorCode::CANCEL);
```

### `FrameError`

A frame the frame layer refused, one variant per rule (`TooLarge`, `BadLength`, `NeedsStream`, `NeedsConnection`, `Padding`, `ZeroIncrement`, `SelfDependency`, `SettingValue`, `PriorityUpdateForZero`, and from the encoder only `IncrementTooLarge` and `DefinedType`). `code()` is the error code RFC 9113 gives for the rule. `#[non_exhaustive]`.

### `HpackError`

A field block the HPACK decoder refused (`Truncated`, `IntegerOverflow`, `Huffman`, `BadIndex`, `SizeUpdateTooLarge`, `SizeUpdateMisplaced`, `SizeUpdateMissing`). Every one is a connection error: `code()` is always `COMPRESSION_ERROR`. `#[non_exhaustive]`.

## `frame`

One frame at a time, as borrowed views of the buffer it was read from. The frame layer checks what a frame says about itself; whether a frame is allowed in the connection's state is the connection's job.

### `decode(input, max_frame_size) -> Result<Decoded, FrameError>`

Reads one frame from the front of `input`. `max_frame_size` is this side's `SETTINGS_MAX_FRAME_SIZE`: a longer frame is refused from its header, before the payload is waited for.

- `Decoded::Incomplete { needed }`: read until the buffer holds `needed` bytes.
- `Decoded::Frame { frame, len }`: one frame of `len` bytes, header included.
- `Decoded::StreamError { stream, error, len }`: a frame RFC 9113 refuses as a stream error; reset `stream` with `error.code()` and go on after `len` bytes.
- `Err(FrameError)`: a connection error; send `GOAWAY` with `code()`.

```rust
use h2_net::frame::{self, Decoded, Frame};

let wire = [0, 0, 4, 0x8, 0, 0, 0, 0, 0, 0, 0, 0x10, 0];
match frame::decode(&wire, frame::DEFAULT_MAX_FRAME_SIZE)? {
    Decoded::Frame { frame: Frame::WindowUpdate { stream, increment }, len } => {
        assert!(stream.is_zero());
        assert_eq!(increment, 4096);
        assert_eq!(len, 13);
    }
    other => panic!("{other:?}"),
}
# Ok::<(), h2_net::FrameError>(())
```

### `encode(frame, max_frame_size, out) -> Result<(), FrameError>`

Appends one frame. `max_frame_size` is the peer's setting. It refuses, writing nothing, every frame `decode` would refuse, so `decode(encode(f)) == f`. Padding is written as zeros; undefined flags are never set.

### `Frame`

`Data`, `Headers`, `Priority`, `RstStream`, `Settings`, `PushPromise`, `Ping`, `GoAway`, `WindowUpdate`, `Continuation`, `PriorityUpdate`, and `Unknown` for types this crate does not define (RFC 9113 says to ignore them). Padding is kept as its length. `kind()`, `stream()`, and `flow_len()` (a `DATA` frame's whole payload, padding included, as flow control counts it). `#[non_exhaustive]`.

### `FrameHeader`, `FrameType`, `StreamId`, `Priority`, `flags`

`FrameHeader::parse` reads the 9-byte header (the reserved bit dropped). `FrameType` has a constant for each type and keeps unknown ones. `StreamId` is 31 bits: `new` refuses larger values, `masked` drops the reserved bit, `is_client_initiated` is true for odd identifiers. `Priority` is the deprecated RFC 7540 signal, read so a stream that depends on itself is refused. `flags` holds `END_STREAM`, `ACK`, `END_HEADERS`, `PADDED`, and `PRIORITY`.

### Constants

`HEADER_LEN` (9), `DEFAULT_MAX_FRAME_SIZE` (16,384), `MAX_FRAME_SIZE_LIMIT` (2^24 - 1), `MAX_WINDOW` (2^31 - 1), `PREFACE` (the client's 24-byte connection preface).

### `Settings`, `SettingId`, `SettingValues`, `settings_frame`

`Settings` is a checked `SETTINGS` payload: `from_payload` refuses a length that is not a multiple of 6 and any value out of its range; `iter()` gives the parameters in order. `SettingId` has a constant for each parameter of RFC 9113, RFC 8441, and RFC 9218, and `check(value)` applies its range. `SettingValues` holds one side's settings, starting at RFC 9113's initial values, and `apply` takes a `Settings` in order. `settings_frame` writes a `SETTINGS` frame from a list of parameters.

```rust
use h2_net::frame::{self, Decoded, Frame, SettingId, SettingValues};

let mut out = Vec::new();
frame::settings_frame(
    &[(SettingId::MAX_CONCURRENT_STREAMS, 100), (SettingId::INITIAL_WINDOW_SIZE, 1 << 20)],
    frame::DEFAULT_MAX_FRAME_SIZE,
    &mut out,
)?;
let Decoded::Frame { frame: Frame::Settings(s), .. } = frame::decode(&out, 16_384)? else {
    panic!()
};
let mut peer = SettingValues::default();
peer.apply(&s);
assert_eq!(peer.max_concurrent_streams, Some(100));
assert_eq!(peer.initial_window_size, 1 << 20);
# Ok::<(), h2_net::FrameError>(())
```

## `hpack`

### `Decoder`

`Decoder::new(max_size)`: `max_size` is the `SETTINGS_HEADER_TABLE_SIZE` this side advertised. `decode(block, list)` decodes one whole field block (the caller joins the `CONTINUATION` fragments) into `list`, which is cleared first. `set_max_size` applies a new advertised size once the peer acknowledged it; when it is lower, the next block must start with a size update at or under it. `table_size`, `table_max`, `max_size`.

### `Encoder`

`Encoder::new(limit)`: the largest dynamic table this side keeps; the table used is the smaller of that and the peer's setting. `encode(fields, out)` appends a field block. `set_peer_max_size` applies the peer's `SETTINGS_HEADER_TABLE_SIZE`; the change is signalled at the start of the next block. Credentials (`authorization`, `proxy-authorization`, `cookie`, `set-cookie`) and fields marked sensitive are never indexed.

### `HeaderList`

A decoded field section with a budget in RFC 9113's terms (each field's name and value plus 32, `FIELD_OVERHEAD`). A field that would pass the budget is not stored and the list reports `is_oversized()`; the block is still decoded to the end so the table stays in step. `iter`, `get`, `len`, `size` (every field decoded, stored or not), `budget`, `set_budget`, `clear`, and `wipe` (zeroes the bytes, spare capacity included). `Debug` prints names and value lengths, never values.

```rust
use h2_net::hpack::{Decoder, HeaderList};

let mut decoder = Decoder::new(4096);
let mut list = HeaderList::new(100);
// ":method: GET" three times is 3 * 42 = 126 bytes.
decoder.decode(b"\x82\x82\x82", &mut list)?;
assert!(list.is_oversized());
assert_eq!(list.len(), 2);
assert_eq!(list.size(), 126);
# Ok::<(), h2_net::HpackError>(())
```

### `HeaderField`

A name, a value, and `sensitive` (never indexed). `new`, `sensitive`, and `size()`.

### `huffman`

`encode`, `decode`, and `encoded_len` for the Huffman code of RFC 7541 Appendix B. `decode` refuses EOS and padding that is 8 bits or longer or not all ones.

```rust
use h2_net::hpack::huffman;

let mut wire = Vec::new();
huffman::encode(b"no-cache", &mut wire);
assert_eq!(wire, [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]);
```

## `conn`

The server side of one HTTP/2 connection, without I/O.

### `ServerConn`

- `new(config)`: the server's `SETTINGS` and a connection `WINDOW_UPDATE` are in the output at once.
- `feed(bytes) -> usize`: copies what fits into the input buffer (two maximum frames).
- `poll() -> Result<Option<Event>, ConnError>`: the next event, or `None` when more input is needed. After an error, a `GOAWAY` is in the output and every call returns the same error.
- `output()` and `consume_output(n)`: the bytes to write.
- `send_headers(stream, status, fields, end_stream)`: a response head, or an informational `1xx`. Names are lowercased; `connection`, `keep-alive`, `proxy-connection`, `transfer-encoding`, and `upgrade` are dropped. `HEAD`, `204`, and `304` end with the head.
- `send_data(stream, data, end_stream) -> usize`: as much as the windows and the output bound allow; `Event::Writable` follows when the rest can go. A `content-length` the head sent is enforced.
- `send_trailers(stream, fields)`, `reset(stream, code)`.
- `release(stream, n)`: gives request body bytes back to the peer's windows once dealt with.
- `shutdown()`: graceful, in two steps; `close(code)`: at once.
- `is_done()`, `settings_acked()`, `open_streams()`, `priority(stream)`.

```rust
use h2_net::conn::{Config, Event, ServerConn};
use h2_net::frame::{self, Frame, StreamId};
use h2_net::hpack::{Encoder, HeaderField};

let mut wire = frame::PREFACE.to_vec();
frame::settings_frame(&[], 16_384, &mut wire)?;
let mut block = Vec::new();
Encoder::new(4096).encode(
    [
        HeaderField::new(b":method", b"POST"),
        HeaderField::new(b":scheme", b"https"),
        HeaderField::new(b":authority", b"example.com"),
        HeaderField::new(b":path", b"/echo"),
        HeaderField::new(b"content-length", b"5"),
    ],
    &mut block,
);
let stream = StreamId::new(1).unwrap();
frame::encode(
    &Frame::Headers { stream, end_stream: false, end_headers: true, priority: None, fragment: &block, padding: None },
    16_384,
    &mut wire,
)?;
frame::encode(&Frame::Data { stream, end_stream: true, data: b"hello", padding: None }, 16_384, &mut wire)?;

let mut conn = ServerConn::new(Config::new());
let _ = conn.feed(&wire);
let mut body = Vec::new();
while let Some(event) = conn.poll()? {
    match event {
        Event::Request { head, .. } => assert_eq!(head.view().content_length(), Some(5)),
        Event::Data { stream, data, end_stream } => {
            body.extend_from_slice(data);
            let n = data.len();
            conn.release(stream, n);
            if end_stream {
                conn.send_headers(stream, 200, &[("content-length", b"5")], false)?;
                conn.send_data(stream, &body, true)?;
            }
        }
        _ => {}
    }
}
assert_eq!(body, b"hello");
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `Config`

Secure defaults, each setter documenting its cost: `max_concurrent_streams` (100), `stream_window` (256 KiB), `connection_window` (1 MiB), `max_frame_size` (16,384), `header_table_size` (4096), `max_header_list_size` (16 KiB; over it, `431`), `max_header_block` (64 KiB), `max_continuations` (32), `encoder_table_size` (4096), `reset_budget` (200, 4), `control_budget` (1000, 10), `max_unread_answers` (1000), `max_output` (256 KiB), `auto_release` (off).

### `Event`

`Request { stream, head, scheme, priority, end_stream }` (`head` is http-net's `OwnedRequestHead`; its framing tells whether a body follows), `Data { stream, data, end_stream }`, `Trailers { stream, fields }`, `Reset { stream, code, remote }`, `Rejected { stream, reason }` (a request answered without the application: malformed, too large, or over the stream cap), `Writable { stream }`, `GoAway { code }`, `Priority { stream, priority }` (a `PRIORITY_UPDATE` for an open stream). `#[non_exhaustive]`.

### `PriorityParams`

A request's priority (RFC 9218): `urgency` 0 to 7 (default 3) and `incremental` (default false). `parse` reads a Priority Field Value as an RFC 8941 dictionary; a value that does not parse gives the defaults, and a member of the wrong type or out of range keeps its default. `try_parse` returns `None` instead for a value that does not parse. The connection reports priorities and orders nothing: scheduling is the driver's.

```rust
use h2_net::conn::PriorityParams;

let p = PriorityParams::parse(b"u=1, i");
assert_eq!((p.urgency, p.incremental), (1, true));
assert_eq!(PriorityParams::parse(b"u=9"), PriorityParams::default());
```

### Errors

`ConnError` has `kind()`, `code()` (sent in the `GOAWAY`), and `is_abuse()` (a budget was crossed: what a connection gate counts). `ConnErrorKind`: `Preface`, `Frame`, `Hpack`, `Protocol(Violation)`, `FlowControl`, `StreamClosed`, `RapidReset`, `ContinuationFlood`, `HeaderBlockTooLarge`, `ControlFlood`, `OutputBacklog`, `Closed`. `SendError` refuses an application call and writes nothing. `Rejection` and `Malformed` say why a request never reached the application.
