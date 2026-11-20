# h2-net &mdash; API Reference

> Every public item in `h2-net`, with examples. The examples run as tests.
> **Status: in development.** The codec (`frame`, `hpack`) is built; the connection engine is next (see [`../dev/ROADMAP.md`](../dev/ROADMAP.md)).

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Table of contents

- [Crate root](#crate-root): `VERSION`, `ErrorCode`, `FrameError`, `HpackError`
- [`frame`](#frame): `decode`, `encode`, `Decoded`, `Frame`, `FrameHeader`, `FrameType`, `StreamId`, `Priority`, `Settings`, `SettingId`, `SettingValues`, `settings_frame`, `flags`, constants
- [`hpack`](#hpack): `Decoder`, `Encoder`, `HeaderList`, `HeaderField`, `huffman`, `FIELD_OVERHEAD`

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
