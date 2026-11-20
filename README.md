<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>h2-net</b>
    <br>
    <sub><sup>HTTP/2</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/h2-net"><img alt="Crates.io" src="https://img.shields.io/crates/v/h2-net"></a>
    <a href="https://crates.io/crates/h2-net"><img alt="Downloads" src="https://img.shields.io/crates/d/h2-net?color=%230099ff"></a>
    <a href="https://docs.rs/h2-net"><img alt="docs.rs" src="https://img.shields.io/docsrs/h2-net"></a>
    <a href="https://github.com/jamesgober/h2-net/actions"><img alt="CI" src="https://github.com/jamesgober/h2-net/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</div>

<br>

<div align="left">
    <p>
        <strong>h2-net</strong> is HTTP/2 the way http-net is HTTP/1.1: a sans-IO engine that refuses what it cannot frame unambiguously and bounds every buffer. serve-net selects it through ALPN after the TLS handshake.
    </p>
    <p>
        It matters for direct mode, where no Apache or nginx sits in front to speak HTTP/2 to browsers.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition). <code>#![forbid(unsafe_code)]</code>. <code>no_std</code> with <code>alloc</code>. No runtime dependencies.
    </p>
    <blockquote>
        <strong>Status: in development.</strong> The codec (frames and HPACK) and the server connection engine are built and tested; serve-net's side (ALPN `h2`, several streams per connection) is next. The schedule is in <a href="./dev/ROADMAP.md"><code>dev/ROADMAP.md</code></a>.
    </blockquote>
</div>

<hr>
<br>

## What is built

- **Frames** (`h2_net::frame`): every frame type of RFC 9113 and `PRIORITY_UPDATE` from RFC 9218, read as borrowed views and written back. Every check RFC 9113 puts on a frame by itself is applied, and the encoder refuses whatever the decoder would refuse. A frame longer than `SETTINGS_MAX_FRAME_SIZE` is refused from its 9-byte header, before its payload is buffered.
- **HPACK** (`h2_net::hpack`): a decoder and encoder with bounded dynamic tables and Huffman coding. A field block decodes into a `HeaderList` with a budget that is checked before any field is copied, so a small block that names a large table entry many times cannot grow past it. A block over the budget still keeps the dynamic table in step, so the request can be refused with 431 without closing the connection. The encoder never indexes credentials.

```rust
use h2_net::hpack::{Decoder, Encoder, HeaderField, HeaderList};

let mut encoder = Encoder::new(4096);
let mut block = Vec::new();
encoder.encode(
    [HeaderField::new(b":status", b"200"), HeaderField::new(b"content-type", b"text/plain")],
    &mut block,
);

let mut decoder = Decoder::new(4096);
let mut fields = HeaderList::new(16 * 1024);
decoder.decode(&block, &mut fields).expect("a block this encoder wrote");
assert_eq!(fields.get(":status"), Some(&b"200"[..]));
```

- **Connection** (`h2_net::conn`): the server side of a connection. Feed it bytes and poll for events; requests arrive as http-net's `OwnedRequestHead`, built by writing the request out as HTTP/1.1 and parsing it with http-net, so both versions get the same type and the same strictness. It answers `SETTINGS` and `PING`, runs flow control in both directions, enforces RFC 9113's rules for requests (pseudo-headers, connection-specific fields, `content-length` against the body), and shuts down gracefully in RFC 9113's two steps. Every known HTTP/2 attack has a budget that ends the connection with `ENHANCE_YOUR_CALM` and marks it as abuse: rapid reset and resets the peer provokes, `CONTINUATION` floods, `SETTINGS` and `PING` floods, a peer that sends but never reads, and stream exhaustion. None of them needs a clock.

The whole API is in [`docs/API.md`](./docs/API.md).

## Next

serve-net's engine slot for several streams per connection, with ALPN `h2` selecting h2-net, and priority signals (RFC 9218) for its scheduler.

See [`dev/PLAN.md`](./dev/PLAN.md) for the design, the threats and what each defence costs, and the decision log.

<hr>
<br>

## Contributing

See <a href="./dev/DIRECTIVES.md"><code>dev/DIRECTIVES.md</code></a> for engineering standards and the definition of done. Before a PR: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` must be clean.

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b> &mdash; <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b> &mdash; <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
