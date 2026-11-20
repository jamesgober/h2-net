<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>h2-net</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

### Added

- `conn::ClientConn`, the client side of a connection: the same protocol
  and budgets as the server side, server push refused, responses checked by
  RFC 9113 section 8.3, and the streams a `GOAWAY` left unprocessed
  reported as reset with `REFUSED_STREAM`. `RequestParts` describes a
  request head; `Event::Response` and `Event::Informational` report
  responses.
- A fuzz target for the client with a hostile server.

### Changed

- `ServerConn` is now `Connection<Server>`, an alias; nothing a server's
  code calls changed.

### Performance

- The HPACK encoder finds static table names with a generated `match`
  instead of a scan of all 61 entries: encoding a typical response is 44%
  faster. A response or request head no longer allocates a list of its
  fields.
- `h1/requests_10k` measures the same work through HTTP/1.1, to compare
  HTTP/2 against.

---

## [0.3.0] - 2026-11-20

The codec (frames and HPACK) and the server connection. The first functional
release; the planned 0.2.0 (the codec alone) was not released on its own.

### Added

- `frame`: every frame type of RFC 9113 and `PRIORITY_UPDATE` (RFC 9218),
  read as borrowed views (`decode`) and written back (`encode`), with every
  check RFC 9113 puts on a frame by itself. A frame over
  `SETTINGS_MAX_FRAME_SIZE` is refused from its header. Refusals RFC 9113
  scopes to a stream are reported apart from connection errors. The encoder
  refuses whatever the decoder would refuse.
- `SETTINGS` parameters with their ranges (RFC 9113, RFC 8441, RFC 9218),
  `SettingValues` for one side's settings, and `settings_frame`.
- `hpack`: `Decoder` and `Encoder` with bounded dynamic tables, Huffman
  coding, and the size update rules of RFC 7541 and RFC 9113. A field block
  decodes into a `HeaderList` with a budget checked before each field is
  copied; a block over the budget keeps the dynamic table in step and is
  reported, so the request can be refused without closing the connection.
  The encoder never indexes credentials or fields marked sensitive.
- `conn::ServerConn`: the server side of a connection, without I/O. It
  answers `SETTINGS` and `PING`, runs flow control in both directions,
  collects field blocks across `CONTINUATION`, checks requests by RFC 9113
  section 8, and shuts down gracefully in two steps. Requests arrive as
  http-net's `OwnedRequestHead` (the request written out as HTTP/1.1 and
  parsed by http-net, so both versions are equally strict); responses go in
  as status and fields, with HTTP/1.1's connection fields dropped.
- Extensible priorities (RFC 9218): `PriorityParams`, read from the
  `priority` field and from `PRIORITY_UPDATE` frames, reported with each
  request and as `Event::Priority` when they change. The connection
  reports them; ordering responses is the driver's.
- Budgets against rapid reset and provoked resets, `CONTINUATION` floods,
  `SETTINGS`, `PING`, and other control floods, a peer that does not read,
  and stream exhaustion, each with an attack test. A request over the header
  list budget is answered `431` without ending the connection.
- `ErrorCode`, `FrameError`, `HpackError`, and the connection's errors.
- Tests: RFC 7541 Appendix C byte for byte, a decode at every split point
  for every frame type, every refusal in RFC 9113 section 6. Fuzz targets
  for the frame decoder, the HPACK decoder, the HPACK round trip, the
  Huffman code, the server connection, and the priority field, with a smoke
  run in CI.
  Benchmarks.
- A dependency on http-net 0.10 (default features off; the crate stays
  `no_std`).

### Changed

- The crate is `no_std` with `alloc`.

---

## [0.1.0] - 2026-10-13

The scaffold and the plan. No functional code yet.

### Added

- Crate manifest (edition 2024, MSRV 1.85, no dependencies), `Apache-2.0 OR MIT`
  license, README, REPS, CI (Linux, macOS, Windows on stable and 1.85; audit
  and deny), `deny.toml`, `clippy.toml`, `rustfmt.toml`, `.gitattributes`.
- `dev/PLAN.md` (purpose, scope, architecture, threats, ecosystem, open
  decisions, decision log), `dev/DIRECTIVES.md`, and `dev/ROADMAP.md`.

[Unreleased]: https://github.com/jamesgober/h2-net/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/jamesgober/h2-net/releases/tag/v0.3.0
[0.1.0]: https://github.com/jamesgober/h2-net/releases/tag/v0.1.0
