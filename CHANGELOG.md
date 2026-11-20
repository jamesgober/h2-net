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

The codec (frames and HPACK) and the server connection.

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
- Budgets against rapid reset and provoked resets, `CONTINUATION` floods,
  `SETTINGS`, `PING`, and other control floods, a peer that does not read,
  and stream exhaustion, each with an attack test. A request over the header
  list budget is answered `431` without ending the connection.
- `ErrorCode`, `FrameError`, `HpackError`, and the connection's errors.
- Tests: RFC 7541 Appendix C byte for byte, a decode at every split point
  for every frame type, every refusal in RFC 9113 section 6. Fuzz targets
  for the frame decoder, the HPACK decoder, the HPACK round trip, the
  Huffman code, and the server connection, with a smoke run in CI.
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

[Unreleased]: https://github.com/jamesgober/h2-net/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jamesgober/h2-net/releases/tag/v0.1.0
