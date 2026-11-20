# h2-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Design and decisions: [`PLAN.md`](./PLAN.md).
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE, 2026-10-13)
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.

## v0.2.0 - Codec (frames and HPACK; API locked for those modules)
The design lock of 0.2.0 now covers the codec only; the connection API moves to 0.3.0, where it is designed with serve-net's engine slot (D-007).
- [x] Every frame type of RFC 9113 and `PRIORITY_UPDATE` (RFC 9218): decode as borrowed views, encode, and every check RFC 9113 puts on a frame by itself. `decode(encode(f)) == f`.
- [x] Size limits from `SETTINGS_MAX_FRAME_SIZE`, checked from the header before the payload is buffered.
- [x] `SETTINGS` parameters with their ranges (RFC 9113, RFC 8441, RFC 9218).
- [x] HPACK decoder and encoder: bounded dynamic tables, Huffman coding, the header list budget, size update rules, credentials never indexed.
- [x] RFC 7541 Appendix C examples, byte for byte, and the static table and Huffman code generated from the RFC's text.
- [x] Fuzz targets for the frame decoder, the HPACK decoder, the HPACK round trip, and the Huffman code; a CI smoke run for each.
- [x] Benchmarks: frame decode and encode, HPACK decode and encode of realistic request and response sections, the HPACK bomb, the Huffman code (baseline in PLAN section 7).
- [ ] Release.

## v0.3.0 - Engine
- [ ] Connection preface, `SETTINGS` exchange and acknowledgment, `PING`, `GOAWAY` and graceful shutdown.
- [ ] Stream state machine (RFC 9113 section 5.1), concurrent stream cap.
- [ ] Flow control: connection and stream windows, `WINDOW_UPDATE`, `SETTINGS_INITIAL_WINDOW_SIZE` changes.
- [ ] Field blocks across `CONTINUATION` with a block budget; pseudo-header and connection-specific field checks (RFC 9113 section 8).
- [ ] Mapping to http-net's request and response types.
- [ ] Every budget in PLAN section 5, each with an attack test that must fail without it; offences reported so serve-net can make them bouncer strikes.
- [ ] Fuzz targets for the connection.

## v0.4.0 - In serve-net
- [ ] serve-net's engine slot for several streams per connection; ALPN `h2` selects h2-net.

## v1.0.0 - Stable
- [ ] Frozen after direct mode has served HTTP/2 in production.
