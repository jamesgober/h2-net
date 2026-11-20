# h2-net - Project Plan

> The design, strategy, and decision record for `h2-net`. A living document: every design decision, idea, or open question about h2-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Status:** in development since 2026-11-20 (D-001). The codec layer (frames and HPACK) is built; the connection engine is next. Published: `0.1.0` (scaffold).

---

## 1. Purpose

HTTP/2 (RFC 9113) as a sans-IO engine with the same strictness and budgets as http-net, selected by serve-net through ALPN.

## 2. Why now

Direct mode (no Apache or nginx in front), and gRPC-style services between our own nodes. Behind a front end, the front end speaks HTTP/2 to browsers and HTTP/1.1 to us; in direct mode serve-net must speak HTTP/2 itself.

## 3. Scope

- Frames: parsing and serialization for every frame type, size limits from settings.
- HPACK (RFC 7541) with bounded dynamic tables and Huffman coding.
- Stream state machine, flow control (connection and stream windows), settings, GOAWAY and graceful shutdown, priority signals (RFC 9218).
- Requests and responses mapped to the same types http-net produces, so serve-net and web-net do not care which version arrived.
- h2c (cleartext) only behind a trusted proxy.

Out of scope: server push (never sent; `SETTINGS_ENABLE_PUSH` is irrelevant to a server, and a `PUSH_PROMISE` from a client is a protocol error), the RFC 7540 priority tree (deprecated by RFC 9113; read and ignored), and HTTP/2 over cleartext upgrade (`Upgrade: h2c` is never honoured, as serve-net already decides).

## 4. Layers

| Layer | Module | State | Status |
|---|---|---|---|
| Frames | `frame` | none: one frame in, one view out; one frame in, bytes out | built (0.2.0) |
| Field compression | `hpack` | one dynamic table per direction | built (0.2.0) |
| Connection | `conn` (planned) | streams, windows, settings, budgets | next (0.3.0) |
| Mapping | `conn` (planned) | none | with the connection |

Every layer is sans-IO and `no_std` with `alloc`. The frame layer checks what a frame says about itself (length, stream identifier, padding, setting values); whether a frame is allowed in the connection's state is the connection's job.

## 5. Threats (HTTP/2 has its own attack history)

Every defence states its cost. Figures marked [est.] are estimates until a benchmark replaces them.

| Attack | Defence | Where | Cost | Status |
|---|---|---|---|---|
| oversized frames | a frame longer than `SETTINGS_MAX_FRAME_SIZE` is refused from its 9-byte header, before its payload is buffered | `frame::decode` | one compare per frame | built |
| HPACK bombs | each field is checked against the header list budget (RFC 9113's size: name, value, 32) before its bytes are copied; the dynamic table never exceeds the size this side advertised | `hpack` | one add and compare per field; memory is the budget | built |
| HPACK state abuse | integers with more than four continuation bytes, size updates over the advertised maximum or after a field, a missing size update after a reduction, and EOS or bad Huffman padding are all refused as `COMPRESSION_ERROR` | `hpack` | none on valid input | built |
| compression side channels (CRIME family) | the encoder never indexes credentials (`authorization`, `proxy-authorization`, `cookie`, `set-cookie`) or a field the caller marks sensitive, and keeps the never-indexed mark when decoding so a proxy can keep it | `hpack::Encoder` | those fields are sent as literals every time (a few dozen bytes per response that sets a cookie) | built |
| rapid reset (CVE-2023-44487) | budget on stream resets per window; offenders become bouncer strikes | `conn` | [est.] one counter per connection | 0.3.0 |
| CONTINUATION floods | header block size budget across CONTINUATION frames, and a count of CONTINUATION frames per block; the block is refused when either is crossed, before more is buffered | `conn` | one add and compare per frame | 0.3.0 |
| settings and ping floods | rate budgets | `conn` | [est.] one counter per frame type | 0.3.0 |
| stream exhaustion | concurrent stream cap | `conn` | none | 0.3.0 |
| request smuggling through downgrade | strict mapping; refuse pseudo-header and connection-specific header violations | `conn` | one pass over the fields already decoded | 0.3.0 |

## 6. Ideas and experiments

- **Work-weighted reset budget** (for 0.3.0). Hypothesis: a rapid-reset client is told apart from a browser that cancels navigations by the ratio of reset streams to streams whose response was sent, better than by resets per second alone, and without a clock. Method: count resets and completed responses per connection; refuse (GOAWAY `ENHANCE_YOUR_CALM`) when resets exceed a floor (for example 100) and also exceed completed responses by a factor (for example 4); compare against a time-window budget with recorded browser traces and with the CVE-2023-44487 pattern. Expected cost [est.]: two counters per connection, one compare per reset.
- **Oversized field sections answered, not fatal.** A block over the header list budget is still decoded to the end (to keep the dynamic table in step) but nothing past the budget is stored, so the request gets 431 and the connection goes on. Built in 0.2.0; the connection layer decides the answer in 0.3.0.

## 7. Benchmarks

`benches/codec.rs`, criterion medians on one Windows development machine (2026-11-20); they compare builds of this crate with each other, not with other servers.

| Benchmark | Median | Per item |
|---|---|---|
| `frame/decode_10k_mixed` (HEADERS, 1 KiB DATA, WINDOW_UPDATE, PING) | 28.9 us | 2.9 ns a frame |
| `frame/encode_16k_data` (1,000 frames) | 257 us | 257 ns a 16 KiB frame (the copy) |
| `hpack/decode_browser_request` (17 fields, 10,000 requests, warm table) | 4.36 ms | 436 ns a request |
| `hpack/encode_response` (11 fields, 10,000 responses) | 5.38 ms | 538 ns a response |
| `hpack/bomb` (1,000 indexed 4 KB fields against a 16 KiB budget) | 4.45 us | stops at the budget |
| `huffman/decode_1k` | 2.91 us | 336 MiB/s |
| `huffman/encode_1k` | 1.29 us | 757 MiB/s |

Known room, not yet taken: the encoder finds names by a linear scan of the static table (a match on the name would replace it), and the Huffman decoder reads one symbol per step (a multi-bit state table would read several). Neither is a budget question; both wait for a profile of the connection engine, which decides what dominates.

## 8. Prerequisites

net-io, tls-net (ALPN), serve-net's engine slot, http-net's request types.

## 9. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-007 | 2026-11-20 | The roadmap is cut by layer: 0.2.0 is the codec (frames and HPACK, API locked for those modules), 0.3.0 the connection engine with every budget in section 5 and the mapping to http-net's types, then serve-net's ALPN selection | the codec has no state beyond the HPACK tables and can be locked and fuzzed on its own; the connection's API depends on serve-net's engine slot, which needs work for several streams per connection |
| D-006 | 2026-11-20 | The HPACK encoder sends an index for any exact match, otherwise a literal with incremental indexing, except for sensitive fields and credentials (never indexed), fields larger than half the table, and names whose values rarely repeat (`:path`, `content-length`, `date`, `etag`, and similar); strings are Huffman coded when that is shorter; the table is the smaller of the caller's limit and the peer's setting, and every change is signalled at the start of the next block (the smallest size since the last block first) | indexing everything evicts the entries that repeat (`content-type`, `server`, `cache-control`) for ones that never will; credentials in a shared table are the CRIME family's target. Cost: none beyond a linear scan of at most 61 static entries and the dynamic entries (at most the table size over 32) per field; a hash index can replace the scan if a benchmark shows it matters |
| D-005 | 2026-11-20 | An HPACK dynamic table stores its entries back to back in one buffer, oldest first; eviction moves the start forward, and when an insert would pass twice the maximum size the live entries move to the front | entries stay contiguous, so a name or value is one slice, and an insert never allocates once the buffer has grown. Cost: memory up to twice the table size per table (8 KiB per direction at the default 4096); at most one byte moved per byte inserted |
| D-004 | 2026-11-20 | The HPACK decoder takes one whole field block (the caller joins `HEADERS` or `PUSH_PROMISE` and its `CONTINUATION` fragments under the block budget) and decodes it into a `HeaderList` with a budget; a block over the budget is decoded to the end without storing the rest, and the list says it is oversized. Integers stop at four continuation bytes (28 bits past the prefix). The static table and Huffman code are generated from RFC 7541's text and checked by tests (canonical, complete, every symbol round-trips, every Appendix C example) | a block decoded in pieces needs a resumable decoder for no gain once the block itself is bounded; stopping at the budget would leave the table out of step with the peer, which turns a too-large request into a dead connection. Security: the work per block is linear in its length and the memory is the budget, whatever the block references. Cost: one copy of each Huffman string into a scratch buffer, none for plain literals |
| D-003 | 2026-11-20 | `frame::decode` reads one frame from the front of a buffer as a borrowed view; refusals RFC 9113 scopes to a stream (`PRIORITY` of the wrong length or depending on itself, `WINDOW_UPDATE` of 0 on a stream) come back as `Decoded::StreamError` with the length to skip, every other refusal is a connection error. A `HEADERS` frame whose stream depends on itself is a connection error. `frame::encode` refuses every frame `decode` would refuse, so `decode(encode(f)) == f` | the connection must skip a stream-scoped bad frame and go on; a `HEADERS` frame cannot be skipped without decoding its field block to keep HPACK in step, and RFC 9113 lets any stream error be treated as a connection error, so the simpler answer is the safe one and no correct peer sends it. Symmetry makes the encoder fuzzable against the decoder |
| D-002 | 2026-11-20 | `no_std` with `alloc`, no features, no runtime dependencies for the codec layer | the codec needs nothing from `std`; http-net is `no_std` too, so the mapping layer can keep it |
| D-001 | 2026-10-13 | Scheduled after the first site. Started 2026-11-20 | the front end handles HTTP/2 in the first deployment; direct mode needs it next |
