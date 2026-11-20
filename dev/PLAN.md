# h2-net - Project Plan

> The design, strategy, and decision record for `h2-net`. A living document: every design decision, idea, or open question about h2-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Status:** in development since 2026-11-20 (D-001). The codec (frames and HPACK), the server and client connection, and RFC 9218 priority signals are built; serve-net's side (several streams per connection, ALPN `h2`) is next, once h2-net is published. Released: `0.3.0` (tagged on GitHub; not yet on crates.io).

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
| Connection | `conn` | streams, windows, settings, budgets | built (0.3.0) |
| Mapping | `conn` | none | built (0.3.0) |

Every layer is sans-IO and `no_std` with `alloc`. The frame layer checks what a frame says about itself (length, stream identifier, padding, setting values); whether a frame is allowed in the connection's state is the connection's job.

## 5. Threats (HTTP/2 has its own attack history)

Every defence states its cost. Figures marked [est.] are estimates until a benchmark replaces them.

| Attack | Defence | Where | Cost | Status |
|---|---|---|---|---|
| oversized frames | a frame longer than `SETTINGS_MAX_FRAME_SIZE` is refused from its 9-byte header, before its payload is buffered | `frame::decode` | one compare per frame | built |
| HPACK bombs | each field is checked against the header list budget (RFC 9113's size: name, value, 32) before its bytes are copied; the dynamic table never exceeds the size this side advertised | `hpack` | one add and compare per field; memory is the budget | built |
| HPACK state abuse | integers with more than four continuation bytes, size updates over the advertised maximum or after a field, a missing size update after a reduction, and EOS or bad Huffman padding are all refused as `COMPRESSION_ERROR` | `hpack` | none on valid input | built |
| compression side channels (CRIME family) | the encoder never indexes credentials (`authorization`, `proxy-authorization`, `cookie`, `set-cookie`) or a field the caller marks sensitive, and keeps the never-indexed mark when decoding so a proxy can keep it | `hpack::Encoder` | those fields are sent as literals every time (a few dozen bytes per response that sets a cookie) | built |
| rapid reset (CVE-2023-44487) | reset budget weighed against work: once streams reset by the peer before their response completed exceed a floor (200) and also 4 times the responses completed, `GOAWAY` `ENHANCE_YOUR_CALM` | `conn` | two counters, one compare per reset | built |
| provoked resets ("MadeYouReset", 2025) | resets this side sends for the peer's errors (a zero `WINDOW_UPDATE`, a bad `content-length`, a malformed request, a stream over the cap) count against the same budget, and the application hears of each reset stream (`Event::Reset`) so it stops the work | `conn` | as above | built |
| CONTINUATION floods (2024) | a field block's bytes are capped (64 KiB) before they are buffered, and its `CONTINUATION` frames are counted (32), empty ones included | `conn` | one add and two compares per frame | built |
| settings, ping, and other control floods | control frames (`SETTINGS` after the first, `PING`, `PRIORITY`, `PRIORITY_UPDATE`, empty `DATA`, unknown types, frames for closed streams) are weighed against work: over a floor (1000) and 10 times the requests and `DATA` frames, `ENHANCE_YOUR_CALM` | `conn` | two counters | built |
| a peer that sends but does not read | answers waiting unread in the output (acknowledgments, resets) are capped (1000), and `send_data` fills the output only up to a bound (256 KiB) whatever window the peer opens | `conn` | one counter; output memory is the bound | built |
| stream exhaustion | concurrent stream cap (100); a stream over it is reset `REFUSED_STREAM`, after its field block is decoded so HPACK stays in step | `conn` | none | built |
| request smuggling through downgrade | the request is checked by RFC 9113 section 8 (lowercase token names, no NUL, CR, LF, or edge whitespace in values, no connection-specific fields, `te` only `trailers`, pseudo-headers known, once, first, and complete, `:path` origin-form or `*` for `OPTIONS`, no userinfo, `host` agreeing with `:authority`), then written as HTTP/1.1 and parsed by http-net with its own strictness; `content-length` is checked against the body | `conn` | one pass over the fields and one HTTP/1.1 parse of the head [est. under 1 us] | built |
| oversized field sections | decoded to the end (HPACK stays in step), answered `431`, and the rest of the body refused with `RST_STREAM` `NO_ERROR`; the connection goes on | `conn` | none beyond the decode | built |

Each budget comes with an attack test that ends the connection with it and gets through with it turned off.

## 6. Ideas and experiments

- **Work-weighted reset budget** (built in 0.3.0; the trace comparison is open). Hypothesis: a rapid-reset client is told apart from a browser that cancels navigations by the ratio of reset streams to streams whose response was sent, better than by resets per second alone, and without a clock. Method: count resets and completed responses per connection; refuse (GOAWAY `ENHANCE_YOUR_CALM`) when resets exceed a floor (for example 100) and also exceed completed responses by a factor (for example 4); compare against a time-window budget with recorded browser traces and with the CVE-2023-44487 pattern. Expected cost [est.]: two counters per connection, one compare per reset.
- **Oversized field sections answered, not fatal.** A block over the header list budget is still decoded to the end (to keep the dynamic table in step) but nothing past the budget is stored, so the request gets 431 and the connection goes on. Built.
- **Head pooling** (tried 2026-11-20, rejected). Hypothesis: reusing a head's vectors removes two allocations per request. Method: parse each head straight into pooled vectors and rebuild the owned head with http-net's `OwnedRequestHead::from_parts`; `conn/requests_10k` with and without the pool. Result: 24.3 ms without the pool, 25.8 ms with every head given back, 29.9 ms with none given back. `from_parts` checks the head again, which costs more than the allocations it saves. The pool was taken out. What would work is a constructor in http-net that keeps a head it has just parsed without checking it again; that is http-net's to offer, and is noted for it.

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
| `conn/requests_10k` (17-field GET, 10-field response with a 1 KiB body, on one connection) | 24.3 ms | 2.4 us a request and its response |

### HTTP/2 against HTTP/1.1 (2026-11-20)

`h1/requests_10k` runs the `conn/requests_10k` work through http-net's HTTP/1.1 server connection: the same 17 request fields, the same response fields and 1 KiB body, one connection, the head written with `write_head` (no allocation). Alternated runs on one machine:

| Benchmark | Before | After the changes below | Per request |
|---|---|---|---|
| `h1/requests_10k` | 3.66 ms | 3.51 ms | 0.35 us |
| `conn/requests_10k` | 24.3 ms | 21.6 ms | 2.16 us |
| `hpack/encode_response` | 5.38 ms | 3.01 ms | 0.30 us |
| `hpack/decode_browser_request` | 4.36 ms | 4.29 ms | 0.43 us |

HTTP/2 costs about six times HTTP/1.1 per request here. Of the 2.16 us: HPACK decode 0.43 and encode 0.30; the mapping onto http-net (the head written out as HTTP/1.1, parsed, and copied into an owned head) about an HTTP/1.1 parse, 0.4 [est.]; the rest, about 1 us, is framing, stream bookkeeping, events, and output, not yet broken down. Taken so far: the encoder finds static names through a generated `match` on the name instead of scanning all 61 entries (encode -44%), and a response head reuses one scratch list instead of allocating one (no allocation per head beyond the owned request head).

Next, each written as an experiment:
- **Profile the 1 us.** Hypothesis: most of it is the per-stream map, the event queue, and the copies of each frame into and out of the buffers. Method: a sampling profile of `conn/requests_10k` on Linux (perf), then a benchmark per piece. Expected cost: none at run time.
- **Owned head without a second check.** Hypothesis: building the owned head straight from the parse saves two allocations and a copy per request. Method: an http-net constructor that keeps a head it has just parsed (the pooling attempt in section 6 failed only on `from_parts` checking the head again). Expected cost [est.]: 50 to 100 ns a request saved; an http-net change.
- **Huffman decode by nibble.** Hypothesis: a 4-bit state table halves Huffman decode, which is most of decoding a `:path` and a `cookie` sent as literals each time. Method: the table generated from the code, fuzzed against the current decoder. Expected cost: a 4 KiB table.

None of these is a budget question: every check stays as it is.

## 8. Prerequisites

net-io, tls-net (ALPN), serve-net's engine slot, http-net's request types.

## 9. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-015 | 2026-11-20 | The connection is `Connection<R: Role>` with `ServerConn` and `ClientConn` as aliases; the role is a sealed marker type, and every place the sides differ reads `R::CLIENT`, a constant, so each side compiles to its own code. Shared: the input and output, settings, `PING`, flow control, field blocks, `GOAWAY`, and every budget except the reset budget, which a client does not charge (a server resetting the client's own requests costs the client nothing it did not choose). The client sends the preface with `SETTINGS_ENABLE_PUSH` 0, opens odd streams with `send_request(RequestParts, end_stream)` (`:authority` carries the host, so a `host` field is dropped with the connection-specific ones), waits with `SendError::Busy` at the peer's stream limit, and checks responses by RFC 9113 section 8.3: one three-digit `:status` first, informational heads never ending the stream and never `101`, no body before the head or on a response to `HEAD`, `204`, or `304`, `content-length` against the body. A malformed response resets its stream with `PROTOCOL_ERROR`. On `GOAWAY` every stream above the last one named is reported reset with `REFUSED_STREAM` (safe to retry). `PUSH_PROMISE` and `PRIORITY_UPDATE` from a server end the connection | one implementation of the protocol and its budgets for both sides, so a fix or a budget on one side is on the other; a generic over a constant keeps the server's code path as it was: `conn/requests_10k` run alternately against the code before, on the same machine, came out level (27.2 against 27.9 ms and 28.6 against 28.8 ms; the machine was busier than for the baseline in section 7). A client is the receiving end of a hostile server as often as a server is of a hostile client (a proxy's upstream), so the same budgets apply. Responses are reported as status and `HeaderList`; http-net has no owned response head to map onto, which is noted for http-net |
| D-014 | 2026-11-20 | Extensible priorities (RFC 9218) are read and reported, not acted on: the `priority` field (several fields joined as one dictionary) gives `Event::Request`'s `priority`, a `PRIORITY_UPDATE` that arrives first wins over it, and a later one is `Event::Priority`; `ServerConn::priority` reads a stream's current one. Values are parsed as RFC 8941 dictionaries: a value that does not parse gives the defaults (a `PRIORITY_UPDATE` with one is ignored), a member of the wrong type or out of range keeps its default. Updates for streams not yet opened are kept for at most the stream cap of streams, and dropped once a higher stream opens. A `PRIORITY_UPDATE` for an even stream ends the connection | ordering responses is the scheduler's job, and the scheduler is the driver's (serve-net's); the engine's part is to read the signals exactly and bound what it keeps. Security: the parser is linear, allocates only when a request carries two or more `priority` fields, and is fuzzed; `PRIORITY_UPDATE` frames still count against the control budget. Cost: no change in `conn/requests_10k` (24.3 ms before and after) |
| D-013 | 2026-11-20 | Graceful shutdown is RFC 9113's two steps: a `GOAWAY` that admits every stream and a `PING`; when the `PING` is answered, a `GOAWAY` naming the last stream served, after which new streams are ignored (their blocks still decoded). `close(code)` ends at once. `SETTINGS_TIMEOUT` and idle deadlines are the driver's: `settings_acked()` says whether to wait | without a clock the round trip is the only safe signal that the client saw the first `GOAWAY`; deadlines belong to the layer that owns time (net-io and serve-net) |
| D-012 | 2026-11-20 | Request bodies are not buffered: `Event::Data` borrows the input, and the application gives bytes back with `release` (window updates at half a window); `auto_release` gives them back as they are handed out. `send_data` takes what the windows and the output bound allow and reports `Event::Writable` when a stream it could not finish has window again. A response's `content-length` is enforced on the bytes sent; `HEAD`, `204`, and `304` end with the head | the window is what holds a peer back while the application is slow, so releasing on hand-out by default would remove the only backpressure per stream. Memory: the input buffer (two frames), the output bound, and whatever the application holds, at most the stream window per stream |
| D-011 | 2026-11-20 | Budgets need no clock: resets and control frames are weighed against work done (responses completed; requests and `DATA` frames received) above a floor, and unread answers are capped. Offences end the connection with `ENHANCE_YOUR_CALM` and `ConnError::is_abuse()`, so serve-net can make them bouncer strikes | a sans-IO engine has no time of its own, and a rate in frames per second punishes a busy legitimate connection as much as an idle hostile one; the ratio tracks what the peer costs against what it asked for. Resets this side sends for the peer's errors count too, which covers resets a peer provokes (the 2025 "MadeYouReset" class). Cost: five counters per connection |
| D-010 | 2026-11-20 | A request maps onto http-net by writing it out as the HTTP/1.1 head a translating proxy would send (`host` from `:authority`, `cookie` fields joined with "; ", `transfer-encoding: chunked` when a body follows without `content-length`) and parsing it with http-net into an `OwnedRequestHead`; the scheme comes alongside. Responses go in as status and `(name, value)` pairs, names lowercased and HTTP/1.1's connection-specific fields dropped, so an HTTP/1.1 response maps across unchanged | the same type, accessors, and strictness for both versions without a second parser to keep in step; the head's framing then tells the truth about the body. `version()` reads HTTP/1.1 until http-net has a value for HTTP/2 (its `Version` is non-exhaustive). Cost: one copy and one HTTP/1.1 parse of each head, and two allocations for the owned head (pooling is in section 6) |
| D-009 | 2026-11-20 | Frames on streams this side reset are ignored for a while (a ring of the last 2 x the stream cap, at least 256); `DATA` or `HEADERS` on other closed streams ends the connection (`STREAM_CLOSED`); `DATA` on a stream the peer already ended resets it. Field blocks are always decoded before the stream is looked at | late frames after a reset are normal; after a clean close they are a bug in the peer, and RFC 9113 lets a stream error be a connection error. Decoding first keeps HPACK in step whatever happens to the stream. Cost: the ring, 4 bytes an entry |
| D-008 | 2026-11-20 | `conn::ServerConn` is the sans-IO server connection: `feed` copies into an input buffer of two maximum frames, `poll` returns `Event`s, `output` and `consume_output` hand out the bytes to write. It writes its `SETTINGS` (with `SETTINGS_NO_RFC7540_PRIORITIES`) and a connection `WINDOW_UPDATE` at once, and answers `SETTINGS`, `PING`, and flow control itself. Depends on http-net 0.10 with default features off, so the crate stays `no_std` | the same shape as http-net's `ServerConn`, so a driver (serve-net) handles both alike. Server push is never sent, and a client's `PUSH_PROMISE` ends the connection |
| D-007 | 2026-11-20 | The roadmap is cut by layer: 0.2.0 is the codec (frames and HPACK, API locked for those modules), 0.3.0 the connection engine with every budget in section 5 and the mapping to http-net's types, then serve-net's ALPN selection | the codec has no state beyond the HPACK tables and can be locked and fuzzed on its own; the connection's API depends on serve-net's engine slot, which needs work for several streams per connection |
| D-006 | 2026-11-20 | The HPACK encoder sends an index for any exact match, otherwise a literal with incremental indexing, except for sensitive fields and credentials (never indexed), fields larger than half the table, and names whose values rarely repeat (`:path`, `content-length`, `date`, `etag`, and similar); strings are Huffman coded when that is shorter; the table is the smaller of the caller's limit and the peer's setting, and every change is signalled at the start of the next block (the smallest size since the last block first) | indexing everything evicts the entries that repeat (`content-type`, `server`, `cache-control`) for ones that never will; credentials in a shared table are the CRIME family's target. Cost: none beyond a linear scan of at most 61 static entries and the dynamic entries (at most the table size over 32) per field; a hash index can replace the scan if a benchmark shows it matters |
| D-005 | 2026-11-20 | An HPACK dynamic table stores its entries back to back in one buffer, oldest first; eviction moves the start forward, and when an insert would pass twice the maximum size the live entries move to the front | entries stay contiguous, so a name or value is one slice, and an insert never allocates once the buffer has grown. Cost: memory up to twice the table size per table (8 KiB per direction at the default 4096); at most one byte moved per byte inserted |
| D-004 | 2026-11-20 | The HPACK decoder takes one whole field block (the caller joins `HEADERS` or `PUSH_PROMISE` and its `CONTINUATION` fragments under the block budget) and decodes it into a `HeaderList` with a budget; a block over the budget is decoded to the end without storing the rest, and the list says it is oversized. Integers stop at four continuation bytes (28 bits past the prefix). The static table and Huffman code are generated from RFC 7541's text and checked by tests (canonical, complete, every symbol round-trips, every Appendix C example) | a block decoded in pieces needs a resumable decoder for no gain once the block itself is bounded; stopping at the budget would leave the table out of step with the peer, which turns a too-large request into a dead connection. Security: the work per block is linear in its length and the memory is the budget, whatever the block references. Cost: one copy of each Huffman string into a scratch buffer, none for plain literals |
| D-003 | 2026-11-20 | `frame::decode` reads one frame from the front of a buffer as a borrowed view; refusals RFC 9113 scopes to a stream (`PRIORITY` of the wrong length or depending on itself, `WINDOW_UPDATE` of 0 on a stream) come back as `Decoded::StreamError` with the length to skip, every other refusal is a connection error. A `HEADERS` frame whose stream depends on itself is a connection error. `frame::encode` refuses every frame `decode` would refuse, so `decode(encode(f)) == f` | the connection must skip a stream-scoped bad frame and go on; a `HEADERS` frame cannot be skipped without decoding its field block to keep HPACK in step, and RFC 9113 lets any stream error be treated as a connection error, so the simpler answer is the safe one and no correct peer sends it. Symmetry makes the encoder fuzzable against the decoder |
| D-002 | 2026-11-20 | `no_std` with `alloc`, no features, no runtime dependencies for the codec layer | the codec needs nothing from `std`; http-net is `no_std` too, so the mapping layer can keep it |
| D-001 | 2026-10-13 | Scheduled after the first site. Started 2026-11-20 | the front end handles HTTP/2 in the first deployment; direct mode needs it next |
