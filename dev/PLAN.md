# h2-net - Project Plan

> The design, strategy, and decision record for `h2-net`. A living document: every design decision, idea, or open question about h2-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Status:** scaffold, `0.1.0`. **Scheduled later** (see `_strategy/WEB-STACK-DELIVERABLES.md`): behind Apache or nginx, the front end speaks HTTP/2 to browsers and HTTP/1.1 to us.

---

## 1. Purpose

HTTP/2 (RFC 9113) as a sans-IO engine with the same strictness and budgets as http-net, selected by serve-net through ALPN.

## 2. Why later, and what triggers it

Direct mode (no Apache in front), or gRPC-style services between our own nodes.

## 3. Scope

- Frames: parsing and serialization for every frame type, size limits from settings.
- HPACK (RFC 7541) with bounded dynamic tables and Huffman coding.
- Stream state machine, flow control (connection and stream windows), settings, GOAWAY and graceful shutdown, priority signals (RFC 9218).
- Requests and responses mapped to the same types http-net produces, so serve-net and web-net do not care which version arrived.
- h2c (cleartext) only behind a trusted proxy.

## 4. Threats (HTTP/2 has its own attack history)

| Attack | Defence |
|---|---|
| rapid reset (CVE-2023-44487) | budget on stream resets per window; offenders become bouncer strikes |
| CONTINUATION floods | header block size budget across CONTINUATION frames |
| HPACK bombs | decoded header size budget; dynamic table cap |
| settings and ping floods | rate budgets |
| stream exhaustion | concurrent stream cap |
| request smuggling through downgrade | strict mapping; refuse pseudo-header and connection-specific header violations |

## 5. Prerequisites

net-io, tls-net (ALPN), serve-net's engine slot, http-net's request types.

## 6. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | Scheduled after the first site | the front end handles HTTP/2 in the first deployment |
