# h2-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Design and decisions: [`PLAN.md`](./PLAN.md).
>
> **Scheduled later** in the stack build order. Work starts when its trigger in PLAN.md is reached.
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE, 2026-10-13)
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.

## v0.2.0 - Design lock
- [ ] Frame, HPACK, stream, and mapping APIs.

## v0.3.0 - Engine
- [ ] Frames, HPACK, streams, flow control, settings, GOAWAY; mapping to http-net types.
- [ ] Attack tests for every row in PLAN section 4.

## v1.0.0 - Stable
- [ ] Frozen after direct mode has served HTTP/2 in production.
