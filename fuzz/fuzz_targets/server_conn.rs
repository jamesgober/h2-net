//! A server connection driven by an arbitrary client (well-formed frames
//! with arbitrary contents, and raw bytes) and an arbitrary application
//! (responses, bodies, trailers, releases, resets, shutdown, reading the
//! output or not). Oracles: no panic; open streams never exceed the cap; the
//! output stays bounded however the client behaves; once the connection
//! fails it reports the same error on every call and takes no more input.

#![no_main]

use arbitrary::Arbitrary;
use h2_net::conn::{Config, Event, ServerConn};
use h2_net::frame::{self, Frame, Priority, StreamId};
use h2_net::hpack::{Encoder, HeaderField};
use h2_net::ErrorCode;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    Raw(Vec<u8>),
    Request { stream: u8, path: u8, end: bool, extra: Vec<(Vec<u8>, Vec<u8>)> },
    Headers { stream: u8, fields: Vec<(Vec<u8>, Vec<u8>)>, end_stream: bool, end_headers: bool },
    Continuation { stream: u8, fragment: Vec<u8>, end: bool },
    Data { stream: u8, len: u16, end: bool, pad: Option<u8> },
    Rst { stream: u8, code: u32 },
    Window { stream: u8, inc: u32 },
    Settings(Vec<(u16, u32)>),
    SettingsAck,
    Ping { ack: bool },
    Priority { stream: u8, dep: u8 },
    PriorityUpdate { stream: u8, field: Vec<u8> },
    GoAway,
    Respond { stream: u8, status: u16, end: bool },
    Send { stream: u8, len: u16, end: bool },
    Trailers { stream: u8 },
    Release { stream: u8, n: u16 },
    Reset { stream: u8 },
    Shutdown,
    ReadOutput,
}

fn sid(n: u8) -> StreamId {
    StreamId::masked(u32::from(n))
}

const CAP: u32 = 8;

fuzz_target!(|ops: Vec<Op>| {
    let config = Config::new()
        .max_concurrent_streams(CAP)
        .max_header_list_size(2048)
        .max_output(64 * 1024);
    let mut conn = ServerConn::new(config);
    let mut enc = Encoder::new(4096);
    let mut wire = frame::PREFACE.to_vec();
    frame::settings_frame(&[], 16_384, &mut wire).unwrap();
    let body = vec![0x61u8; 70_000];
    let mut failed = None;

    for op in ops.iter().take(200) {
        let mut out = Vec::new();
        let enc_frame = |f: &Frame<'_>, out: &mut Vec<u8>| {
            let _ = frame::encode(f, 16_384, out);
        };
        match op {
            Op::Raw(b) => out.extend_from_slice(b),
            Op::Request { stream, path, end, extra } => {
                let path = format!("/{path}");
                let mut fields = vec![
                    HeaderField::new(b":method", if *end { b"GET" } else { b"POST" }),
                    HeaderField::new(b":scheme", b"https"),
                    HeaderField::new(b":authority", b"a.example"),
                    HeaderField::new(b":path", path.as_bytes()),
                ];
                for (n, v) in extra.iter().take(4) {
                    fields.push(HeaderField::new(n, v));
                }
                let mut block = Vec::new();
                enc.encode(fields, &mut block);
                enc_frame(
                    &Frame::Headers {
                        stream: sid(*stream),
                        end_stream: *end,
                        end_headers: true,
                        priority: None,
                        fragment: &block,
                        padding: None,
                    },
                    &mut out,
                );
            }
            Op::Headers { stream, fields, end_stream, end_headers } => {
                let mut block = Vec::new();
                enc.encode(fields.iter().take(8).map(|(n, v)| HeaderField::new(n, v)), &mut block);
                enc_frame(
                    &Frame::Headers {
                        stream: sid(*stream),
                        end_stream: *end_stream,
                        end_headers: *end_headers,
                        priority: None,
                        fragment: &block,
                        padding: None,
                    },
                    &mut out,
                );
            }
            Op::Continuation { stream, fragment, end } => enc_frame(
                &Frame::Continuation { stream: sid(*stream), end_headers: *end, fragment },
                &mut out,
            ),
            Op::Data { stream, len, end, pad } => enc_frame(
                &Frame::Data {
                    stream: sid(*stream),
                    end_stream: *end,
                    data: &body[..usize::from(*len).min(16_000)],
                    padding: *pad,
                },
                &mut out,
            ),
            Op::Rst { stream, code } => enc_frame(
                &Frame::RstStream { stream: sid(*stream), code: ErrorCode::new(*code) },
                &mut out,
            ),
            Op::Window { stream, inc } => enc_frame(
                &Frame::WindowUpdate { stream: sid(*stream), increment: *inc },
                &mut out,
            ),
            Op::Settings(params) => {
                let p: Vec<_> = params
                    .iter()
                    .take(8)
                    .map(|(i, v)| (frame::SettingId::new(*i), *v))
                    .collect();
                let _ = frame::settings_frame(&p, 16_384, &mut out);
            }
            Op::SettingsAck => enc_frame(&Frame::Settings(frame::Settings::ack()), &mut out),
            Op::Ping { ack } => enc_frame(&Frame::Ping { ack: *ack, payload: [1; 8] }, &mut out),
            Op::Priority { stream, dep } => enc_frame(
                &Frame::Priority {
                    stream: sid(*stream),
                    priority: Priority { exclusive: false, depends_on: sid(*dep), weight: 0 },
                },
                &mut out,
            ),
            Op::PriorityUpdate { stream, field } => enc_frame(
                &Frame::PriorityUpdate { prioritized: sid(*stream), field },
                &mut out,
            ),
            Op::GoAway => enc_frame(
                &Frame::GoAway { last_stream: StreamId::ZERO, code: ErrorCode::NO_ERROR, debug: b"" },
                &mut out,
            ),
            Op::Respond { stream, status, end } => {
                let _ = conn.send_headers(sid(*stream), *status, &[("content-type", b"text/plain")], *end);
            }
            Op::Send { stream, len, end } => {
                let _ = conn.send_data(sid(*stream), &body[..usize::from(*len)], *end);
            }
            Op::Trailers { stream } => {
                let _ = conn.send_trailers(sid(*stream), &[("x-done", b"1")]);
            }
            Op::Release { stream, n } => conn.release(sid(*stream), usize::from(*n)),
            Op::Reset { stream } => conn.reset(sid(*stream), ErrorCode::CANCEL),
            Op::Shutdown => conn.shutdown(),
            Op::ReadOutput => {
                let n = conn.output().len();
                conn.consume_output(n);
            }
        }
        wire.extend_from_slice(&out);

        // Feed what the client wrote, polling as a driver would.
        loop {
            let n = conn.feed(&wire);
            if failed.is_some() {
                assert_eq!(n, 0, "a failed connection took input");
            }
            let _ = wire.drain(..n);
            loop {
                match conn.poll() {
                    Ok(Some(Event::Request { stream, end_stream, .. })) => {
                        if end_stream {
                            let _ = conn.send_headers(stream, 204, &[], true);
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(e) => {
                        if let Some(prev) = failed {
                            assert_eq!(prev, e, "a failed connection changed its error");
                        }
                        failed = Some(e);
                        break;
                    }
                }
            }
            assert!(conn.open_streams() <= CAP as usize);
            if n == 0 || wire.is_empty() || failed.is_some() {
                break;
            }
        }
        // Output: the data budget, plus headers the application wrote, plus
        // answers under their own budget. Generous, but bounded.
        assert!(conn.output().len() <= 64 * 1024 + 16_384 + 1000 * 32 + 200 * 4096, "{}", conn.output().len());
    }
});
