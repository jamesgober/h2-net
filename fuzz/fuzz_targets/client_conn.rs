//! A client connection driven by an arbitrary server (well-formed frames
//! with arbitrary contents, and raw bytes) while it sends requests and
//! bodies. Oracles: no panic; open streams never exceed what the client
//! opened; once the connection fails it reports the same error on every
//! call and takes no more input; a refused request writes nothing.

#![no_main]

use arbitrary::Arbitrary;
use h2_net::ErrorCode;
use h2_net::conn::{ClientConn, Config, RequestParts, Scheme};
use h2_net::frame::{self, Frame, StreamId};
use h2_net::hpack::{Encoder, HeaderField};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    Raw(Vec<u8>),
    Settings(Vec<(u16, u32)>),
    SettingsAck,
    Headers { stream: u8, fields: Vec<(Vec<u8>, Vec<u8>)>, end_stream: bool, end_headers: bool },
    Status { stream: u8, status: u16, end_stream: bool },
    Continuation { stream: u8, fragment: Vec<u8>, end: bool },
    Data { stream: u8, len: u16, end: bool },
    Rst { stream: u8, code: u32 },
    Window { stream: u8, inc: u32 },
    Ping { ack: bool },
    GoAway { last: u8, code: u32 },
    Request { path: u8, end: bool, body: bool },
    Send { stream: u8, len: u16, end: bool },
    Release { stream: u8, n: u16 },
    Reset { stream: u8 },
    Shutdown,
    ReadOutput,
}

fn sid(n: u8) -> StreamId {
    StreamId::masked(u32::from(n))
}

fuzz_target!(|ops: Vec<Op>| {
    let mut client = ClientConn::new(Config::new().max_header_list_size(2048));
    let mut enc = Encoder::new(4096);
    let body = vec![0x62u8; 40_000];
    let mut opened = 0usize;
    let mut failed = None;
    for op in ops.iter().take(200) {
        let mut wire = Vec::new();
        let put = |f: &Frame<'_>, wire: &mut Vec<u8>| {
            let _ = frame::encode(f, 16_384, wire);
        };
        match op {
            Op::Raw(b) => wire.extend_from_slice(b),
            Op::Settings(p) => {
                let p: Vec<_> = p.iter().take(8).map(|(i, v)| (frame::SettingId::new(*i), *v)).collect();
                let _ = frame::settings_frame(&p, 16_384, &mut wire);
            }
            Op::SettingsAck => put(&Frame::Settings(frame::Settings::ack()), &mut wire),
            Op::Headers { stream, fields, end_stream, end_headers } => {
                let mut block = Vec::new();
                enc.encode(fields.iter().take(8).map(|(n, v)| HeaderField::new(n, v)), &mut block);
                put(
                    &Frame::Headers {
                        stream: sid(*stream),
                        end_stream: *end_stream,
                        end_headers: *end_headers,
                        priority: None,
                        fragment: &block,
                        padding: None,
                    },
                    &mut wire,
                );
            }
            Op::Status { stream, status, end_stream } => {
                let text = status.to_string();
                let mut block = Vec::new();
                enc.encode([HeaderField::new(b":status", text.as_bytes())], &mut block);
                put(
                    &Frame::Headers {
                        stream: sid(*stream),
                        end_stream: *end_stream,
                        end_headers: true,
                        priority: None,
                        fragment: &block,
                        padding: None,
                    },
                    &mut wire,
                );
            }
            Op::Continuation { stream, fragment, end } => put(
                &Frame::Continuation { stream: sid(*stream), end_headers: *end, fragment },
                &mut wire,
            ),
            Op::Data { stream, len, end } => put(
                &Frame::Data {
                    stream: sid(*stream),
                    end_stream: *end,
                    data: &body[..usize::from(*len).min(16_000)],
                    padding: None,
                },
                &mut wire,
            ),
            Op::Rst { stream, code } => put(
                &Frame::RstStream { stream: sid(*stream), code: ErrorCode::new(*code) },
                &mut wire,
            ),
            Op::Window { stream, inc } => put(
                &Frame::WindowUpdate { stream: sid(*stream), increment: *inc },
                &mut wire,
            ),
            Op::Ping { ack } => put(&Frame::Ping { ack: *ack, payload: [3; 8] }, &mut wire),
            Op::GoAway { last, code } => put(
                &Frame::GoAway { last_stream: sid(*last), code: ErrorCode::new(*code), debug: b"" },
                &mut wire,
            ),
            Op::Request { path, end, body } => {
                let path = format!("/{path}");
                let length = if *body { "5" } else { "0" };
                let head = RequestParts {
                    method: "POST",
                    scheme: Scheme::Https,
                    authority: "a.example",
                    path: &path,
                    fields: &[("content-length", length.as_bytes())],
                };
                let before = client.output().len();
                match client.send_request(&head, *end && !*body) {
                    Ok(_) => opened += 1,
                    Err(_) => assert_eq!(client.output().len(), before, "a refused request wrote"),
                }
            }
            Op::Send { stream, len, end } => {
                let n = usize::from(*len).min(body.len());
                let _ = client.send_data(sid(*stream), &body[..n], *end);
            }
            Op::Release { stream, n } => client.release(sid(*stream), usize::from(*n)),
            Op::Reset { stream } => client.reset(sid(*stream), ErrorCode::CANCEL),
            Op::Shutdown => client.shutdown(),
            Op::ReadOutput => {
                let n = client.output().len();
                client.consume_output(n);
            }
        }
        let mut rest = &wire[..];
        loop {
            let n = client.feed(rest);
            if failed.is_some() {
                assert_eq!(n, 0, "a failed connection took input");
            }
            rest = &rest[n..];
            loop {
                match client.poll() {
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
            assert!(client.open_streams() <= opened);
            if n == 0 || rest.is_empty() || failed.is_some() {
                break;
            }
        }
    }
});
