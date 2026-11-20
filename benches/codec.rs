//! Criterion benchmarks of the codec at realistic scale.
//!
//! - `frame/decode_10k_mixed`: 10,000 frames read back to back from one
//!   buffer, in the mix a page load sends (HEADERS, 1 KiB DATA,
//!   WINDOW_UPDATE, PING).
//! - `frame/encode_16k_data`: 1,000 DATA frames of 16 KiB.
//! - `hpack/decode_browser_request`: a browser-sized request section, 10,000
//!   times through one decoder, so the dynamic table is warm as it is on a
//!   real connection.
//! - `hpack/encode_response`: a typical response section, 10,000 times
//!   through one encoder.
//! - `hpack/bomb`: a 1,000-byte block of indexed fields that each name a
//!   4,000-byte entry, against a 16 KiB budget.
//! - `huffman/decode_1k` and `huffman/encode_1k`: a 1 KiB cookie-like value.
//! - `conn/requests_10k`: 10,000 browser-sized GET requests on one
//!   connection, each answered with a head and a 1 KiB body, the output read
//!   after each: the whole server path (frames, HPACK both ways, the
//!   mapping onto http-net, flow control).
//! - `h1/requests_10k`: the `conn/requests_10k` work through http-net's
//!   HTTP/1.1 server connection instead (the same request fields, the
//!   same response fields and 1 KiB body, one connection, the head written
//!   with `write_head`, which allocates nothing): the baseline HTTP/2 is
//!   compared with.
//! - `conn/client_server_10k`: 10,000 requests from a `ClientConn` to a
//!   `ServerConn` in memory, 100 at a time, each answered with a 1 KiB body:
//!   both sides of the protocol.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use h2_net::conn::{ClientConn, Config, Event, RequestParts, Scheme, ServerConn};
use h2_net::frame::{self, Decoded, Frame, StreamId};
use h2_net::hpack::{Decoder, Encoder, HeaderField, HeaderList, huffman};

const REQUEST: &[(&[u8], &[u8])] = &[
    (b":method", b"GET"),
    (b":scheme", b"https"),
    (b":authority", b"www.example.com"),
    (b":path", b"/assets/app.4f3c2a.js?v=20261120"),
    (b"sec-ch-ua", b"\"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\""),
    (b"sec-ch-ua-mobile", b"?0"),
    (b"user-agent", b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
    (b"sec-ch-ua-platform", b"\"Windows\""),
    (b"accept", b"*/*"),
    (b"sec-fetch-site", b"same-origin"),
    (b"sec-fetch-mode", b"no-cors"),
    (b"sec-fetch-dest", b"script"),
    (b"referer", b"https://www.example.com/"),
    (b"accept-encoding", b"gzip, deflate, br, zstd"),
    (b"accept-language", b"en-US,en;q=0.9"),
    (b"cookie", b"session=4f9a1c7e2b8d4e6f9a1c7e2b8d4e6f9a; theme=dark; consent=1"),
    (b"priority", b"u=1"),
];

const RESPONSE: &[(&[u8], &[u8])] = &[
    (b":status", b"200"),
    (b"content-type", b"text/javascript; charset=utf-8"),
    (b"content-length", b"48213"),
    (b"cache-control", b"public, max-age=31536000, immutable"),
    (b"etag", b"\"4f3c2a-bc55\""),
    (b"last-modified", b"Thu, 19 Nov 2026 10:00:00 GMT"),
    (b"date", b"Fri, 20 Nov 2026 12:00:00 GMT"),
    (b"server", b"serve-net"),
    (
        b"strict-transport-security",
        b"max-age=63072000; includeSubDomains",
    ),
    (b"x-content-type-options", b"nosniff"),
    (b"vary", b"accept-encoding"),
];

fn fields(
    list: &'static [(&'static [u8], &'static [u8])],
) -> impl Iterator<Item = HeaderField<'static>> {
    list.iter().map(|(n, v)| HeaderField::new(n, v))
}

fn sid(n: u32) -> StreamId {
    StreamId::new(n).unwrap()
}

fn bench_frames(c: &mut Criterion) {
    let mut g = c.benchmark_group("frame");
    let mut block = Vec::new();
    Encoder::new(4096).encode(fields(REQUEST), &mut block);
    let body = vec![0x5a; 1024];
    let mut wire = Vec::new();
    for i in 0..2500u32 {
        let stream = sid(i * 2 + 1);
        let frames = [
            Frame::Headers {
                stream,
                end_stream: false,
                end_headers: true,
                priority: None,
                fragment: &block,
                padding: None,
            },
            Frame::Data {
                stream,
                end_stream: true,
                data: &body,
                padding: None,
            },
            Frame::WindowUpdate {
                stream: StreamId::ZERO,
                increment: 1024,
            },
            Frame::Ping {
                ack: false,
                payload: [7; 8],
            },
        ];
        for f in &frames {
            frame::encode(f, frame::DEFAULT_MAX_FRAME_SIZE, &mut wire).unwrap();
        }
    }
    g.throughput(Throughput::Bytes(wire.len() as u64));
    g.bench_function("decode_10k_mixed", |b| {
        b.iter(|| {
            let mut rest = black_box(&wire[..]);
            let mut n = 0usize;
            while let Ok(Decoded::Frame { frame, len }) =
                frame::decode(rest, frame::DEFAULT_MAX_FRAME_SIZE)
            {
                n += frame.flow_len() as usize;
                rest = &rest[len..];
            }
            n
        });
    });

    let data = vec![0x33; 16 * 1024];
    let mut out = Vec::with_capacity(1000 * (9 + data.len()));
    g.throughput(Throughput::Bytes(1000 * data.len() as u64));
    g.bench_function("encode_16k_data", |b| {
        b.iter(|| {
            out.clear();
            for i in 0..1000u32 {
                let f = Frame::Data {
                    stream: sid(i * 2 + 1),
                    end_stream: true,
                    data: black_box(&data),
                    padding: None,
                };
                frame::encode(&f, frame::DEFAULT_MAX_FRAME_SIZE, &mut out).unwrap();
            }
            out.len()
        });
    });
    g.finish();
}

fn bench_hpack(c: &mut Criterion) {
    let mut g = c.benchmark_group("hpack");
    // What one client encoder sends for 10,000 requests in a row.
    let mut enc = Encoder::new(4096);
    let blocks: Vec<Vec<u8>> = (0..10_000)
        .map(|_| {
            let mut b = Vec::new();
            enc.encode(fields(REQUEST), &mut b);
            b
        })
        .collect();
    g.throughput(Throughput::Elements(blocks.len() as u64));
    g.bench_function("decode_browser_request", |b| {
        let mut list = HeaderList::new(64 * 1024);
        b.iter(|| {
            let mut dec = Decoder::new(4096);
            for block in &blocks {
                dec.decode(black_box(block), &mut list).unwrap();
            }
            list.len()
        });
    });
    g.bench_function("encode_response", |b| {
        let mut out = Vec::with_capacity(512);
        b.iter(|| {
            let mut enc = Encoder::new(4096);
            for _ in 0..10_000 {
                out.clear();
                enc.encode(fields(RESPONSE), &mut out);
            }
            out.len()
        });
    });
    g.throughput(Throughput::Elements(1));
    let mut seed = vec![0x40, 0x01, b'x', 0x7f];
    // A value of 3,960 bytes: 127 + 3,833 in the continuation bytes.
    seed.extend_from_slice(&[0xf9, 0x1d]);
    seed.resize(seed.len() + 3960, b'v');
    let bomb = vec![0xbe; 1000];
    g.bench_function("bomb", |b| {
        let mut list = HeaderList::new(16 * 1024);
        b.iter(|| {
            let mut dec = Decoder::new(4096);
            dec.decode(&seed, &mut list).unwrap();
            dec.decode(black_box(&bomb), &mut list).unwrap();
            list.is_oversized()
        });
    });
    g.finish();
}

fn bench_huffman(c: &mut Criterion) {
    let mut g = c.benchmark_group("huffman");
    let text: Vec<u8> =
        b"session=4f9a1c7e2b8d4e6f; theme=dark; consent=1; _ga=GA1.2.1234567890.1700000000; "
            .iter()
            .copied()
            .cycle()
            .take(1024)
            .collect();
    let mut wire = Vec::new();
    huffman::encode(&text, &mut wire);
    g.throughput(Throughput::Bytes(text.len() as u64));
    g.bench_function("decode_1k", |b| {
        let mut out = Vec::with_capacity(2048);
        b.iter(|| {
            out.clear();
            huffman::decode(black_box(&wire), &mut out).unwrap();
            out.len()
        });
    });
    g.bench_function("encode_1k", |b| {
        let mut out = Vec::with_capacity(2048);
        b.iter(|| {
            out.clear();
            huffman::encode(black_box(&text), &mut out);
            out.len()
        });
    });
    g.finish();
}

fn bench_conn(c: &mut Criterion) {
    let mut g = c.benchmark_group("conn");
    let mut enc = Encoder::new(4096);
    let mut wire = frame::PREFACE.to_vec();
    frame::settings_frame(&[], 16_384, &mut wire).unwrap();
    // A large window, so the responses never wait.
    frame::encode(
        &Frame::WindowUpdate {
            stream: StreamId::ZERO,
            increment: frame::MAX_WINDOW - 65_535,
        },
        16_384,
        &mut wire,
    )
    .unwrap();
    for i in 0..10_000u32 {
        let mut block = Vec::new();
        enc.encode(fields(REQUEST), &mut block);
        frame::encode(
            &Frame::Headers {
                stream: sid(2 * i + 1),
                end_stream: true,
                end_headers: true,
                priority: None,
                fragment: &block,
                padding: None,
            },
            16_384,
            &mut wire,
        )
        .unwrap();
    }
    let body = vec![0x41u8; 1024];
    let resp: Vec<(&str, &[u8])> = RESPONSE
        .iter()
        .skip(1)
        .map(|(n, v)| (std::str::from_utf8(n).unwrap(), &v[..]))
        .filter(|(n, _)| *n != "content-length")
        .collect();
    g.throughput(Throughput::Elements(10_000));
    g.bench_function("requests_10k", |b| {
        b.iter(|| {
            let mut conn = ServerConn::new(Config::new().max_concurrent_streams(20_000));
            let mut rest = black_box(&wire[..]);
            let mut served = 0u32;
            while !rest.is_empty() {
                let n = conn.feed(rest);
                rest = &rest[n..];
                while let Some(e) = conn.poll().unwrap() {
                    if let Event::Request { stream, .. } = e {
                        conn.send_headers(stream, 200, &resp, false).unwrap();
                        conn.send_data(stream, &body, true).unwrap();
                        served += 1;
                    }
                }
                let out = conn.output().len();
                conn.consume_output(out);
            }
            served
        });
    });
    g.bench_function("client_server_10k", |b| {
        let fields: Vec<(&str, &[u8])> = REQUEST
            .iter()
            .skip(4)
            .map(|(n, v)| (std::str::from_utf8(n).unwrap(), &v[..]))
            .collect();
        let head = RequestParts {
            method: "GET",
            scheme: Scheme::Https,
            authority: "www.example.com",
            path: "/assets/app.4f3c2a.js?v=20261120",
            fields: &fields,
        };
        b.iter(|| {
            let mut client = ClientConn::new(Config::new().auto_release(true));
            let mut server = ServerConn::new(Config::new().max_concurrent_streams(200));
            let mut done = 0u32;
            let mut sent = 0u32;
            while done < 10_000 {
                while sent < 10_000 && sent - done < 100 {
                    if client.send_request(black_box(&head), true).is_err() {
                        break;
                    }
                    sent += 1;
                }
                let out = client.output().to_vec();
                let n = server.feed(&out);
                client.consume_output(n);
                while let Some(e) = server.poll().unwrap() {
                    if let Event::Request { stream, .. } = e {
                        server.send_headers(stream, 200, &resp, false).unwrap();
                        server.send_data(stream, &body, true).unwrap();
                    }
                }
                let out = server.output().to_vec();
                let n = client.feed(&out);
                server.consume_output(n);
                while let Some(e) = client.poll().unwrap() {
                    if let Event::Data {
                        end_stream: true, ..
                    } = e
                    {
                        done += 1;
                    }
                }
            }
            done
        });
    });
    g.finish();
}

fn bench_h1(c: &mut Criterion) {
    use http_net::{OutgoingBody, ResponseHeadRef, ServerConn as H1, ServerEvent};

    let mut g = c.benchmark_group("h1");
    let mut one = Vec::new();
    one.extend_from_slice(
        b"GET /assets/app.4f3c2a.js?v=20261120 HTTP/1.1\r\nhost: www.example.com\r\n",
    );
    for (n, v) in REQUEST.iter().skip(4) {
        one.extend_from_slice(n);
        one.extend_from_slice(b": ");
        one.extend_from_slice(v);
        one.extend_from_slice(b"\r\n");
    }
    one.extend_from_slice(b"\r\n");
    let wire: Vec<u8> = one
        .iter()
        .copied()
        .cycle()
        .take(one.len() * 10_000)
        .collect();
    let body = vec![0x41u8; 1024];
    let fields: Vec<(&str, &[u8])> = RESPONSE
        .iter()
        .skip(1)
        .map(|(n, v)| (std::str::from_utf8(n).unwrap(), &v[..]))
        .filter(|(n, _)| *n != "content-length")
        .collect();
    g.throughput(Throughput::Elements(10_000));
    g.bench_function("requests_10k", |b| {
        let mut out = Vec::with_capacity(4096);
        b.iter(|| {
            let mut conn = H1::new();
            let mut rest = black_box(&wire[..]);
            let mut served = 0u32;
            loop {
                let n = conn.feed(rest);
                rest = &rest[n..];
                loop {
                    match conn.poll().unwrap() {
                        ServerEvent::RequestEnd => {
                            out.clear();
                            let head = ResponseHeadRef::new(
                                200,
                                &fields,
                                OutgoingBody::Full(body.len() as u64),
                            );
                            conn.write_head(&head, None, &mut out).unwrap();
                            out.extend_from_slice(&body);
                            served += 1;
                        }
                        ServerEvent::NeedInput => break,
                        _ => {}
                    }
                }
                if rest.is_empty() && served == 10_000 {
                    break;
                }
            }
            served
        });
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_frames,
    bench_hpack,
    bench_huffman,
    bench_conn,
    bench_h1
);
criterion_main!(benches);
