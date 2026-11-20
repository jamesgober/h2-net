// The test client returns itself for chaining; most calls drop it.
#![allow(unused_results)]

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::frame::{Priority, Settings};

fn sid(n: u32) -> StreamId {
    StreamId::new(n).unwrap()
}

/// A client that writes real frames with the crate's own encoders.
struct Client {
    enc: Encoder,
    wire: Vec<u8>,
}

impl Client {
    fn new() -> Self {
        let mut wire = PREFACE.to_vec();
        frame::settings_frame(&[], 16_384, &mut wire).unwrap();
        Self {
            enc: Encoder::new(4096),
            wire,
        }
    }

    fn bare() -> Self {
        Self {
            enc: Encoder::new(4096),
            wire: Vec::new(),
        }
    }

    fn frame(&mut self, f: &Frame<'_>) -> &mut Self {
        frame::encode(f, 1 << 24, &mut self.wire).unwrap();
        self
    }

    fn block(&mut self, fields: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut block = vec![];
        self.enc.encode(
            fields.iter().map(|(n, v)| HeaderField::new(n, v)),
            &mut block,
        );
        block
    }

    fn headers(&mut self, stream: u32, fields: &[(&[u8], &[u8])], end_stream: bool) -> &mut Self {
        let block = self.block(fields);
        self.frame(&Frame::Headers {
            stream: sid(stream),
            end_stream,
            end_headers: true,
            priority: None,
            fragment: &block,
            padding: None,
        })
    }

    fn get(&mut self, stream: u32, path: &str) -> &mut Self {
        let fields = request("GET", path);
        let f: Vec<(&[u8], &[u8])> = fields
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
            .collect();
        self.headers(stream, &f, true)
    }

    fn post(&mut self, stream: u32, extra: &[(&[u8], &[u8])]) -> &mut Self {
        let fields = request("POST", "/upload");
        let mut f: Vec<(&[u8], &[u8])> = fields
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
            .collect();
        f.extend_from_slice(extra);
        self.headers(stream, &f, false)
    }

    fn data(&mut self, stream: u32, data: &[u8], end_stream: bool) -> &mut Self {
        self.frame(&Frame::Data {
            stream: sid(stream),
            end_stream,
            data,
            padding: None,
        })
    }

    fn take(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.wire)
    }
}

fn request(method: &str, path: &str) -> Vec<(String, String)> {
    vec![
        (":method".into(), method.into()),
        (":scheme".into(), "https".into()),
        (":authority".into(), "example.com".into()),
        (":path".into(), path.into()),
    ]
}

/// Events, owned, for comparing.
#[derive(Debug, PartialEq, Eq)]
enum Ev {
    Request {
        stream: u32,
        path: String,
        end: bool,
    },
    Data {
        stream: u32,
        data: Vec<u8>,
        end: bool,
    },
    Trailers {
        stream: u32,
        fields: usize,
    },
    Reset {
        stream: u32,
        code: ErrorCode,
        remote: bool,
    },
    Rejected {
        stream: u32,
        reason: Rejection,
    },
    Writable(u32),
    GoAway(ErrorCode),
    Error(ConnErrorKind),
}

/// Feeds `wire` (in pieces of `chunk` bytes) and collects every event.
fn run_chunked(conn: &mut ServerConn, wire: &[u8], chunk: usize) -> Vec<Ev> {
    let mut evs = vec![];
    let mut rest = wire;
    loop {
        let piece = rest.get(..chunk.min(rest.len())).unwrap();
        let n = conn.feed(piece);
        rest = &rest[n..];
        loop {
            match conn.poll() {
                Ok(Some(e)) => evs.push(own(e)),
                Ok(None) => break,
                Err(e) => {
                    evs.push(Ev::Error(*e.kind()));
                    return evs;
                }
            }
        }
        if rest.is_empty() || conn.is_done() {
            return evs;
        }
    }
}

fn run(conn: &mut ServerConn, wire: &[u8]) -> Vec<Ev> {
    run_chunked(conn, wire, usize::MAX)
}

fn own(e: Event<'_>) -> Ev {
    match e {
        Event::Request {
            stream,
            head,
            end_stream,
            ..
        } => Ev::Request {
            stream: stream.value(),
            path: head.view().target().to_string(),
            end: end_stream,
        },
        Event::Data {
            stream,
            data,
            end_stream,
        } => Ev::Data {
            stream: stream.value(),
            data: data.to_vec(),
            end: end_stream,
        },
        Event::Trailers { stream, fields } => Ev::Trailers {
            stream: stream.value(),
            fields: fields.len(),
        },
        Event::Reset {
            stream,
            code,
            remote,
        } => Ev::Reset {
            stream: stream.value(),
            code,
            remote,
        },
        Event::Rejected { stream, reason } => Ev::Rejected {
            stream: stream.value(),
            reason,
        },
        Event::Writable { stream } => Ev::Writable(stream.value()),
        Event::GoAway { code } => Ev::GoAway(code),
    }
}

/// The server's frames, owned.
#[derive(Debug, PartialEq, Eq)]
enum Out {
    Settings {
        ack: bool,
        params: Vec<(u16, u32)>,
    },
    Headers {
        stream: u32,
        end: bool,
        fields: Vec<(String, String)>,
    },
    Data {
        stream: u32,
        len: usize,
        end: bool,
    },
    Rst {
        stream: u32,
        code: ErrorCode,
    },
    Window {
        stream: u32,
        inc: u32,
    },
    Ping {
        ack: bool,
    },
    GoAway {
        last: u32,
        code: ErrorCode,
    },
}

struct Reader {
    dec: Decoder,
}

impl Reader {
    fn new() -> Self {
        Self {
            dec: Decoder::new(4096),
        }
    }

    /// Takes the server's output and parses it.
    fn read(&mut self, conn: &mut ServerConn) -> Vec<Out> {
        let bytes = conn.output().to_vec();
        conn.consume_output(bytes.len());
        let mut rest = &bytes[..];
        let mut out = vec![];
        let mut block = vec![];
        let mut block_info = None;
        while !rest.is_empty() {
            let Decoded::Frame { frame, len } = frame::decode(rest, 1 << 24).unwrap() else {
                panic!("partial output")
            };
            rest = &rest[len..];
            match frame {
                Frame::Settings(s) => out.push(Out::Settings {
                    ack: s.is_ack(),
                    params: s.iter().map(|(i, v)| (i.value(), v)).collect(),
                }),
                Frame::Headers {
                    stream,
                    end_stream,
                    end_headers,
                    fragment,
                    ..
                } => {
                    block.clear();
                    block.extend_from_slice(fragment);
                    block_info = Some((stream, end_stream));
                    if end_headers {
                        out.push(self.headers(&block, stream, end_stream));
                    }
                }
                Frame::Continuation {
                    end_headers,
                    fragment,
                    ..
                } => {
                    block.extend_from_slice(fragment);
                    if end_headers {
                        let (stream, end) = block_info.unwrap();
                        out.push(self.headers(&block, stream, end));
                    }
                }
                Frame::Data {
                    stream,
                    end_stream,
                    data,
                    ..
                } => out.push(Out::Data {
                    stream: stream.value(),
                    len: data.len(),
                    end: end_stream,
                }),
                Frame::RstStream { stream, code } => out.push(Out::Rst {
                    stream: stream.value(),
                    code,
                }),
                Frame::WindowUpdate { stream, increment } => out.push(Out::Window {
                    stream: stream.value(),
                    inc: increment,
                }),
                Frame::Ping { ack, .. } => out.push(Out::Ping { ack }),
                Frame::GoAway {
                    last_stream, code, ..
                } => out.push(Out::GoAway {
                    last: last_stream.value(),
                    code,
                }),
                other => panic!("unexpected {other:?}"),
            }
        }
        out
    }

    fn headers(&mut self, block: &[u8], stream: StreamId, end: bool) -> Out {
        let mut list = HeaderList::new(1 << 20);
        self.dec.decode(block, &mut list).unwrap();
        Out::Headers {
            stream: stream.value(),
            end,
            fields: list
                .iter()
                .map(|f| {
                    (
                        String::from_utf8(f.name.to_vec()).unwrap(),
                        String::from_utf8(f.value.to_vec()).unwrap(),
                    )
                })
                .collect(),
        }
    }
}

/// A connection past the preface, its own preface output read.
fn open(config: Config) -> (ServerConn, Reader) {
    let mut conn = ServerConn::new(config);
    let mut reader = Reader::new();
    let _ = reader.read(&mut conn);
    let evs = run(&mut conn, &Client::new().take());
    assert!(evs.is_empty(), "{evs:?}");
    // The settings acknowledgment.
    assert_eq!(
        reader.read(&mut conn),
        [Out::Settings {
            ack: true,
            params: vec![]
        }]
    );
    (conn, reader)
}

#[test]
fn test_server_preface_is_written_at_once() {
    let mut conn = ServerConn::new(Config::new());
    let out = Reader::new().read(&mut conn);
    assert_eq!(
        out,
        [
            Out::Settings {
                ack: false,
                params: vec![(0x3, 100), (0x6, 16 * 1024), (0x9, 1), (0x4, 256 * 1024)]
            },
            Out::Window {
                stream: 0,
                inc: 1024 * 1024 - 65_535
            },
        ]
    );
    assert!(!conn.settings_acked());
    let mut ack = vec![];
    frame::encode(&Frame::Settings(Settings::ack()), 16_384, &mut ack).unwrap();
    let mut wire = Client::new().take();
    wire.extend_from_slice(&ack);
    let _ = run(&mut conn, &wire);
    assert!(conn.settings_acked());
}

#[test]
fn test_a_request_and_its_response() {
    let (mut conn, mut reader) = open(Config::new());
    let evs = run(&mut conn, &Client::bare().get(1, "/hello?x=1").take());
    assert_eq!(
        evs,
        [Ev::Request {
            stream: 1,
            path: "/hello?x=1".into(),
            end: true
        }]
    );
    conn.send_headers(
        sid(1),
        200,
        &[("Content-Type", b"text/plain"), ("Connection", b"close")],
        false,
    )
    .unwrap();
    assert_eq!(conn.send_data(sid(1), b"hello", true), Ok(5));
    assert_eq!(
        reader.read(&mut conn),
        [
            Out::Headers {
                stream: 1,
                end: false,
                fields: vec![
                    (":status".into(), "200".into()),
                    ("content-type".into(), "text/plain".into())
                ]
            },
            Out::Data {
                stream: 1,
                len: 5,
                end: true
            }
        ]
    );
    assert_eq!(conn.open_streams(), 0);
    assert_eq!(
        conn.send_data(sid(1), b"x", false),
        Err(SendError::UnknownStream)
    );
}

#[test]
fn test_fed_one_byte_at_a_time_gives_the_same_events() {
    let mut c = Client::new();
    c.post(1, &[(b"content-length", b"6")])
        .data(1, b"abc", false)
        .data(1, b"def", true)
        .get(3, "/b");
    let wire = c.take();
    let whole = run(
        &mut ServerConn::new(Config::new().auto_release(true)),
        &wire,
    );
    let bytewise = run_chunked(
        &mut ServerConn::new(Config::new().auto_release(true)),
        &wire,
        1,
    );
    assert_eq!(whole, bytewise);
    assert_eq!(whole.len(), 4, "{whole:?}");
}

#[test]
fn test_preface_and_first_frame_rules() {
    let mut conn = ServerConn::new(Config::new());
    assert_eq!(
        run(&mut conn, b"GET / HTTP/1.1\r\n"),
        [Ev::Error(ConnErrorKind::Preface)]
    );
    // Every later call reports the same error.
    assert_eq!(conn.poll().unwrap_err().kind(), &ConnErrorKind::Preface);

    let mut conn = ServerConn::new(Config::new());
    let mut c = Client::bare();
    c.wire.extend_from_slice(PREFACE);
    c.frame(&Frame::Ping {
        ack: false,
        payload: [0; 8],
    });
    assert_eq!(
        run(&mut conn, &c.take()),
        [Ev::Error(ConnErrorKind::Protocol(Violation::SettingsFirst))]
    );
    let out = Reader::new().read(&mut conn);
    assert_eq!(
        out.last(),
        Some(&Out::GoAway {
            last: 0,
            code: ErrorCode::PROTOCOL_ERROR
        })
    );
}

#[test]
fn test_ping_is_answered() {
    let (mut conn, mut reader) = open(Config::new());
    let mut c = Client::bare();
    c.frame(&Frame::Ping {
        ack: false,
        payload: [9; 8],
    });
    assert!(run(&mut conn, &c.take()).is_empty());
    assert_eq!(reader.read(&mut conn), [Out::Ping { ack: true }]);
}

#[test]
fn test_body_flow_control_and_release() {
    let (mut conn, mut reader) = open(
        Config::new()
            .stream_window(65_535)
            .connection_window(65_535),
    );
    let mut c = Client::bare();
    c.post(1, &[]);
    let chunk = vec![7u8; 16_384];
    for _ in 0..3 {
        c.data(1, &chunk, false);
    }
    let evs = run(&mut conn, &c.take());
    assert_eq!(evs.len(), 4);
    // Nothing released yet: no window updates.
    assert!(reader.read(&mut conn).is_empty());
    conn.release(sid(1), 3 * 16_384);
    assert_eq!(
        reader.read(&mut conn),
        [
            Out::Window {
                stream: 1,
                inc: 3 * 16_384
            },
            Out::Window {
                stream: 0,
                inc: 3 * 16_384
            }
        ]
    );
    // Past the window: a flow-control error.
    let mut c = Client::bare();
    for _ in 0..5 {
        c.data(1, &chunk, false);
    }
    let evs = run(&mut conn, &c.take());
    assert_eq!(evs.last(), Some(&Ev::Error(ConnErrorKind::FlowControl)));
}

#[test]
fn test_content_length_must_match_the_body() {
    let (mut conn, mut reader) = open(Config::new().auto_release(true));
    let mut c = Client::bare();
    c.post(1, &[(b"content-length", b"3")])
        .data(1, b"abcd", true);
    let evs = run(&mut conn, &c.take());
    assert_eq!(
        evs,
        [
            Ev::Request {
                stream: 1,
                path: "/upload".into(),
                end: false
            },
            Ev::Reset {
                stream: 1,
                code: ErrorCode::PROTOCOL_ERROR,
                remote: false
            }
        ]
    );
    assert!(reader.read(&mut conn).contains(&Out::Rst {
        stream: 1,
        code: ErrorCode::PROTOCOL_ERROR
    }));
    // Short of it at the end, too.
    let mut c = Client::bare();
    c.post(3, &[(b"content-length", b"3")]).data(3, b"ab", true);
    let evs = run(&mut conn, &c.take());
    assert!(evs.contains(&Ev::Reset {
        stream: 3,
        code: ErrorCode::PROTOCOL_ERROR,
        remote: false
    }));
}

#[test]
fn test_trailers() {
    let (mut conn, _) = open(Config::new().auto_release(true));
    let mut c = Client::bare();
    c.post(1, &[])
        .data(1, b"x", false)
        .headers(1, &[(b"x-sum", b"1")], true);
    let evs = run(&mut conn, &c.take());
    assert_eq!(
        evs.last(),
        Some(&Ev::Trailers {
            stream: 1,
            fields: 1
        })
    );
    // Trailers without END_STREAM are malformed.
    let mut c = Client::bare();
    c.post(3, &[]).headers(3, &[(b"x-sum", b"1")], false);
    let evs = run(&mut conn, &c.take());
    assert!(evs.contains(&Ev::Reset {
        stream: 3,
        code: ErrorCode::PROTOCOL_ERROR,
        remote: false
    }));
}

#[test]
fn test_malformed_request_is_reset_without_reaching_the_application() {
    let (mut conn, mut reader) = open(Config::new());
    let mut c = Client::bare();
    c.headers(1, &[(b":method", b"GET"), (b":path", b"/")], true);
    let evs = run(&mut conn, &c.take());
    assert_eq!(
        evs,
        [Ev::Rejected {
            stream: 1,
            reason: Rejection::Malformed(Malformed::MissingPseudo)
        }]
    );
    assert_eq!(
        reader.read(&mut conn),
        [Out::Rst {
            stream: 1,
            code: ErrorCode::PROTOCOL_ERROR
        }]
    );
}

#[test]
fn test_oversized_headers_get_431_and_the_connection_goes_on() {
    let (mut conn, mut reader) = open(Config::new().max_header_list_size(200));
    let big = vec![b'a'; 300];
    let mut fields: Vec<(Vec<u8>, Vec<u8>)> = request("GET", "/")
        .into_iter()
        .map(|(n, v)| (n.into_bytes(), v.into_bytes()))
        .collect();
    fields.push((b"x-big".to_vec(), big));
    let f: Vec<(&[u8], &[u8])> = fields.iter().map(|(n, v)| (&n[..], &v[..])).collect();
    let mut c = Client::bare();
    c.headers(1, &f, true).get(3, "/next");
    let evs = run(&mut conn, &c.take());
    assert_eq!(
        evs,
        [
            Ev::Rejected {
                stream: 1,
                reason: Rejection::HeadersTooLarge
            },
            Ev::Request {
                stream: 3,
                path: "/next".into(),
                end: true
            }
        ]
    );
    assert_eq!(
        reader.read(&mut conn),
        [Out::Headers {
            stream: 1,
            end: true,
            fields: vec![(":status".into(), "431".into())]
        }]
    );
}

#[test]
fn test_stream_cap_refuses_and_keeps_hpack_in_step() {
    let (mut conn, mut reader) = open(Config::new().max_concurrent_streams(1));
    let mut c = Client::bare();
    c.get(1, "/a");
    // Stream 3 is over the cap; its block adds "x-new: 1" to the table, and
    // stream 5 (after stream 1 completes) refers to that entry.
    c.headers(
        3,
        &[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"a"),
            (b":path", b"/b"),
            (b"x-new", b"1"),
        ],
        true,
    );
    let evs = run(&mut conn, &c.take());
    assert_eq!(
        evs,
        [
            Ev::Request {
                stream: 1,
                path: "/a".into(),
                end: true
            },
            Ev::Rejected {
                stream: 3,
                reason: Rejection::TooManyStreams
            }
        ]
    );
    assert_eq!(
        reader.read(&mut conn),
        [Out::Rst {
            stream: 3,
            code: ErrorCode::REFUSED_STREAM
        }]
    );
    conn.send_headers(sid(1), 204, &[], true).unwrap();
    let mut c2 = Client::bare();
    c2.enc = core::mem::replace(&mut c.enc, Encoder::new(0));
    c2.headers(
        5,
        &[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"a"),
            (b":path", b"/c"),
            (b"x-new", b"1"),
        ],
        true,
    );
    let evs = run(&mut conn, &c2.take());
    assert_eq!(
        evs,
        [Ev::Request {
            stream: 5,
            path: "/c".into(),
            end: true
        }]
    );
}

#[test]
fn test_continuation_assembly_and_interruption() {
    let (mut conn, _) = open(Config::new());
    let mut c = Client::bare();
    let block = c.block(&[
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"a"),
        (b":path", b"/split"),
    ]);
    let (a, b) = block.split_at(3);
    c.frame(&Frame::Headers {
        stream: sid(1),
        end_stream: true,
        end_headers: false,
        priority: None,
        fragment: a,
        padding: None,
    })
    .frame(&Frame::Continuation {
        stream: sid(1),
        end_headers: false,
        fragment: b"",
    })
    .frame(&Frame::Continuation {
        stream: sid(1),
        end_headers: true,
        fragment: b,
    });
    let evs = run(&mut conn, &c.take());
    assert_eq!(
        evs,
        [Ev::Request {
            stream: 1,
            path: "/split".into(),
            end: true
        }]
    );
    // A PING in the middle of a block.
    let mut c = Client::bare();
    c.frame(&Frame::Headers {
        stream: sid(3),
        end_stream: true,
        end_headers: false,
        priority: None,
        fragment: b"\x82",
        padding: None,
    })
    .frame(&Frame::Ping {
        ack: false,
        payload: [0; 8],
    });
    assert_eq!(
        run(&mut conn, &c.take()),
        [Ev::Error(ConnErrorKind::Protocol(
            Violation::ContinuationExpected
        ))]
    );
}

#[test]
fn test_stream_identifier_rules() {
    type Build = fn(&mut Client);
    let cases: [(Build, ConnErrorKind); 4] = [
        (
            |c| {
                c.get(2, "/");
            },
            ConnErrorKind::Protocol(Violation::BadStreamId {
                stream: StreamId::masked(2),
            }),
        ),
        (
            |c| {
                c.get(5, "/").get(3, "/");
            },
            ConnErrorKind::StreamClosed {
                stream: StreamId::masked(3),
            },
        ),
        (
            |c| {
                c.data(1, b"x", false);
            },
            ConnErrorKind::Protocol(Violation::IdleStream {
                kind: frame::FrameType::DATA,
                stream: StreamId::masked(1),
            }),
        ),
        (
            |c| {
                c.frame(&Frame::RstStream {
                    stream: sid(9),
                    code: ErrorCode::CANCEL,
                });
            },
            ConnErrorKind::Protocol(Violation::IdleStream {
                kind: frame::FrameType::RST_STREAM,
                stream: StreamId::masked(9),
            }),
        ),
    ];
    for (build, want) in cases {
        let (mut conn, _) = open(Config::new());
        let mut c = Client::bare();
        build(&mut c);
        let evs = run(&mut conn, &c.take());
        assert_eq!(evs.last(), Some(&Ev::Error(want)), "{evs:?}");
    }
}

#[test]
fn test_push_promise_from_a_client() {
    let (mut conn, _) = open(Config::new());
    let mut c = Client::bare();
    c.get(1, "/").frame(&Frame::PushPromise {
        stream: sid(1),
        end_headers: true,
        promised: sid(2),
        fragment: b"\x82",
        padding: None,
    });
    let evs = run(&mut conn, &c.take());
    assert_eq!(
        evs.last(),
        Some(&Ev::Error(ConnErrorKind::Protocol(Violation::PushPromise)))
    );
}

#[test]
fn test_send_window_and_writable() {
    let (mut conn, mut reader) = open(Config::new());
    let _ = run(&mut conn, &Client::bare().get(1, "/big").take());
    conn.send_headers(sid(1), 200, &[], false).unwrap();
    let body = vec![1u8; 100_000];
    // The peer's initial windows are 65,535.
    assert_eq!(conn.send_data(sid(1), &body, true), Ok(65_535));
    assert_eq!(conn.send_data(sid(1), &body[65_535..], true), Ok(0));
    let out = reader.read(&mut conn);
    assert_eq!(
        out.iter().filter(|o| matches!(o, Out::Data { .. })).count(),
        4
    );
    let mut c = Client::bare();
    c.frame(&Frame::WindowUpdate {
        stream: StreamId::ZERO,
        increment: 100_000,
    })
    .frame(&Frame::WindowUpdate {
        stream: sid(1),
        increment: 100_000,
    });
    let evs = run(&mut conn, &c.take());
    assert_eq!(evs, [Ev::Writable(1)]);
    assert_eq!(
        conn.send_data(sid(1), &body[65_535..], true),
        Ok(100_000 - 65_535)
    );
    assert_eq!(conn.open_streams(), 0);
}

#[test]
fn test_peer_initial_window_change_applies_to_open_streams() {
    let (mut conn, _) = open(Config::new());
    let _ = run(&mut conn, &Client::bare().get(1, "/").take());
    conn.send_headers(sid(1), 200, &[], false).unwrap();
    let mut c = Client::bare();
    c.frame(&Frame::Settings(
        Settings::from_payload(&[0, 4, 0, 0, 0, 10]).unwrap(),
    ));
    let _ = run(&mut conn, &c.take());
    // The window shrank to 10.
    assert_eq!(conn.send_data(sid(1), &[0; 100], false), Ok(10));
    // An update that would take an open stream's window over 2^31 - 1.
    let mut c = Client::bare();
    c.frame(&Frame::Settings(
        Settings::from_payload(&[0, 4, 0x7f, 0xff, 0xff, 0xff]).unwrap(),
    ));
    c.frame(&Frame::WindowUpdate {
        stream: sid(1),
        increment: 100,
    });
    let evs = run(&mut conn, &c.take());
    assert!(
        evs.contains(&Ev::Reset {
            stream: 1,
            code: ErrorCode::FLOW_CONTROL_ERROR,
            remote: false
        }),
        "{evs:?}"
    );
}

#[test]
fn test_head_and_bodiless_statuses_end_with_the_head() {
    let (mut conn, mut reader) = open(Config::new());
    let fields = request("HEAD", "/");
    let f: Vec<(&[u8], &[u8])> = fields
        .iter()
        .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
        .collect();
    let mut c = Client::bare();
    c.headers(1, &f, true).get(3, "/");
    let _ = run(&mut conn, &c.take());
    conn.send_headers(sid(1), 200, &[("content-length", b"10")], false)
        .unwrap();
    conn.send_headers(sid(3), 304, &[], false).unwrap();
    let out = reader.read(&mut conn);
    assert!(
        out.iter()
            .all(|o| matches!(o, Out::Headers { end: true, .. })),
        "{out:?}"
    );
    assert_eq!(conn.open_streams(), 0);
}

#[test]
fn test_send_api_refusals() {
    let (mut conn, _) = open(Config::new());
    let _ = run(&mut conn, &Client::bare().get(1, "/").take());
    assert_eq!(
        conn.send_data(sid(1), b"x", false),
        Err(SendError::OutOfOrder)
    );
    assert_eq!(
        conn.send_headers(sid(1), 101, &[], false),
        Err(SendError::Status)
    );
    assert_eq!(
        conn.send_headers(sid(1), 600, &[], false),
        Err(SendError::Status)
    );
    assert_eq!(
        conn.send_headers(sid(1), 103, &[], true),
        Err(SendError::Status)
    );
    assert!(matches!(
        conn.send_headers(sid(1), 200, &[("a", b"x\r\ny")], false),
        Err(SendError::Field(_))
    ));
    assert!(matches!(
        conn.send_headers(sid(1), 200, &[("a b", b"x")], false),
        Err(SendError::Field(_))
    ));
    // Informational heads, then the final one.
    conn.send_headers(sid(1), 103, &[("link", b"</a.css>; rel=preload")], false)
        .unwrap();
    conn.send_headers(sid(1), 200, &[("content-length", b"2")], false)
        .unwrap();
    assert_eq!(
        conn.send_headers(sid(1), 200, &[], false),
        Err(SendError::OutOfOrder)
    );
    assert_eq!(conn.send_data(sid(1), b"abc", true), Err(SendError::Body));
    assert_eq!(conn.send_data(sid(1), b"a", true), Err(SendError::Body));
    assert_eq!(conn.send_data(sid(1), b"ab", true), Ok(2));
    assert_eq!(
        conn.send_headers(sid(7), 200, &[], false),
        Err(SendError::UnknownStream)
    );
}

#[test]
fn test_graceful_shutdown() {
    let (mut conn, mut reader) = open(Config::new());
    let _ = run(&mut conn, &Client::bare().get(1, "/").take());
    conn.shutdown();
    assert_eq!(
        reader.read(&mut conn),
        [
            Out::GoAway {
                last: StreamId::MAX.value(),
                code: ErrorCode::NO_ERROR
            },
            Out::Ping { ack: false }
        ]
    );
    // Stream 3 arrives before the client saw the GOAWAY: still served.
    let mut c = Client::bare();
    c.get(3, "/late").frame(&Frame::Ping {
        ack: true,
        payload: SHUTDOWN_PING,
    });
    let evs = run(&mut conn, &c.take());
    assert_eq!(
        evs,
        [Ev::Request {
            stream: 3,
            path: "/late".into(),
            end: true
        }]
    );
    assert_eq!(
        reader.read(&mut conn),
        [Out::GoAway {
            last: 3,
            code: ErrorCode::NO_ERROR
        }]
    );
    // Stream 5, after the final GOAWAY: ignored.
    assert!(run(&mut conn, &c.get(5, "/ignored").take()).is_empty());
    assert!(!conn.is_done());
    conn.send_headers(sid(1), 204, &[], true).unwrap();
    conn.send_headers(sid(3), 204, &[], true).unwrap();
    assert!(conn.is_done());
}

#[test]
fn test_close_with_a_code() {
    let (mut conn, mut reader) = open(Config::new());
    conn.close(ErrorCode::SETTINGS_TIMEOUT);
    assert_eq!(
        reader.read(&mut conn),
        [Out::GoAway {
            last: 0,
            code: ErrorCode::SETTINGS_TIMEOUT
        }]
    );
    assert!(conn.is_done());
    assert_eq!(conn.poll().unwrap_err().code(), ErrorCode::SETTINGS_TIMEOUT);
}

#[test]
fn test_large_response_head_is_split_into_continuations() {
    let (mut conn, mut reader) = open(Config::new().encoder_table_size(0));
    let _ = run(&mut conn, &Client::bare().get(1, "/").take());
    let big = vec![b'v'; 40_000];
    conn.send_headers(sid(1), 200, &[("x-big", &big)], true)
        .unwrap();
    let out = reader.read(&mut conn);
    assert_eq!(out.len(), 1);
    let Out::Headers { fields, end, .. } = &out[0] else {
        panic!()
    };
    assert!(*end);
    assert_eq!(fields[1].1.len(), 40_000);
}

#[test]
fn test_padded_data_and_priority_frames() {
    let (mut conn, mut reader) = open(
        Config::new()
            .stream_window(65_535)
            .connection_window(65_535),
    );
    let mut c = Client::bare();
    c.post(1, &[])
        .frame(&Frame::Data {
            stream: sid(1),
            end_stream: false,
            data: b"ab",
            padding: Some(200),
        })
        .frame(&Frame::Priority {
            stream: sid(1),
            priority: Priority {
                exclusive: false,
                depends_on: StreamId::ZERO,
                weight: 3,
            },
        });
    let evs = run(&mut conn, &c.take());
    assert_eq!(
        evs.last(),
        Some(&Ev::Data {
            stream: 1,
            data: b"ab".to_vec(),
            end: false
        })
    );
    // Padding is not counted against the application.
    conn.release(sid(1), 2);
    let _ = reader.read(&mut conn);
}

// ---- Attacks: each one must end the connection with its budget, and must
// get through when the budget is turned off.

/// Rapid reset (CVE-2023-44487): open a stream and reset it at once,
/// forever.
fn rapid_reset(config: Config, streams: u32) -> Vec<Ev> {
    let (mut conn, _) = open(config);
    let mut c = Client::bare();
    for i in 0..streams {
        let id = 2 * i + 1;
        c.get(id, "/").frame(&Frame::RstStream {
            stream: sid(id),
            code: ErrorCode::CANCEL,
        });
    }
    let mut evs = run(&mut conn, &c.take());
    evs.retain(|e| matches!(e, Ev::Error(_)));
    evs
}

#[test]
fn test_attack_rapid_reset() {
    assert_eq!(
        rapid_reset(Config::new(), 1000),
        [Ev::Error(ConnErrorKind::RapidReset)]
    );
    assert!(rapid_reset(Config::new().reset_budget(u32::MAX, u32::MAX), 1000).is_empty());
}

#[test]
fn test_browser_cancels_stay_under_the_reset_budget() {
    // 1,000 requests answered, and one in five cancelled before its answer.
    let (mut conn, _) = open(Config::new());
    for i in 0..1000u32 {
        let id = 2 * i + 1;
        let mut c = Client::bare();
        c.get(id, "/");
        if i % 5 == 0 {
            c.frame(&Frame::RstStream {
                stream: sid(id),
                code: ErrorCode::CANCEL,
            });
        }
        let evs = run(&mut conn, &c.take());
        assert!(
            !evs.iter().any(|e| matches!(e, Ev::Error(_))),
            "{i}: {evs:?}"
        );
        if i % 5 != 0 {
            conn.send_headers(sid(id), 204, &[], true).unwrap();
        }
        let n = conn.output().len();
        conn.consume_output(n);
    }
}

/// Provoked resets ("MadeYouReset"): frames that make the server reset the
/// stream itself, here a zero WINDOW_UPDATE.
#[test]
fn test_attack_provoked_resets() {
    let attack = |config: Config| {
        let (mut conn, _) = open(config);
        let mut c = Client::bare();
        for i in 0..1000u32 {
            let id = 2 * i + 1;
            c.get(id, "/");
            c.wire
                .extend_from_slice(&[0, 0, 4, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            // The stream identifier is bytes 5 to 8 of the 13-byte frame.
            let at = c.wire.len() - 8;
            c.wire[at..at + 4].copy_from_slice(&id.to_be_bytes());
        }
        let mut evs = run(&mut conn, &c.take());
        evs.retain(|e| matches!(e, Ev::Error(_)));
        evs
    };
    assert_eq!(
        attack(Config::new()),
        [Ev::Error(ConnErrorKind::RapidReset)]
    );
    assert!(attack(Config::new().reset_budget(u32::MAX, u32::MAX)).is_empty());
}

#[test]
fn test_attack_continuation_flood() {
    let attack = |config: Config| {
        let (mut conn, _) = open(config);
        let mut c = Client::bare();
        c.frame(&Frame::Headers {
            stream: sid(1),
            end_stream: true,
            end_headers: false,
            priority: None,
            fragment: b"",
            padding: None,
        });
        for _ in 0..10_000 {
            c.frame(&Frame::Continuation {
                stream: sid(1),
                end_headers: false,
                fragment: b"",
            });
        }
        let mut evs = run(&mut conn, &c.take());
        evs.retain(|e| matches!(e, Ev::Error(_)));
        evs
    };
    assert_eq!(
        attack(Config::new()),
        [Ev::Error(ConnErrorKind::ContinuationFlood)]
    );
    assert!(attack(Config::new().max_continuations(u32::MAX)).is_empty());
}

#[test]
fn test_attack_header_block_too_large() {
    let attack = |config: Config| {
        let (mut conn, _) = open(config);
        let mut c = Client::bare();
        let junk = vec![0x82u8; 16_000];
        c.frame(&Frame::Headers {
            stream: sid(1),
            end_stream: true,
            end_headers: false,
            priority: None,
            fragment: &junk,
            padding: None,
        });
        for _ in 0..10 {
            c.frame(&Frame::Continuation {
                stream: sid(1),
                end_headers: false,
                fragment: &junk,
            });
        }
        let mut evs = run(&mut conn, &c.take());
        evs.retain(|e| matches!(e, Ev::Error(_)));
        evs
    };
    assert_eq!(
        attack(Config::new()),
        [Ev::Error(ConnErrorKind::HeaderBlockTooLarge)]
    );
    assert!(attack(Config::new().max_header_block(u32::MAX)).is_empty());
}

#[test]
fn test_attack_hpack_bomb_is_answered_431() {
    let (mut conn, mut reader) = open(Config::new());
    let mut c = Client::bare();
    // A 4,000-byte entry, then index 62 a thousand times in one block.
    let mut block = vec![0x40, 0x01, b'x', 0x7f, 0xf9, 0x1d];
    block.resize(block.len() + 3960, b'v');
    block.extend_from_slice(&[0xbe; 1000]);
    c.frame(&Frame::Headers {
        stream: sid(1),
        end_stream: true,
        end_headers: true,
        priority: None,
        fragment: &block,
        padding: None,
    });
    let evs = run(&mut conn, &c.take());
    assert_eq!(
        evs,
        [Ev::Rejected {
            stream: 1,
            reason: Rejection::HeadersTooLarge
        }]
    );
    let out = reader.read(&mut conn);
    assert!(matches!(&out[0], Out::Headers { fields, .. } if fields[0].1 == "431"));
}

fn control_flood(config: Config, frame: &Frame<'_>, count: usize) -> Vec<Ev> {
    let (mut conn, _) = open(config);
    let mut c = Client::bare();
    for _ in 0..count {
        c.frame(frame);
    }
    // The flood is fed in pieces with the output read between them, so the
    // unread-answer budget is not what stops it.
    let wire = c.take();
    let mut evs = vec![];
    for piece in wire.chunks(4096) {
        evs.extend(run(&mut conn, piece));
        let n = conn.output().len();
        conn.consume_output(n);
        if evs.iter().any(|e| matches!(e, Ev::Error(_))) {
            break;
        }
    }
    evs.retain(|e| matches!(e, Ev::Error(_)));
    evs
}

#[test]
fn test_attack_ping_flood() {
    let ping = Frame::Ping {
        ack: false,
        payload: [0; 8],
    };
    assert_eq!(
        control_flood(Config::new(), &ping, 20_000),
        [Ev::Error(ConnErrorKind::ControlFlood)]
    );
    assert!(
        control_flood(
            Config::new().control_budget(u32::MAX, u32::MAX),
            &ping,
            20_000
        )
        .is_empty()
    );
}

#[test]
fn test_attack_settings_flood() {
    let settings = Frame::Settings(Settings::from_payload(&[0, 3, 0, 0, 0, 100]).unwrap());
    assert_eq!(
        control_flood(Config::new(), &settings, 20_000),
        [Ev::Error(ConnErrorKind::ControlFlood)]
    );
    assert!(
        control_flood(
            Config::new().control_budget(u32::MAX, u32::MAX),
            &settings,
            20_000
        )
        .is_empty()
    );
}

#[test]
fn test_attack_empty_data_flood() {
    let attack = |config: Config| {
        let (mut conn, _) = open(config);
        let mut c = Client::bare();
        c.post(1, &[]);
        for _ in 0..20_000 {
            c.data(1, b"", false);
        }
        let mut evs = run(&mut conn, &c.take());
        evs.retain(|e| matches!(e, Ev::Error(_)));
        evs
    };
    assert_eq!(
        attack(Config::new()),
        [Ev::Error(ConnErrorKind::ControlFlood)]
    );
    assert!(attack(Config::new().control_budget(u32::MAX, u32::MAX)).is_empty());
}

#[test]
fn test_attack_ping_without_reading() {
    let attack = |config: Config| {
        let (mut conn, _) = open(config);
        let mut c = Client::bare();
        for _ in 0..5000 {
            c.frame(&Frame::Ping {
                ack: false,
                payload: [0; 8],
            });
        }
        // Nothing is read from the output.
        let mut evs = run(&mut conn, &c.take());
        evs.retain(|e| matches!(e, Ev::Error(_)));
        (evs, conn.output().len())
    };
    // With the control budget on, it stops the flood first; off, the
    // unread answers are what stop it.
    assert_eq!(
        attack(Config::new()).0,
        [Ev::Error(ConnErrorKind::ControlFlood)]
    );
    let no_control = Config::new().control_budget(u32::MAX, u32::MAX);
    let (evs, out) = attack(no_control);
    assert_eq!(evs, [Ev::Error(ConnErrorKind::OutputBacklog)]);
    assert!(out < 1100 * 17 + 100, "{out}");
    let (evs, out) = attack(no_control.max_unread_answers(u32::MAX));
    assert!(evs.is_empty());
    assert!(out >= 5000 * 17);
}

#[test]
fn test_attack_stream_exhaustion_is_refused_not_queued() {
    let (mut conn, _) = open(Config::new());
    let mut c = Client::bare();
    for i in 0..150u32 {
        c.get(2 * i + 1, "/");
    }
    let evs = run(&mut conn, &c.take());
    let requests = evs
        .iter()
        .filter(|e| matches!(e, Ev::Request { .. }))
        .count();
    let refused = evs
        .iter()
        .filter(|e| {
            matches!(
                e,
                Ev::Rejected {
                    reason: Rejection::TooManyStreams,
                    ..
                }
            )
        })
        .count();
    assert_eq!((requests, refused), (100, 50));
    assert_eq!(conn.open_streams(), 100);
}

#[test]
fn test_abuse_errors_are_marked() {
    let e = ConnError::new(ConnErrorKind::RapidReset);
    assert!(e.is_abuse());
    assert_eq!(e.code(), ErrorCode::ENHANCE_YOUR_CALM);
    assert!(!ConnError::new(ConnErrorKind::FlowControl).is_abuse());
}
