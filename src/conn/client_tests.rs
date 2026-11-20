//! The client side, mostly against the server side in memory: each side's
//! output is the other's input.

// Test helpers return values most calls drop.
#![allow(unused_results)]

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::*;

fn sid(n: u32) -> StreamId {
    StreamId::new(n).unwrap()
}

/// What the client saw, owned.
#[derive(Debug, PartialEq, Eq)]
enum C {
    Response {
        stream: u32,
        status: u16,
        end: bool,
    },
    Informational {
        stream: u32,
        status: u16,
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
    GoAway(ErrorCode),
    Writable(u32),
    Error(ConnErrorKind),
}

/// What the server saw, owned.
#[derive(Debug, PartialEq, Eq)]
enum S {
    Request {
        stream: u32,
        target: String,
        end: bool,
    },
    Data {
        stream: u32,
        data: Vec<u8>,
        end: bool,
    },
    Trailers {
        stream: u32,
    },
    Reset {
        stream: u32,
    },
    Other,
}

fn drain_client(c: &mut ClientConn) -> Vec<C> {
    let mut out = vec![];
    loop {
        match c.poll() {
            Ok(Some(e)) => out.push(match e {
                Event::Response {
                    stream,
                    status,
                    end_stream,
                    ..
                } => C::Response {
                    stream: stream.value(),
                    status,
                    end: end_stream,
                },
                Event::Informational { stream, status, .. } => C::Informational {
                    stream: stream.value(),
                    status,
                },
                Event::Data {
                    stream,
                    data,
                    end_stream,
                } => {
                    let d = data.to_vec();
                    c.release(stream, d.len());
                    C::Data {
                        stream: stream.value(),
                        data: d,
                        end: end_stream,
                    }
                }
                Event::Trailers { stream, fields } => C::Trailers {
                    stream: stream.value(),
                    fields: fields.len(),
                },
                Event::Reset {
                    stream,
                    code,
                    remote,
                } => C::Reset {
                    stream: stream.value(),
                    code,
                    remote,
                },
                Event::Rejected { stream, reason } => C::Rejected {
                    stream: stream.value(),
                    reason,
                },
                Event::GoAway { code } => C::GoAway(code),
                Event::Writable { stream } => C::Writable(stream.value()),
                other => panic!("a client reported {other:?}"),
            }),
            Ok(None) => return out,
            Err(e) => {
                out.push(C::Error(*e.kind()));
                return out;
            }
        }
    }
}

fn drain_server(s: &mut ServerConn) -> Vec<S> {
    let mut out = vec![];
    while let Ok(Some(e)) = s.poll() {
        out.push(match e {
            Event::Request {
                stream,
                head,
                end_stream,
                ..
            } => S::Request {
                stream: stream.value(),
                target: head.view().target().to_string(),
                end: end_stream,
            },
            Event::Data {
                stream,
                data,
                end_stream,
            } => {
                let d = data.to_vec();
                s.release(stream, d.len());
                S::Data {
                    stream: stream.value(),
                    data: d,
                    end: end_stream,
                }
            }
            Event::Trailers { stream, .. } => S::Trailers {
                stream: stream.value(),
            },
            Event::Reset { stream, .. } => S::Reset {
                stream: stream.value(),
            },
            _ => S::Other,
        });
    }
    out
}

/// Moves bytes both ways until neither side has anything to say.
fn pump(c: &mut ClientConn, s: &mut ServerConn) -> (Vec<C>, Vec<S>) {
    let (mut ce, mut se) = (vec![], vec![]);
    for _ in 0..64 {
        let mut moved = false;
        let out = c.output().to_vec();
        if !out.is_empty() {
            let n = s.feed(&out);
            c.consume_output(n);
            moved |= n > 0;
        }
        se.extend(drain_server(s));
        let out = s.output().to_vec();
        if !out.is_empty() {
            let n = c.feed(&out);
            s.consume_output(n);
            moved |= n > 0;
        }
        ce.extend(drain_client(c));
        if !moved {
            break;
        }
    }
    (ce, se)
}

fn pair(server: Config) -> (ClientConn, ServerConn) {
    let mut c = ClientConn::new(Config::new());
    let mut s = ServerConn::new(server);
    let (ce, se) = pump(&mut c, &mut s);
    assert!(ce.is_empty() && se.is_empty(), "{ce:?} {se:?}");
    assert!(c.settings_acked() && s.settings_acked());
    (c, s)
}

fn get(path: &str) -> RequestParts<'_> {
    RequestParts {
        method: "GET",
        scheme: Scheme::Https,
        authority: "example.com",
        path,
        fields: &[],
    }
}

#[test]
fn test_client_preface_refuses_push() {
    let c = ClientConn::new(Config::new());
    let out = c.output();
    assert!(out.starts_with(PREFACE));
    let Decoded::Frame {
        frame: Frame::Settings(s),
        ..
    } = frame::decode(&out[PREFACE.len()..], 1 << 24).unwrap()
    else {
        panic!()
    };
    assert!(
        s.iter()
            .any(|(id, v)| id == SettingId::ENABLE_PUSH && v == 0)
    );
}

#[test]
fn test_request_and_response_round_trip() {
    let (mut c, mut s) = pair(Config::new());
    let stream = c.send_request(&get("/hello?x=1"), true).unwrap();
    assert_eq!(stream.value(), 1);
    let (_, se) = pump(&mut c, &mut s);
    assert_eq!(
        se,
        [S::Request {
            stream: 1,
            target: "/hello?x=1".into(),
            end: true
        }]
    );
    s.send_headers(stream, 200, &[("content-type", b"text/plain")], false)
        .unwrap();
    s.send_data(stream, b"hi", true).unwrap();
    let (ce, _) = pump(&mut c, &mut s);
    assert_eq!(
        ce,
        [
            C::Response {
                stream: 1,
                status: 200,
                end: false
            },
            C::Data {
                stream: 1,
                data: b"hi".to_vec(),
                end: true
            }
        ]
    );
    assert_eq!((c.open_streams(), s.open_streams()), (0, 0));
    // The next stream is 3.
    assert_eq!(c.send_request(&get("/"), true).unwrap().value(), 3);
}

#[test]
fn test_request_body_informational_and_trailers() {
    let (mut c, mut s) = pair(Config::new());
    let head = RequestParts {
        method: "POST",
        scheme: Scheme::Https,
        authority: "example.com",
        path: "/upload",
        fields: &[
            ("Content-Length", b"5"),
            ("Connection", b"close"),
            ("Host", b"x"),
        ],
    };
    let stream = c.send_request(&head, false).unwrap();
    assert_eq!(c.send_data(stream, b"hel", false), Ok(3));
    // More than the content-length is refused.
    assert_eq!(c.send_data(stream, b"lo!", true), Err(SendError::Body));
    assert_eq!(c.send_data(stream, b"lo", true), Ok(2));
    let (_, se) = pump(&mut c, &mut s);
    assert_eq!(
        se,
        [
            S::Request {
                stream: 1,
                target: "/upload".into(),
                end: false
            },
            S::Data {
                stream: 1,
                data: b"hel".to_vec(),
                end: false
            },
            S::Data {
                stream: 1,
                data: b"lo".to_vec(),
                end: true
            }
        ]
    );
    s.send_headers(stream, 103, &[("link", b"</a.css>; rel=preload")], false)
        .unwrap();
    s.send_headers(stream, 200, &[], false).unwrap();
    s.send_data(stream, b"ok", false).unwrap();
    s.send_trailers(stream, &[("x-sum", b"1")]).unwrap();
    let (ce, _) = pump(&mut c, &mut s);
    assert_eq!(
        ce,
        [
            C::Informational {
                stream: 1,
                status: 103
            },
            C::Response {
                stream: 1,
                status: 200,
                end: false
            },
            C::Data {
                stream: 1,
                data: b"ok".to_vec(),
                end: false
            },
            C::Trailers {
                stream: 1,
                fields: 1
            }
        ]
    );
}

#[test]
fn test_head_response_carries_no_body() {
    let (mut c, mut s) = pair(Config::new());
    let head = RequestParts {
        method: "HEAD",
        ..get("/")
    };
    let stream = c.send_request(&head, true).unwrap();
    pump(&mut c, &mut s);
    s.send_headers(stream, 200, &[("content-length", b"10")], false)
        .unwrap();
    let (ce, _) = pump(&mut c, &mut s);
    assert_eq!(
        ce,
        [C::Response {
            stream: 1,
            status: 200,
            end: true
        }]
    );
    assert_eq!(c.open_streams(), 0);
}

#[test]
fn test_the_peer_stream_limit_makes_the_client_wait() {
    let (mut c, mut s) = pair(Config::new().max_concurrent_streams(1));
    let first = c.send_request(&get("/a"), true).unwrap();
    assert_eq!(c.send_request(&get("/b"), true), Err(SendError::Busy));
    pump(&mut c, &mut s);
    s.send_headers(first, 204, &[], true).unwrap();
    pump(&mut c, &mut s);
    assert!(c.send_request(&get("/b"), true).is_ok());
}

#[test]
fn test_request_head_checks() {
    let (mut c, _) = pair(Config::new());
    let bad = [
        RequestParts {
            path: "http://x/",
            ..get("/")
        },
        RequestParts {
            path: "",
            ..get("/")
        },
        RequestParts {
            authority: "user@example.com",
            ..get("/")
        },
        RequestParts {
            authority: "",
            ..get("/")
        },
        RequestParts {
            method: "G T",
            ..get("/")
        },
        RequestParts {
            fields: &[("a b", b"1")],
            ..get("/")
        },
        RequestParts {
            fields: &[("x", b"a\r\nb")],
            ..get("/")
        },
        RequestParts {
            fields: &[("te", b"gzip")],
            ..get("/")
        },
    ];
    for head in bad {
        assert!(
            matches!(c.send_request(&head, true), Err(SendError::Field(_))),
            "{head:?}"
        );
    }
    assert!(c.output().is_empty() || c.output().len() < 200);
    // CONNECT carries no :scheme or :path.
    let connect = RequestParts {
        method: "CONNECT",
        path: "",
        authority: "example.com:443",
        ..get("/")
    };
    assert!(c.send_request(&connect, false).is_ok());
    // A body promised as empty with END_STREAM is fine; a non-empty one is not.
    let head = RequestParts {
        fields: &[("content-length", b"3")],
        ..get("/")
    };
    assert_eq!(c.send_request(&head, true), Err(SendError::Body));
}

#[test]
fn test_goaway_refuses_unprocessed_streams() {
    let (mut c, mut s) = pair(Config::new());
    for path in ["/a", "/b", "/c"] {
        c.send_request(&get(path), true).unwrap();
    }
    pump(&mut c, &mut s);
    // A server that processed stream 1 only.
    let mut wire = vec![];
    frame::encode(
        &Frame::GoAway {
            last_stream: sid(1),
            code: ErrorCode::NO_ERROR,
            debug: b"",
        },
        16_384,
        &mut wire,
    )
    .unwrap();
    c.feed(&wire);
    let ce = drain_client(&mut c);
    assert_eq!(
        ce,
        [
            C::GoAway(ErrorCode::NO_ERROR),
            C::Reset {
                stream: 3,
                code: ErrorCode::REFUSED_STREAM,
                remote: true
            },
            C::Reset {
                stream: 5,
                code: ErrorCode::REFUSED_STREAM,
                remote: true
            }
        ]
    );
    assert_eq!(c.open_streams(), 1);
    assert_eq!(c.send_request(&get("/d"), true), Err(SendError::GoingAway));
}

#[test]
fn test_server_graceful_shutdown_seen_by_a_client() {
    let (mut c, mut s) = pair(Config::new());
    let stream = c.send_request(&get("/a"), true).unwrap();
    pump(&mut c, &mut s);
    s.shutdown();
    let (ce, _) = pump(&mut c, &mut s);
    assert_eq!(ce, [C::GoAway(ErrorCode::NO_ERROR)]);
    s.send_headers(stream, 204, &[], true).unwrap();
    let (ce, _) = pump(&mut c, &mut s);
    assert_eq!(
        ce,
        [C::Response {
            stream: 1,
            status: 204,
            end: true
        }]
    );
    assert!(s.is_done());
    assert!(c.is_done());
}

#[test]
fn test_client_shutdown() {
    let (mut c, mut s) = pair(Config::new());
    let stream = c.send_request(&get("/a"), true).unwrap();
    c.shutdown();
    assert_eq!(c.send_request(&get("/b"), true), Err(SendError::GoingAway));
    let (_, se) = pump(&mut c, &mut s);
    assert!(matches!(se.first(), Some(S::Request { .. })));
    assert!(!c.is_done());
    s.send_headers(stream, 204, &[], true).unwrap();
    pump(&mut c, &mut s);
    assert!(c.is_done());
}

// ---- A misbehaving server, written by hand.

/// A client past the settings exchange, with stream 1 open.
fn client_with_stream(method: &str) -> ClientConn {
    let mut c = ClientConn::new(Config::new());
    let mut wire = vec![];
    frame::settings_frame(&[], 16_384, &mut wire).unwrap();
    c.feed(&wire);
    assert!(drain_client(&mut c).is_empty());
    c.send_request(&RequestParts { method, ..get("/") }, true)
        .unwrap();
    c
}

fn headers(
    c: &mut ClientConn,
    enc: &mut Encoder,
    stream: u32,
    fields: &[(&[u8], &[u8])],
    end: bool,
) -> Vec<C> {
    let mut block = vec![];
    enc.encode(
        fields.iter().map(|(n, v)| HeaderField::new(n, v)),
        &mut block,
    );
    let mut wire = vec![];
    frame::encode(
        &Frame::Headers {
            stream: sid(stream),
            end_stream: end,
            end_headers: true,
            priority: None,
            fragment: &block,
            padding: None,
        },
        1 << 24,
        &mut wire,
    )
    .unwrap();
    c.feed(&wire);
    drain_client(c)
}

fn rejected(reason: Malformed) -> Vec<C> {
    vec![
        C::Rejected {
            stream: 1,
            reason: Rejection::Malformed(reason),
        },
        C::Reset {
            stream: 1,
            code: ErrorCode::PROTOCOL_ERROR,
            remote: false,
        },
    ]
}

#[test]
fn test_malformed_responses_are_reset() {
    type Fields = &'static [(&'static [u8], &'static [u8])];
    let cases: [(Fields, bool, Malformed); 8] = [
        (&[(b"content-type", b"x")], false, Malformed::Status),
        (&[(b":status", b"20")], false, Malformed::Status),
        (&[(b":status", b"600")], false, Malformed::Status),
        (&[(b":status", b"101")], false, Malformed::Status),
        (&[(b":status", b"100")], true, Malformed::Status),
        (
            &[(b":status", b"200"), (b":path", b"/")],
            false,
            Malformed::UnknownPseudo,
        ),
        (
            &[(b":status", b"200"), (b"Content-Type", b"x")],
            false,
            Malformed::FieldName,
        ),
        (
            &[(b":status", b"200"), (b"content-length", b"4")],
            true,
            Malformed::ContentLength,
        ),
    ];
    for (fields, end, why) in cases {
        let mut c = client_with_stream("GET");
        let got = headers(&mut c, &mut Encoder::new(4096), 1, fields, end);
        assert_eq!(got, rejected(why), "{fields:?}");
        assert_eq!(c.open_streams(), 0);
    }
}

#[test]
fn test_response_body_rules() {
    let data = |c: &mut ClientConn, d: &[u8], end: bool| {
        let mut wire = vec![];
        frame::encode(
            &Frame::Data {
                stream: sid(1),
                end_stream: end,
                data: d,
                padding: None,
            },
            1 << 24,
            &mut wire,
        )
        .unwrap();
        c.feed(&wire);
        drain_client(c)
    };
    let reset = |code| C::Reset {
        stream: 1,
        code,
        remote: false,
    };
    // DATA before the response head.
    let mut c = client_with_stream("GET");
    assert_eq!(data(&mut c, b"x", true), [reset(ErrorCode::PROTOCOL_ERROR)]);
    // A body on 204.
    let mut c = client_with_stream("GET");
    let mut enc = Encoder::new(4096);
    headers(&mut c, &mut enc, 1, &[(b":status", b"204")], false);
    assert_eq!(data(&mut c, b"x", true), [reset(ErrorCode::PROTOCOL_ERROR)]);
    // More than the content-length.
    let mut c = client_with_stream("GET");
    let mut enc = Encoder::new(4096);
    headers(
        &mut c,
        &mut enc,
        1,
        &[(b":status", b"200"), (b"content-length", b"2")],
        false,
    );
    assert_eq!(
        data(&mut c, b"abc", true),
        [reset(ErrorCode::PROTOCOL_ERROR)]
    );
    // A HEAD response's content-length promises nothing on the wire.
    let mut c = client_with_stream("HEAD");
    let mut enc = Encoder::new(4096);
    let got = headers(
        &mut c,
        &mut enc,
        1,
        &[(b":status", b"200"), (b"content-length", b"10")],
        true,
    );
    assert_eq!(
        got,
        [C::Response {
            stream: 1,
            status: 200,
            end: true
        }]
    );
}

#[test]
fn test_server_only_frames_end_the_connection() {
    // PUSH_PROMISE: push was refused in the client's SETTINGS.
    let mut c = client_with_stream("GET");
    let mut wire = vec![];
    frame::encode(
        &Frame::PushPromise {
            stream: sid(1),
            end_headers: true,
            promised: sid(2),
            fragment: b"\x82",
            padding: None,
        },
        1 << 24,
        &mut wire,
    )
    .unwrap();
    c.feed(&wire);
    assert_eq!(
        drain_client(&mut c),
        [C::Error(ConnErrorKind::Protocol(Violation::PushPromise))]
    );
    // PRIORITY_UPDATE is a client's frame.
    let mut c = client_with_stream("GET");
    let mut wire = vec![];
    frame::encode(
        &Frame::PriorityUpdate {
            prioritized: sid(1),
            field: b"u=1",
        },
        1 << 24,
        &mut wire,
    )
    .unwrap();
    c.feed(&wire);
    assert_eq!(
        drain_client(&mut c),
        [C::Error(ConnErrorKind::Protocol(Violation::PriorityUpdate))]
    );
    // A response on a stream the client never opened.
    let mut c = client_with_stream("GET");
    let got = headers(
        &mut c,
        &mut Encoder::new(4096),
        5,
        &[(b":status", b"200")],
        true,
    );
    assert!(matches!(
        got.as_slice(),
        [C::Error(ConnErrorKind::Protocol(
            Violation::IdleStream { .. }
        ))]
    ));
    // The first frame must be SETTINGS.
    let mut c = ClientConn::new(Config::new());
    let mut wire = vec![];
    frame::encode(
        &Frame::Ping {
            ack: false,
            payload: [0; 8],
        },
        16_384,
        &mut wire,
    )
    .unwrap();
    c.feed(&wire);
    assert_eq!(
        drain_client(&mut c),
        [C::Error(ConnErrorKind::Protocol(Violation::SettingsFirst))]
    );
}

#[test]
fn test_server_resets_do_not_count_against_the_client() {
    let (mut c, mut s) = pair(Config::new());
    for _ in 0..500 {
        let stream = c.send_request(&get("/"), true).unwrap();
        pump(&mut c, &mut s);
        s.reset(stream, ErrorCode::CANCEL);
        let (ce, _) = pump(&mut c, &mut s);
        assert!(!ce.iter().any(|e| matches!(e, C::Error(_))), "{ce:?}");
    }
}

#[test]
fn test_continuation_flood_from_a_server_is_refused() {
    let mut c = client_with_stream("GET");
    let mut wire = vec![];
    frame::encode(
        &Frame::Headers {
            stream: sid(1),
            end_stream: true,
            end_headers: false,
            priority: None,
            fragment: b"",
            padding: None,
        },
        1 << 24,
        &mut wire,
    )
    .unwrap();
    for _ in 0..1000 {
        frame::encode(
            &Frame::Continuation {
                stream: sid(1),
                end_headers: false,
                fragment: b"",
            },
            1 << 24,
            &mut wire,
        )
        .unwrap();
    }
    let mut got = vec![];
    for chunk in wire.chunks(4096) {
        c.feed(chunk);
        got.extend(drain_client(&mut c));
        if !got.is_empty() {
            // The error is sticky: every later call reports it again.
            break;
        }
    }
    assert_eq!(got, [C::Error(ConnErrorKind::ContinuationFlood)]);
}
