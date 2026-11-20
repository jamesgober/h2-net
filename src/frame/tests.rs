use alloc::vec;
use alloc::vec::Vec;

use super::*;

fn sid(n: u32) -> StreamId {
    StreamId::new(n).unwrap()
}

/// One frame of every type and shape, encodable as is.
fn samples() -> Vec<Frame<'static>> {
    let prio = Priority {
        exclusive: true,
        depends_on: sid(3),
        weight: 15,
    };
    vec![
        Frame::Data {
            stream: sid(1),
            end_stream: false,
            data: b"hello",
            padding: None,
        },
        Frame::Data {
            stream: sid(1),
            end_stream: true,
            data: b"",
            padding: Some(7),
        },
        Frame::Data {
            stream: sid(1),
            end_stream: true,
            data: b"x",
            padding: Some(0),
        },
        Frame::Headers {
            stream: sid(1),
            end_stream: true,
            end_headers: true,
            priority: None,
            fragment: b"\x82\x86\x84",
            padding: None,
        },
        Frame::Headers {
            stream: sid(5),
            end_stream: false,
            end_headers: false,
            priority: Some(prio),
            fragment: b"\x82",
            padding: Some(3),
        },
        Frame::Priority {
            stream: sid(5),
            priority: prio,
        },
        Frame::RstStream {
            stream: sid(7),
            code: ErrorCode::CANCEL,
        },
        Frame::Settings(Settings::ack()),
        Frame::Settings(
            Settings::from_payload(&[0, 3, 0, 0, 0, 100, 0, 0x99, 1, 2, 3, 4]).unwrap(),
        ),
        Frame::Settings(Settings::from_payload(&[]).unwrap()),
        Frame::PushPromise {
            stream: sid(1),
            end_headers: true,
            promised: sid(2),
            fragment: b"\x82",
            padding: Some(2),
        },
        Frame::Ping {
            ack: false,
            payload: [1, 2, 3, 4, 5, 6, 7, 8],
        },
        Frame::Ping {
            ack: true,
            payload: [0; 8],
        },
        Frame::GoAway {
            last_stream: sid(9),
            code: ErrorCode::ENHANCE_YOUR_CALM,
            debug: b"rapid reset",
        },
        Frame::GoAway {
            last_stream: StreamId::ZERO,
            code: ErrorCode::NO_ERROR,
            debug: b"",
        },
        Frame::WindowUpdate {
            stream: StreamId::ZERO,
            increment: MAX_WINDOW,
        },
        Frame::WindowUpdate {
            stream: sid(3),
            increment: 1,
        },
        Frame::Continuation {
            stream: sid(1),
            end_headers: true,
            fragment: b"\x84",
        },
        Frame::Continuation {
            stream: sid(1),
            end_headers: false,
            fragment: b"",
        },
        Frame::PriorityUpdate {
            prioritized: sid(1),
            field: b"u=3, i",
        },
        Frame::Unknown {
            kind: FrameType::new(0xfa),
            flags: 0xff,
            stream: sid(1),
            payload: b"ignored",
        },
    ]
}

fn encoded(f: &Frame<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    encode(f, DEFAULT_MAX_FRAME_SIZE, &mut out).unwrap();
    out
}

fn decode_one(wire: &[u8]) -> Result<Decoded<'_>, FrameError> {
    decode(wire, DEFAULT_MAX_FRAME_SIZE)
}

fn connection_error(wire: &[u8]) -> FrameError {
    decode_one(wire).unwrap_err()
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap().to_be_bytes();
    let mut v = vec![len[1], len[2], len[3], kind, flags];
    v.extend_from_slice(&stream.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

#[test]
fn test_every_frame_round_trips() {
    for f in samples() {
        let wire = encoded(&f);
        assert_eq!(
            decode_one(&wire).unwrap(),
            Decoded::Frame {
                frame: f,
                len: wire.len()
            },
            "{f:?}"
        );
    }
}

#[test]
fn test_split_at_every_byte_is_incomplete_then_whole() {
    for f in samples() {
        let wire = encoded(&f);
        for cut in 0..wire.len() {
            let needed = if cut < HEADER_LEN {
                HEADER_LEN
            } else {
                wire.len()
            };
            assert_eq!(
                decode_one(&wire[..cut]).unwrap(),
                Decoded::Incomplete { needed },
                "{f:?} cut at {cut}"
            );
        }
        // Bytes after the frame are left for the next call.
        let mut more = wire.clone();
        more.extend_from_slice(&[0, 0]);
        let Decoded::Frame { len, .. } = decode_one(&more).unwrap() else {
            panic!("{f:?}")
        };
        assert_eq!(len, wire.len());
    }
}

#[test]
fn test_too_large_is_refused_from_the_header_alone() {
    let header = [0, 0x40, 0x01, 0x0, 0, 0, 0, 0, 1]; // 16,385 bytes of DATA
    assert_eq!(
        connection_error(&header),
        FrameError::TooLarge {
            len: 16_385,
            max: 16_384
        }
    );
    assert_eq!(
        decode(&header, 16_385).unwrap(),
        Decoded::Incomplete { needed: 9 + 16_385 }
    );
    let big = [0; 20_000];
    let f = Frame::Data {
        stream: sid(1),
        end_stream: false,
        data: &big,
        padding: None,
    };
    let mut out = Vec::new();
    assert!(matches!(
        encode(&f, DEFAULT_MAX_FRAME_SIZE, &mut out),
        Err(FrameError::TooLarge { len: 20_000, .. })
    ));
    assert!(out.is_empty());
    encode(&f, 20_000, &mut out).unwrap();
}

#[test]
fn test_reserved_bit_and_undefined_flags_are_ignored() {
    // DATA on stream 1 with the reserved bit and every flag set except
    // PADDED: reads as END_STREAM only.
    let mut wire = frame(0x0, !flags::PADDED, 1, b"ab");
    wire[5] |= 0x80;
    let Decoded::Frame { frame, .. } = decode_one(&wire).unwrap() else {
        panic!()
    };
    assert_eq!(
        frame,
        Frame::Data {
            stream: sid(1),
            end_stream: true,
            data: b"ab",
            padding: None
        }
    );
}

#[test]
fn test_stream_frames_on_stream_zero_are_protocol_errors() {
    for (kind, payload) in [
        (0x0u8, &b""[..]),
        (0x1, b""),
        (0x2, &[0, 0, 0, 1, 0]),
        (0x3, &[0, 0, 0, 0]),
        (0x5, &[0, 0, 0, 2]),
        (0x9, b""),
    ] {
        let e = connection_error(&frame(kind, 0, 0, payload));
        assert_eq!(
            e,
            FrameError::NeedsStream {
                kind: FrameType::new(kind)
            }
        );
        assert_eq!(e.code(), ErrorCode::PROTOCOL_ERROR);
    }
}

#[test]
fn test_connection_frames_on_a_stream_are_protocol_errors() {
    for (kind, payload) in [
        (0x4u8, &b""[..]),
        (0x6, &[0; 8]),
        (0x7, &[0; 8]),
        (0x10, &[0, 0, 0, 1]),
    ] {
        let e = connection_error(&frame(kind, 0, 3, payload));
        assert_eq!(
            e,
            FrameError::NeedsConnection {
                kind: FrameType::new(kind),
                stream: sid(3)
            }
        );
        assert_eq!(e.code(), ErrorCode::PROTOCOL_ERROR);
    }
}

#[test]
fn test_padding_that_fills_the_payload_is_a_protocol_error() {
    // Pad length 3 in a 3-byte payload (the length byte and two more).
    for kind in [0x0u8, 0x1] {
        let e = connection_error(&frame(kind, flags::PADDED, 1, &[3, 0, 0]));
        assert_eq!(
            e,
            FrameError::Padding {
                kind: FrameType::new(kind)
            }
        );
        assert_eq!(e.code(), ErrorCode::PROTOCOL_ERROR);
        // Pad length 2: allowed, an empty body.
        assert!(matches!(
            decode_one(&frame(kind, flags::PADDED, 1, &[2, 0, 0])).unwrap(),
            Decoded::Frame { .. }
        ));
        // PADDED with no room for the length byte.
        assert!(matches!(
            connection_error(&frame(kind, flags::PADDED, 1, &[])),
            FrameError::Padding { .. }
        ));
    }
    let e = connection_error(&frame(0x5, flags::PADDED, 1, &[5, 0, 0, 0, 2]));
    assert!(matches!(e, FrameError::Padding { .. }));
}

#[test]
fn test_padding_is_counted_by_flow_control() {
    let wire = frame(0x0, flags::PADDED, 1, &[4, b'a', b'b', 0, 0, 0, 0]);
    let Decoded::Frame { frame, .. } = decode_one(&wire).unwrap() else {
        panic!()
    };
    assert_eq!(frame.flow_len(), 7);
    assert!(matches!(frame, Frame::Data { data: b"ab", .. }));
}

#[test]
fn test_headers_priority_shapes() {
    // PRIORITY flag with fewer than 5 bytes: a frame size error.
    let e = connection_error(&frame(0x1, flags::PRIORITY, 1, &[0, 0, 0]));
    assert_eq!(e.code(), ErrorCode::FRAME_SIZE_ERROR);
    // A HEADERS frame whose stream depends on itself ends the connection.
    let e = connection_error(&frame(0x1, flags::PRIORITY, 1, &[0, 0, 0, 1, 0]));
    assert_eq!(e, FrameError::SelfDependency { stream: sid(1) });
}

#[test]
fn test_priority_frame_errors_are_stream_errors() {
    let wire = frame(0x2, 0, 3, &[0, 0, 0, 1]);
    assert_eq!(
        decode_one(&wire).unwrap(),
        Decoded::StreamError {
            stream: sid(3),
            error: FrameError::BadLength {
                kind: FrameType::PRIORITY,
                len: 4
            },
            len: wire.len()
        }
    );
    let wire = frame(0x2, 0, 3, &[0, 0, 0, 3, 0]);
    let Decoded::StreamError { error, .. } = decode_one(&wire).unwrap() else {
        panic!()
    };
    assert_eq!(error, FrameError::SelfDependency { stream: sid(3) });
    assert_eq!(error.code(), ErrorCode::PROTOCOL_ERROR);
}

#[test]
fn test_fixed_length_frames_refuse_other_lengths() {
    for (kind, stream, good) in [(0x3u8, 1, 4usize), (0x6, 0, 8), (0x8, 1, 4), (0x8, 0, 4)] {
        for len in [0, good - 1, good + 1] {
            let e = connection_error(&frame(kind, 0, stream, &vec![1; len]));
            assert_eq!(e.code(), ErrorCode::FRAME_SIZE_ERROR, "{kind} {len}");
        }
    }
    assert_eq!(
        connection_error(&frame(0x7, 0, 0, &[0; 7])).code(),
        ErrorCode::FRAME_SIZE_ERROR
    );
    assert_eq!(
        connection_error(&frame(0x10, 0, 0, &[0; 3])).code(),
        ErrorCode::FRAME_SIZE_ERROR
    );
}

#[test]
fn test_window_update_zero() {
    let e = connection_error(&frame(0x8, 0, 0, &[0, 0, 0, 0]));
    assert_eq!(e, FrameError::ZeroIncrement);
    let wire = frame(0x8, 0, 5, &[0x80, 0, 0, 0]); // only the reserved bit
    assert_eq!(
        decode_one(&wire).unwrap(),
        Decoded::StreamError {
            stream: sid(5),
            error: FrameError::ZeroIncrement,
            len: wire.len()
        }
    );
}

#[test]
fn test_settings_rules() {
    // ACK with a payload.
    let e = connection_error(&frame(0x4, flags::ACK, 0, &[0, 1, 0, 0, 0, 0]));
    assert_eq!(e.code(), ErrorCode::FRAME_SIZE_ERROR);
    // Not a multiple of 6.
    let e = connection_error(&frame(0x4, 0, 0, &[0, 1, 0, 0, 0]));
    assert_eq!(e.code(), ErrorCode::FRAME_SIZE_ERROR);
    // Out-of-range values, and the code each one takes.
    for (id, value, code) in [
        (0x2u16, 2u32, ErrorCode::PROTOCOL_ERROR),
        (0x4, 1 << 31, ErrorCode::FLOW_CONTROL_ERROR),
        (0x5, 16_383, ErrorCode::PROTOCOL_ERROR),
        (0x5, 1 << 24, ErrorCode::PROTOCOL_ERROR),
        (0x8, 2, ErrorCode::PROTOCOL_ERROR),
        (0x9, 2, ErrorCode::PROTOCOL_ERROR),
    ] {
        let mut p = id.to_be_bytes().to_vec();
        p.extend_from_slice(&value.to_be_bytes());
        let e = connection_error(&frame(0x4, 0, 0, &p));
        assert_eq!(e, FrameError::SettingValue { id, value });
        assert_eq!(e.code(), code);
    }
    // The edges of each range are accepted.
    for (id, value) in [
        (0x4u16, MAX_WINDOW),
        (0x5, 16_384),
        (0x5, MAX_FRAME_SIZE_LIMIT),
        (0x2, 0),
    ] {
        let mut p = id.to_be_bytes().to_vec();
        p.extend_from_slice(&value.to_be_bytes());
        assert!(matches!(
            decode_one(&frame(0x4, 0, 0, &p)).unwrap(),
            Decoded::Frame { .. }
        ));
    }
}

#[test]
fn test_setting_values_apply_in_order() {
    let s =
        Settings::from_payload(&[0, 3, 0, 0, 0, 1, 0, 3, 0, 0, 0, 2, 0, 2, 0, 0, 0, 0]).unwrap();
    let mut v = SettingValues::default();
    v.apply(&s);
    assert_eq!(v.max_concurrent_streams, Some(2));
    assert!(!v.enable_push);
    v.set(SettingId::MAX_FRAME_SIZE, 1);
    assert_eq!(v.max_frame_size, DEFAULT_MAX_FRAME_SIZE);
}

#[test]
fn test_settings_frame_writer() {
    let mut out = Vec::new();
    assert!(settings_frame(&[(SettingId::ENABLE_PUSH, 2)], 16_384, &mut out).is_err());
    let many = vec![(SettingId::new(0x99), 0); 3000];
    assert!(matches!(
        settings_frame(&many, 16_384, &mut out),
        Err(FrameError::TooLarge { .. })
    ));
    assert!(out.is_empty());
}

#[test]
fn test_priority_update_for_stream_zero() {
    let e = connection_error(&frame(0x10, 0, 0, &[0, 0, 0, 0, b'u']));
    assert_eq!(e, FrameError::PriorityUpdateForZero);
}

#[test]
fn test_encode_refuses_what_decode_refuses() {
    let mut out = Vec::new();
    let refused = [
        Frame::Data {
            stream: StreamId::ZERO,
            end_stream: false,
            data: b"",
            padding: None,
        },
        Frame::Priority {
            stream: sid(1),
            priority: Priority {
                exclusive: false,
                depends_on: sid(1),
                weight: 0,
            },
        },
        Frame::WindowUpdate {
            stream: sid(1),
            increment: 0,
        },
        Frame::WindowUpdate {
            stream: sid(1),
            increment: MAX_WINDOW + 1,
        },
        Frame::PriorityUpdate {
            prioritized: StreamId::ZERO,
            field: b"",
        },
        Frame::Unknown {
            kind: FrameType::DATA,
            flags: 0,
            stream: sid(1),
            payload: b"",
        },
    ];
    for f in refused {
        assert!(
            encode(&f, DEFAULT_MAX_FRAME_SIZE, &mut out).is_err(),
            "{f:?}"
        );
    }
    assert!(out.is_empty());
}

#[test]
fn test_stream_id_edges() {
    assert_eq!(StreamId::new(StreamId::MAX.value()), Some(StreamId::MAX));
    assert_eq!(StreamId::masked(u32::MAX), StreamId::MAX);
    assert!(!sid(2).is_client_initiated());
}
