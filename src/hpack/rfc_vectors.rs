//! RFC 7541 Appendix C, generated from the RFC's text.

pub(crate) struct Example {
    pub(crate) id: &'static str,
    pub(crate) headers: &'static [(&'static [u8], &'static [u8])],
    pub(crate) wire: &'static [u8],
    /// The dynamic table after decoding, newest first.
    pub(crate) table: &'static [(&'static [u8], &'static [u8])],
    pub(crate) table_size: usize,
}

/// C.2: independent examples (each with a fresh decoder).
pub(crate) const C2: &[Example] = &[
    Example {
        id: "C.2.1",
        headers: &[(b"custom-key", b"custom-header")],
        wire: b"\x40\x0a\x63\x75\x73\x74\x6f\x6d\x2d\x6b\x65\x79\x0d\x63\x75\x73\x74\x6f\x6d\x2d\x68\x65\x61\x64\x65\x72",
        table: &[(b"custom-key", b"custom-header")],
        table_size: 55,
    },
    Example {
        id: "C.2.2",
        headers: &[(b":path", b"/sample/path")],
        wire: b"\x04\x0c\x2f\x73\x61\x6d\x70\x6c\x65\x2f\x70\x61\x74\x68",
        table: &[],
        table_size: 0,
    },
    Example {
        id: "C.2.3",
        headers: &[(b"password", b"secret")],
        wire: b"\x10\x08\x70\x61\x73\x73\x77\x6f\x72\x64\x06\x73\x65\x63\x72\x65\x74",
        table: &[],
        table_size: 0,
    },
    Example {
        id: "C.2.4",
        headers: &[(b":method", b"GET")],
        wire: b"\x82",
        table: &[],
        table_size: 0,
    },
];

/// C.3: requests without Huffman coding.
pub(crate) const C3: &[Example] = &[
    Example {
        id: "C.3.1",
        headers: &[(b":method", b"GET"), (b":scheme", b"http"), (b":path", b"/"), (b":authority", b"www.example.com")],
        wire: b"\x82\x86\x84\x41\x0f\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d",
        table: &[(b":authority", b"www.example.com")],
        table_size: 57,
    },
    Example {
        id: "C.3.2",
        headers: &[(b":method", b"GET"), (b":scheme", b"http"), (b":path", b"/"), (b":authority", b"www.example.com"), (b"cache-control", b"no-cache")],
        wire: b"\x82\x86\x84\xbe\x58\x08\x6e\x6f\x2d\x63\x61\x63\x68\x65",
        table: &[(b"cache-control", b"no-cache"), (b":authority", b"www.example.com")],
        table_size: 110,
    },
    Example {
        id: "C.3.3",
        headers: &[(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/index.html"), (b":authority", b"www.example.com"), (b"custom-key", b"custom-value")],
        wire: b"\x82\x87\x85\xbf\x40\x0a\x63\x75\x73\x74\x6f\x6d\x2d\x6b\x65\x79\x0c\x63\x75\x73\x74\x6f\x6d\x2d\x76\x61\x6c\x75\x65",
        table: &[(b"custom-key", b"custom-value"), (b"cache-control", b"no-cache"), (b":authority", b"www.example.com")],
        table_size: 164,
    },
];

/// C.4: requests with Huffman coding.
pub(crate) const C4: &[Example] = &[
    Example {
        id: "C.4.1",
        headers: &[(b":method", b"GET"), (b":scheme", b"http"), (b":path", b"/"), (b":authority", b"www.example.com")],
        wire: b"\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff",
        table: &[(b":authority", b"www.example.com")],
        table_size: 57,
    },
    Example {
        id: "C.4.2",
        headers: &[(b":method", b"GET"), (b":scheme", b"http"), (b":path", b"/"), (b":authority", b"www.example.com"), (b"cache-control", b"no-cache")],
        wire: b"\x82\x86\x84\xbe\x58\x86\xa8\xeb\x10\x64\x9c\xbf",
        table: &[(b"cache-control", b"no-cache"), (b":authority", b"www.example.com")],
        table_size: 110,
    },
    Example {
        id: "C.4.3",
        headers: &[(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/index.html"), (b":authority", b"www.example.com"), (b"custom-key", b"custom-value")],
        wire: b"\x82\x87\x85\xbf\x40\x88\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f\x89\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf",
        table: &[(b"custom-key", b"custom-value"), (b"cache-control", b"no-cache"), (b":authority", b"www.example.com")],
        table_size: 164,
    },
];

/// C.5: responses without Huffman coding, a 256-byte table.
pub(crate) const C5: &[Example] = &[
    Example {
        id: "C.5.1",
        headers: &[(b":status", b"302"), (b"cache-control", b"private"), (b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"), (b"location", b"https://www.example.com")],
        wire: b"\x48\x03\x33\x30\x32\x58\x07\x70\x72\x69\x76\x61\x74\x65\x61\x1d\x4d\x6f\x6e\x2c\x20\x32\x31\x20\x4f\x63\x74\x20\x32\x30\x31\x33\x20\x32\x30\x3a\x31\x33\x3a\x32\x31\x20\x47\x4d\x54\x6e\x17\x68\x74\x74\x70\x73\x3a\x2f\x2f\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d",
        table: &[(b"location", b"https://www.example.com"), (b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"), (b"cache-control", b"private"), (b":status", b"302")],
        table_size: 222,
    },
    Example {
        id: "C.5.2",
        headers: &[(b":status", b"307"), (b"cache-control", b"private"), (b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"), (b"location", b"https://www.example.com")],
        wire: b"\x48\x03\x33\x30\x37\xc1\xc0\xbf",
        table: &[(b":status", b"307"), (b"location", b"https://www.example.com"), (b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"), (b"cache-control", b"private")],
        table_size: 222,
    },
    Example {
        id: "C.5.3",
        headers: &[(b":status", b"200"), (b"cache-control", b"private"), (b"date", b"Mon, 21 Oct 2013 20:13:22 GMT"), (b"location", b"https://www.example.com"), (b"content-encoding", b"gzip"), (b"set-cookie", b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1")],
        wire: b"\x88\xc1\x61\x1d\x4d\x6f\x6e\x2c\x20\x32\x31\x20\x4f\x63\x74\x20\x32\x30\x31\x33\x20\x32\x30\x3a\x31\x33\x3a\x32\x32\x20\x47\x4d\x54\xc0\x5a\x04\x67\x7a\x69\x70\x77\x38\x66\x6f\x6f\x3d\x41\x53\x44\x4a\x4b\x48\x51\x4b\x42\x5a\x58\x4f\x51\x57\x45\x4f\x50\x49\x55\x41\x58\x51\x57\x45\x4f\x49\x55\x3b\x20\x6d\x61\x78\x2d\x61\x67\x65\x3d\x33\x36\x30\x30\x3b\x20\x76\x65\x72\x73\x69\x6f\x6e\x3d\x31",
        table: &[(b"set-cookie", b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"), (b"content-encoding", b"gzip"), (b"date", b"Mon, 21 Oct 2013 20:13:22 GMT")],
        table_size: 215,
    },
];

/// C.6: responses with Huffman coding, a 256-byte table.
pub(crate) const C6: &[Example] = &[
    Example {
        id: "C.6.1",
        headers: &[(b":status", b"302"), (b"cache-control", b"private"), (b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"), (b"location", b"https://www.example.com")],
        wire: b"\x48\x82\x64\x02\x58\x85\xae\xc3\x77\x1a\x4b\x61\x96\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x82\xa6\x2d\x1b\xff\x6e\x91\x9d\x29\xad\x17\x18\x63\xc7\x8f\x0b\x97\xc8\xe9\xae\x82\xae\x43\xd3",
        table: &[(b"location", b"https://www.example.com"), (b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"), (b"cache-control", b"private"), (b":status", b"302")],
        table_size: 222,
    },
    Example {
        id: "C.6.2",
        headers: &[(b":status", b"307"), (b"cache-control", b"private"), (b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"), (b"location", b"https://www.example.com")],
        wire: b"\x48\x83\x64\x0e\xff\xc1\xc0\xbf",
        table: &[(b":status", b"307"), (b"location", b"https://www.example.com"), (b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"), (b"cache-control", b"private")],
        table_size: 222,
    },
    Example {
        id: "C.6.3",
        headers: &[(b":status", b"200"), (b"cache-control", b"private"), (b"date", b"Mon, 21 Oct 2013 20:13:22 GMT"), (b"location", b"https://www.example.com"), (b"content-encoding", b"gzip"), (b"set-cookie", b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1")],
        wire: b"\x88\xc1\x61\x96\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x84\xa6\x2d\x1b\xff\xc0\x5a\x83\x9b\xd9\xab\x77\xad\x94\xe7\x82\x1d\xd7\xf2\xe6\xc7\xb3\x35\xdf\xdf\xcd\x5b\x39\x60\xd5\xaf\x27\x08\x7f\x36\x72\xc1\xab\x27\x0f\xb5\x29\x1f\x95\x87\x31\x60\x65\xc0\x03\xed\x4e\xe5\xb1\x06\x3d\x50\x07",
        table: &[(b"set-cookie", b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"), (b"content-encoding", b"gzip"), (b"date", b"Mon, 21 Oct 2013 20:13:22 GMT")],
        table_size: 215,
    },
];
