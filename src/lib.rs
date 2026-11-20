//! # h2_net
//!
//! An HTTP/2 engine that does no I/O itself (RFC 9113, with HPACK from
//! RFC 7541). Feed it the bytes a socket delivered; it hands back frames and
//! decoded field sections, and serializes what you send back. The caller
//! owns sockets, threads, and timers.
//!
//! Parsing follows the RFCs strictly, and every buffer and count has a
//! budget that is checked before the resource is committed. A frame longer
//! than `SETTINGS_MAX_FRAME_SIZE` is refused from its 9-byte header, before
//! its payload is buffered; an HPACK block cannot decode to more than its
//! header list budget, however small it is on the wire.
//!
//! ## Layers
//!
//! - [`frame`]: the frame header, every frame type, and the checks RFC 9113
//!   puts on each frame by itself. `decode(encode(f)) == f`.
//! - [`hpack`]: field section compression with a bounded dynamic table,
//!   Huffman coding, and a decoded-size budget.
//!
//! ```
//! use h2_net::frame::{self, Decoded, Frame};
//! use h2_net::hpack::{Decoder, HeaderList};
//!
//! // A HEADERS frame carrying RFC 7541's first example request (C.3.1).
//! let block = b"\x82\x86\x84\x41\x0fwww.example.com";
//! let mut wire = vec![0, 0, block.len() as u8, 0x1, 0x5, 0, 0, 0, 1];
//! wire.extend_from_slice(block);
//!
//! let Decoded::Frame { frame: Frame::Headers { fragment, end_headers, .. }, .. } =
//!     frame::decode(&wire, frame::DEFAULT_MAX_FRAME_SIZE)?
//! else {
//!     panic!("not a HEADERS frame")
//! };
//! assert!(end_headers);
//!
//! let mut decoder = Decoder::new(4096);
//! let mut fields = HeaderList::new(16 * 1024);
//! decoder.decode(fragment, &mut fields)?;
//! assert_eq!(fields.get(":authority"), Some(&b"www.example.com"[..]));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/h2-net")]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(unused_must_use)]
#![deny(unused_results)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::print_stdout)]
#![deny(clippy::print_stderr)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::unreachable)]
#![deny(clippy::indexing_slicing)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod error;
pub mod frame;
pub mod hpack;

pub use error::{ErrorCode, FrameError};
pub use hpack::HpackError;

/// The crate version, as published (`CARGO_PKG_VERSION`).
///
/// # Examples
///
/// ```
/// assert_eq!(h2_net::VERSION.split('.').count(), 3);
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// The README's and the API reference's examples run as doctests, so their
// claims stay true.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

#[cfg(doctest)]
#[doc = include_str!("../docs/API.md")]
struct ApiDoctests;

#[cfg(test)]
mod tests {
    #[test]
    fn test_version_matches_the_manifest() {
        assert_eq!(crate::VERSION, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_public_types_are_send_and_sync() {
        fn assert<T: Send + Sync>() {}
        assert::<crate::ErrorCode>();
        assert::<crate::FrameError>();
        assert::<crate::frame::Frame<'_>>();
        assert::<crate::hpack::Decoder>();
        assert::<crate::hpack::Encoder>();
        assert::<crate::hpack::HeaderList>();
        assert::<crate::HpackError>();
    }
}
