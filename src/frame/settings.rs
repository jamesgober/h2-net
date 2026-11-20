//! `SETTINGS` (RFC 9113 section 6.5, RFC 8441 section 3, RFC 9218 section
//! 2.1).

use alloc::vec::Vec;
use core::fmt;

use super::{
    DEFAULT_MAX_FRAME_SIZE, FrameHeader, FrameType, MAX_FRAME_SIZE_LIMIT, MAX_WINDOW, StreamId,
};
use crate::error::FrameError;

/// A `SETTINGS` parameter identifier. Identifiers this crate does not
/// define are read and ignored, as RFC 9113 says.
///
/// # Examples
///
/// ```
/// use h2_net::frame::SettingId;
///
/// assert_eq!(SettingId::MAX_FRAME_SIZE.value(), 0x5);
/// assert_eq!(format!("{:?}", SettingId::new(0x5)), "MAX_FRAME_SIZE");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SettingId(u16);

impl SettingId {
    /// `SETTINGS_HEADER_TABLE_SIZE`: the largest HPACK dynamic table the
    /// sender's decoder keeps.
    pub const HEADER_TABLE_SIZE: Self = Self(0x1);
    /// `SETTINGS_ENABLE_PUSH`: 0 or 1.
    pub const ENABLE_PUSH: Self = Self(0x2);
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`.
    pub const MAX_CONCURRENT_STREAMS: Self = Self(0x3);
    /// `SETTINGS_INITIAL_WINDOW_SIZE`: at most 2^31 - 1.
    pub const INITIAL_WINDOW_SIZE: Self = Self(0x4);
    /// `SETTINGS_MAX_FRAME_SIZE`: 2^14 to 2^24 - 1.
    pub const MAX_FRAME_SIZE: Self = Self(0x5);
    /// `SETTINGS_MAX_HEADER_LIST_SIZE`: advisory.
    pub const MAX_HEADER_LIST_SIZE: Self = Self(0x6);
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 8441): 0 or 1.
    pub const ENABLE_CONNECT_PROTOCOL: Self = Self(0x8);
    /// `SETTINGS_NO_RFC7540_PRIORITIES` (RFC 9218): 0 or 1.
    pub const NO_RFC7540_PRIORITIES: Self = Self(0x9);

    /// The identifier with this value.
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// The identifier's value on the wire.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Checks `value` against the range RFC 9113, RFC 8441, and RFC 9218
    /// give this parameter. Unknown parameters take any value.
    ///
    /// # Errors
    ///
    /// [`FrameError::SettingValue`].
    ///
    /// # Examples
    ///
    /// ```
    /// use h2_net::frame::SettingId;
    ///
    /// assert!(SettingId::MAX_FRAME_SIZE.check(16_384).is_ok());
    /// assert!(SettingId::MAX_FRAME_SIZE.check(16_383).is_err());
    /// assert!(SettingId::ENABLE_PUSH.check(2).is_err());
    /// assert!(SettingId::new(0xff).check(u32::MAX).is_ok());
    /// ```
    pub const fn check(self, value: u32) -> Result<(), FrameError> {
        let ok = match self {
            Self::ENABLE_PUSH | Self::ENABLE_CONNECT_PROTOCOL | Self::NO_RFC7540_PRIORITIES => {
                value <= 1
            }
            Self::INITIAL_WINDOW_SIZE => value <= MAX_WINDOW,
            Self::MAX_FRAME_SIZE => {
                value >= DEFAULT_MAX_FRAME_SIZE && value <= MAX_FRAME_SIZE_LIMIT
            }
            _ => true,
        };
        if ok {
            Ok(())
        } else {
            Err(FrameError::SettingValue { id: self.0, value })
        }
    }
}

impl fmt::Debug for SettingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::HEADER_TABLE_SIZE => "HEADER_TABLE_SIZE",
            Self::ENABLE_PUSH => "ENABLE_PUSH",
            Self::MAX_CONCURRENT_STREAMS => "MAX_CONCURRENT_STREAMS",
            Self::INITIAL_WINDOW_SIZE => "INITIAL_WINDOW_SIZE",
            Self::MAX_FRAME_SIZE => "MAX_FRAME_SIZE",
            Self::MAX_HEADER_LIST_SIZE => "MAX_HEADER_LIST_SIZE",
            Self::ENABLE_CONNECT_PROTOCOL => "ENABLE_CONNECT_PROTOCOL",
            Self::NO_RFC7540_PRIORITIES => "NO_RFC7540_PRIORITIES",
            _ => return write!(f, "SettingId({:#x})", self.0),
        };
        f.write_str(name)
    }
}

/// The parameters of a `SETTINGS` frame, every value already checked.
///
/// # Examples
///
/// ```
/// use h2_net::frame::{SettingId, Settings};
///
/// let payload = [0, 0x3, 0, 0, 0, 100, 0, 0x4, 0, 1, 0, 0];
/// let s = Settings::from_payload(&payload)?;
/// let all: Vec<_> = s.iter().collect();
/// assert_eq!(
///     all,
///     [(SettingId::MAX_CONCURRENT_STREAMS, 100), (SettingId::INITIAL_WINDOW_SIZE, 65_536)]
/// );
/// assert!(Settings::from_payload(&payload[..5]).is_err());
/// # Ok::<(), h2_net::FrameError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Settings<'a> {
    ack: bool,
    payload: &'a [u8],
}

impl<'a> Settings<'a> {
    /// An acknowledgment: the `ACK` flag and no parameters.
    #[must_use]
    pub const fn ack() -> Settings<'static> {
        Settings {
            ack: true,
            payload: &[],
        }
    }

    /// Parameters from a `SETTINGS` payload, checked.
    ///
    /// # Errors
    ///
    /// [`FrameError::BadLength`] when the payload is not a whole number of
    /// 6-byte parameters; [`FrameError::SettingValue`] for the first value
    /// out of its range.
    pub fn from_payload(payload: &'a [u8]) -> Result<Self, FrameError> {
        if payload.len() % 6 != 0 {
            return Err(FrameError::BadLength {
                kind: FrameType::SETTINGS,
                len: u32::try_from(payload.len()).unwrap_or(u32::MAX),
            });
        }
        let settings = Self {
            ack: false,
            payload,
        };
        for (id, value) in settings.iter() {
            id.check(value)?;
        }
        Ok(settings)
    }

    /// Whether this is an acknowledgment.
    #[must_use]
    pub const fn is_ack(&self) -> bool {
        self.ack
    }

    /// The raw payload.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// The number of parameters.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.payload.len() / 6
    }

    /// Whether there are no parameters.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    /// The parameters in the order sent. A parameter may repeat; the last
    /// one wins.
    #[must_use]
    pub fn iter(&self) -> SettingsIter<'a> {
        SettingsIter { rest: self.payload }
    }
}

impl fmt::Debug for Settings<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.ack {
            return f.write_str("Settings(ACK)");
        }
        f.debug_map().entries(self.iter()).finish()
    }
}

/// The parameters of a [`Settings`], in order.
#[derive(Clone, Debug)]
pub struct SettingsIter<'a> {
    rest: &'a [u8],
}

impl Iterator for SettingsIter<'_> {
    type Item = (SettingId, u32);

    fn next(&mut self) -> Option<Self::Item> {
        let (p, rest) = self.rest.split_first_chunk::<6>()?;
        self.rest = rest;
        Some((
            SettingId(u16::from_be_bytes([p[0], p[1]])),
            u32::from_be_bytes([p[2], p[3], p[4], p[5]]),
        ))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.rest.len() / 6;
        (n, Some(n))
    }
}

impl ExactSizeIterator for SettingsIter<'_> {}

/// Appends a `SETTINGS` frame carrying `params` to `out`.
///
/// # Errors
///
/// [`FrameError::SettingValue`] for a value out of its range, or
/// [`FrameError::TooLarge`] when the parameters do not fit in
/// `max_frame_size`. Nothing is written.
///
/// # Examples
///
/// ```
/// use h2_net::frame::{self, Decoded, Frame, SettingId};
///
/// let mut out = Vec::new();
/// frame::settings_frame(&[(SettingId::MAX_CONCURRENT_STREAMS, 100)], 16_384, &mut out)?;
/// let Decoded::Frame { frame: Frame::Settings(s), .. } = frame::decode(&out, 16_384)? else {
///     panic!()
/// };
/// assert_eq!(s.iter().next(), Some((SettingId::MAX_CONCURRENT_STREAMS, 100)));
/// # Ok::<(), h2_net::FrameError>(())
/// ```
pub fn settings_frame(
    params: &[(SettingId, u32)],
    max_frame_size: u32,
    out: &mut Vec<u8>,
) -> Result<(), FrameError> {
    for (id, value) in params {
        id.check(*value)?;
    }
    let len = params.len().saturating_mul(6);
    let max = max_frame_size.min(MAX_FRAME_SIZE_LIMIT);
    let len = match u32::try_from(len) {
        Ok(len) if len <= max => len,
        _ => {
            return Err(FrameError::TooLarge {
                len: u32::try_from(len).unwrap_or(u32::MAX),
                max,
            });
        }
    };
    out.reserve(super::HEADER_LEN + len as usize);
    FrameHeader {
        len,
        kind: FrameType::SETTINGS,
        flags: 0,
        stream: StreamId::ZERO,
    }
    .write(out);
    for (id, value) in params {
        out.extend_from_slice(&id.0.to_be_bytes());
        out.extend_from_slice(&value.to_be_bytes());
    }
    Ok(())
}

/// The values of every parameter this crate acts on, starting at RFC 9113's
/// initial values. One side's settings: what it told the other side.
///
/// # Examples
///
/// ```
/// use h2_net::frame::{SettingValues, Settings};
///
/// let mut peer = SettingValues::default();
/// assert_eq!(peer.initial_window_size, 65_535);
/// peer.apply(&Settings::from_payload(&[0, 0x4, 0, 0, 0x10, 0])?);
/// assert_eq!(peer.initial_window_size, 4096);
/// # Ok::<(), h2_net::FrameError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettingValues {
    /// `SETTINGS_HEADER_TABLE_SIZE` (initially 4096).
    pub header_table_size: u32,
    /// `SETTINGS_ENABLE_PUSH` (initially on).
    pub enable_push: bool,
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` (initially unlimited, `None`).
    pub max_concurrent_streams: Option<u32>,
    /// `SETTINGS_INITIAL_WINDOW_SIZE` (initially 65,535).
    pub initial_window_size: u32,
    /// `SETTINGS_MAX_FRAME_SIZE` (initially 16,384).
    pub max_frame_size: u32,
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` (initially unlimited, `None`).
    pub max_header_list_size: Option<u32>,
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (initially off).
    pub enable_connect_protocol: bool,
    /// `SETTINGS_NO_RFC7540_PRIORITIES` (initially off).
    pub no_rfc7540_priorities: bool,
}

impl Default for SettingValues {
    fn default() -> Self {
        Self {
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: None,
            initial_window_size: 65_535,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size: None,
            enable_connect_protocol: false,
            no_rfc7540_priorities: false,
        }
    }
}

impl SettingValues {
    /// Applies every parameter of `settings` in order. The values were
    /// checked when the frame was read.
    pub fn apply(&mut self, settings: &Settings<'_>) {
        for (id, value) in settings.iter() {
            self.set(id, value);
        }
    }

    /// Sets one parameter. Unknown parameters are ignored; a value out of
    /// range is ignored too (a [`Settings`] never carries one).
    pub fn set(&mut self, id: SettingId, value: u32) {
        if id.check(value).is_err() {
            return;
        }
        match id {
            SettingId::HEADER_TABLE_SIZE => self.header_table_size = value,
            SettingId::ENABLE_PUSH => self.enable_push = value == 1,
            SettingId::MAX_CONCURRENT_STREAMS => self.max_concurrent_streams = Some(value),
            SettingId::INITIAL_WINDOW_SIZE => self.initial_window_size = value,
            SettingId::MAX_FRAME_SIZE => self.max_frame_size = value,
            SettingId::MAX_HEADER_LIST_SIZE => self.max_header_list_size = Some(value),
            SettingId::ENABLE_CONNECT_PROTOCOL => self.enable_connect_protocol = value == 1,
            SettingId::NO_RFC7540_PRIORITIES => self.no_rfc7540_priorities = value == 1,
            _ => {}
        }
    }
}
