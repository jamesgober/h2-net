//! Error codes (RFC 9113 section 7) and the errors the frame layer reports.

use core::fmt;

use crate::frame::{FrameType, StreamId};

/// An HTTP/2 error code, as carried by `RST_STREAM` and `GOAWAY` (RFC 9113
/// section 7). Unknown codes are kept as they arrived: RFC 9113 says an
/// endpoint must not treat an unknown code as anything special.
///
/// # Examples
///
/// ```
/// use h2_net::ErrorCode;
///
/// assert_eq!(ErrorCode::PROTOCOL_ERROR.value(), 0x1);
/// assert_eq!(ErrorCode::new(0xb), ErrorCode::ENHANCE_YOUR_CALM);
/// assert_eq!(ErrorCode::new(0xb).name(), Some("ENHANCE_YOUR_CALM"));
/// assert_eq!(ErrorCode::new(0x99).name(), None);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorCode(u32);

impl ErrorCode {
    /// Graceful shutdown, or no error.
    pub const NO_ERROR: Self = Self(0x0);
    /// An unspecific protocol error.
    pub const PROTOCOL_ERROR: Self = Self(0x1);
    /// An unexpected internal error.
    pub const INTERNAL_ERROR: Self = Self(0x2);
    /// The peer broke the flow-control protocol.
    pub const FLOW_CONTROL_ERROR: Self = Self(0x3);
    /// A `SETTINGS` frame was not acknowledged in time.
    pub const SETTINGS_TIMEOUT: Self = Self(0x4);
    /// A frame arrived after the stream was half-closed.
    pub const STREAM_CLOSED: Self = Self(0x5);
    /// A frame had an invalid size.
    pub const FRAME_SIZE_ERROR: Self = Self(0x6);
    /// The stream was refused before any application processing.
    pub const REFUSED_STREAM: Self = Self(0x7);
    /// The stream is no longer needed.
    pub const CANCEL: Self = Self(0x8);
    /// The field section compression context cannot be kept.
    pub const COMPRESSION_ERROR: Self = Self(0x9);
    /// The connection for a `CONNECT` request was reset or closed.
    pub const CONNECT_ERROR: Self = Self(0xa);
    /// The peer is generating excessive load.
    pub const ENHANCE_YOUR_CALM: Self = Self(0xb);
    /// The transport does not meet the minimum security requirements.
    pub const INADEQUATE_SECURITY: Self = Self(0xc);
    /// The peer must use HTTP/1.1 for this request.
    pub const HTTP_1_1_REQUIRED: Self = Self(0xd);

    /// The code with this value.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// The code's value on the wire.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }

    /// The code's name in RFC 9113, or `None` for a code it does not define.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self.0 {
            0x0 => "NO_ERROR",
            0x1 => "PROTOCOL_ERROR",
            0x2 => "INTERNAL_ERROR",
            0x3 => "FLOW_CONTROL_ERROR",
            0x4 => "SETTINGS_TIMEOUT",
            0x5 => "STREAM_CLOSED",
            0x6 => "FRAME_SIZE_ERROR",
            0x7 => "REFUSED_STREAM",
            0x8 => "CANCEL",
            0x9 => "COMPRESSION_ERROR",
            0xa => "CONNECT_ERROR",
            0xb => "ENHANCE_YOUR_CALM",
            0xc => "INADEQUATE_SECURITY",
            0xd => "HTTP_1_1_REQUIRED",
            _ => return None,
        })
    }
}

impl fmt::Debug for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "ErrorCode({:#x})", self.0),
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// A frame the frame layer refused. Each variant names the rule it broke;
/// [`code`](Self::code) is the error code RFC 9113 gives for it.
///
/// # Examples
///
/// ```
/// use h2_net::{ErrorCode, frame};
///
/// // A PING frame on stream 1: PING belongs to the connection.
/// let mut wire = vec![0, 0, 8, 0x6, 0, 0, 0, 0, 1];
/// wire.extend_from_slice(&[0; 8]);
/// let error = frame::decode(&wire, frame::DEFAULT_MAX_FRAME_SIZE).unwrap_err();
/// assert_eq!(error.code(), ErrorCode::PROTOCOL_ERROR);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The frame's length is over the receiver's `SETTINGS_MAX_FRAME_SIZE`.
    TooLarge {
        /// The length the frame header declared.
        len: u32,
        /// The largest length allowed.
        max: u32,
    },
    /// The frame's length is wrong for its type (a `PING` that is not 8
    /// bytes, a `RST_STREAM` that is not 4, a `SETTINGS` that is not a
    /// multiple of 6, a `SETTINGS` acknowledgment with a payload).
    BadLength {
        /// The frame's type.
        kind: FrameType,
        /// The length the frame header declared.
        len: u32,
    },
    /// A frame that belongs to a stream arrived on stream 0.
    NeedsStream {
        /// The frame's type.
        kind: FrameType,
    },
    /// A frame that belongs to the connection arrived on a stream.
    NeedsConnection {
        /// The frame's type.
        kind: FrameType,
        /// The stream it named.
        stream: StreamId,
    },
    /// The padding is as long as the payload or longer.
    Padding {
        /// The frame's type.
        kind: FrameType,
    },
    /// A `WINDOW_UPDATE` with an increment of 0.
    ZeroIncrement,
    /// A stream that depends on itself in a priority signal.
    SelfDependency {
        /// The stream.
        stream: StreamId,
    },
    /// A `SETTINGS` parameter with a value outside its range.
    SettingValue {
        /// The parameter's identifier.
        id: u16,
        /// The value it carried.
        value: u32,
    },
    /// A `PRIORITY_UPDATE` (RFC 9218) naming stream 0.
    PriorityUpdateForZero,
    /// Only from [`encode`](crate::frame::encode): a window increment over
    /// 2^31 - 1.
    IncrementTooLarge {
        /// The increment.
        increment: u32,
    },
    /// Only from [`encode`](crate::frame::encode): an
    /// [`Unknown`](crate::frame::Frame::Unknown) frame with a type this
    /// crate defines, which would read back as that type.
    DefinedType {
        /// The type.
        kind: FrameType,
    },
}

impl FrameError {
    /// The error code RFC 9113 (or RFC 9218) gives for this refusal.
    ///
    /// # Examples
    ///
    /// ```
    /// use h2_net::{ErrorCode, FrameError};
    ///
    /// assert_eq!(FrameError::ZeroIncrement.code(), ErrorCode::PROTOCOL_ERROR);
    /// assert_eq!(
    ///     FrameError::TooLarge { len: 20_000, max: 16_384 }.code(),
    ///     ErrorCode::FRAME_SIZE_ERROR
    /// );
    /// ```
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::TooLarge { .. } | Self::BadLength { .. } => ErrorCode::FRAME_SIZE_ERROR,
            // An initial window over 2^31 - 1 is a flow-control error; every
            // other bad setting is a protocol error (RFC 9113 section 6.5.2).
            Self::SettingValue { id: 0x4, .. } | Self::IncrementTooLarge { .. } => {
                ErrorCode::FLOW_CONTROL_ERROR
            }
            Self::DefinedType { .. }
            | Self::NeedsStream { .. }
            | Self::NeedsConnection { .. }
            | Self::Padding { .. }
            | Self::ZeroIncrement
            | Self::SelfDependency { .. }
            | Self::SettingValue { .. }
            | Self::PriorityUpdateForZero => ErrorCode::PROTOCOL_ERROR,
        }
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { len, max } => {
                write!(f, "frame of {len} bytes is over the maximum of {max}")
            }
            Self::BadLength { kind, len } => write!(f, "{kind} frame of {len} bytes"),
            Self::NeedsStream { kind } => write!(f, "{kind} frame on stream 0"),
            Self::NeedsConnection { kind, stream } => {
                write!(f, "{kind} frame on stream {}", stream.value())
            }
            Self::Padding { kind } => write!(f, "{kind} frame padding fills the payload"),
            Self::ZeroIncrement => f.write_str("WINDOW_UPDATE with an increment of 0"),
            Self::SelfDependency { stream } => {
                write!(f, "stream {} depends on itself", stream.value())
            }
            Self::SettingValue { id, value } => {
                write!(f, "setting {id:#x} with the value {value} is out of range")
            }
            Self::PriorityUpdateForZero => f.write_str("PRIORITY_UPDATE for stream 0"),
            Self::IncrementTooLarge { increment } => {
                write!(f, "window increment {increment} is over 2^31 - 1")
            }
            Self::DefinedType { kind } => write!(f, "{kind} given as an unknown frame type"),
        }
    }
}

impl core::error::Error for FrameError {}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    #[test]
    fn test_error_code_names_cover_rfc_9113() {
        for v in 0..=0xd {
            assert!(ErrorCode::new(v).name().is_some(), "{v}");
        }
        assert_eq!(ErrorCode::new(0xe).name(), None);
        assert_eq!(format!("{:?}", ErrorCode::new(0xe)), "ErrorCode(0xe)");
        assert_eq!(format!("{}", ErrorCode::CANCEL), "CANCEL");
    }

    #[test]
    fn test_initial_window_setting_is_a_flow_control_error() {
        let e = FrameError::SettingValue {
            id: 0x4,
            value: 1 << 31,
        };
        assert_eq!(e.code(), ErrorCode::FLOW_CONTROL_ERROR);
        let e = FrameError::SettingValue { id: 0x2, value: 2 };
        assert_eq!(e.code(), ErrorCode::PROTOCOL_ERROR);
    }
}
