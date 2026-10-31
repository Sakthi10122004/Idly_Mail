//! Parse errors, each mapped to the reply a server should send.

use core::fmt;

/// An enhanced mail system status code such as `5.5.2`.
///
/// RFC 3463 §2: `status-code = class "." subject "." detail`, where class is
/// 2, 4 or 5 and subject and detail are 1–3 digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnhancedCode {
    /// 2 (success), 4 (persistent transient failure) or 5 (permanent failure).
    pub class: u8,
    /// Subject sub-code, 0–999.
    pub subject: u16,
    /// Detail sub-code, 0–999.
    pub detail: u16,
}

impl EnhancedCode {
    /// Creates an enhanced status code. The caller ensures the ranges above.
    pub const fn new(class: u8, subject: u16, detail: u16) -> Self {
        Self {
            class,
            subject,
            detail,
        }
    }
}

impl fmt::Display for EnhancedCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.class, self.subject, self.detail)
    }
}

/// An error found while parsing SMTP protocol input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A CR not followed by LF. RFC 5321 §2.3.8 allows CR only as part of CRLF.
    BareCr,
    /// An LF not preceded by CR. RFC 5321 §2.3.8, §4.1.1.4.
    BareLf,
    /// The line exceeds `limit` octets, CRLF included. RFC 5321 §4.5.3.1.
    LineTooLong {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// The command line is not valid UTF-8. RFC 6531 §3.3 extends SMTP to
    /// UTF-8 only; any other 8-bit input is invalid.
    InvalidUtf8,
    /// The command verb is not one we recognize.
    UnrecognizedCommand,
    /// The command's arguments do not match its grammar.
    Syntax(&'static str),
    /// A mailbox, domain or address literal is malformed.
    InvalidAddress(&'static str),
    /// The MAIL FROM reverse-path is malformed.
    InvalidSender(&'static str),
    /// The RCPT TO forward-path is malformed.
    InvalidRecipient(&'static str),
    /// A MAIL or RCPT parameter is malformed or has an invalid value.
    InvalidParameter(&'static str),
    /// The same MAIL or RCPT parameter appears more than once.
    DuplicateParameter,
    /// A reply from the server is malformed (client side).
    InvalidReply(&'static str),
}

impl Error {
    /// The reply code and enhanced status code a server should send in
    /// response to this error. `None` for errors that only a client sees.
    ///
    /// Reply codes are from RFC 5321 §4.2.2 and §4.2.4; enhanced codes are
    /// from RFC 3463 §3.2 (addressing) and §3.6 (protocol).
    pub fn reply_code(&self) -> Option<(u16, EnhancedCode)> {
        let r = match self {
            // RFC 5321 §4.5.3.1.10: "500 Line too long."
            Self::BareCr | Self::BareLf | Self::LineTooLong { .. } | Self::InvalidUtf8 => {
                (500, EnhancedCode::new(5, 5, 2))
            }
            // RFC 5321 §4.2.4: 500 for an unrecognized command; RFC 3463 X.5.1.
            Self::UnrecognizedCommand => (500, EnhancedCode::new(5, 5, 1)),
            // RFC 5321 §4.2.2: 501 syntax error in parameters or arguments;
            // RFC 3463 X.5.4 invalid command arguments.
            Self::Syntax(_) | Self::InvalidParameter(_) | Self::DuplicateParameter => {
                (501, EnhancedCode::new(5, 5, 4))
            }
            // RFC 3463 X.1.3 bad destination mailbox address syntax.
            Self::InvalidAddress(_) | Self::InvalidRecipient(_) => {
                (501, EnhancedCode::new(5, 1, 3))
            }
            // RFC 3463 X.1.7 bad sender's mailbox address syntax.
            Self::InvalidSender(_) => (501, EnhancedCode::new(5, 1, 7)),
            Self::InvalidReply(_) => return None,
        };
        Some(r)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BareCr => f.write_str("bare CR received"),
            Self::BareLf => f.write_str("bare LF received"),
            Self::LineTooLong { limit } => write!(f, "line too long (limit {limit} octets)"),
            Self::InvalidUtf8 => f.write_str("invalid UTF-8"),
            Self::UnrecognizedCommand => f.write_str("command not recognized"),
            Self::Syntax(m) => write!(f, "syntax error: {m}"),
            Self::InvalidAddress(m) => write!(f, "invalid address: {m}"),
            Self::InvalidSender(m) => write!(f, "invalid sender address: {m}"),
            Self::InvalidRecipient(m) => write!(f, "invalid recipient address: {m}"),
            Self::InvalidParameter(m) => write!(f, "invalid parameter: {m}"),
            Self::DuplicateParameter => f.write_str("duplicate parameter"),
            Self::InvalidReply(m) => write!(f, "invalid reply: {m}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_line_endings_map_to_500_5_5_2() {
        for e in [Error::BareCr, Error::BareLf] {
            assert_eq!(e.reply_code(), Some((500, EnhancedCode::new(5, 5, 2))));
        }
    }

    #[test]
    fn sender_and_recipient_codes_differ() {
        assert_eq!(
            Error::InvalidSender("x").reply_code(),
            Some((501, EnhancedCode::new(5, 1, 7)))
        );
        assert_eq!(
            Error::InvalidRecipient("x").reply_code(),
            Some((501, EnhancedCode::new(5, 1, 3)))
        );
    }

    #[test]
    fn client_only_errors_have_no_reply() {
        assert_eq!(Error::InvalidReply("x").reply_code(), None);
    }

    #[test]
    fn enhanced_code_display() {
        assert_eq!(EnhancedCode::new(5, 7, 1).to_string(), "5.7.1");
    }
}
