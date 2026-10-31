//! Sans-I/O SMTP protocol types for Idly Mail.
//!
//! This crate parses and serializes SMTP commands, replies and message data.
//! It does no I/O: callers feed it bytes and write out the bytes it returns.
//!
//! Strictness is deliberate. Only CRLF ends a line and only `CRLF . CRLF`
//! ends DATA; bare CR and bare LF are errors everywhere. This closes off SMTP
//! smuggling (RFC 5321 §2.3.8, §4.1.1.4).

#![forbid(unsafe_code)]

pub mod address;
pub mod command;
mod cursor;
pub mod error;
pub mod limits;
pub mod line;
pub mod params;

pub use address::{ForwardPath, Host, Mailbox, ReversePath};
pub use command::{Command, InitialResponse};
pub use error::{EnhancedCode, Error};
pub use params::{BodyType, MailParam, Notify, RawParam, RcptParam, Ret};
