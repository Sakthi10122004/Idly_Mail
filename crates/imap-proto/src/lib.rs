//! IMAP4rev2 (RFC 9051) protocol pieces without I/O: framing the client's
//! byte stream into commands, parsing them, and writing responses.
//!
//! Framing is strict (CLAUDE.md): only CRLF ends a line, and lines and
//! literals are bounded. Parsing never panics on network input (fuzz
//! targets `imap_command` and `imap_frame`).

#![forbid(unsafe_code)]

pub mod command;
pub mod fetch;
pub mod frame;
pub mod parse;
pub mod response;
pub mod search;
pub mod utf7;

pub use command::{
    Command, CommandBody, CommandError, Flag, ListReturn, ListSelect, QResync, SearchReturn,
    StatusItem, StoreMode, parse_command,
};
pub use fetch::{FetchAttr, Section, SectionText};
pub use frame::{Event, FrameError, Framer, Limits};
pub use parse::{SeqNum, SeqSet};
pub use search::SearchKey;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests;
