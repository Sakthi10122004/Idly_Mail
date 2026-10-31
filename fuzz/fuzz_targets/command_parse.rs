//! Fuzzes the server-side command path: line splitting, then command,
//! mailbox and host parsing. None of these may panic on any input.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use smtp_proto::limits::AUTH_COMMAND_LINE;
use smtp_proto::line::split_line;
use smtp_proto::{Command, Host, Mailbox};

fuzz_target!(|data: &[u8]| {
    // The whole input as one line, as if already split.
    let _ = Command::parse(data);

    // Through the line splitter, as a server reads a pipelined stream.
    let mut buf = data;
    while let Ok(Some((line, consumed))) = split_line(buf, AUTH_COMMAND_LINE) {
        assert!(!line.contains(&b'\r') && !line.contains(&b'\n'));
        let _ = Command::parse(line);
        buf = buf.get(consumed..).unwrap_or_default();
    }

    if let Ok(s) = core::str::from_utf8(data) {
        let _ = Mailbox::parse(s);
        let _ = Host::parse(s);
    }
});
