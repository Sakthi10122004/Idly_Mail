//! Fuzzes the client-side reply path: multi-line reply parsing, enhanced
//! status codes and EHLO capability parsing.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use smtp_proto::limits::REPLY_LINE;
use smtp_proto::{EhloResponse, Reply};

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    while let Ok(Some((reply, consumed))) = Reply::parse(buf, REPLY_LINE) {
        assert!(consumed > 0 && consumed <= buf.len());
        assert!((200..=559).contains(&reply.code));
        assert!(!reply.lines.is_empty());
        let _ = EhloResponse::from_reply(&reply);
        buf = buf.get(consumed..).unwrap_or_default();
    }
});
