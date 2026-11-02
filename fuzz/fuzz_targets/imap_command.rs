//! Fuzzes the IMAP command parser (RFC 9051 §9 grammar): any framed
//! command parses or fails cleanly, and sequence sets answer membership
//! queries without panicking.

#![no_main]
#![forbid(unsafe_code)]

use imap_proto::{CommandBody, SeqSet, parse_command};
use libfuzzer_sys::fuzz_target;

fn probe(set: &SeqSet) {
    for n in [0, 1, 7, u32::MAX] {
        let _ = set.contains(n, 100);
    }
}

fuzz_target!(|data: &[u8]| {
    match parse_command(data) {
        Ok(cmd) => {
            assert!(!cmd.tag.is_empty() && !cmd.tag.contains(' ') && !cmd.tag.contains('+'));
            match &cmd.body {
                CommandBody::Fetch { set, .. }
                | CommandBody::Store { set, .. }
                | CommandBody::Copy { set, .. }
                | CommandBody::Move { set, .. } => probe(set),
                CommandBody::Append { message, .. } => assert!(message.len() <= data.len()),
                _ => {}
            }
        }
        Err(e) => assert!(!e.message.is_empty()),
    }
    let _ = imap_proto::utf7::decode(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let enc = imap_proto::utf7::encode(s);
        assert_eq!(imap_proto::utf7::decode(enc.as_bytes()).as_deref(), Some(s));
    }
});
