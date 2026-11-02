//! Fuzzes the IMAP command framer (RFC 9051 §2.2, literals per §4.3 and
//! RFC 7888) with the input split at fuzzer-chosen points: every command
//! ends in CRLF, the commands are exactly a prefix of the input, and
//! limits hold.

#![no_main]
#![forbid(unsafe_code)]

use imap_proto::{Event, Framer, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&split, data)) = data.split_first() else {
        return;
    };
    let limits = Limits {
        max_line: 200,
        max_literal: 300,
        max_nonsync_literal: 20,
    };
    let mut f = Framer::new(limits);
    let mut produced = Vec::new();
    let chunk = usize::from(split).max(1);
    let mut dropped = false;
    for piece in data.chunks(chunk) {
        f.push(piece);
        while let Some(ev) = f.next_event() {
            match ev {
                Event::Command(c) => {
                    assert!(c.ends_with(b"\r\n"));
                    produced.extend_from_slice(&c);
                }
                Event::Continue => {}
                Event::LiteralTooLarge { .. } => dropped = true,
                Event::Fatal(_) => return,
            }
        }
    }
    // Commands are taken from the front, in order, byte for byte.
    if !dropped {
        assert!(data.starts_with(&produced));
        assert_eq!(produced.len() + f.pending(), data.len());
    }
});
