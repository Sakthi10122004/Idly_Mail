//! Fuzzes the MIME structure parser (RFC 2045, RFC 2046) used for IMAP
//! BODYSTRUCTURE/ENVELOPE and JMAP: every range stays inside the message,
//! limits hold, and decoding (including Date, RFC 5322 §3.3) never panics.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use mail_auth_glue::structure::{self, Kind, MAX_PARTS, Part};

fn check(p: &Part, len: usize) {
    assert!(p.header.start <= p.header.end && p.header.end <= len);
    assert!(p.body.start <= p.body.end && p.body.end <= len);
    assert_eq!(p.header.end, p.body.start);
    assert!(!p.media_type.is_empty() && !p.media_subtype.is_empty());
    match &p.kind {
        Kind::Leaf => {}
        Kind::Multipart(parts) => {
            for c in parts {
                assert!(c.header.start >= p.body.start && c.body.end <= p.body.end);
                check(c, len);
            }
        }
        Kind::Message(m) => check(&m.1, len),
    }
}

fuzz_target!(|data: &[u8]| {
    let root = structure::parse(data);
    check(&root, data.len());
    let all = root.walk();
    assert!(all.len() <= MAX_PARTS + 1);
    for p in all.iter().take(50) {
        let _ = p.text(data);
        let _ = p.filename();
    }
    let env = structure::envelope(data);
    for m in structure::address::mailboxes(&env.from) {
        let _ = m.display_name();
    }
    let _ = root.section(&[1, 2, 1]);
    if let Some(d) = env.date.as_deref() {
        let _ = structure::date::parse(d);
    }
    let _ = structure::date::parse(&String::from_utf8_lossy(data));
});
