//! Fuzzes the MTA-STS TXT record and policy parsers (RFC 8461 §3.1,
//! §3.2), and checks what an accepted policy may contain.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use smtp_client::mta_sts::{Mode, mx_matches, parse_policy, parse_txt};

fuzz_target!(|data: &[u8]| {
    if let Some(id) = parse_txt(&[data.to_vec()]) {
        assert!((1..=32).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric()));
    }
    if let Ok(text) = std::str::from_utf8(data)
        && let Some(p) = parse_policy(text)
    {
        assert!(p.max_age <= 31_557_600);
        assert!(p.mode == Mode::None || !p.mx.is_empty());
        for pattern in &p.mx {
            let _ = mx_matches(pattern, "mail.example.com");
        }
    }
});
