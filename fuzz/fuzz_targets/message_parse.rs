//! Fuzzes RFC 5322 header parsing, From-domain extraction and DKIM/DMARC
//! tag lists. None may panic; parsed headers must point into the input.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use mail_auth_glue::message::{Message, address_domains};
use mail_auth_glue::tags::TagList;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = Message::parse(data) {
        let mut total = 0usize;
        for h in &m.headers {
            assert!(h.raw.ends_with(h.value));
            assert!(!h.name.is_empty());
            total += h.raw.len();
            let _ = address_domains(h.value);
        }
        assert!(total + m.body.len() <= data.len());
    }
    let _ = address_domains(data);
    if let Ok(s) = core::str::from_utf8(data) {
        if let Ok(t) = TagList::parse(s) {
            let _ = t.get("v");
        }
    }
});
