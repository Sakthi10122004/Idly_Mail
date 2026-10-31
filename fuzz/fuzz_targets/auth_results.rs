//! Fuzzes Authentication-Results handling: authserv-id parsing and the
//! removal of forged fields. The output must never grow.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use mail_auth_glue::auth_results::{authserv_id, strip_forged};

fuzz_target!(|data: &[u8]| {
    let _ = authserv_id(data);
    let out = strip_forged(data, "mx.example.org");
    assert!(out.len() <= data.len());
});
