//! Fuzzes the submission long-line fixer (MIME walking, QP/base64
//! re-encoding, header folding). If it succeeds, no line may exceed 998
//! octets; a message that already complied must come back unchanged.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use mail_auth_glue::mime::{fix_long_lines, has_long_lines};

fuzz_target!(|data: &[u8]| {
    let compliant = !has_long_lines(data);
    if let Ok(out) = fix_long_lines(data) {
        assert!(!has_long_lines(&out));
        if compliant {
            assert_eq!(&*out, data);
        }
    }
});
