//! Fuzzes the submission long-line fixer and the 8-bit downgrade (MIME
//! walking, QP/base64 re-encoding, header folding). If the fixer succeeds,
//! no line may exceed 998 octets; if the downgrade succeeds, no octet may
//! be 8-bit either. Compliant input must come back unchanged.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use mail_auth_glue::mime::{fix_long_lines, has_long_lines, is_eight_bit, to_seven_bit};

fuzz_target!(|data: &[u8]| {
    let compliant = !has_long_lines(data);
    if let Ok(out) = fix_long_lines(data) {
        assert!(!has_long_lines(&out));
        if compliant {
            assert_eq!(&*out, data);
        }
    }
    if let Ok(out) = to_seven_bit(data) {
        assert!(!has_long_lines(&out) && !is_eight_bit(&out));
        if compliant && !is_eight_bit(data) {
            assert_eq!(&*out, data);
        }
    }
});
