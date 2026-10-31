//! Fuzzes the DATA decoder. Beyond not panicking, it checks the smuggling
//! invariants:
//! - the data ends only at a real CRLF.CRLF (or ".CRLF" at the very start);
//! - the decoded message never contains a bare CR or LF;
//! - feeding the input in two chunks gives the same result as one.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use smtp_proto::data::{self, DataDecoder, Progress};
use smtp_proto::limits::TEXT_LINE;

fn decode(parts: &[&[u8]], max_line: Option<usize>) -> (Result<usize, smtp_proto::Error>, Vec<u8>) {
    let mut d = DataDecoder::new(max_line);
    let mut out = Vec::new();
    let mut offset = 0usize;
    for part in parts {
        match d.decode(part, &mut out) {
            Ok(Progress::Done { consumed }) => return (Ok(offset + consumed), out),
            Ok(Progress::NeedMore) => offset += part.len(),
            Err(e) => return (Err(e), out),
        }
    }
    (Ok(usize::MAX), out)
}

fuzz_target!(|input: &[u8]| {
    let Some((&split, data)) = input.split_first() else {
        return;
    };
    let max_line = if split & 1 == 0 {
        Some(TEXT_LINE)
    } else {
        None
    };

    let (whole, out) = decode(&[data], max_line);
    if let Ok(consumed) = whole {
        if consumed != usize::MAX {
            let end = data.get(..consumed).unwrap_or_default();
            assert!(
                end == b".\r\n" || end.ends_with(b"\r\n.\r\n"),
                "ended early: {end:?}"
            );
            // The decoded message is clean CRLF text: re-encoding must succeed.
            let mut wire = Vec::new();
            data::encode(&out, &mut wire).expect("decoded data has bare CR/LF");
            let (again, out2) = decode(&[&wire], None);
            assert_eq!(again, Ok(wire.len()));
            assert_eq!(out2, out);
        }
    }

    let at = usize::from(split).min(data.len());
    let (a, b) = data.split_at(at);
    let (chunked, chunked_out) = decode(&[a, b], max_line);
    assert_eq!(chunked, whole);
    if whole.is_ok() {
        assert_eq!(chunked_out, out);
    }
});
