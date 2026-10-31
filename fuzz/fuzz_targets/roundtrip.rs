//! Anything that parses must serialize and parse back to the same value:
//! commands, replies, EHLO responses and DATA.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use smtp_proto::data::{self, DataDecoder, Progress};
use smtp_proto::{Command, EhloResponse, Reply};

fuzz_target!(|data: &[u8]| {
    if let Ok(cmd) = Command::parse(data) {
        let bytes = cmd.to_bytes();
        let line = bytes
            .strip_suffix(b"\r\n")
            .expect("serialized command ends in CRLF");
        assert_eq!(
            Command::parse(line).as_ref(),
            Ok(&cmd),
            "{:?}",
            String::from_utf8_lossy(&bytes)
        );
    }

    // Replies: lossy UTF-8 can make serialized text longer, so reparse
    // without the line limit.
    if let Ok(Some((reply, _))) = Reply::parse(data, usize::MAX) {
        let bytes = reply.to_bytes();
        let again = Reply::parse(&bytes, usize::MAX);
        assert_eq!(again, Ok(Some((reply.clone(), bytes.len()))));

        if let Ok(ehlo) = EhloResponse::from_reply(&reply) {
            let bytes = ehlo.to_reply().to_bytes();
            let (r, _) = Reply::parse(&bytes, usize::MAX)
                .ok()
                .flatten()
                .expect("reparse EHLO reply");
            assert_eq!(EhloResponse::from_reply(&r).as_ref(), Ok(&ehlo));
        }
    }

    // DATA: any CRLF-clean message survives encode then decode.
    let mut wire = Vec::new();
    if data::encode(data, &mut wire).is_ok() {
        let mut d = DataDecoder::new(None);
        let mut out = Vec::new();
        assert_eq!(
            d.decode(&wire, &mut out),
            Ok(Progress::Done {
                consumed: wire.len()
            })
        );
        let expected_len = if data.is_empty() || data.ends_with(b"\r\n") {
            data.len()
        } else {
            data.len() + 2
        };
        assert_eq!(out.len(), expected_len);
        assert_eq!(out.get(..data.len()), Some(data));
    }
});
