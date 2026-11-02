//! Fuzzes DMARC: Policy Record parsing, then a full evaluation with the
//! input published as the record for example.com, and as a From field.

#![no_main]
#![forbid(unsafe_code)]

use dns::testing::StaticResolver;
use libfuzzer_sys::fuzz_target;
use mail_auth_glue::dmarc::record::Record;
use mail_auth_glue::dmarc::{Inputs, evaluate};
use mail_auth_glue::spf::SpfResult;

fuzz_target!(|data: &[u8]| {
    let _ = Record::parse(data);
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let resolver = StaticResolver::new()
        .with_txt("_dmarc.example.com", text)
        .with_txt("_dmarc.com", "v=DMARC1; p=none; psd=y")
        .with_ip("child.example.com", "192.0.2.1".parse().expect("ip"));
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    let inputs = Inputs {
        spf: (SpfResult::Pass, "child.example.com"),
        dkim: &[],
    };
    let msg = b"From: a@sub.child.example.com\r\n\r\nx\r\n";
    let _ = rt.block_on(evaluate(&resolver, msg, &inputs));
    // The input as a From field value.
    let mut msg = b"From:".to_vec();
    msg.extend_from_slice(data);
    msg.extend_from_slice(b"\r\n\r\nx\r\n");
    let _ = rt.block_on(evaluate(&resolver, &msg, &inputs));
});
