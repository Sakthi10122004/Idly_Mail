//! Fuzzes DKIM: DKIM-Signature and key-record parsing, and full
//! verification of arbitrary messages against fixed keys (RFC 8463
//! Appendix A), exercising canonicalization, b= removal and header
//! selection on hostile input.

#![no_main]
#![forbid(unsafe_code)]

use std::sync::OnceLock;

use dns::testing::StaticResolver;
use libfuzzer_sys::fuzz_target;
use mail_auth_glue::dkim::key::KeyRecord;
use mail_auth_glue::dkim::{Signature, verify};

fn resolver() -> &'static StaticResolver {
    static R: OnceLock<StaticResolver> = OnceLock::new();
    R.get_or_init(|| {
        StaticResolver::new()
            .with_txt(
                "brisbane._domainkey.football.example.com",
                "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
            )
            .with_txt(
                "test._domainkey.football.example.com",
                "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB",
            )
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = Signature::parse(data);
    let _ = KeyRecord::parse(data, "rsa");
    let _ = KeyRecord::parse(data, "ed25519");
    let rt = tokio::runtime::Builder::new_current_thread().build().expect("runtime");
    let results = rt.block_on(verify(resolver(), data, 1_528_637_969));
    assert!(results.len() <= 8);
});
