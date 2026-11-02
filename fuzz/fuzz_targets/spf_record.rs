//! Fuzzes SPF: record parsing, then full check_host() evaluation with the
//! input published as example.com's record (macros, includes, redirects
//! and the DNS-term and void-lookup limits all run on hostile input).

#![no_main]
#![forbid(unsafe_code)]

use dns::testing::StaticResolver;
use libfuzzer_sys::fuzz_target;
use mail_auth_glue::spf::record::Record;
use mail_auth_glue::spf::{SpfResult, check_host};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let _ = Record::parse(text);
    let ip = |s: &str| s.parse().expect("ip");
    let resolver = StaticResolver::new()
        .with_txt("example.com", text)
        .with_txt("inc.example.com", "v=spf1 a mx ptr -all")
        .with_txt("loop.example.com", "v=spf1 include:loop.example.com")
        .with_mx("example.com", 10, "mx.example.com")
        .with_ip("mx.example.com", ip("192.0.2.1"))
        .with_ip("example.com", ip("192.0.2.2"))
        .with_ptr(ip("192.0.2.3"), "host.example.com")
        .with_ip("host.example.com", ip("192.0.2.3"));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime");
    for client in ["192.0.2.3", "2001:db8::1"] {
        let r = rt.block_on(check_host(
            &resolver,
            ip(client),
            "example.com",
            "user+tag@example.com",
            "helo.example.net",
        ));
        // A loop must end in a limit, never hang or overflow the stack.
        let _ = r == SpfResult::Pass;
    }
});
