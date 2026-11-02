//! Fuzzes the TLS reporting TXT record parser (RFC 8460 §3), including
//! its mailto and https URIs, and checks what an accepted record may
//! contain: report destinations are never address literals, other ports,
//! or anything that could smuggle a second header or request line.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use smtp_client::tlsrpt::{MAX_RUA, Rua, parse_txt};

fuzz_target!(|data: &[u8]| {
    // The input as one record, and split at NUL into several.
    let several: Vec<Vec<u8>> = data.split(|&b| b == 0).map(<[u8]>::to_vec).collect();
    for records in [vec![data.to_vec()], several] {
        let Some(rua) = parse_txt(&records) else {
            continue;
        };
        assert!(!rua.is_empty() && rua.len() <= MAX_RUA);
        for r in rua {
            match r {
                Rua::Mailto(addr) => {
                    let (_, domain) = addr.rsplit_once('@').expect("an address");
                    assert!(!domain.starts_with('['), "no address literals");
                    assert!(!addr.chars().any(|c| c.is_control()));
                }
                Rua::Https { host, path } => {
                    assert!(host.is_ascii() && !host.is_empty());
                    assert!(host.parse::<std::net::IpAddr>().is_err());
                    assert!(!host.contains([':', '@', '/', '[']));
                    assert!(path.starts_with('/'));
                    assert!(path.bytes().all(|b| (0x21..=0x7e).contains(&b)));
                }
            }
        }
    }
});
