//! Fuzzes reading certificates from the ACME CA or the operator's files:
//! the PEM chain splitter and the DER inspection of the leaf
//! (RFC 5280 §4.1).

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(info) = acme::cert::inspect(data) {
        // renew_at stays inside the validity period.
        let at = info.renew_at();
        assert!(
            info.not_after < info.not_before || (info.not_before..=info.not_after).contains(&at)
        );
        assert!(info.names.iter().all(|n| n.to_ascii_lowercase() == *n));
        assert!(!info.spki.is_empty());
    }
    if let Ok(chain) = acme::cert::chain(data) {
        assert!(!chain.is_empty());
        for cert in &chain {
            let _ = acme::cert::inspect(cert);
        }
    }
});
