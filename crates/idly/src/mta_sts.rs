//! The MTA-STS policy we publish (RFC 8461 §3.2) and its id for the
//! `_mta-sts` TXT record (RFC 8461 §3.1). Every domain gets the same
//! policy: its only MX is our host name.

use std::collections::HashMap;

use smtp_proto::address::domain_to_ascii;

use crate::config::Config;

/// The policy text, CRLF-terminated lines (RFC 8461 §3.2).
pub(crate) fn policy(config: &Config) -> String {
    let hostname = domain_to_ascii(&config.server.hostname)
        .unwrap_or_else(|_| config.server.hostname.to_ascii_lowercase());
    format!(
        "version: STSv1\r\nmode: {}\r\nmx: {hostname}\r\nmax_age: {}\r\n",
        config.mta_sts.mode.as_str(),
        config.mta_sts.max_age
    )
}

/// The policy id: it must change whenever the policy does (RFC 8461 §3.1),
/// so it is derived from the text. `1*32(ALPHA / DIGIT)`.
pub(crate) fn policy_id(policy: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, policy.as_bytes());
    digest
        .as_ref()
        .iter()
        .take(10)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `mta-sts.<domain>` (A-label) to policy, for the HTTPS server.
pub(crate) fn policies(config: &Config) -> HashMap<String, String> {
    let text = policy(config);
    config
        .domains
        .iter()
        .filter_map(|d| domain_to_ascii(&d.name).ok())
        .map(|d| (format!("mta-sts.{d}"), text.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
        [server]
        hostname = "MX.example.org"
        data_dir = "/var/lib/idly"
        [[domain]]
        name = "example.org"
        [[domain]]
        name = "bücher.example"
        [[account]]
        address = "alice@example.org"
        password_hash = "$argon2id$v=19$m=19456,t=2,p=1$ZGVtb2RlbW9kZW1v$ZGVtby1vbmx5LW5vdC1hLXJlYWwtaGFzaA"
        [mta_sts]
        enabled = true
        mode = "enforce"
        max_age = 86400
    "#;

    #[test]
    fn policy_parses_with_our_own_parser() {
        let c = Config::parse(CONFIG).unwrap();
        let text = policy(&c);
        assert_eq!(
            text,
            "version: STSv1\r\nmode: enforce\r\nmx: mx.example.org\r\nmax_age: 86400\r\n"
        );
        // What senders (and our own client) will make of it.
        let parsed = smtp_client::mta_sts::parse_policy(&text).unwrap();
        assert_eq!(parsed.mode, smtp_client::mta_sts::Mode::Enforce);
        assert_eq!(parsed.mx, ["mx.example.org"]);
        assert_eq!(parsed.max_age, 86400);
        let map = policies(&c);
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("mta-sts.xn--bcher-kva.example"));
    }

    #[test]
    fn id_changes_with_the_policy() {
        let mut c = Config::parse(CONFIG).unwrap();
        let a = policy_id(&policy(&c));
        assert_eq!(a.len(), 20);
        assert!(a.bytes().all(|b| b.is_ascii_alphanumeric()));
        assert_eq!(a, policy_id(&policy(&c)));
        c.mta_sts.max_age = 86401;
        assert_ne!(a, policy_id(&policy(&c)));
    }
}
