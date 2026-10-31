//! Maps recipients to the accounts in the configuration.

use std::collections::HashMap;

use smtp_proto::address::domain_to_ascii;
use smtp_proto::{ForwardPath, Host, Mailbox};
use smtp_server::{Directory, Recipient};

use crate::config::Config;

/// Local accounts from `[[account]]`, keyed by normalized address.
#[derive(Debug)]
pub(crate) struct ConfigDirectory {
    /// Local domains in A-label form.
    domains: Vec<String>,
    /// "local-part@a-label-domain", lower-case -> canonical account address.
    accounts: HashMap<String, String>,
    /// Account that receives mail for postmaster (RFC 5321 §4.5.1).
    postmaster: String,
}

/// The lookup key for a mailbox: ASCII-lower-cased local-part (local-parts
/// are compared case-insensitively here, as nearly every server does) and
/// the A-label domain.
fn key(m: &Mailbox) -> Option<String> {
    match &m.host {
        Host::Domain(d) => Some(format!(
            "{}@{}",
            m.local_part.to_lowercase(),
            domain_to_ascii(d).ok()?
        )),
        _ => None,
    }
}

impl ConfigDirectory {
    /// Builds the directory from a validated configuration.
    pub(crate) fn new(config: &Config) -> Self {
        let domains = config
            .domains
            .iter()
            .filter_map(|d| domain_to_ascii(&d.name).ok())
            .collect();
        let mut accounts = HashMap::new();
        for a in &config.accounts {
            if let Some(k) = Mailbox::parse(&a.address).ok().as_ref().and_then(key) {
                accounts.insert(k, a.address.to_lowercase());
            }
        }
        // Prefer an explicit postmaster@ account; otherwise the first account.
        let postmaster = config
            .accounts
            .iter()
            .find(|a| a.address.to_lowercase().starts_with("postmaster@"))
            .or_else(|| config.accounts.first())
            .map(|a| a.address.to_lowercase())
            .unwrap_or_default();
        Self {
            domains,
            accounts,
            postmaster,
        }
    }
}

impl Directory for ConfigDirectory {
    fn resolve(&self, to: &ForwardPath) -> Recipient {
        let m = match to {
            // RFC 5321 §4.1.1.3, §4.5.1: <Postmaster> must always be accepted.
            ForwardPath::Postmaster => return Recipient::Local(self.postmaster.clone()),
            ForwardPath::Mailbox(m) => m,
        };
        let Host::Domain(d) = &m.host else {
            return Recipient::NotLocal;
        };
        let Ok(domain) = domain_to_ascii(d) else {
            return Recipient::NotLocal;
        };
        if !self.domains.contains(&domain) {
            return Recipient::NotLocal;
        }
        if let Some(account) = key(m).and_then(|k| self.accounts.get(&k)) {
            return Recipient::Local(account.clone());
        }
        // RFC 5321 §4.5.1: postmaster@ every local domain must work.
        if m.local_part.eq_ignore_ascii_case("postmaster") {
            return Recipient::Local(self.postmaster.clone());
        }
        Recipient::UnknownUser
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> ConfigDirectory {
        let c = Config::parse(
            r#"
            [server]
            hostname = "mx.example.org"
            data_dir = "/var/lib/idly"
            [[domain]]
            name = "example.org"
            [[domain]]
            name = "bücher.example"
            [[account]]
            address = "Alice@example.org"
            password_hash = "$argon2id$x"
            [[account]]
            address = "kim@bücher.example"
            password_hash = "$argon2id$x"
        "#,
        )
        .unwrap();
        ConfigDirectory::new(&c)
    }

    fn to(s: &str) -> ForwardPath {
        ForwardPath::Mailbox(Mailbox::parse(s).unwrap())
    }

    #[test]
    fn resolves_accounts() {
        let d = dir();
        assert_eq!(
            d.resolve(&to("alice@EXAMPLE.org")),
            Recipient::Local("alice@example.org".into())
        );
        assert_eq!(
            d.resolve(&to("ALICE@example.org")),
            Recipient::Local("alice@example.org".into())
        );
        assert_eq!(
            d.resolve(&to("kim@xn--bcher-kva.example")),
            Recipient::Local("kim@bücher.example".into())
        );
        assert_eq!(d.resolve(&to("bob@example.org")), Recipient::UnknownUser);
        assert_eq!(d.resolve(&to("alice@gmail.com")), Recipient::NotLocal);
        assert_eq!(d.resolve(&to("alice@[127.0.0.1]")), Recipient::NotLocal);
    }

    #[test]
    fn postmaster_falls_back_to_first_account() {
        let d = dir();
        assert_eq!(
            d.resolve(&ForwardPath::Postmaster),
            Recipient::Local("alice@example.org".into())
        );
        assert_eq!(
            d.resolve(&to("PostMaster@bücher.example")),
            Recipient::Local("alice@example.org".into())
        );
    }
}
