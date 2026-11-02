//! Submission accounts from `[[account]]`: Argon2id password checks and
//! which addresses each account may send as.

use std::collections::HashMap;

use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use smtp_proto::Mailbox;

use crate::config::Config;
use crate::directory::key;

/// Accounts and their password hashes, keyed like the directory.
#[derive(Debug)]
pub(crate) struct ConfigAccounts {
    /// Normalized address -> (canonical account name, PHC hash).
    accounts: HashMap<String, (String, String)>,
    /// Checked when the account doesn't exist, so a wrong user name costs
    /// as much as a wrong password and timing reveals nothing.
    dummy_hash: String,
}

/// Hashes a password with Argon2id and the default parameters, as a PHC
/// string. Used by `idly user hash-password` and for the dummy hash.
pub(crate) fn hash_password(password: &[u8]) -> Result<String, String> {
    Argon2::default()
        .hash_password(password)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

impl ConfigAccounts {
    /// Builds the accounts from a validated configuration.
    pub(crate) fn new(config: &Config) -> Result<Self, String> {
        let mut accounts = HashMap::new();
        for a in &config.accounts {
            if let Some(k) = Mailbox::parse(&a.address).ok().as_ref().and_then(key) {
                accounts.insert(k, (a.address.to_lowercase(), a.password_hash.clone()));
            }
        }
        // The dummy password needn't be secret: even if it matches, there
        // is no account to log in to.
        Ok(Self {
            accounts,
            dummy_hash: hash_password(b"idly-dummy-password")?,
        })
    }
}

impl smtp_server::Accounts for ConfigAccounts {
    fn verify(&self, username: &str, password: &str) -> Option<String> {
        let found = Mailbox::parse(username)
            .ok()
            .as_ref()
            .and_then(key)
            .and_then(|k| self.accounts.get(&k));
        let (hash, account) = match found {
            Some((account, hash)) => (hash.as_str(), Some(account)),
            None => (self.dummy_hash.as_str(), None),
        };
        // The hash's own parameters are used (argon2 reads them from the
        // PHC string); a malformed hash simply fails.
        let ok = Argon2::default()
            .verify_password(password.as_bytes(), hash)
            .is_ok();
        account.filter(|_| ok).cloned()
    }

    fn may_send_as(&self, account: &str, address: &str) -> bool {
        // An account sends only as its own address (aliases come later).
        Mailbox::parse(address)
            .ok()
            .as_ref()
            .and_then(key)
            .and_then(|k| self.accounts.get(&k))
            .is_some_and(|(owner, _)| owner == account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smtp_server::Accounts;

    fn accounts() -> ConfigAccounts {
        let hash = hash_password(b"secret").unwrap();
        let text = format!(
            r#"
            [server]
            hostname = "mx.example.org"
            data_dir = "/var/lib/idly"
            [[domain]]
            name = "example.org"
            [[account]]
            address = "Alice@example.org"
            password_hash = "{hash}"
            "#
        );
        ConfigAccounts::new(&Config::parse(&text).unwrap()).unwrap()
    }

    #[test]
    fn verifies_passwords() {
        let a = accounts();
        assert_eq!(
            a.verify("alice@EXAMPLE.org", "secret").as_deref(),
            Some("alice@example.org")
        );
        assert_eq!(a.verify("alice@example.org", "wrong"), None);
        assert_eq!(a.verify("nobody@example.org", "secret"), None);
        assert_eq!(a.verify("not an address", "secret"), None);
    }

    #[test]
    fn sends_only_as_itself() {
        let a = accounts();
        assert!(a.may_send_as("alice@example.org", "ALICE@example.org"));
        assert!(!a.may_send_as("alice@example.org", "bob@example.org"));
        assert!(!a.may_send_as("bob@example.org", "alice@example.org"));
    }

    #[test]
    fn unknown_user_costs_a_hash_check() {
        let a = accounts();
        let t = std::time::Instant::now();
        a.verify("alice@example.org", "wrong");
        let known = t.elapsed();
        let t = std::time::Instant::now();
        a.verify("nobody@example.org", "wrong");
        let unknown = t.elapsed();
        // Same Argon2 parameters, so within a generous factor of each other.
        assert!(
            unknown * 3 > known && known * 3 > unknown,
            "{known:?} vs {unknown:?}"
        );
    }
}
