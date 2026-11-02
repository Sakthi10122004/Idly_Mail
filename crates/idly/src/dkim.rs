//! DKIM keys on disk: `<data_dir>/dkim/<domain>/<selector>.key` holds a
//! PKCS #8 DER private key (mode 0600) and `<selector>.txt` the DNS record
//! to publish at `<selector>._domainkey.<domain>`.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use mail_auth_glue::dkim::{Signer, SigningKey, keygen};
use smtp_proto::address::domain_to_ascii;
use smtp_server::DkimKeys;

use crate::config::Config;

/// Which key types to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Algorithm {
    Rsa,
    Ed25519,
    /// Both, for dual signing (RFC 8463 §1): `<selector>-rsa` and
    /// `<selector>-ed25519`.
    Both,
}

/// A key generator from `mail_auth_glue::dkim::keygen`.
type Keygen = fn() -> Result<keygen::GeneratedKey, keygen::KeygenError>;

/// The directory holding `domain`'s keys.
fn domain_dir(data_dir: &Path, domain: &str) -> Result<PathBuf, String> {
    let ascii = domain_to_ascii(domain).map_err(|_| format!("not a valid domain: {domain}"))?;
    Ok(data_dir.join("dkim").join(ascii))
}

/// A selector is one DNS label (RFC 6376 §3.1); keep it to letters,
/// digits and hyphens so it is also a safe file name.
fn valid_selector(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

/// Generates keys and writes them; returns `(selector, dns_record)` pairs.
/// Never overwrites an existing key.
pub(crate) fn generate(
    data_dir: &Path,
    domain: &str,
    selector: &str,
    algorithm: Algorithm,
) -> Result<Vec<(String, String)>, String> {
    let dir = domain_dir(data_dir, domain)?;
    let wanted: Vec<(String, Keygen)> = match algorithm {
        Algorithm::Rsa => vec![(selector.to_owned(), keygen::rsa)],
        Algorithm::Ed25519 => vec![(selector.to_owned(), keygen::ed25519)],
        Algorithm::Both => vec![
            (format!("{selector}-rsa"), keygen::rsa),
            (format!("{selector}-ed25519"), keygen::ed25519),
        ],
    };
    for (sel, _) in &wanted {
        if !valid_selector(sel) {
            return Err(format!(
                "invalid selector {sel:?}: use letters, digits and hyphens"
            ));
        }
        if dir.join(format!("{sel}.key")).exists() {
            return Err(format!(
                "{} already exists; choose a new selector to rotate keys",
                dir.join(format!("{sel}.key")).display()
            ));
        }
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for (sel, make) in wanted {
        let key = make().map_err(|_| "key generation failed".to_owned())?;
        let path = dir.join(format!("{sel}.key"));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        f.write_all(&key.private_pkcs8)
            .and_then(|()| f.sync_all())
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let txt = dir.join(format!("{sel}.txt"));
        std::fs::write(&txt, format!("{}\n", key.dns_record))
            .map_err(|e| format!("{}: {e}", txt.display()))?;
        out.push((sel, key.dns_record));
    }
    Ok(out)
}

/// Loads every key of every configured domain. A domain without keys is
/// only warned about: its mail goes out unsigned.
pub(crate) fn load(config: &Config) -> Result<DkimKeys, String> {
    let mut keys = DkimKeys::new();
    for d in &config.domains {
        let dir = domain_dir(&config.server.data_dir, &d.name)?;
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(domain = %d.name, "no DKIM keys; run `idly dkim generate`");
                continue;
            }
            Err(e) => return Err(format!("{}: {e}", dir.display())),
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "key"))
            .collect();
        paths.sort();
        let mut found = false;
        for path in paths {
            let Some(selector) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if !valid_selector(selector) {
                return Err(format!("{}: invalid selector name", path.display()));
            }
            let meta = std::fs::metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            if meta.permissions().mode() & 0o077 != 0 {
                tracing::warn!(path = %path.display(), "DKIM private key is readable by other users; chmod 600 it");
            }
            let der = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let key = SigningKey::from_pkcs8(&der)
                .map_err(|e| format!("{}: not a usable key: {e:?}", path.display()))?;
            let signer = Signer::new(key, &d.name, selector)
                .map_err(|e| format!("{}: {e:?}", path.display()))?;
            tracing::info!(domain = %d.name, selector, "DKIM key loaded");
            keys.add(&d.name, signer);
            found = true;
        }
        if !found {
            tracing::warn!(domain = %d.name, "no DKIM keys; run `idly dkim generate`");
        }
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_load() {
        let tmp = tempfile::tempdir().unwrap();
        let text = format!(
            r#"
            [server]
            hostname = "mx.example.org"
            data_dir = "{}"
            [[domain]]
            name = "example.org"
            [[account]]
            address = "a@example.org"
            password_hash = "$argon2id$v=19$m=19456,t=2,p=1$ZGVtb2RlbW9kZW1v$ZGVtby1vbmx5LW5vdC1hLXJlYWwtaGFzaA"
            "#,
            tmp.path().display()
        );
        let config = Config::parse(&text).unwrap();
        let made = generate(tmp.path(), "example.org", "s1", Algorithm::Both).unwrap();
        assert_eq!(made.len(), 2);
        assert!(made[0].1.starts_with("v=DKIM1; k=rsa; p="));
        assert!(made[1].1.starts_with("v=DKIM1; k=ed25519; p="));
        let key = tmp.path().join("dkim/example.org/s1-rsa.key");
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Never overwrites.
        assert!(generate(tmp.path(), "example.org", "s1", Algorithm::Both).is_err());
        assert!(generate(tmp.path(), "example.org", "../x", Algorithm::Rsa).is_err());
        let keys = load(&config).unwrap();
        assert!(keys.has("example.org"));
    }
}
