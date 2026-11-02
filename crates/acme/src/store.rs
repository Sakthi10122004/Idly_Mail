//! Files under `<data_dir>/acme/`: the certificate key (`tls.key`), the
//! issued chain (`cert.pem`) and one ACME account per directory URL
//! (`account-<hash>.json`). Secrets are written with mode 0600, and every
//! file is replaced atomically (write, fsync, rename, fsync the directory),
//! so a crash never leaves half a key or certificate behind.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rcgen::KeyPair;

/// The ACME state directory.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// Opens (creating, mode 0700) the directory.
    pub fn open(dir: &Path) -> io::Result<Self> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        Ok(Self { dir: dir.into() })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn key_path(&self) -> PathBuf {
        self.dir.join("tls.key")
    }

    pub fn cert_path(&self) -> PathBuf {
        self.dir.join("cert.pem")
    }

    /// The certificate key, created on first use. The same key is kept
    /// across renewals so a published DANE `3 1 1` TLSA record (a hash of
    /// the public key, RFC 7671 §5.1) stays valid.
    pub fn key(&self) -> Result<KeyPair, String> {
        let path = self.key_path();
        match fs::read_to_string(&path) {
            Ok(pem) => KeyPair::from_pem(&pem).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // ECDSA P-256: small, fast, accepted everywhere.
                let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
                    .map_err(|e| format!("generating the TLS key: {e}"))?;
                write_atomic(&path, key.serialize_pem().as_bytes(), 0o600)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                tracing::info!(path = %path.display(), "generated the TLS certificate key");
                Ok(key)
            }
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// The stored chain, if any.
    pub fn cert(&self) -> io::Result<Option<Vec<u8>>> {
        match fs::read(self.cert_path()) {
            Ok(pem) => Ok(Some(pem)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn save_cert(&self, pem: &[u8]) -> io::Result<()> {
        write_atomic(&self.cert_path(), pem, 0o644)
    }

    /// Where the account for `directory` is kept. Each CA (and staging
    /// versus production) gets its own account file.
    pub fn account_path(&self, directory: &str) -> PathBuf {
        let digest = ring::digest::digest(&ring::digest::SHA256, directory.as_bytes());
        let hex: String = digest
            .as_ref()
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect();
        self.dir.join(format!("account-{hex}.json"))
    }

    pub fn account(&self, directory: &str) -> io::Result<Option<Vec<u8>>> {
        match fs::read(self.account_path(directory)) {
            Ok(json) => Ok(Some(json)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn save_account(&self, directory: &str, json: &[u8]) -> io::Result<()> {
        write_atomic(&self.account_path(directory), json, 0o600)
    }
}

/// The DER SubjectPublicKeyInfo of a PEM private key (for the TLSA
/// record `idly dns` prints).
pub fn public_key(pem: &str) -> Result<Vec<u8>, String> {
    use rcgen::PublicKeyData;
    KeyPair::from_pem(pem)
        .map(|k| k.subject_public_key_info())
        .map_err(|e| e.to_string())
}

/// Replaces `path` with `data`, durably.
fn write_atomic(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(".{name}.tmp"));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    fs::File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn key_is_created_once_and_kept_private() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("acme")).unwrap();
        let a = store.key().unwrap();
        let b = store.key().unwrap();
        assert_eq!(
            a.serialize_der(),
            b.serialize_der(),
            "the same key every time"
        );
        let mode = fs::metadata(store.key_path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let mode = fs::metadata(store.dir()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn accounts_are_per_directory() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let prod = "https://acme-v02.api.letsencrypt.org/directory";
        let staging = "https://acme-staging-v02.api.letsencrypt.org/directory";
        assert_ne!(store.account_path(prod), store.account_path(staging));
        assert_eq!(store.account(prod).unwrap(), None);
        store.save_account(prod, b"{}").unwrap();
        assert_eq!(store.account(prod).unwrap().as_deref(), Some(&b"{}"[..]));
        assert_eq!(store.account(staging).unwrap(), None);
        let mode = fs::metadata(store.account_path(prod))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_corrupt_key_is_an_error_not_a_new_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        fs::write(store.key_path(), "not a key").unwrap();
        assert!(store.key().is_err());
        assert_eq!(fs::read(store.key_path()).unwrap(), b"not a key");
    }
}
