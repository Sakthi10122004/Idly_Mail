//! Local delivery to Maildir: one directory per account, each message
//! written to `tmp/`, fsynced, then renamed into `new/` (the Maildir
//! delivery protocol). Phase 2 imports these into the mail store.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWriteExt;

use queue::space::{self, SpaceProbe, Statvfs};

use crate::{Envelope, Rcpt, Sink};

/// Delivers into `<root>/<account>/{tmp,new,cur}`.
pub struct Maildir {
    root: PathBuf,
    hostname: String,
    counter: AtomicU64,
    min_free: u64,
    probe: Arc<dyn SpaceProbe>,
}

impl std::fmt::Debug for Maildir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Maildir")
            .field("root", &self.root)
            .field("min_free", &self.min_free)
            .finish_non_exhaustive()
    }
}

impl Maildir {
    /// A Maildir tree rooted at `root`, naming files after `hostname`.
    pub fn new(root: impl Into<PathBuf>, hostname: &str) -> Self {
        // Maildir file names must not contain '/' or ':'.
        let hostname = hostname.replace(['/', ':'], "_");
        Self {
            root: root.into(),
            hostname,
            counter: AtomicU64::new(0),
            min_free: 0,
            probe: Arc::new(Statvfs),
        }
    }

    /// Refuse new mail when the filesystem has less than `min_free` bytes
    /// free, as measured by `probe`.
    pub fn with_min_free_space(mut self, min_free: u64, probe: Arc<dyn SpaceProbe>) -> Self {
        self.min_free = min_free;
        self.probe = probe;
        self
    }

    /// The Maildir directory of an account.
    pub fn account_dir(&self, account: &str) -> PathBuf {
        self.root.join(safe_dir_name(account))
    }

    fn unique_name(&self) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        format!(
            "{}.M{}P{}Q{n}.{}",
            now.as_secs(),
            now.subsec_micros(),
            std::process::id(),
            self.hostname
        )
    }

    async fn deliver_one(
        &self,
        account: &str,
        junk: bool,
        headers: &[u8],
        message: &[u8],
    ) -> std::io::Result<PathBuf> {
        // Junk goes to the Maildir++ ".Junk" folder inside the account.
        let dir = if junk {
            self.account_dir(account).join(".Junk")
        } else {
            self.account_dir(account)
        };
        for sub in ["tmp", "new", "cur"] {
            tokio::fs::create_dir_all(dir.join(sub)).await?;
        }
        let name = self.unique_name();
        let tmp = dir.join("tmp").join(&name);
        let new = dir.join("new").join(&name);
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .await?;
        file.write_all(headers).await?;
        file.write_all(message).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&tmp, &new).await?;
        // Make the rename itself durable.
        tokio::fs::File::open(dir.join("new"))
            .await?
            .sync_all()
            .await?;
        Ok(new)
    }
}

/// An account address as a single safe path component: lower-case, with
/// every byte outside `[a-z0-9@._+-]` (and a leading '.') written as `%XX`.
/// Local-parts may legally contain '/', so this is not optional.
pub fn safe_dir_name(account: &str) -> String {
    let mut out = String::with_capacity(account.len());
    for (i, b) in account.to_lowercase().bytes().enumerate() {
        let ok = b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || matches!(b, b'@' | b'_' | b'+' | b'-')
            || (b == b'.' && i > 0);
        if ok {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl Sink for Maildir {
    fn has_space(&self) -> bool {
        // The root may not exist yet; measure its nearest existing ancestor.
        let mut path = self.root.as_path();
        while !path.exists() {
            match path.parent() {
                Some(p) => path = p,
                None => break,
            }
        }
        self.min_free == 0 || space::enough(self.probe.as_ref(), path, self.min_free)
    }

    async fn deliver(&self, envelope: &Envelope, message: &[u8]) -> std::io::Result<()> {
        // RFC 5321 §4.4: the delivery server adds Return-Path at final delivery.
        let mut done = Vec::new();
        for rcpt in &envelope.recipients {
            let account = match rcpt {
                Rcpt::Local(a) => a,
                // Remote recipients belong to the queue, never to Maildir.
                Rcpt::Remote(_) => {
                    return Err(std::io::Error::other(
                        "remote recipient given to the Maildir sink",
                    ));
                }
            };
            let headers = format!(
                "Return-Path: {}\r\nDelivered-To: {account}\r\n",
                envelope.from
            );
            match self
                .deliver_one(account, envelope.junk, headers.as_bytes(), message)
                .await
            {
                Ok(p) => done.push(p),
                Err(e) => {
                    // All or nothing: the client will retry after a 4xx.
                    for p in done {
                        let _ = tokio::fs::remove_file(p).await;
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_names_are_single_safe_components() {
        assert_eq!(safe_dir_name("Alice@Example.org"), "alice@example.org");
        assert_eq!(safe_dir_name("a/../b@x"), "a%2F..%2Fb@x");
        assert_eq!(safe_dir_name(".hidden@x"), "%2Ehidden@x");
        assert_eq!(safe_dir_name("\"a b\"@x"), "%22a%20b%22@x");
        assert!(!safe_dir_name("../../etc/passwd").contains('/'));
    }

    #[test]
    fn unique_names_differ() {
        let m = Maildir::new("/tmp/x", "mx:host/name");
        let (a, b) = (m.unique_name(), m.unique_name());
        assert_ne!(a, b);
        assert!(a.ends_with("mx_host_name") && !a.contains(':'));
    }
}
