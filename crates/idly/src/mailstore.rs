//! The mail store in the server: local delivery into it (remote
//! recipients still go to the queue), the Maildir import of Phase 1 mail,
//! and its maintenance.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use queue::Queue;
use queue::space::{self, SpaceProbe};
use smtp_server::{Envelope, Rcpt, Sink};
use store::{Role, Store, StoreError};

use crate::config::Config;

/// Unreferenced blobs younger than this are kept (a delivery may be
/// writing them).
const GC_GRACE: Duration = Duration::from_secs(24 * 3600);
const GC_INTERVAL: Duration = Duration::from_secs(24 * 3600);

/// Opens the store under `<data_dir>/store` and `<data_dir>/blobs`, and
/// makes sure every configured account exists with its quota.
pub(crate) fn open(config: &Config) -> Result<Arc<Store>, String> {
    let data = &config.server.data_dir;
    let blobs = blob::Disk::open(&data.join("blobs"))
        .map_err(|e| format!("{}: {e}", data.join("blobs").display()))?;
    let store = Store::open(&data.join("store"), Arc::new(blobs)).map_err(|e| e.to_string())?;
    for a in &config.accounts {
        let id = store
            .ensure_account(&a.address)
            .map_err(|e| e.to_string())?;
        store
            .set_quota(id, config.limits.quota)
            .map_err(|e| e.to_string())?;
    }
    Ok(Arc::new(store))
}

/// Removes unreferenced blobs once a day.
pub(crate) async fn collect_garbage(store: Arc<Store>) {
    let mut tick = tokio::time::interval(GC_INTERVAL);
    loop {
        tick.tick().await;
        let s = store.clone();
        match tokio::task::spawn_blocking(move || s.collect_garbage(GC_GRACE)).await {
            Ok(Ok(n)) if n > 0 => tracing::info!(removed = n, "removed unreferenced blobs"),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::error!(error = %e, "blob garbage collection failed"),
            Err(e) => tracing::error!(error = %e, "blob garbage collection panicked"),
        }
    }
}

/// The production sink: local recipients into the store (INBOX, or Junk
/// for DMARC quarantine), remote recipients into the outbound queue.
pub(crate) struct StoreDelivery {
    pub(crate) store: Arc<Store>,
    pub(crate) queue: Arc<Queue>,
    pub(crate) data_dir: PathBuf,
    pub(crate) min_free: u64,
    pub(crate) probe: Arc<dyn SpaceProbe>,
}

impl std::fmt::Debug for StoreDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreDelivery").finish_non_exhaustive()
    }
}

fn io(e: StoreError) -> std::io::Error {
    match e {
        StoreError::OverQuota => std::io::ErrorKind::QuotaExceeded.into(),
        StoreError::Io(e) => e,
        other => std::io::Error::other(other.to_string()),
    }
}

impl Sink for StoreDelivery {
    fn has_space(&self) -> bool {
        (self.min_free == 0 || space::enough(self.probe.as_ref(), &self.data_dir, self.min_free))
            && self.queue.has_space()
    }

    async fn deliver(&self, envelope: &Envelope, message: &[u8]) -> std::io::Result<()> {
        let local: Vec<String> = envelope
            .recipients
            .iter()
            .filter_map(|r| match r {
                Rcpt::Local(a) => Some(a.clone()),
                Rcpt::Remote(_) => None,
            })
            .collect();
        let remote: Vec<String> = envelope
            .recipients
            .iter()
            .filter_map(|r| match r {
                Rcpt::Remote(a) => Some(a.clone()),
                Rcpt::Local(_) => None,
            })
            .collect();

        if !local.is_empty() {
            // RFC 5321 §4.4: the delivering server adds Return-Path. The
            // same bytes for every recipient, so the blob is shared.
            let mut raw = format!("Return-Path: {}\r\n", envelope.from).into_bytes();
            raw.extend_from_slice(message);
            let store = self.store.clone();
            let junk = envelope.junk;
            tokio::task::spawn_blocking(move || deliver_local(&store, &local, &raw, junk))
                .await
                .map_err(std::io::Error::other)?
                .map_err(io)?;
        }
        if !remote.is_empty() {
            let sender = match &envelope.from {
                smtp_proto::ReversePath::Null => None,
                smtp_proto::ReversePath::Mailbox(m) => Some(m.to_string()),
            };
            let queue = self.queue.clone();
            let msg = message.to_vec();
            let result = tokio::task::spawn_blocking(move || {
                queue.enqueue(sender.as_deref(), &remote, &msg)
            })
            .await
            .map_err(std::io::Error::other)?;
            match result {
                Ok(_) => {}
                Err(queue::QueueError::NoSpace) => {
                    return Err(std::io::ErrorKind::StorageFull.into());
                }
                Err(e) => return Err(std::io::Error::other(e.to_string())),
            }
        }
        Ok(())
    }
}

/// All or nothing: if one recipient fails, copies already stored for the
/// others are removed, so the client's retry doesn't duplicate them.
fn deliver_local(
    store: &Store,
    accounts: &[String],
    raw: &[u8],
    junk: bool,
) -> Result<(), StoreError> {
    let received = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let mut done: Vec<(store::AccountId, store::EmailId)> = Vec::new();
    for address in accounts {
        let result = (|| {
            let account = store.ensure_account(address)?;
            let role = if junk { Role::Junk } else { Role::Inbox };
            let mailbox = store.mailbox_by_role(account, role)?.id;
            let msg = store.append(
                account,
                mailbox,
                store::NewMessage {
                    raw,
                    flags: 0,
                    keywords: vec![],
                    received,
                },
            )?;
            Ok::<_, StoreError>((account, msg.id))
        })();
        match result {
            Ok(d) => done.push(d),
            Err(e) => {
                for (account, id) in done {
                    let _ = store.expunge(account, &[id]);
                }
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Whether `<data_dir>/maildir` still holds Phase 1 mail.
pub(crate) fn maildir_pending(data_dir: &Path) -> bool {
    maildir_files(&data_dir.join("maildir")).is_ok_and(|f| !f.is_empty())
}

/// Every message file: (account directory name, junk?, path).
fn maildir_files(root: &Path) -> std::io::Result<Vec<(String, bool, PathBuf)>> {
    let mut out = Vec::new();
    let accounts = match std::fs::read_dir(root) {
        Ok(a) => a,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for account in accounts {
        let account = account?;
        if !account.file_type()?.is_dir() {
            continue;
        }
        let name = account.file_name().to_string_lossy().into_owned();
        for (junk, dir) in [
            (false, account.path()),
            (true, account.path().join(".Junk")),
        ] {
            for sub in ["new", "cur"] {
                let Ok(files) = std::fs::read_dir(dir.join(sub)) else {
                    continue;
                };
                for f in files {
                    let f = f?;
                    if f.file_type()?.is_file() {
                        out.push((name.clone(), junk, f.path()));
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| a.2.cmp(&b.2));
    Ok(out)
}

/// Maildir info flags (`:2,FRS`) as store flags.
fn maildir_flags(path: &Path) -> u8 {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let Some((_, info)) = name.rsplit_once(":2,") else {
        return 0;
    };
    let mut f = 0;
    for c in info.chars() {
        f |= match c {
            'S' => store::flags::SEEN,
            'R' => store::flags::ANSWERED,
            'F' => store::flags::FLAGGED,
            'T' => store::flags::DELETED,
            'D' => store::flags::DRAFT,
            _ => 0,
        };
    }
    f
}

/// Bare LF line ends become CRLF (the store keeps wire format).
fn crlf(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + raw.len() / 40);
    let mut prev = 0u8;
    for &b in raw {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    out
}

/// `idly import maildir`: imports `<data_dir>/maildir` into the store and
/// moves each imported file to `<data_dir>/maildir.imported/`. Running it
/// again is safe: a message already in the target mailbox is not added
/// twice. Returns (imported, skipped as duplicates, unknown accounts).
pub(crate) fn import_maildir(
    config: &Config,
    store: &Store,
) -> Result<(usize, usize, Vec<String>), String> {
    let root = config.server.data_dir.join("maildir");
    let done_root = config.server.data_dir.join("maildir.imported");
    let files = maildir_files(&root).map_err(|e| format!("{}: {e}", root.display()))?;
    let by_dir: std::collections::HashMap<String, &str> = config
        .accounts
        .iter()
        .map(|a| {
            (
                smtp_server::maildir::safe_dir_name(&a.address),
                a.address.as_str(),
            )
        })
        .collect();
    let (mut imported, mut duplicates) = (0, 0);
    let mut unknown = Vec::new();
    for (dir, junk, path) in files {
        let Some(address) = by_dir.get(&dir) else {
            if !unknown.contains(&dir) {
                unknown.push(dir);
            }
            continue;
        };
        let raw = crlf(&std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?);
        let received = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
        let account = store.ensure_account(address).map_err(|e| e.to_string())?;
        let role = if junk { Role::Junk } else { Role::Inbox };
        let mailbox = store
            .mailbox_by_role(account, role)
            .map_err(|e| e.to_string())?
            .id;
        if store
            .contains_blob(account, mailbox, &store::BlobId::of(&raw))
            .map_err(|e| e.to_string())?
        {
            duplicates += 1;
        } else {
            store
                .append(
                    account,
                    mailbox,
                    store::NewMessage {
                        raw: &raw,
                        flags: maildir_flags(&path),
                        keywords: vec![],
                        received,
                    },
                )
                .map_err(|e| format!("{}: {e}", path.display()))?;
            imported += 1;
        }
        let rel = path.strip_prefix(&root).unwrap_or(&path);
        let target = done_root.join(rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        std::fs::rename(&path, &target).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok((imported, duplicates, unknown))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &Path) -> Config {
        Config::parse(&format!(
            r#"
            [server]
            hostname = "mx.example.org"
            data_dir = "{}"
            [[domain]]
            name = "example.org"
            [[account]]
            address = "alice@example.org"
            password_hash = "$argon2id$v=19$m=19456,t=2,p=1$ZGVtb2RlbW9kZW1v$ZGVtby1vbmx5LW5vdC1hLXJlYWwtaGFzaA"
            "#,
            dir.display()
        ))
        .unwrap()
    }

    #[test]
    fn maildir_import_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let c = config(dir.path());
        let md = dir.path().join("maildir");
        let inbox = md.join("alice@example.org");
        std::fs::create_dir_all(inbox.join("new")).unwrap();
        std::fs::create_dir_all(inbox.join("cur")).unwrap();
        std::fs::create_dir_all(inbox.join(".Junk/new")).unwrap();
        std::fs::create_dir_all(md.join("ghost@example.org/new")).unwrap();
        std::fs::write(inbox.join("new/1.x"), "Subject: one\n\nhello\n").unwrap();
        std::fs::write(inbox.join("cur/2.x:2,FS"), "Subject: two\r\n\r\nseen\r\n").unwrap();
        std::fs::write(inbox.join(".Junk/new/3.x"), "Subject: spam\r\n\r\nbuy\r\n").unwrap();
        std::fs::write(md.join("ghost@example.org/new/4.x"), "Subject: ?\r\n\r\n").unwrap();
        assert!(maildir_pending(dir.path()));

        let store = open(&c).unwrap();
        let (n, dup, unknown) = import_maildir(&c, &store).unwrap();
        assert_eq!((n, dup), (3, 0));
        assert_eq!(unknown, ["ghost@example.org"]);
        let a = store.account_id("alice@example.org").unwrap().unwrap();
        let inbox_id = store.mailbox_by_role(a, Role::Inbox).unwrap().id;
        let msgs = store.messages(a, inbox_id).unwrap();
        assert_eq!(msgs.len(), 2);
        // Imported in path order: cur/ before new/.
        assert_eq!(msgs[0].flags, store::flags::SEEN | store::flags::FLAGGED);
        assert_eq!(
            store.read(a, msgs[1].id).unwrap(),
            b"Subject: one\r\n\r\nhello\r\n"
        );
        let junk = store.mailbox_by_role(a, Role::Junk).unwrap();
        assert_eq!(junk.messages, 1);
        assert!(
            dir.path()
                .join("maildir.imported/alice@example.org/cur/2.x:2,FS")
                .exists()
        );

        // A crash after storing but before moving the file: no duplicate.
        std::fs::write(inbox.join("new/1.x"), "Subject: one\n\nhello\n").unwrap();
        let (n, dup, _) = import_maildir(&c, &store).unwrap();
        assert_eq!((n, dup), (0, 1));
        assert_eq!(store.messages(a, inbox_id).unwrap().len(), 2);
    }

    #[test]
    fn lf_becomes_crlf_once() {
        assert_eq!(crlf(b"a\nb\r\nc\n"), b"a\r\nb\r\nc\r\n");
    }
}
