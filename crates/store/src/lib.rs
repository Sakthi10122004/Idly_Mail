//! The mail store: accounts, mailboxes and messages in SQLite, message
//! content in a [`BlobStore`].
//!
//! Model (shared by IMAP and JMAP):
//! - every message (JMAP Email) is in exactly one mailbox, with an IMAP UID
//!   there; JMAP advertises `maxMailboxesPerEmail: 1` (RFC 8621 §1.3.1).
//!   IMAP COPY makes a new message that shares the blob; MOVE changes the
//!   message's mailbox and UID;
//! - one modification sequence per account: every change gets the next
//!   value. It is the CONDSTORE MODSEQ (RFC 7162 §3.1) and the JMAP state
//!   (RFC 8620 §5.2);
//! - expunges are logged (with their MODSEQ) for QRESYNC VANISHED
//!   (RFC 7162 §3.2.10) and JMAP `destroyed`; a move is logged as an
//!   expunge of the old UID that JMAP doesn't count as destroyed.
//!
//! Durability: a new message's blob is fsynced before the transaction that
//! references it commits (synchronous=FULL), so a message that was
//! acknowledged is complete. A blob without a row (a crash in between)
//! is removed by [`Store::collect_garbage`].
//!
//! Calls block; async callers use `spawn_blocking`.

#![forbid(unsafe_code)]

mod mailboxes;
mod messages;
mod meta;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use blob::BlobStore;
use rusqlite::Connection;
use tokio::sync::broadcast;

pub use blob::BlobId;
pub use mailboxes::{SEPARATOR, normalize as normalize_mailbox_name};
pub use messages::{FlagOp, FlagResult, Message, NewMessage, valid_keyword};

pub type AccountId = i64;
pub type MailboxId = i64;
pub type EmailId = i64;

/// IMAP system flags (RFC 9051 §2.3.2) as bits; JMAP maps them to the
/// `$seen`, `$answered`, `$flagged`, `$draft` keywords (RFC 8621 §4.1.1).
/// `\Deleted` exists only in IMAP.
pub mod flags {
    pub const SEEN: u8 = 1;
    pub const ANSWERED: u8 = 2;
    pub const FLAGGED: u8 = 4;
    pub const DELETED: u8 = 8;
    pub const DRAFT: u8 = 16;
    pub const ALL: u8 = 31;
}

/// The most keywords (non-system flags) one account may use, and per
/// message (RFC 9051 leaves this to the server).
pub const MAX_KEYWORDS: usize = 64;

/// A mailbox role (RFC 8621 §2, RFC 6154 special-use).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Inbox,
    Sent,
    Drafts,
    Junk,
    Trash,
    Archive,
}

impl Role {
    pub const ALL: [Role; 6] = [
        Role::Inbox,
        Role::Sent,
        Role::Drafts,
        Role::Junk,
        Role::Trash,
        Role::Archive,
    ];

    /// The JMAP role name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inbox => "inbox",
            Self::Sent => "sent",
            Self::Drafts => "drafts",
            Self::Junk => "junk",
            Self::Trash => "trash",
            Self::Archive => "archive",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }

    /// The mailbox created for this role in a new account.
    pub fn default_name(self) -> &'static str {
        match self {
            Self::Inbox => "INBOX",
            Self::Sent => "Sent",
            Self::Drafts => "Drafts",
            Self::Junk => "Junk",
            Self::Trash => "Trash",
            Self::Archive => "Archive",
        }
    }
}

/// A mailbox and its counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    pub id: MailboxId,
    pub account: AccountId,
    /// Full name, `/` separating levels; "INBOX" for the inbox.
    pub name: String,
    pub role: Option<Role>,
    pub uidvalidity: u32,
    pub uidnext: u32,
    pub highest_modseq: u64,
    pub subscribed: bool,
    pub messages: u32,
    pub unseen: u32,
    pub size: u64,
}

/// A change notification, sent after the change is committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub account: AccountId,
    /// The mailboxes whose contents changed.
    pub mailboxes: Vec<MailboxId>,
    /// The mailbox list itself changed (create, rename, delete).
    pub mailbox_list: bool,
    pub modseq: u64,
}

/// Why a store operation failed.
#[derive(Debug)]
pub enum StoreError {
    NotFound,
    AlreadyExists,
    /// The request breaks a rule (a bad name, deleting INBOX, ...).
    Invalid(String),
    /// The account is over its quota (RFC 9208's OVERQUOTA; SMTP 452 4.2.2).
    OverQuota,
    /// UNCHANGEDSINCE failed for some messages (RFC 7162 §3.1.3).
    Modified(Vec<EmailId>),
    Db(String),
    Io(std::io::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("not found"),
            Self::AlreadyExists => f.write_str("already exists"),
            Self::Invalid(why) => f.write_str(why),
            Self::OverQuota => f.write_str("over quota"),
            Self::Modified(_) => f.write_str("modified since"),
            Self::Db(e) => write!(f, "store database error: {e}"),
            Self::Io(e) => write!(f, "blob I/O error: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Db(e.to_string())
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

const SCHEMA: &str = "
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = FULL;
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS accounts (
        id              INTEGER PRIMARY KEY,
        address         TEXT NOT NULL UNIQUE,
        modseq          INTEGER NOT NULL DEFAULT 1,
        last_uidvalidity INTEGER NOT NULL DEFAULT 0,
        next_thread     INTEGER NOT NULL DEFAULT 1,
        quota           INTEGER
    );
    CREATE TABLE IF NOT EXISTS mailboxes (
        id              INTEGER PRIMARY KEY,
        account_id      INTEGER NOT NULL REFERENCES accounts(id),
        name            TEXT NOT NULL,
        role            TEXT,
        uidvalidity     INTEGER NOT NULL,
        uidnext         INTEGER NOT NULL DEFAULT 1,
        highest_modseq  INTEGER NOT NULL,
        subscribed      INTEGER NOT NULL DEFAULT 1,
        created_modseq  INTEGER NOT NULL,
        modseq          INTEGER NOT NULL,
        deleted         INTEGER NOT NULL DEFAULT 0
    );
    CREATE UNIQUE INDEX IF NOT EXISTS mailbox_names
        ON mailboxes(account_id, name) WHERE deleted = 0;
    CREATE TABLE IF NOT EXISTS messages (
        id              INTEGER PRIMARY KEY,
        account_id      INTEGER NOT NULL REFERENCES accounts(id),
        mailbox_id      INTEGER NOT NULL REFERENCES mailboxes(id),
        uid             INTEGER NOT NULL,
        blob            TEXT NOT NULL,
        size            INTEGER NOT NULL,
        received        INTEGER NOT NULL,
        sent            INTEGER,
        flags           INTEGER NOT NULL DEFAULT 0,
        keywords        TEXT NOT NULL DEFAULT '',
        modseq          INTEGER NOT NULL,
        created_modseq  INTEGER NOT NULL,
        thread_id       INTEGER NOT NULL,
        message_id      TEXT,
        subject         TEXT NOT NULL DEFAULT '',
        sender          TEXT NOT NULL DEFAULT '',
        recipients      TEXT NOT NULL DEFAULT '',
        preview         TEXT NOT NULL DEFAULT '',
        has_attachment  INTEGER NOT NULL DEFAULT 0,
        indexed         INTEGER NOT NULL DEFAULT 0
    );
    CREATE UNIQUE INDEX IF NOT EXISTS message_uids ON messages(mailbox_id, uid);
    CREATE INDEX IF NOT EXISTS message_modseq ON messages(account_id, modseq);
    CREATE INDEX IF NOT EXISTS message_blobs ON messages(blob);
    CREATE INDEX IF NOT EXISTS message_threads ON messages(account_id, thread_id);
    CREATE TABLE IF NOT EXISTS expunged (
        account_id      INTEGER NOT NULL,
        mailbox_id      INTEGER NOT NULL,
        uid             INTEGER NOT NULL,
        email_id        INTEGER NOT NULL,
        thread_id       INTEGER NOT NULL,
        modseq          INTEGER NOT NULL,
        moved           INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS expunged_modseq ON expunged(mailbox_id, modseq);
    CREATE INDEX IF NOT EXISTS expunged_account ON expunged(account_id, modseq);
    CREATE TABLE IF NOT EXISTS thread_ids (
        account_id      INTEGER NOT NULL,
        msgid           TEXT NOT NULL,
        thread_id       INTEGER NOT NULL,
        PRIMARY KEY (account_id, msgid)
    );
";

/// The SQLite store.
pub struct Store {
    db: Mutex<Connection>,
    blobs: Arc<dyn BlobStore>,
    events: Mutex<HashMap<AccountId, broadcast::Sender<Change>>>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

impl Store {
    /// Opens (creating) `<dir>/store.db`, with content in `blobs`.
    pub fn open(dir: &Path, blobs: Arc<dyn BlobStore>) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let db = Connection::open(dir.join("store.db"))?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(SCHEMA)?;
        Ok(Self {
            db: Mutex::new(db),
            blobs,
            events: Mutex::new(HashMap::new()),
        })
    }

    fn db(&self) -> MutexGuard<'_, Connection> {
        self.db
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn blobs(&self) -> &Arc<dyn BlobStore> {
        &self.blobs
    }

    /// Changes in `account`, for IDLE, notifications and JMAP push.
    pub fn subscribe(&self, account: AccountId) -> broadcast::Receiver<Change> {
        let mut map = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.entry(account)
            .or_insert_with(|| broadcast::channel(256).0)
            .subscribe()
    }

    fn notify(&self, change: Change) {
        let map = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(tx) = map.get(&change.account) {
            let _ = tx.send(change);
        }
    }

    /// The account for `address` (lower-cased), created with the default
    /// mailboxes on first use.
    pub fn ensure_account(&self, address: &str) -> Result<AccountId> {
        let address = address.to_lowercase();
        if let Some(id) = self.account_id(&address)? {
            return Ok(id);
        }
        let mut db = self.db();
        let tx = db.transaction()?;
        tx.execute("INSERT INTO accounts(address) VALUES (?1)", [&address])?;
        let id = tx.last_insert_rowid();
        for role in Role::ALL {
            mailboxes::insert(&tx, id, role.default_name(), Some(role))?;
        }
        tx.commit()?;
        tracing::info!(account = %address, "created the mail store account");
        Ok(id)
    }

    /// The account for `address`, if it exists.
    pub fn account_id(&self, address: &str) -> Result<Option<AccountId>> {
        let db = self.db();
        let mut stmt = db.prepare("SELECT id FROM accounts WHERE address = ?1")?;
        let mut rows = stmt.query([address.to_lowercase()])?;
        Ok(match rows.next()? {
            Some(r) => Some(r.get(0)?),
            None => None,
        })
    }

    /// Every account address.
    pub fn accounts(&self) -> Result<Vec<(AccountId, String)>> {
        let db = self.db();
        let mut stmt = db.prepare("SELECT id, address FROM accounts ORDER BY address")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        Ok(rows)
    }

    /// Sets the account's quota in octets (None: unlimited).
    pub fn set_quota(&self, account: AccountId, quota: Option<u64>) -> Result<()> {
        let quota = quota.map(|q| i64::try_from(q).unwrap_or(i64::MAX));
        self.db().execute(
            "UPDATE accounts SET quota = ?1 WHERE id = ?2",
            rusqlite::params![quota, account],
        )?;
        Ok(())
    }

    /// The account's message count and octets.
    pub fn usage(&self, account: AccountId) -> Result<(u64, u64)> {
        let db = self.db();
        Ok(db.query_row(
            "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM messages WHERE account_id = ?1",
            [account],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    }

    /// The account's current modification sequence (the JMAP state).
    pub fn modseq(&self, account: AccountId) -> Result<u64> {
        let db = self.db();
        Ok(db.query_row(
            "SELECT modseq FROM accounts WHERE id = ?1",
            [account],
            |r| r.get(0),
        )?)
    }

    /// Deletes blobs no message refers to and that are older than
    /// `grace` (so a delivery in progress is never touched). Returns how
    /// many were removed.
    pub fn collect_garbage(&self, grace: std::time::Duration) -> Result<usize> {
        let listed = self.blobs.list()?;
        let cutoff = std::time::SystemTime::now()
            .checked_sub(grace)
            .unwrap_or(std::time::UNIX_EPOCH);
        let mut removed = 0;
        for (id, mtime) in listed {
            if mtime > cutoff {
                continue;
            }
            let used: bool = self.db().query_row(
                "SELECT EXISTS(SELECT 1 FROM messages WHERE blob = ?1)",
                [id.to_string()],
                |r| r.get(0),
            )?;
            if !used && self.blobs.delete(&id)? {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// Takes the next modification sequence of `account` inside `tx`.
fn next_modseq(tx: &rusqlite::Transaction<'_>, account: AccountId) -> Result<u64> {
    tx.execute(
        "UPDATE accounts SET modseq = modseq + 1 WHERE id = ?1",
        [account],
    )?;
    Ok(tx.query_row(
        "SELECT modseq FROM accounts WHERE id = ?1",
        [account],
        |r| r.get(0),
    )?)
}
