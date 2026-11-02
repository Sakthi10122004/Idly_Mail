//! The persistent outbound queue.
//!
//! Each message is a spool file `<dir>/spool/<id>.eml` plus rows in SQLite
//! (`<dir>/queue.db`): one per message, one per recipient.
//!
//! Durability order (RFC 5321 §6.1: once we say 250, the message is ours):
//! 1. write the spool file to `spool/tmp/`, fsync, rename into `spool/`,
//!    fsync the directory;
//! 2. commit the database rows (WAL, synchronous=FULL);
//! 3. only then may the caller reply 250.
//!
//! Recovery on open undoes a crash at any point: a spool file without a
//! database row was never acknowledged, so it is deleted (the client still
//! has the message and will retry); a row whose spool file is missing can
//! only come from corruption, and is failed with a bounce.
//!
//! Delivery is at-least-once: a crash after a remote server accepted a
//! message but before we recorded it means one retry after the lease
//! expires (RFC 5321 §6.1 accepts this risk of duplicates over loss).

#![forbid(unsafe_code)]

pub mod dsn;
mod runner;
pub mod space;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, params};

pub use runner::{Connector, Runner};
use space::SpaceProbe;

/// Queue settings.
#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// Our host name: Reporting-MTA and MAILER-DAEMON of bounces.
    pub hostname: String,
    /// Delays before retries 1, 2, ...; the last one repeats.
    pub retry: Vec<u64>,
    /// Give up after this many seconds. RFC 5321 §4.5.4.1: at least 4–5 days.
    pub max_age: u64,
    /// Refuse new mail when the spool's filesystem has less free space.
    pub min_free_space: u64,
    /// Test mode: deliver only to these domains (lower-case A-labels);
    /// everything else is held, never sent and never bounced.
    pub test_mode_allow: Option<Vec<String>>,
    /// Delivery attempts in flight per destination domain.
    pub per_domain_concurrency: usize,
    /// How long a claimed job is reserved for one worker.
    pub lease: u64,
}

impl QueueConfig {
    /// Defaults: retries after 5, 10, 20, 40, 80 minutes, then every 4
    /// hours; give up after 5 days; 1 GiB free space floor.
    pub fn new(hostname: &str) -> Self {
        Self {
            hostname: hostname.to_owned(),
            retry: vec![300, 600, 1200, 2400, 4800, 14_400],
            max_age: 5 * 86_400,
            min_free_space: space::DEFAULT_MIN_FREE,
            test_mode_allow: None,
            per_domain_concurrency: 2,
            lease: 600,
        }
    }

    fn retry_delay(&self, attempts: u32) -> u64 {
        let i = usize::try_from(attempts.saturating_sub(1)).unwrap_or(usize::MAX);
        self.retry
            .get(i)
            .or(self.retry.last())
            .copied()
            .unwrap_or(14_400)
    }

    /// Whether test mode forbids delivering to `domain`.
    pub fn held_by_test_mode(&self, domain: &str) -> bool {
        self.test_mode_allow
            .as_ref()
            .is_some_and(|allow| !allow.iter().any(|d| d.eq_ignore_ascii_case(domain)))
    }
}

/// Seconds since the Unix epoch, replaceable in tests.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> u64;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        dsn::unix_now()
    }
}

/// Why the queue refused or failed.
#[derive(Debug)]
pub enum QueueError {
    /// Free space is below the floor: reply 452 4.3.1.
    NoSpace,
    /// Another process (a running `idly serve`) has the queue open.
    Busy,
    Io(std::io::Error),
    Db(String),
    /// Test-only: a simulated crash.
    #[cfg(test)]
    Crashed,
}

impl std::fmt::Display for QueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSpace => f.write_str("insufficient system storage"),
            Self::Busy => f.write_str("the queue is in use by another idly process"),
            Self::Io(e) => write!(f, "spool I/O error: {e}"),
            Self::Db(e) => write!(f, "queue database error: {e}"),
            #[cfg(test)]
            Self::Crashed => f.write_str("simulated crash"),
        }
    }
}

impl std::error::Error for QueueError {}

impl From<std::io::Error> for QueueError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<rusqlite::Error> for QueueError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Db(e.to_string())
    }
}

/// The result of trying to deliver to one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Delivered,
    /// Try again later (4xx, connection problems, DNS trouble).
    Temporary(String),
    /// Give up: bounce with this RFC 3463 status and diagnostic.
    Permanent {
        status: String,
        diagnostic: String,
    },
}

/// What a queued message is, which changes how it is delivered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Kind {
    /// Ordinary mail: the full TLS policy applies.
    #[default]
    Mail,
    /// A TLS report (RFC 8460 §3): delivered despite TLS policy failures,
    /// and its sessions are left out of the next report.
    TlsReport,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Mail => "mail",
            Self::TlsReport => "tls-report",
        }
    }

    fn from_db(s: &str) -> Self {
        match s {
            "tls-report" => Self::TlsReport,
            _ => Self::Mail,
        }
    }
}

/// Some recipients of one message for one domain, claimed for delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub message_id: String,
    pub domain: String,
    /// MAIL FROM; None for the null reverse-path.
    pub sender: Option<String>,
    pub kind: Kind,
    /// (recipient row id, address).
    pub recipients: Vec<(i64, String)>,
}

/// A queued recipient, for `idly queue list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub message_id: String,
    pub sender: Option<String>,
    pub recipient: String,
    pub status: String,
    pub attempts: u32,
    pub next_attempt: u64,
    pub last_error: Option<String>,
}

/// Where a test can simulate a crash during `enqueue`.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrashPoint {
    AfterSpoolWrite,
    AfterDbCommit,
}

/// The queue.
pub struct Queue {
    db: Mutex<Connection>,
    /// The exclusive lock on `<dir>/lock`, held while the queue is open
    /// for delivery; None when attached by a command-line tool.
    _lock: Option<std::fs::File>,
    spool: PathBuf,
    config: QueueConfig,
    clock: Arc<dyn Clock>,
    space: Arc<dyn SpaceProbe>,
    counter: AtomicU64,
}

impl std::fmt::Debug for Queue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Queue")
            .field("spool", &self.spool)
            .finish_non_exhaustive()
    }
}

const SCHEMA: &str = "
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = FULL;
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS messages (
        id      TEXT PRIMARY KEY,
        sender  TEXT,              -- NULL is the null reverse-path
        arrival INTEGER NOT NULL,
        size    INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS recipients (
        rid          INTEGER PRIMARY KEY,
        message_id   TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
        address      TEXT NOT NULL,
        domain       TEXT NOT NULL,
        status       TEXT NOT NULL, -- queued | held | delivered | failed
        attempts     INTEGER NOT NULL DEFAULT 0,
        next_attempt INTEGER NOT NULL,
        last_error   TEXT,
        lease_owner  TEXT,          -- for clustering (Phase 4) and crash recovery
        lease_until  INTEGER
    );
    CREATE INDEX IF NOT EXISTS recipients_due ON recipients(status, next_attempt);
";

/// Columns added after the first schema: (table, column, definition).
const ADDED_COLUMNS: &[(&str, &str, &str)] = &[(
    "messages",
    "kind",
    "TEXT NOT NULL DEFAULT 'mail'", // mail | tls-report
)];

/// Adds the columns an older database lacks.
fn migrate(db: &Connection) -> rusqlite::Result<()> {
    for (table, column, definition) in ADDED_COLUMNS {
        let mut stmt = db.prepare(&format!("PRAGMA table_info({table})"))?;
        let names: Vec<String> = stmt
            .query_map([], |r| r.get(1))?
            .collect::<Result<_, _>>()?;
        if !names.iter().any(|n| n == column) {
            db.execute_batch(&format!(
                "ALTER TABLE {table} ADD COLUMN {column} {definition}"
            ))?;
        }
    }
    Ok(())
}

fn domain_of(address: &str) -> String {
    address
        .rsplit_once('@')
        .map_or(address, |(_, d)| d)
        .to_ascii_lowercase()
}

/// fsync a directory so a rename into it is durable.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

impl Queue {
    /// Opens (or creates) the queue in `dir` and recovers from any crash.
    /// Only one process may have it open: recovery would delete the spool
    /// file of a message another process is just accepting. A second
    /// open fails with [`QueueError::Busy`].
    pub fn open(
        dir: &Path,
        config: QueueConfig,
        clock: Arc<dyn Clock>,
        space: Arc<dyn SpaceProbe>,
    ) -> Result<Self, QueueError> {
        let spool = dir.join("spool");
        std::fs::create_dir_all(spool.join("tmp"))?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("lock"))?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
            |e| {
                if e == rustix::io::Errno::WOULDBLOCK {
                    QueueError::Busy
                } else {
                    QueueError::Io(e.into())
                }
            },
        )?;
        let q = Self::connect(dir, config, clock, space, Some(lock))?;
        q.recover()?;
        Ok(q)
    }

    /// Opens an existing queue that a running server may also have open,
    /// for `idly queue` commands: no lock and no crash recovery, only
    /// listing and the operator actions, which SQLite keeps consistent.
    pub fn attach(
        dir: &Path,
        config: QueueConfig,
        clock: Arc<dyn Clock>,
        space: Arc<dyn SpaceProbe>,
    ) -> Result<Self, QueueError> {
        if !dir.join("queue.db").exists() {
            return Err(QueueError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no queue in {}", dir.display()),
            )));
        }
        Self::connect(dir, config, clock, space, None)
    }

    fn connect(
        dir: &Path,
        config: QueueConfig,
        clock: Arc<dyn Clock>,
        space: Arc<dyn SpaceProbe>,
        lock: Option<std::fs::File>,
    ) -> Result<Self, QueueError> {
        let spool = dir.join("spool");
        let db = Connection::open(dir.join("queue.db"))?;
        // A command-line tool and the server may write at the same time.
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(SCHEMA)?;
        migrate(&db)?;
        Ok(Self {
            db: Mutex::new(db),
            _lock: lock,
            spool,
            config,
            clock,
            space,
            counter: AtomicU64::new(0),
        })
    }

    /// The configuration.
    pub fn config(&self) -> &QueueConfig {
        &self.config
    }

    fn db(&self) -> MutexGuard<'_, Connection> {
        // A poisoned lock only means another thread panicked; the
        // connection itself is still consistent (SQLite transactions).
        self.db
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn spool_path(&self, id: &str) -> PathBuf {
        self.spool.join(format!("{id}.eml"))
    }

    /// Whether there is room for new mail (the disk-space guard).
    pub fn has_space(&self) -> bool {
        space::enough(self.space.as_ref(), &self.spool, self.config.min_free_space)
    }

    fn new_id(&self) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        format!(
            "{:x}{:08x}{:x}{:04x}",
            now.as_secs(),
            now.subsec_nanos(),
            std::process::id(),
            n & 0xffff
        )
    }

    /// Stores a message durably. When this returns Ok, the caller may reply
    /// 250. `sender` is None for the null reverse-path.
    pub fn enqueue(
        &self,
        sender: Option<&str>,
        recipients: &[String],
        message: &[u8],
    ) -> Result<String, QueueError> {
        self.enqueue_inner(sender, recipients, message, Kind::Mail, None)
    }

    /// Queues a message of a given kind (see [`Kind`]).
    pub fn enqueue_kind(
        &self,
        sender: Option<&str>,
        recipients: &[String],
        message: &[u8],
        kind: Kind,
    ) -> Result<String, QueueError> {
        self.enqueue_inner(sender, recipients, message, kind, None)
    }

    fn enqueue_inner(
        &self,
        sender: Option<&str>,
        recipients: &[String],
        message: &[u8],
        kind: Kind,
        #[cfg(test)] crash: Option<CrashPoint>,
        #[cfg(not(test))] _crash: Option<()>,
    ) -> Result<String, QueueError> {
        if !self.has_space() {
            return Err(QueueError::NoSpace);
        }
        let id = self.new_id();
        // Step 1: the spool file, durable before the database row.
        let tmp = self.spool.join("tmp").join(&id);
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            f.write_all(message)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, self.spool_path(&id))?;
        sync_dir(&self.spool)?;
        #[cfg(test)]
        if crash == Some(CrashPoint::AfterSpoolWrite) {
            return Err(QueueError::Crashed);
        }
        // Step 2: the rows, in one transaction.
        let now = self.clock.now();
        {
            let mut db = self.db();
            let tx = db.transaction()?;
            tx.execute(
                "INSERT INTO messages (id, sender, arrival, size, kind) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    id,
                    sender,
                    now,
                    i64::try_from(message.len()).unwrap_or(i64::MAX),
                    kind.as_str()
                ],
            )?;
            for r in recipients {
                let domain = domain_of(r);
                let (status, note) = if self.config.held_by_test_mode(&domain) {
                    ("held", Some("held: test mode (domain not allow-listed)"))
                } else {
                    ("queued", None)
                };
                tx.execute(
                    "INSERT INTO recipients (message_id, address, domain, status, next_attempt, last_error)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![id, r, domain, status, now, note],
                )?;
            }
            tx.commit()?;
        }
        #[cfg(test)]
        if crash == Some(CrashPoint::AfterDbCommit) {
            return Err(QueueError::Crashed);
        }
        tracing::info!(id = %id, recipients = recipients.len(), size = message.len(), "message queued");
        Ok(id)
    }

    /// Undoes a crash at any point of `enqueue` or delivery.
    fn recover(&self) -> Result<(), QueueError> {
        // Half-written spool files.
        for e in std::fs::read_dir(self.spool.join("tmp"))? {
            std::fs::remove_file(e?.path())?;
        }
        let known: HashSet<String> = {
            let db = self.db();
            let mut stmt = db.prepare("SELECT id FROM messages")?;
            // Bound so the rows are collected while `stmt` is still alive.
            #[allow(clippy::let_and_return)]
            let ids = stmt
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<_, _>>()?;
            ids
        };
        // Spool files without a row were never acknowledged: delete them.
        let mut on_disk = HashSet::new();
        for e in std::fs::read_dir(&self.spool)? {
            let path = e?.path();
            let Some(id) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".eml"))
            else {
                continue;
            };
            if known.contains(id) {
                on_disk.insert(id.to_owned());
            } else {
                tracing::warn!(id, "removing unacknowledged spool file left by a crash");
                std::fs::remove_file(&path)?;
            }
        }
        // Rows without a spool file: the content is gone. Fail the
        // recipients and tell the sender, rather than deliver nothing.
        for id in known.difference(&on_disk) {
            tracing::error!(id = %id, "spool file missing for queued message; failing it");
            let pending = self.pending_recipients(id)?;
            let failures: Vec<dsn::Failure> = pending
                .iter()
                .map(|(_, a)| dsn::Failure {
                    recipient: a.clone(),
                    status: "4.3.0".into(),
                    diagnostic: "message content was lost by the mail system".into(),
                })
                .collect();
            let outcomes: Vec<(i64, Outcome)> = pending
                .into_iter()
                .map(|(rid, _)| {
                    (
                        rid,
                        Outcome::Permanent {
                            status: "5.3.0".into(),
                            diagnostic: "spool file missing".into(),
                        },
                    )
                })
                .collect();
            let sender = self.sender_of(id)?;
            self.apply(id, &outcomes, false)?;
            self.bounce(id, sender.as_deref(), &failures, None)?;
        }
        Ok(())
    }

    fn pending_recipients(&self, id: &str) -> Result<Vec<(i64, String)>, QueueError> {
        let db = self.db();
        let mut stmt = db.prepare("SELECT rid, address FROM recipients WHERE message_id = ?1 AND status IN ('queued', 'held')")?;
        let rows = stmt
            .query_map([id], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }

    fn sender_of(&self, id: &str) -> Result<Option<String>, QueueError> {
        let db = self.db();
        Ok(db
            .query_row("SELECT sender FROM messages WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()?
            .flatten())
    }

    /// Claims up to `limit` due recipients for `owner`, grouped into jobs by
    /// message and domain. Claimed rows are leased, so a crashed worker's
    /// jobs come back after the lease expires.
    pub fn claim_due(&self, owner: &str, limit: usize) -> Result<Vec<Job>, QueueError> {
        let now = self.clock.now();
        let mut db = self.db();
        let tx = db.transaction()?;
        let rows: Vec<(i64, String, String, String, Option<String>, String)> = {
            let mut stmt = tx.prepare(
                "SELECT r.rid, r.message_id, r.address, r.domain, m.sender, m.kind
                 FROM recipients r JOIN messages m ON m.id = r.message_id
                 WHERE r.status = 'queued' AND r.next_attempt <= ?1
                   AND (r.lease_until IS NULL OR r.lease_until < ?1)
                 ORDER BY r.next_attempt LIMIT ?2",
            )?;
            // Bound so the rows are collected while `stmt` is still alive.
            #[allow(clippy::let_and_return)]
            let rows = stmt
                .query_map(
                    params![now, i64::try_from(limit).unwrap_or(i64::MAX)],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                        ))
                    },
                )?
                .collect::<Result<_, _>>()?;
            rows
        };
        for (rid, ..) in &rows {
            tx.execute(
                "UPDATE recipients SET lease_owner = ?1, lease_until = ?2 WHERE rid = ?3",
                params![owner, now.saturating_add(self.config.lease), rid],
            )?;
        }
        tx.commit()?;
        let mut jobs: Vec<Job> = Vec::new();
        for (rid, message_id, address, domain, sender, kind) in rows {
            match jobs
                .iter_mut()
                .find(|j| j.message_id == message_id && j.domain == domain)
            {
                Some(j) => j.recipients.push((rid, address)),
                None => jobs.push(Job {
                    message_id,
                    domain,
                    sender,
                    kind: Kind::from_db(&kind),
                    recipients: vec![(rid, address)],
                }),
            }
        }
        Ok(jobs)
    }

    /// The spool file of a message.
    pub fn read_message(&self, id: &str) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.spool_path(id))
    }

    /// Holds a job (test mode): never sent, never bounced.
    pub fn hold(&self, job: &Job, reason: &str) -> Result<(), QueueError> {
        let db = self.db();
        for (rid, _) in &job.recipients {
            db.execute(
                "UPDATE recipients SET status = 'held', last_error = ?1, lease_owner = NULL, lease_until = NULL WHERE rid = ?2",
                params![reason, rid],
            )?;
        }
        tracing::warn!(id = %job.message_id, domain = %job.domain, reason, "message held");
        Ok(())
    }

    /// Records delivery outcomes for a job: retries with back-off, gives up
    /// after `max_age`, and bounces permanent failures.
    pub fn record(&self, job: &Job, outcomes: &[(i64, Outcome)]) -> Result<(), QueueError> {
        let failures = self.apply(&job.message_id, outcomes, true)?;
        if !failures.is_empty() {
            let headers = self.read_message(&job.message_id).ok();
            self.bounce(
                &job.message_id,
                job.sender.as_deref(),
                &failures,
                headers.as_deref().map(dsn::header_section),
            )?;
        }
        self.finish_if_done(&job.message_id)
    }

    /// Updates recipient rows; returns the recipients that failed for good.
    fn apply(
        &self,
        id: &str,
        outcomes: &[(i64, Outcome)],
        may_retry: bool,
    ) -> Result<Vec<dsn::Failure>, QueueError> {
        let now = self.clock.now();
        let mut failures = Vec::new();
        let mut db = self.db();
        let tx = db.transaction()?;
        let arrival: u64 = tx
            .query_row("SELECT arrival FROM messages WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()?
            .unwrap_or(now);
        for (rid, outcome) in outcomes {
            let (address, attempts): (String, u32) = match tx
                .query_row(
                    "SELECT address, attempts FROM recipients WHERE rid = ?1",
                    [rid],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
            {
                Some(row) => row,
                None => continue,
            };
            let attempts = attempts.saturating_add(1);
            let fail = |failures: &mut Vec<dsn::Failure>, status: &str, diagnostic: &str| {
                failures.push(dsn::Failure {
                    recipient: address.clone(),
                    status: status.into(),
                    diagnostic: diagnostic.into(),
                });
            };
            match outcome {
                Outcome::Delivered => {
                    tx.execute("UPDATE recipients SET status = 'delivered', attempts = ?1, lease_owner = NULL, lease_until = NULL WHERE rid = ?2", params![attempts, rid])?;
                }
                Outcome::Temporary(err)
                    if may_retry && now.saturating_sub(arrival) < self.config.max_age =>
                {
                    let next = now.saturating_add(self.config.retry_delay(attempts));
                    tx.execute(
                        "UPDATE recipients SET attempts = ?1, next_attempt = ?2, last_error = ?3, lease_owner = NULL, lease_until = NULL WHERE rid = ?4",
                        params![attempts, next, err, rid],
                    )?;
                }
                Outcome::Temporary(err) => {
                    // RFC 3463 §3.5 X.4.7: delivery time expired.
                    let diag = format!("delivery time expired; last error: {err}");
                    tx.execute("UPDATE recipients SET status = 'failed', attempts = ?1, last_error = ?2, lease_owner = NULL, lease_until = NULL WHERE rid = ?3", params![attempts, diag, rid])?;
                    fail(&mut failures, "5.4.7", &diag);
                }
                Outcome::Permanent { status, diagnostic } => {
                    tx.execute("UPDATE recipients SET status = 'failed', attempts = ?1, last_error = ?2, lease_owner = NULL, lease_until = NULL WHERE rid = ?3", params![attempts, diagnostic, rid])?;
                    fail(&mut failures, status, diagnostic);
                }
            }
        }
        tx.commit()?;
        Ok(failures)
    }

    /// Queues a bounce, unless the no-loop rules forbid one.
    fn bounce(
        &self,
        id: &str,
        sender: Option<&str>,
        failures: &[dsn::Failure],
        headers: Option<&[u8]>,
    ) -> Result<(), QueueError> {
        if failures.is_empty() {
            return Ok(());
        }
        let Some(to) = dsn::bounce_recipient(sender, &self.config.hostname) else {
            tracing::info!(id, "not bouncing: null sender or our own MAILER-DAEMON");
            return Ok(());
        };
        let now = self.clock.now();
        let arrival: u64 = self
            .db()
            .query_row("SELECT arrival FROM messages WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()?
            .unwrap_or(now);
        let message = dsn::build(
            &self.config.hostname,
            &to,
            arrival,
            now,
            failures,
            headers,
            &self.new_id(),
        );
        // RFC 5321 §4.5.5: bounces use the null reverse-path, so a bounce
        // can never cause another bounce.
        match self.enqueue(None, &[to], &message) {
            Ok(bounce_id) => {
                tracing::info!(id, bounce_id = %bounce_id, "bounce queued");
                Ok(())
            }
            Err(e) => {
                tracing::error!(id, error = %e, "could not queue bounce");
                Ok(())
            }
        }
    }

    /// Deletes a message once no recipient is queued or held.
    fn finish_if_done(&self, id: &str) -> Result<(), QueueError> {
        let open: i64 = self.db().query_row(
            "SELECT COUNT(*) FROM recipients WHERE message_id = ?1 AND status IN ('queued', 'held')",
            [id],
            |r| r.get(0),
        )?;
        if open == 0 {
            self.db()
                .execute("DELETE FROM messages WHERE id = ?1", [id])?;
            match std::fs::remove_file(self.spool_path(id)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Every recipient still in the queue, for `idly queue list`.
    pub fn list(&self) -> Result<Vec<Entry>, QueueError> {
        let db = self.db();
        let mut stmt = db.prepare(
            "SELECT r.message_id, m.sender, r.address, r.status, r.attempts, r.next_attempt, r.last_error
             FROM recipients r JOIN messages m ON m.id = r.message_id
             WHERE r.status IN ('queued', 'held') ORDER BY m.arrival, r.rid",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Entry {
                    message_id: r.get(0)?,
                    sender: r.get(1)?,
                    recipient: r.get(2)?,
                    status: r.get(3)?,
                    attempts: r.get(4)?,
                    next_attempt: r.get(5)?,
                    last_error: r.get(6)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }

    /// Makes a message's queued recipients due now (`idly queue retry`).
    /// Held recipients stay held. Returns how many were rescheduled.
    pub fn retry_now(&self, id: &str) -> Result<usize, QueueError> {
        let now = self.clock.now();
        Ok(self.db().execute(
            "UPDATE recipients SET next_attempt = ?1, lease_owner = NULL, lease_until = NULL WHERE message_id = ?2 AND status = 'queued'",
            params![now, id],
        )?)
    }

    /// Removes a message without delivering or bouncing it (`idly queue drop`).
    pub fn drop_message(&self, id: &str) -> Result<bool, QueueError> {
        let n = self
            .db()
            .execute("DELETE FROM messages WHERE id = ?1", [id])?;
        if n > 0 {
            let _ = std::fs::remove_file(self.spool_path(id));
        }
        Ok(n > 0)
    }
}

#[cfg(test)]
mod tests;
