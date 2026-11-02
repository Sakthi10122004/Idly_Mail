//! What outbound delivery remembers across restarts, in one SQLite file
//! (`<data_dir>/outbound.db`): MTA-STS policies (RFC 8461 §5.1 caching),
//! TLS-RPT session counts (RFC 8460 §4), and report uploads waiting for a
//! retry (RFC 8460 §5.5). Losing it is harmless: policies are fetched
//! again and one day's report is incomplete.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, params};

/// Distinct report rows kept per UTC day. Beyond it, new kinds of result
/// are dropped (existing rows still count), so hostile variety can't grow
/// the file without bound.
#[cfg(not(test))]
const MAX_ROWS_PER_DAY: i64 = 50_000;
#[cfg(test)]
const MAX_ROWS_PER_DAY: i64 = 100;
/// Uploads waiting for a retry.
const MAX_OUTBOX: i64 = 10_000;

const SCHEMA: &str = "
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    CREATE TABLE IF NOT EXISTS mta_sts (
        domain  TEXT PRIMARY KEY,
        id      TEXT NOT NULL,
        policy  TEXT NOT NULL,    -- the policy lines, LF-separated
        fetched INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tlsrpt_results (
        day     INTEGER NOT NULL, -- days since 1970-01-01, UTC
        domain  TEXT NOT NULL,    -- the policy domain
        policy  TEXT NOT NULL,    -- JSON: the report's \"policy\" object
        failure TEXT NOT NULL,    -- JSON failure details; '' for a success
        count   INTEGER NOT NULL,
        PRIMARY KEY (day, domain, policy, failure)
    );
    CREATE TABLE IF NOT EXISTS tlsrpt_outbox (
        id       INTEGER PRIMARY KEY,
        host     TEXT NOT NULL,
        path     TEXT NOT NULL,
        body     BLOB NOT NULL,   -- the gzipped report
        created  INTEGER NOT NULL,
        next_try INTEGER NOT NULL,
        tries    INTEGER NOT NULL DEFAULT 0
    );
";

/// A saved MTA-STS policy: (domain, policy id, policy text, fetch time).
pub(crate) type SavedPolicy = (String, String, String, u64);

/// A report upload waiting for a retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Upload {
    pub(crate) id: i64,
    pub(crate) host: String,
    pub(crate) path: String,
    pub(crate) body: Vec<u8>,
    pub(crate) created: u64,
    pub(crate) tries: u32,
}

/// The outbound state database.
#[derive(Debug)]
pub struct State {
    db: Mutex<Connection>,
}

impl State {
    /// Opens (or creates) the database at `path`.
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        Self::with(Connection::open(path)?)
    }

    /// A database that lives only in memory (tests, the demo).
    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        Self::with(Connection::open_in_memory()?)
    }

    fn with(db: Connection) -> Result<Self, rusqlite::Error> {
        db.execute_batch(SCHEMA)?;
        Ok(Self { db: Mutex::new(db) })
    }

    fn db(&self) -> MutexGuard<'_, Connection> {
        self.db
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Every saved MTA-STS policy.
    pub(crate) fn policies(&self) -> rusqlite::Result<Vec<SavedPolicy>> {
        let db = self.db();
        let mut stmt = db.prepare("SELECT domain, id, policy, fetched FROM mta_sts")?;
        // Bound so the rows are collected while `stmt` is still alive.
        #[allow(clippy::let_and_return)]
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect();
        rows
    }

    /// Saves a fetched MTA-STS policy, replacing the domain's old one.
    pub(crate) fn save_policy(
        &self,
        domain: &str,
        id: &str,
        text: &str,
        fetched: u64,
    ) -> rusqlite::Result<()> {
        self.db().execute(
            "INSERT OR REPLACE INTO mta_sts (domain, id, policy, fetched) VALUES (?1, ?2, ?3, ?4)",
            params![domain, id, text, fetched],
        )?;
        Ok(())
    }

    /// Removes saved policies fetched before `before` (expired ones).
    pub(crate) fn forget_policies(&self, before: u64) -> rusqlite::Result<()> {
        self.db()
            .execute("DELETE FROM mta_sts WHERE fetched < ?1", [before])?;
        Ok(())
    }

    /// Counts one session in a day's report for `domain`.
    pub(crate) fn count(
        &self,
        day: u64,
        domain: &str,
        policy: &str,
        failure: &str,
    ) -> rusqlite::Result<()> {
        let db = self.db();
        let updated = db.execute(
            "UPDATE tlsrpt_results SET count = count + 1
             WHERE day = ?1 AND domain = ?2 AND policy = ?3 AND failure = ?4",
            params![day, domain, policy, failure],
        )?;
        if updated > 0 {
            return Ok(());
        }
        let rows: i64 = db.query_row(
            "SELECT COUNT(*) FROM tlsrpt_results WHERE day = ?1",
            [day],
            |r| r.get(0),
        )?;
        if rows >= MAX_ROWS_PER_DAY {
            tracing::warn!(day, "TLS report row limit reached; result not counted");
            return Ok(());
        }
        db.execute(
            "INSERT INTO tlsrpt_results (day, domain, policy, failure, count) VALUES (?1, ?2, ?3, ?4, 1)",
            params![day, domain, policy, failure],
        )?;
        Ok(())
    }

    /// The (day, domain) pairs with results from before `day`.
    pub(crate) fn report_keys_before(&self, day: u64) -> rusqlite::Result<Vec<(u64, String)>> {
        let db = self.db();
        let mut stmt = db.prepare(
            "SELECT DISTINCT day, domain FROM tlsrpt_results WHERE day < ?1 ORDER BY day, domain",
        )?;
        // Bound so the rows are collected while `stmt` is still alive.
        #[allow(clippy::let_and_return)]
        let rows = stmt
            .query_map([day], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect();
        rows
    }

    /// A day's results for one domain: (policy, failure, count).
    pub(crate) fn results(
        &self,
        day: u64,
        domain: &str,
    ) -> rusqlite::Result<Vec<(String, String, u64)>> {
        let db = self.db();
        let mut stmt = db.prepare(
            "SELECT policy, failure, count FROM tlsrpt_results WHERE day = ?1 AND domain = ?2
             ORDER BY policy, failure",
        )?;
        // Bound so the rows are collected while `stmt` is still alive.
        #[allow(clippy::let_and_return)]
        let rows = stmt
            .query_map(params![day, domain], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect();
        rows
    }

    /// Forgets a day's results for one domain (reported or not wanted).
    pub(crate) fn forget_results(&self, day: u64, domain: &str) -> rusqlite::Result<()> {
        self.db().execute(
            "DELETE FROM tlsrpt_results WHERE day = ?1 AND domain = ?2",
            params![day, domain],
        )?;
        Ok(())
    }

    /// Keeps a failed upload for a retry at `next_try`.
    pub(crate) fn add_upload(
        &self,
        host: &str,
        path: &str,
        body: &[u8],
        created: u64,
        next_try: u64,
    ) -> rusqlite::Result<()> {
        let db = self.db();
        let n: i64 = db.query_row("SELECT COUNT(*) FROM tlsrpt_outbox", [], |r| r.get(0))?;
        if n >= MAX_OUTBOX {
            tracing::warn!("TLS report upload queue is full; dropping a report");
            return Ok(());
        }
        db.execute(
            "INSERT INTO tlsrpt_outbox (host, path, body, created, next_try, tries)
             VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            params![host, path, body, created, next_try],
        )?;
        Ok(())
    }

    /// Uploads due for a retry at `now`.
    pub(crate) fn due_uploads(&self, now: u64) -> rusqlite::Result<Vec<Upload>> {
        let db = self.db();
        let mut stmt = db.prepare(
            "SELECT id, host, path, body, created, tries FROM tlsrpt_outbox
             WHERE next_try <= ?1 ORDER BY next_try LIMIT 100",
        )?;
        // Bound so the rows are collected while `stmt` is still alive.
        #[allow(clippy::let_and_return)]
        let rows = stmt
            .query_map([now], |r| {
                Ok(Upload {
                    id: r.get(0)?,
                    host: r.get(1)?,
                    path: r.get(2)?,
                    body: r.get(3)?,
                    created: r.get(4)?,
                    tries: r.get(5)?,
                })
            })?
            .collect();
        rows
    }

    /// Schedules another retry of an upload.
    pub(crate) fn retry_upload(&self, id: i64, next_try: u64) -> rusqlite::Result<()> {
        self.db().execute(
            "UPDATE tlsrpt_outbox SET next_try = ?1, tries = tries + 1 WHERE id = ?2",
            params![next_try, id],
        )?;
        Ok(())
    }

    /// Removes an upload (sent, or given up).
    pub(crate) fn remove_upload(&self, id: i64) -> rusqlite::Result<()> {
        self.db()
            .execute("DELETE FROM tlsrpt_outbox WHERE id = ?1", [id])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_accumulate_and_are_bounded() {
        let s = State::in_memory().unwrap();
        s.count(10, "a.example", "{}", "").unwrap();
        s.count(10, "a.example", "{}", "").unwrap();
        s.count(10, "a.example", "{}", "{\"x\":1}").unwrap();
        s.count(11, "b.example", "{}", "").unwrap();
        assert_eq!(
            s.results(10, "a.example").unwrap(),
            vec![
                ("{}".into(), String::new(), 2),
                ("{}".into(), "{\"x\":1}".into(), 1)
            ]
        );
        assert_eq!(
            s.report_keys_before(11).unwrap(),
            vec![(10, "a.example".into())]
        );
        s.forget_results(10, "a.example").unwrap();
        assert!(s.results(10, "a.example").unwrap().is_empty());

        // The per-day row limit.
        for i in 0..MAX_ROWS_PER_DAY {
            s.count(20, "c.example", "{}", &i.to_string()).unwrap();
        }
        s.count(20, "c.example", "{}", "one too many").unwrap();
        s.count(20, "c.example", "{}", "0").unwrap();
        let rows = s.results(20, "c.example").unwrap();
        assert_eq!(rows.len(), usize::try_from(MAX_ROWS_PER_DAY).unwrap());
        assert!(
            rows.iter().any(|(_, f, n)| f == "0" && *n == 2),
            "existing rows still count"
        );
    }

    #[test]
    fn policies_and_uploads_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outbound.db");
        {
            let s = State::open(&path).unwrap();
            s.save_policy("a.example", "1", "version: STSv1", 100)
                .unwrap();
            s.save_policy("a.example", "2", "version: STSv1", 200)
                .unwrap();
            s.save_policy("old.example", "1", "version: STSv1", 5)
                .unwrap();
            s.add_upload("r.example", "/tlsrpt", b"gz", 100, 400)
                .unwrap();
        }
        let s = State::open(&path).unwrap();
        s.forget_policies(50).unwrap();
        assert_eq!(
            s.policies().unwrap(),
            vec![("a.example".into(), "2".into(), "version: STSv1".into(), 200)]
        );
        assert!(s.due_uploads(399).unwrap().is_empty());
        let up = s.due_uploads(400).unwrap();
        assert_eq!((up[0].host.as_str(), up[0].tries), ("r.example", 1));
        s.retry_upload(up[0].id, 1000).unwrap();
        assert!(s.due_uploads(999).unwrap().is_empty());
        assert_eq!(s.due_uploads(1000).unwrap()[0].tries, 2);
        s.remove_upload(up[0].id).unwrap();
        assert!(s.due_uploads(u64::MAX >> 1).unwrap().is_empty());
    }
}
