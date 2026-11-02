//! Mailboxes: names, roles, UIDVALIDITY and the IMAP/JMAP counters.

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{OptionalExtension, Transaction, params};

use crate::{AccountId, Change, Mailbox, MailboxId, Result, Role, Store, StoreError, next_modseq};

/// The hierarchy separator (RFC 9051 §5.1.1); the same for JMAP names.
pub const SEPARATOR: char = '/';
/// Bounds on names, to keep listings and paths sane.
const MAX_NAME: usize = 1000;
const MAX_LEVEL: usize = 255;
const MAX_DEPTH: usize = 20;

/// Checks and normalizes a mailbox name: levels are non-empty, there are
/// no control characters, and any spelling of INBOX (RFC 9051 §5.1:
/// case-insensitive) as the first level becomes "INBOX".
pub fn normalize(name: &str) -> Result<String> {
    let bad = |why: &str| Err(StoreError::Invalid(format!("mailbox name: {why}")));
    if name.is_empty() || name.len() > MAX_NAME {
        return bad("empty or too long");
    }
    if name.chars().any(char::is_control) {
        return bad("control characters");
    }
    let levels: Vec<&str> = name.split(SEPARATOR).collect();
    if levels.len() > MAX_DEPTH {
        return bad("too deeply nested");
    }
    if levels.iter().any(|l| l.is_empty() || l.len() > MAX_LEVEL) {
        return bad("empty level");
    }
    let mut out: Vec<String> = levels.iter().map(|l| (*l).to_owned()).collect();
    if let Some(first) = out.first_mut()
        && first.eq_ignore_ascii_case("INBOX")
    {
        *first = "INBOX".into();
    }
    Ok(out.join(&SEPARATOR.to_string()))
}

/// Inserts a mailbox (no checks besides uniqueness).
pub(crate) fn insert(
    tx: &Transaction<'_>,
    account: AccountId,
    name: &str,
    role: Option<Role>,
) -> Result<MailboxId> {
    // A fresh UIDVALIDITY that never repeats for this account, so a
    // re-created name can't be mistaken for the old mailbox (RFC 9051
    // §2.3.1.1).
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |d| d.as_secs());
    let last: u32 = tx.query_row(
        "SELECT last_uidvalidity FROM accounts WHERE id = ?1",
        [account],
        |r| r.get(0),
    )?;
    let uidvalidity = u32::try_from(now)
        .unwrap_or(u32::MAX)
        .max(last.saturating_add(1))
        .max(1);
    let modseq = next_modseq(tx, account)?;
    tx.execute(
        "UPDATE accounts SET last_uidvalidity = ?1 WHERE id = ?2",
        params![uidvalidity, account],
    )?;
    let inserted = tx.execute(
        "INSERT INTO mailboxes(account_id, name, role, uidvalidity, highest_modseq, created_modseq, modseq)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?5)",
        params![account, name, role.map(Role::as_str), uidvalidity, modseq],
    );
    match inserted {
        Ok(_) => Ok(tx.last_insert_rowid()),
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Err(StoreError::AlreadyExists)
        }
        Err(e) => Err(e.into()),
    }
}

const SELECT: &str = "SELECT m.id, m.account_id, m.name, m.role, m.uidvalidity, m.uidnext,
        m.highest_modseq, m.subscribed,
        (SELECT COUNT(*) FROM messages WHERE mailbox_id = m.id),
        (SELECT COUNT(*) FROM messages WHERE mailbox_id = m.id AND flags & 1 = 0),
        (SELECT COALESCE(SUM(size), 0) FROM messages WHERE mailbox_id = m.id)
    FROM mailboxes m";

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Mailbox> {
    let role: Option<String> = r.get(3)?;
    Ok(Mailbox {
        id: r.get(0)?,
        account: r.get(1)?,
        name: r.get(2)?,
        role: role.as_deref().and_then(Role::parse),
        uidvalidity: r.get(4)?,
        uidnext: r.get(5)?,
        highest_modseq: r.get(6)?,
        subscribed: r.get(7)?,
        messages: r.get(8)?,
        unseen: r.get(9)?,
        size: r.get(10)?,
    })
}

impl Store {
    /// Every mailbox of the account, by name.
    pub fn mailboxes(&self, account: AccountId) -> Result<Vec<Mailbox>> {
        let db = self.db();
        let mut stmt = db.prepare(&format!(
            "{SELECT} WHERE m.account_id = ?1 AND m.deleted = 0 ORDER BY m.name"
        ))?;
        let rows = stmt
            .query_map([account], row)?
            .collect::<std::result::Result<_, _>>()?;
        Ok(rows)
    }

    pub fn mailbox(&self, account: AccountId, id: MailboxId) -> Result<Mailbox> {
        let db = self.db();
        db.query_row(
            &format!("{SELECT} WHERE m.id = ?1 AND m.account_id = ?2 AND m.deleted = 0"),
            [id, account],
            row,
        )
        .optional()?
        .ok_or(StoreError::NotFound)
    }

    pub fn mailbox_by_name(&self, account: AccountId, name: &str) -> Result<Mailbox> {
        let name = normalize(name)?;
        let db = self.db();
        db.query_row(
            &format!("{SELECT} WHERE m.account_id = ?1 AND m.name = ?2 AND m.deleted = 0"),
            params![account, name],
            row,
        )
        .optional()?
        .ok_or(StoreError::NotFound)
    }

    pub fn mailbox_by_role(&self, account: AccountId, role: Role) -> Result<Mailbox> {
        let db = self.db();
        db.query_row(
            &format!("{SELECT} WHERE m.account_id = ?1 AND m.role = ?2 AND m.deleted = 0"),
            params![account, role.as_str()],
            row,
        )
        .optional()?
        .ok_or(StoreError::NotFound)
    }

    /// Creates a mailbox. Missing parent levels are created too
    /// (RFC 9051 §6.3.4).
    pub fn create_mailbox(&self, account: AccountId, name: &str) -> Result<MailboxId> {
        let name = normalize(name)?;
        let mut db = self.db();
        let tx = db.transaction()?;
        let levels: Vec<&str> = name.split(SEPARATOR).collect();
        for depth in 1..levels.len() {
            let parent = levels.get(..depth).unwrap_or_default().join("/");
            match insert(&tx, account, &parent, None) {
                Ok(_) | Err(StoreError::AlreadyExists) => {}
                Err(e) => return Err(e),
            }
        }
        let id = insert(&tx, account, &name, None)?;
        let modseq = next_modseq(&tx, account)?;
        tx.commit()?;
        drop(db);
        self.notify(Change {
            account,
            mailboxes: vec![id],
            mailbox_list: true,
            modseq,
        });
        Ok(id)
    }

    /// Renames a mailbox and everything below it (RFC 9051 §6.3.6).
    /// Renaming INBOX moves its messages to a new mailbox and leaves INBOX
    /// empty, as RFC 9051 requires.
    pub fn rename_mailbox(&self, account: AccountId, id: MailboxId, to: &str) -> Result<()> {
        let to = normalize(to)?;
        let mb = self.mailbox(account, id)?;
        if mb.name == "INBOX" {
            let new = self.create_mailbox(account, &to)?;
            let ids: Vec<_> = self
                .messages(account, id)?
                .into_iter()
                .map(|m| m.id)
                .collect();
            self.move_messages(account, &ids, new)?;
            return Ok(());
        }
        if to == "INBOX" || to == mb.name {
            return Err(StoreError::AlreadyExists);
        }
        if to.starts_with(&format!("{}/", mb.name)) {
            return Err(StoreError::Invalid(
                "can't move a mailbox into itself".into(),
            ));
        }
        let mut db = self.db();
        let tx = db.transaction()?;
        let modseq = next_modseq(&tx, account)?;
        let prefix = format!("{}/", mb.name);
        let mut stmt = tx.prepare(
            "SELECT id, name FROM mailboxes WHERE account_id = ?1 AND deleted = 0 AND (id = ?2 OR substr(name, 1, ?3) = ?4)",
        )?;
        let targets: Vec<(MailboxId, String)> = stmt
            .query_map(params![account, id, prefix.chars().count(), prefix], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?
            .collect::<std::result::Result<_, _>>()?;
        drop(stmt);
        let mut ids = Vec::new();
        for (mid, old) in targets {
            let new = format!("{to}{}", old.get(mb.name.len()..).unwrap_or_default());
            let updated = tx.execute(
                "UPDATE mailboxes SET name = ?1, modseq = ?2 WHERE id = ?3",
                params![new, modseq, mid],
            );
            match updated {
                Ok(_) => ids.push(mid),
                Err(rusqlite::Error::SqliteFailure(e, _))
                    if e.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    return Err(StoreError::AlreadyExists);
                }
                Err(e) => return Err(e.into()),
            }
        }
        // Parents of the new name must exist.
        let levels: Vec<&str> = to.split(SEPARATOR).collect();
        for depth in 1..levels.len() {
            let parent = levels.get(..depth).unwrap_or_default().join("/");
            match insert(&tx, account, &parent, None) {
                Ok(_) | Err(StoreError::AlreadyExists) => {}
                Err(e) => return Err(e),
            }
        }
        tx.commit()?;
        drop(db);
        self.notify(Change {
            account,
            mailboxes: ids,
            mailbox_list: true,
            modseq,
        });
        Ok(())
    }

    /// Deletes a mailbox and its messages. INBOX can't be deleted
    /// (RFC 9051 §6.3.5); mailboxes below it stay.
    pub fn delete_mailbox(&self, account: AccountId, id: MailboxId) -> Result<()> {
        let mb = self.mailbox(account, id)?;
        if mb.name == "INBOX" {
            return Err(StoreError::Invalid("INBOX can't be deleted".into()));
        }
        let ids: Vec<_> = self
            .messages(account, id)?
            .into_iter()
            .map(|m| m.id)
            .collect();
        self.expunge(account, &ids)?;
        let mut db = self.db();
        let tx = db.transaction()?;
        let modseq = next_modseq(&tx, account)?;
        tx.execute(
            "UPDATE mailboxes SET deleted = 1, modseq = ?1 WHERE id = ?2",
            params![modseq, id],
        )?;
        tx.commit()?;
        drop(db);
        self.notify(Change {
            account,
            mailboxes: vec![id],
            mailbox_list: true,
            modseq,
        });
        Ok(())
    }

    /// Sets the IMAP subscription (RFC 9051 §6.3.7) / JMAP isSubscribed.
    pub fn set_subscribed(&self, account: AccountId, id: MailboxId, on: bool) -> Result<()> {
        let mut db = self.db();
        let tx = db.transaction()?;
        let modseq = next_modseq(&tx, account)?;
        let n = tx.execute(
            "UPDATE mailboxes SET subscribed = ?1, modseq = ?2 WHERE id = ?3 AND account_id = ?4 AND deleted = 0",
            params![on, modseq, id, account],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        tx.commit()?;
        Ok(())
    }
}
