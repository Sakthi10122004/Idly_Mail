//! Messages: append, flags, copy, move, expunge, and changes since a
//! MODSEQ.

use std::collections::BTreeSet;

use rusqlite::{OptionalExtension, Transaction, params};

use crate::meta::{self, Meta};
use crate::{
    AccountId, BlobId, Change, EmailId, MAX_KEYWORDS, MailboxId, Result, Store, StoreError, flags,
    next_modseq,
};

/// A message in a mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: EmailId,
    pub mailbox: MailboxId,
    pub uid: u32,
    /// System flags, [`crate::flags`] bits.
    pub flags: u8,
    /// Other keywords, lower-case, sorted.
    pub keywords: Vec<String>,
    pub modseq: u64,
    pub size: u64,
    /// When it arrived (IMAP INTERNALDATE, JMAP receivedAt), Unix seconds.
    pub received: i64,
    /// The Date header, if it parses.
    pub sent: Option<i64>,
    pub blob: BlobId,
    pub thread: i64,
}

/// A message to add.
#[derive(Debug, Clone)]
pub struct NewMessage<'a> {
    pub raw: &'a [u8],
    pub flags: u8,
    pub keywords: Vec<String>,
    pub received: i64,
}

/// How STORE changes flags (RFC 9051 §6.4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagOp {
    Add,
    Remove,
    Replace,
}

/// The outcome of a flag change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlagResult {
    /// Messages whose flags changed, with their new state.
    pub changed: Vec<Message>,
    /// Messages left alone because their MODSEQ was above UNCHANGEDSINCE
    /// (RFC 7162 §3.1.3).
    pub modified: Vec<EmailId>,
}

/// A keyword is an IMAP atom (RFC 9051 §9 `flag-keyword`) and never a
/// system flag; stored lower-case (JMAP keywords are case-insensitive,
/// RFC 8621 §4.1.1).
pub fn valid_keyword(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= 100
        && k.bytes()
            .all(|b| b.is_ascii_graphic() && !b"(){%*\"\\]".contains(&b))
}

fn keywords_text(k: &BTreeSet<String>) -> String {
    k.iter().cloned().collect::<Vec<_>>().join(" ")
}

const COLUMNS: &str =
    "id, mailbox_id, uid, flags, keywords, modseq, size, received, sent, blob, thread_id";

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Message> {
    let keywords: String = r.get(4)?;
    let blob: String = r.get(9)?;
    Ok(Message {
        id: r.get(0)?,
        mailbox: r.get(1)?,
        uid: r.get(2)?,
        flags: r.get(3)?,
        keywords: keywords.split_whitespace().map(String::from).collect(),
        modseq: r.get(5)?,
        size: r.get(6)?,
        received: r.get(7)?,
        sent: r.get(8)?,
        blob: BlobId::parse(&blob).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                9,
                rusqlite::types::Type::Text,
                "bad blob id".into(),
            )
        })?,
        thread: r.get(10)?,
    })
}

fn get(tx: &Transaction<'_>, account: AccountId, id: EmailId) -> Result<Message> {
    tx.query_row(
        &format!("SELECT {COLUMNS} FROM messages WHERE id = ?1 AND account_id = ?2"),
        [id, account],
        row,
    )
    .optional()?
    .ok_or(StoreError::NotFound)
}

/// Takes the next UID of `mailbox`.
fn next_uid(tx: &Transaction<'_>, account: AccountId, mailbox: MailboxId) -> Result<u32> {
    let uid: Option<u32> = tx
        .query_row(
            "SELECT uidnext FROM mailboxes WHERE id = ?1 AND account_id = ?2 AND deleted = 0",
            [mailbox, account],
            |r| r.get(0),
        )
        .optional()?;
    let uid = uid.ok_or(StoreError::NotFound)?;
    if uid == u32::MAX {
        // RFC 9051 §2.3.1.1: UIDs are 32-bit; a new UIDVALIDITY would be
        // needed. Practically unreachable; refuse rather than wrap.
        return Err(StoreError::Invalid("mailbox UID space exhausted".into()));
    }
    tx.execute(
        "UPDATE mailboxes SET uidnext = uidnext + 1 WHERE id = ?1",
        [mailbox],
    )?;
    Ok(uid)
}

fn touch(tx: &Transaction<'_>, mailbox: MailboxId, modseq: u64) -> Result<()> {
    tx.execute(
        "UPDATE mailboxes SET highest_modseq = ?1 WHERE id = ?2",
        params![modseq, mailbox],
    )?;
    Ok(())
}

/// The thread for a new message: that of any known message it refers to,
/// or that refers to it; else a new one (RFC 8621 §3). Records the ids.
fn thread_for(tx: &Transaction<'_>, account: AccountId, meta: &Meta) -> Result<i64> {
    let mut ids: Vec<&String> = meta.message_id.iter().collect();
    ids.extend(meta.parents.iter());
    let mut found = None;
    for id in &ids {
        let t: Option<i64> = tx
            .query_row(
                "SELECT thread_id FROM thread_ids WHERE account_id = ?1 AND msgid = ?2",
                params![account, id],
                |r| r.get(0),
            )
            .optional()?;
        if t.is_some() {
            found = t;
            break;
        }
    }
    let thread = match found {
        Some(t) => t,
        None => {
            let t: i64 = tx.query_row(
                "SELECT next_thread FROM accounts WHERE id = ?1",
                [account],
                |r| r.get(0),
            )?;
            tx.execute(
                "UPDATE accounts SET next_thread = next_thread + 1 WHERE id = ?1",
                [account],
            )?;
            t
        }
    };
    for id in ids {
        tx.execute(
            "INSERT OR IGNORE INTO thread_ids(account_id, msgid, thread_id) VALUES (?1, ?2, ?3)",
            params![account, id, thread],
        )?;
    }
    Ok(thread)
}

#[allow(clippy::too_many_arguments)]
fn insert(
    tx: &Transaction<'_>,
    account: AccountId,
    mailbox: MailboxId,
    uid: u32,
    blob: &BlobId,
    size: u64,
    received: i64,
    flags: u8,
    keywords: &str,
    modseq: u64,
    thread: i64,
    meta: &Meta,
) -> Result<EmailId> {
    tx.execute(
        "INSERT INTO messages(account_id, mailbox_id, uid, blob, size, received, sent, flags, keywords,
            modseq, created_modseq, thread_id, message_id, subject, sender, recipients, preview, has_attachment)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        params![
            account,
            mailbox,
            uid,
            blob.to_string(),
            size,
            received,
            meta.sent,
            flags,
            keywords,
            modseq,
            thread,
            meta.message_id,
            meta.subject,
            meta.sender,
            meta.recipients,
            meta.preview,
            meta.has_attachment,
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

impl Store {
    /// Adds a message to a mailbox: delivery, IMAP APPEND, JMAP import.
    /// The blob is durable before the row is committed.
    pub fn append(
        &self,
        account: AccountId,
        mailbox: MailboxId,
        new: NewMessage<'_>,
    ) -> Result<Message> {
        let size = new.raw.len() as u64;
        let quota: Option<u64> =
            self.db()
                .query_row("SELECT quota FROM accounts WHERE id = ?1", [account], |r| {
                    r.get(0)
                })?;
        if let Some(q) = quota {
            let (_, used) = self.usage(account)?;
            if used.saturating_add(size) > q {
                return Err(StoreError::OverQuota);
            }
        }
        let mut kw = BTreeSet::new();
        for k in &new.keywords {
            let k = k.to_ascii_lowercase();
            if !valid_keyword(&k) {
                return Err(StoreError::Invalid(format!("invalid keyword {k:?}")));
            }
            kw.insert(k);
        }
        if kw.len() > MAX_KEYWORDS {
            return Err(StoreError::Invalid("too many keywords".into()));
        }
        let meta = meta::extract(new.raw);
        let blob = self.blobs.put(new.raw)?;

        let mut db = self.db();
        let tx = db.transaction()?;
        let modseq = next_modseq(&tx, account)?;
        let uid = next_uid(&tx, account, mailbox)?;
        let thread = thread_for(&tx, account, &meta)?;
        let id = insert(
            &tx,
            account,
            mailbox,
            uid,
            &blob,
            size,
            new.received,
            new.flags & flags::ALL,
            &keywords_text(&kw),
            modseq,
            thread,
            &meta,
        )?;
        touch(&tx, mailbox, modseq)?;
        let msg = get(&tx, account, id)?;
        tx.commit()?;
        drop(db);
        self.notify(Change {
            account,
            mailboxes: vec![mailbox],
            mailbox_list: false,
            modseq,
        });
        Ok(msg)
    }

    /// The messages of a mailbox in UID order.
    pub fn messages(&self, account: AccountId, mailbox: MailboxId) -> Result<Vec<Message>> {
        let db = self.db();
        let mut stmt = db.prepare(&format!(
            "SELECT {COLUMNS} FROM messages WHERE account_id = ?1 AND mailbox_id = ?2 ORDER BY uid"
        ))?;
        let rows = stmt
            .query_map([account, mailbox], row)?
            .collect::<std::result::Result<_, _>>()?;
        Ok(rows)
    }

    pub fn message(&self, account: AccountId, id: EmailId) -> Result<Message> {
        let db = self.db();
        db.query_row(
            &format!("SELECT {COLUMNS} FROM messages WHERE id = ?1 AND account_id = ?2"),
            [id, account],
            row,
        )
        .optional()?
        .ok_or(StoreError::NotFound)
    }

    /// The message's content.
    pub fn read(&self, account: AccountId, id: EmailId) -> Result<Vec<u8>> {
        let msg = self.message(account, id)?;
        self.blobs.get(&msg.blob)?.ok_or_else(|| {
            StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("blob {} of message {id} is missing", msg.blob),
            ))
        })
    }

    /// Changes flags and keywords of `ids`. With `unchanged_since`,
    /// messages with a higher MODSEQ are left alone and reported
    /// (CONDSTORE, RFC 7162 §3.1.3). Messages whose flags end up the same
    /// get no new MODSEQ.
    pub fn store_flags(
        &self,
        account: AccountId,
        ids: &[EmailId],
        op: FlagOp,
        system: u8,
        keywords: &[String],
        unchanged_since: Option<u64>,
    ) -> Result<FlagResult> {
        let mut kws = BTreeSet::new();
        for k in keywords {
            let k = k.to_ascii_lowercase();
            if !valid_keyword(&k) {
                return Err(StoreError::Invalid(format!("invalid keyword {k:?}")));
            }
            kws.insert(k);
        }
        let system = system & flags::ALL;
        let mut db = self.db();
        let tx = db.transaction()?;
        let mut result = FlagResult::default();
        let mut modseq = None;
        let mut touched = BTreeSet::new();
        for &id in ids {
            let msg = match get(&tx, account, id) {
                Ok(m) => m,
                Err(StoreError::NotFound) => continue,
                Err(e) => return Err(e),
            };
            if unchanged_since.is_some_and(|u| msg.modseq > u) {
                result.modified.push(id);
                continue;
            }
            let current: BTreeSet<String> = msg.keywords.iter().cloned().collect();
            let (new_flags, new_kw) = match op {
                FlagOp::Add => (msg.flags | system, current.union(&kws).cloned().collect()),
                FlagOp::Remove => (
                    msg.flags & !system,
                    current.difference(&kws).cloned().collect(),
                ),
                FlagOp::Replace => (system, kws.clone()),
            };
            if new_kw.len() > MAX_KEYWORDS {
                return Err(StoreError::Invalid("too many keywords".into()));
            }
            if new_flags == msg.flags && new_kw == current {
                continue;
            }
            let m = match modseq {
                Some(m) => m,
                None => {
                    let m = next_modseq(&tx, account)?;
                    modseq = Some(m);
                    m
                }
            };
            tx.execute(
                "UPDATE messages SET flags = ?1, keywords = ?2, modseq = ?3 WHERE id = ?4",
                params![new_flags, keywords_text(&new_kw), m, id],
            )?;
            touch(&tx, msg.mailbox, m)?;
            touched.insert(msg.mailbox);
            result.changed.push(get(&tx, account, id)?);
        }
        tx.commit()?;
        drop(db);
        if let Some(m) = modseq {
            self.notify(Change {
                account,
                mailboxes: touched.into_iter().collect(),
                mailbox_list: false,
                modseq: m,
            });
        }
        Ok(result)
    }

    /// Copies messages into `dest` (sharing their blobs), keeping flags
    /// and arrival time (RFC 9051 §6.4.7). Returns (source, copy) pairs.
    pub fn copy_messages(
        &self,
        account: AccountId,
        ids: &[EmailId],
        dest: MailboxId,
    ) -> Result<Vec<(Message, Message)>> {
        let mut total = 0u64;
        for &id in ids {
            total = total.saturating_add(self.message(account, id)?.size);
        }
        let quota: Option<u64> =
            self.db()
                .query_row("SELECT quota FROM accounts WHERE id = ?1", [account], |r| {
                    r.get(0)
                })?;
        if let Some(q) = quota
            && self.usage(account)?.1.saturating_add(total) > q
        {
            return Err(StoreError::OverQuota);
        }
        let mut db = self.db();
        let tx = db.transaction()?;
        let modseq = next_modseq(&tx, account)?;
        let mut out = Vec::new();
        for &id in ids {
            let src = get(&tx, account, id)?;
            let uid = next_uid(&tx, account, dest)?;
            tx.execute(
                "INSERT INTO messages(account_id, mailbox_id, uid, blob, size, received, sent, flags, keywords,
                    modseq, created_modseq, thread_id, message_id, subject, sender, recipients, preview, has_attachment)
                 SELECT account_id, ?1, ?2, blob, size, received, sent, flags, keywords, ?3, ?3, thread_id,
                    message_id, subject, sender, recipients, preview, has_attachment
                 FROM messages WHERE id = ?4",
                params![dest, uid, modseq, id],
            )?;
            let copy = get(&tx, account, tx.last_insert_rowid())?;
            out.push((src, copy));
        }
        touch(&tx, dest, modseq)?;
        tx.commit()?;
        drop(db);
        self.notify(Change {
            account,
            mailboxes: vec![dest],
            mailbox_list: false,
            modseq,
        });
        Ok(out)
    }

    /// Moves messages into `dest` (RFC 6851): each gets a new UID there;
    /// the old UID is logged as expunged (as a move, which JMAP sees as
    /// an update). Returns (old mailbox, old UID, moved message).
    pub fn move_messages(
        &self,
        account: AccountId,
        ids: &[EmailId],
        dest: MailboxId,
    ) -> Result<Vec<(MailboxId, u32, Message)>> {
        let mut db = self.db();
        let tx = db.transaction()?;
        let modseq = next_modseq(&tx, account)?;
        let mut out = Vec::new();
        let mut touched = BTreeSet::from([dest]);
        for &id in ids {
            let src = get(&tx, account, id)?;
            if src.mailbox == dest {
                continue;
            }
            let uid = next_uid(&tx, account, dest)?;
            tx.execute(
                "INSERT INTO expunged(account_id, mailbox_id, uid, email_id, thread_id, modseq, moved)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
                params![account, src.mailbox, src.uid, id, src.thread, modseq],
            )?;
            tx.execute(
                "UPDATE messages SET mailbox_id = ?1, uid = ?2, modseq = ?3 WHERE id = ?4",
                params![dest, uid, modseq, id],
            )?;
            touch(&tx, src.mailbox, modseq)?;
            touched.insert(src.mailbox);
            out.push((src.mailbox, src.uid, get(&tx, account, id)?));
        }
        touch(&tx, dest, modseq)?;
        tx.commit()?;
        drop(db);
        self.notify(Change {
            account,
            mailboxes: touched.into_iter().collect(),
            mailbox_list: false,
            modseq,
        });
        Ok(out)
    }

    /// Removes messages for good. Their blobs go once no message uses them
    /// ([`Store::collect_garbage`]). Returns (mailbox, UID) of each.
    pub fn expunge(&self, account: AccountId, ids: &[EmailId]) -> Result<Vec<(MailboxId, u32)>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut db = self.db();
        let tx = db.transaction()?;
        let modseq = next_modseq(&tx, account)?;
        let mut out = Vec::new();
        let mut touched = BTreeSet::new();
        for &id in ids {
            let msg = match get(&tx, account, id) {
                Ok(m) => m,
                Err(StoreError::NotFound) => continue,
                Err(e) => return Err(e),
            };
            tx.execute(
                "INSERT INTO expunged(account_id, mailbox_id, uid, email_id, thread_id, modseq)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![account, msg.mailbox, msg.uid, id, msg.thread, modseq],
            )?;
            tx.execute("DELETE FROM messages WHERE id = ?1", [id])?;
            touch(&tx, msg.mailbox, modseq)?;
            touched.insert(msg.mailbox);
            out.push((msg.mailbox, msg.uid));
        }
        tx.commit()?;
        drop(db);
        self.notify(Change {
            account,
            mailboxes: touched.into_iter().collect(),
            mailbox_list: false,
            modseq,
        });
        Ok(out)
    }

    /// For QRESYNC (RFC 7162 §3.2.5): the messages of `mailbox` changed
    /// after `modseq`, and the UIDs expunged (or moved away) after it.
    pub fn changes_since(
        &self,
        account: AccountId,
        mailbox: MailboxId,
        modseq: u64,
    ) -> Result<(Vec<Message>, Vec<u32>)> {
        let db = self.db();
        let mut stmt = db.prepare(&format!(
            "SELECT {COLUMNS} FROM messages WHERE account_id = ?1 AND mailbox_id = ?2 AND modseq > ?3 ORDER BY uid"
        ))?;
        let changed = stmt
            .query_map(params![account, mailbox, modseq], row)?
            .collect::<std::result::Result<_, _>>()?;
        let mut stmt = db.prepare(
            "SELECT uid FROM expunged WHERE mailbox_id = ?1 AND modseq > ?2 ORDER BY uid",
        )?;
        let vanished = stmt
            .query_map(params![mailbox, modseq], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        Ok((changed, vanished))
    }

    /// Whether `mailbox` already holds a message with exactly this content
    /// (used to make imports idempotent).
    pub fn contains_blob(
        &self,
        account: AccountId,
        mailbox: MailboxId,
        blob: &BlobId,
    ) -> Result<bool> {
        Ok(self.db().query_row(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE account_id = ?1 AND mailbox_id = ?2 AND blob = ?3)",
            params![account, mailbox, blob.to_string()],
            |r| r.get(0),
        )?)
    }
}
