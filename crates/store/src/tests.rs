use std::sync::Arc;
use std::time::Duration;

use super::*;

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let blobs = Arc::new(blob::Disk::open(&dir.path().join("blobs")).unwrap());
    let s = Store::open(&dir.path().join("db"), blobs).unwrap();
    (dir, s)
}

fn msg(subject: &str, extra: &str) -> Vec<u8> {
    format!("From: a@x.test\r\nSubject: {subject}\r\n{extra}\r\nbody {subject}\r\n").into_bytes()
}

fn new(raw: &[u8]) -> NewMessage<'_> {
    NewMessage {
        raw,
        flags: 0,
        keywords: vec![],
        received: 1_800_000_000,
    }
}

#[test]
fn accounts_get_default_mailboxes() {
    let (_d, s) = store();
    let a = s.ensure_account("Alice@Example.ORG").unwrap();
    assert_eq!(s.ensure_account("alice@example.org").unwrap(), a);
    let names: Vec<_> = s
        .mailboxes(a)
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    assert_eq!(
        names,
        ["Archive", "Drafts", "INBOX", "Junk", "Sent", "Trash"]
    );
    let inbox = s.mailbox_by_role(a, Role::Inbox).unwrap();
    assert_eq!(s.mailbox_by_name(a, "inbox").unwrap().id, inbox.id);
    assert_eq!(inbox.uidnext, 1);
    // UIDVALIDITY values never repeat within an account.
    let mut v: Vec<_> = s
        .mailboxes(a)
        .unwrap()
        .iter()
        .map(|m| m.uidvalidity)
        .collect();
    v.dedup();
    assert_eq!(v.len(), 6);
}

#[test]
fn append_assigns_uids_and_modseqs() {
    let (_d, s) = store();
    let a = s.ensure_account("a@x.test").unwrap();
    let inbox = s.mailbox_by_role(a, Role::Inbox).unwrap().id;
    let m1 = s.append(a, inbox, new(&msg("one", ""))).unwrap();
    let m2 = s.append(a, inbox, new(&msg("two", ""))).unwrap();
    assert_eq!((m1.uid, m2.uid), (1, 2));
    assert!(m2.modseq > m1.modseq);
    let mb = s.mailbox(a, inbox).unwrap();
    assert_eq!((mb.uidnext, mb.messages, mb.unseen), (3, 2, 2));
    assert_eq!(mb.highest_modseq, m2.modseq);
    assert_eq!(s.read(a, m1.id).unwrap(), msg("one", ""));
    assert_eq!(s.usage(a).unwrap().0, 2);
    // Identical content is stored once.
    s.append(a, inbox, new(&msg("one", ""))).unwrap();
    assert_eq!(s.blobs().list().unwrap().len(), 2);
}

#[test]
fn flags_and_unchangedsince() {
    let (_d, s) = store();
    let a = s.ensure_account("a@x.test").unwrap();
    let inbox = s.mailbox_by_role(a, Role::Inbox).unwrap().id;
    let m = s.append(a, inbox, new(&msg("one", ""))).unwrap();
    let r = s
        .store_flags(
            a,
            &[m.id],
            FlagOp::Add,
            flags::SEEN,
            &["$Forwarded".into()],
            None,
        )
        .unwrap();
    let after = &r.changed[0];
    assert_eq!(after.flags, flags::SEEN);
    assert_eq!(after.keywords, ["$forwarded"]);
    assert!(after.modseq > m.modseq);
    // No change: no new MODSEQ.
    let same = s
        .store_flags(a, &[m.id], FlagOp::Add, flags::SEEN, &[], None)
        .unwrap();
    assert!(same.changed.is_empty());
    // RFC 7162 §3.1.3: a stale UNCHANGEDSINCE is refused per message.
    let stale = s
        .store_flags(a, &[m.id], FlagOp::Replace, 0, &[], Some(m.modseq))
        .unwrap();
    assert_eq!(stale.modified, [m.id]);
    assert!(stale.changed.is_empty());
    assert!(
        s.store_flags(a, &[m.id], FlagOp::Add, 0, &["bad\\kw".into()], None)
            .is_err()
    );
    assert_eq!(s.mailbox(a, inbox).unwrap().unseen, 0);
}

#[test]
fn copy_move_expunge_and_qresync_changes() {
    let (_d, s) = store();
    let a = s.ensure_account("a@x.test").unwrap();
    let inbox = s.mailbox_by_role(a, Role::Inbox).unwrap().id;
    let trash = s.mailbox_by_role(a, Role::Trash).unwrap().id;
    let m1 = s.append(a, inbox, new(&msg("one", ""))).unwrap();
    let m2 = s.append(a, inbox, new(&msg("two", ""))).unwrap();
    let since = s.mailbox(a, inbox).unwrap().highest_modseq;

    let copies = s.copy_messages(a, &[m1.id], trash).unwrap();
    assert_eq!(copies[0].1.uid, 1);
    assert_eq!(copies[0].1.blob, m1.blob);
    let moved = s.move_messages(a, &[m2.id], trash).unwrap();
    assert_eq!((moved[0].0, moved[0].1, moved[0].2.uid), (inbox, 2, 2));
    assert_eq!(moved[0].2.id, m2.id, "a move keeps the email id");
    let gone = s.expunge(a, &[m1.id]).unwrap();
    assert_eq!(gone, [(inbox, 1)]);

    let (changed, vanished) = s.changes_since(a, inbox, since).unwrap();
    assert!(changed.is_empty());
    assert_eq!(vanished, [1, 2]);
    assert_eq!(s.messages(a, inbox).unwrap().len(), 0);
    assert_eq!(s.messages(a, trash).unwrap().len(), 2);
    assert!(s.mailbox(a, inbox).unwrap().highest_modseq > since);
}

#[test]
fn threads_follow_references() {
    let (_d, s) = store();
    let a = s.ensure_account("a@x.test").unwrap();
    let inbox = s.mailbox_by_role(a, Role::Inbox).unwrap().id;
    // The reply arrives before its parent; the parent still joins.
    let reply = s
        .append(
            a,
            inbox,
            new(&msg("Re: x", "Message-ID: <r@x>\r\nIn-Reply-To: <p@x>\r\n")),
        )
        .unwrap();
    let parent = s
        .append(a, inbox, new(&msg("x", "Message-ID: <p@x>\r\n")))
        .unwrap();
    let other = s
        .append(a, inbox, new(&msg("y", "Message-ID: <o@x>\r\n")))
        .unwrap();
    assert_eq!(reply.thread, parent.thread);
    assert_ne!(other.thread, parent.thread);
}

#[test]
fn quota_is_enforced() {
    let (_d, s) = store();
    let a = s.ensure_account("a@x.test").unwrap();
    let inbox = s.mailbox_by_role(a, Role::Inbox).unwrap().id;
    let raw = msg("one", "");
    s.set_quota(a, Some(raw.len() as u64 + 10)).unwrap();
    let m = s.append(a, inbox, new(&raw)).unwrap();
    assert!(matches!(
        s.append(a, inbox, new(&msg("two", ""))),
        Err(StoreError::OverQuota)
    ));
    let trash = s.mailbox_by_role(a, Role::Trash).unwrap().id;
    assert!(matches!(
        s.copy_messages(a, &[m.id], trash),
        Err(StoreError::OverQuota)
    ));
}

#[test]
fn mailbox_create_rename_delete() {
    let (_d, s) = store();
    let a = s.ensure_account("a@x.test").unwrap();
    let id = s.create_mailbox(a, "Work/2026/Q4").unwrap();
    assert!(s.mailbox_by_name(a, "Work").is_ok(), "parents created");
    assert!(matches!(
        s.create_mailbox(a, "Work/2026/Q4"),
        Err(StoreError::AlreadyExists)
    ));
    for bad in ["", "a//b", "/a", "a/", "x\u{1}"] {
        assert!(
            matches!(s.create_mailbox(a, bad), Err(StoreError::Invalid(_))),
            "{bad:?}"
        );
    }
    let work = s.mailbox_by_name(a, "Work").unwrap().id;
    s.rename_mailbox(a, work, "Jobs/Old").unwrap();
    assert_eq!(s.mailbox(a, id).unwrap().name, "Jobs/Old/2026/Q4");
    assert!(s.mailbox_by_name(a, "Jobs").is_ok());
    assert!(s.rename_mailbox(a, work, "Jobs/Old/2026/x").is_err());

    // Renaming INBOX moves its messages out and keeps INBOX.
    let inbox = s.mailbox_by_role(a, Role::Inbox).unwrap().id;
    s.append(a, inbox, new(&msg("one", ""))).unwrap();
    s.rename_mailbox(a, inbox, "Old Inbox").unwrap();
    assert_eq!(s.mailbox(a, inbox).unwrap().messages, 0);
    assert_eq!(s.mailbox_by_name(a, "Old Inbox").unwrap().messages, 1);

    assert!(s.delete_mailbox(a, inbox).is_err());
    let old = s.mailbox_by_name(a, "Old Inbox").unwrap().id;
    s.delete_mailbox(a, old).unwrap();
    assert!(s.mailbox_by_name(a, "Old Inbox").is_err());
    // The name can be used again, with a new UIDVALIDITY.
    let again = s.create_mailbox(a, "Old Inbox").unwrap();
    assert_ne!(again, old);
}

#[test]
fn garbage_collection_keeps_shared_blobs() {
    let (_d, s) = store();
    let a = s.ensure_account("a@x.test").unwrap();
    let inbox = s.mailbox_by_role(a, Role::Inbox).unwrap().id;
    let trash = s.mailbox_by_role(a, Role::Trash).unwrap().id;
    let m = s.append(a, inbox, new(&msg("one", ""))).unwrap();
    s.copy_messages(a, &[m.id], trash).unwrap();
    s.expunge(a, &[m.id]).unwrap();
    assert_eq!(
        s.collect_garbage(Duration::ZERO).unwrap(),
        0,
        "the copy still uses it"
    );
    let copy = s.messages(a, trash).unwrap()[0].id;
    s.expunge(a, &[copy]).unwrap();
    // Young blobs survive (a delivery may be in progress).
    assert_eq!(s.collect_garbage(Duration::from_secs(3600)).unwrap(), 0);
    assert_eq!(s.collect_garbage(Duration::ZERO).unwrap(), 1);
}

#[test]
fn changes_are_broadcast() {
    let (_d, s) = store();
    let a = s.ensure_account("a@x.test").unwrap();
    let mut rx = s.subscribe(a);
    let inbox = s.mailbox_by_role(a, Role::Inbox).unwrap().id;
    let m = s.append(a, inbox, new(&msg("one", ""))).unwrap();
    let c = rx.try_recv().unwrap();
    assert_eq!((c.mailboxes, c.modseq), (vec![inbox], m.modseq));
    assert_eq!(s.modseq(a).unwrap(), m.modseq);
}
