use crate::*;

fn p(s: &str) -> CommandBody {
    let input = format!("{s}\r\n");
    match parse_command(input.as_bytes()) {
        Ok(c) => {
            assert_eq!(c.tag, "a1");
            c.body
        }
        Err(e) => panic!("{s:?}: {e:?}"),
    }
}

fn bad(s: &str) -> CommandError {
    parse_command(format!("{s}\r\n").as_bytes()).unwrap_err()
}

#[test]
fn simple_commands() {
    assert_eq!(p("a1 capability"), CommandBody::Capability);
    assert_eq!(p("a1 NOOP"), CommandBody::Noop);
    assert_eq!(p("a1 IDLE"), CommandBody::Idle);
    assert_eq!(p("a1 UNSELECT"), CommandBody::Unselect);
    assert_eq!(
        p("a1 ENABLE QRESYNC utf8=accept"),
        CommandBody::Enable(vec!["QRESYNC".into(), "UTF8=ACCEPT".into()])
    );
    assert_eq!(
        p("a1 ID (\"name\" \"Thunderbird\" \"version\" NIL)"),
        CommandBody::Id(Some(vec![
            ("name".into(), Some("Thunderbird".into())),
            ("version".into(), None)
        ]))
    );
}

#[test]
fn login_and_authenticate() {
    assert_eq!(
        p("a1 LOGIN alice@example.org {6}\r\nse\"cr3"),
        CommandBody::Login {
            user: b"alice@example.org".to_vec(),
            password: b"se\"cr3".to_vec()
        }
    );
    assert_eq!(
        p("a1 AUTHENTICATE plain AGFsaWNlAHB3"),
        CommandBody::Authenticate {
            mechanism: "PLAIN".into(),
            initial: Some(b"AGFsaWNlAHB3".to_vec())
        }
    );
    assert_eq!(
        p("a1 AUTHENTICATE PLAIN"),
        CommandBody::Authenticate {
            mechanism: "PLAIN".into(),
            initial: None
        }
    );
}

#[test]
fn select_with_qresync() {
    match p("a1 SELECT INBOX (QRESYNC (67890007 20050715194045000 41,43:211,214:541))") {
        CommandBody::Select {
            mailbox,
            read_only,
            qresync: Some(q),
            ..
        } => {
            assert_eq!(mailbox, b"INBOX");
            assert!(!read_only);
            assert_eq!((q.uidvalidity, q.modseq), (67_890_007, 20_050_715_194_045_000));
            assert!(q.known_uids.unwrap().contains(300, 1000));
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        p("a1 EXAMINE \"Sent Items\" (CONDSTORE)"),
        CommandBody::Select { read_only: true, condstore: true, .. }
    ));
}

#[test]
fn list_forms() {
    match p("a1 LIST \"\" *") {
        CommandBody::List { patterns, lsub, .. } => {
            assert_eq!(patterns, [b"*".to_vec()]);
            assert!(!lsub);
        }
        other => panic!("{other:?}"),
    }
    match p("a1 LIST (SUBSCRIBED RECURSIVEMATCH) \"\" (INBOX* %/x) RETURN (CHILDREN STATUS (MESSAGES UNSEEN))") {
        CommandBody::List {
            select,
            patterns,
            returns,
            ..
        } => {
            assert_eq!(select, [ListSelect::Subscribed, ListSelect::RecursiveMatch]);
            assert_eq!(patterns.len(), 2);
            assert_eq!(
                returns,
                [
                    ListReturn::Children,
                    ListReturn::Status(vec![StatusItem::Messages, StatusItem::Unseen])
                ]
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(p("a1 LSUB \"\" %"), CommandBody::List { lsub: true, .. }));
    assert!(bad("a1 LIST (RECURSIVEMATCH) \"\" *").message.contains("RECURSIVEMATCH"));
}

#[test]
fn append() {
    match p("a1 APPEND saved-messages (\\Seen $Forwarded) \"7-Feb-1994 21:52:25 -0800\" {5+}\r\nhello") {
        CommandBody::Append {
            mailbox,
            flags,
            date,
            message,
        } => {
            assert_eq!(mailbox, b"saved-messages");
            assert_eq!(flags, [Flag::Seen, Flag::Keyword("$Forwarded".into())]);
            assert_eq!(date, Some(760_686_745));
            assert_eq!(message, b"hello");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        p("a1 APPEND INBOX ~{2}\r\n\0x"),
        CommandBody::Append { message, .. } if message == b"\0x"
    ));
}

#[test]
fn fetch_items() {
    match p("a1 UID FETCH 1:* (FLAGS BODY.PEEK[1.2.HEADER.FIELDS (From Subject)]<0.100> BINARY[2] RFC822.SIZE BODYSTRUCTURE MODSEQ) (CHANGEDSINCE 12345 VANISHED)") {
        CommandBody::Fetch {
            uid: true,
            attrs,
            changed_since: Some(12345),
            vanished: true,
            ..
        } => {
            assert_eq!(attrs.len(), 6);
            assert_eq!(
                attrs[1],
                FetchAttr::BodySection {
                    peek: true,
                    section: Section {
                        part: vec![1, 2],
                        text: Some(SectionText::HeaderFields {
                            not: false,
                            fields: vec!["From".into(), "Subject".into()]
                        })
                    },
                    partial: Some((0, 100))
                }
            );
            assert_eq!(
                attrs[2],
                FetchAttr::Binary {
                    peek: false,
                    part: vec![2],
                    partial: None
                }
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(p("a1 FETCH 1 ALL"), CommandBody::Fetch { attrs, .. } if attrs.len() == 4));
    assert!(matches!(p("a1 FETCH 2 body[]"), CommandBody::Fetch { attrs, .. } if matches!(attrs[0], FetchAttr::BodySection { peek: false, .. })));
    assert!(matches!(p("a1 FETCH 2 BODY"), CommandBody::Fetch { attrs, .. } if attrs[0] == FetchAttr::Body));
    assert!(bad("a1 FETCH 1 (CHANGEDSINCE 1)").message.contains("FETCH"));
    assert!(bad("a1 FETCH 1:* FLAGS (VANISHED CHANGEDSINCE 1)").message.contains("VANISHED"));
    assert!(bad("a1 FETCH 1 BODY[MIME]").message.contains("section"));
}

#[test]
fn store_forms() {
    assert_eq!(
        p("a1 UID STORE 1:3 (UNCHANGEDSINCE 320162338) +FLAGS.SILENT (\\Deleted)"),
        CommandBody::Store {
            uid: true,
            set: SeqSet::Ranges(vec![(SeqNum::Value(1), SeqNum::Value(3))]),
            mode: StoreMode::Add,
            silent: true,
            flags: vec![Flag::Deleted],
            unchanged_since: Some(320_162_338)
        }
    );
    assert!(matches!(
        p("a1 STORE 2 -FLAGS \\Seen $Junk"),
        CommandBody::Store { mode: StoreMode::Remove, flags, .. } if flags.len() == 2
    ));
    assert!(bad("a1 STORE 1 FLAGS (\\Bogus)").message.contains("Bogus"));
}

#[test]
fn search_keys() {
    match p("a1 UID SEARCH RETURN (MIN COUNT) CHARSET UTF-8 OR FROM \"Smith\" (SINCE 1-Feb-1994 NOT SEEN) 1:5 HEADER X-Spam yes") {
        CommandBody::Search {
            uid: true,
            returns: Some(r),
            key: SearchKey::And(keys),
        } => {
            assert_eq!(r, [SearchReturn::Min, SearchReturn::Count]);
            assert_eq!(keys.len(), 3);
            assert!(matches!(&keys[0], SearchKey::Or(a, _) if **a == SearchKey::From("Smith".into())));
            assert!(matches!(&keys[2], SearchKey::Header { field, value } if field == "X-Spam" && value == "yes"));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        p("a1 SEARCH MODSEQ \"/flags/\\\\draft\" all 620162338"),
        CommandBody::Search {
            uid: false,
            returns: None,
            key: SearchKey::ModSeq(620_162_338)
        }
    );
    assert!(bad("a1 SEARCH CHARSET KOI8-R TEXT x").message.contains("BADCHARSET"));
    let deep = format!("a1 SEARCH {}ALL{}", "(".repeat(100), ")".repeat(100));
    assert!(bad(&deep).message.contains("deeply"));
}

#[test]
fn errors_carry_the_tag() {
    let e = bad("t9 FROB");
    assert_eq!(e.tag.as_deref(), Some("t9"));
    assert_eq!(bad("+x NOOP").tag, None);
    assert!(bad("a1 NOOP extra").message.contains("end"));
    assert!(bad("a1 COPY 1:2").tag.is_some());
}

#[test]
fn copy_move_expunge() {
    assert!(matches!(p("a1 UID MOVE 4:6 Trash"), CommandBody::Move { uid: true, .. }));
    assert!(matches!(p("a1 COPY 1 \"Old Mail\""), CommandBody::Copy { uid: false, .. }));
    assert!(matches!(p("a1 UID EXPUNGE 3000:3002"), CommandBody::Expunge(Some(_))));
}
