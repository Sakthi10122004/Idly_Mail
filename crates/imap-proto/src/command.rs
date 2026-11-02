//! IMAP commands (RFC 9051 §6) and the extensions Idly supports: ID
//! (RFC 2971), ENABLE (RFC 5161), IDLE (RFC 2177), UIDPLUS (RFC 4315),
//! MOVE (RFC 6851), CONDSTORE/QRESYNC (RFC 7162), LIST-EXTENDED
//! (RFC 5258), LIST-STATUS (RFC 5819), SPECIAL-USE (RFC 6154), UNSELECT,
//! ESEARCH (RFC 4731), SASL-IR (RFC 4959), STATUS=SIZE (RFC 8438).

use crate::fetch::{FetchAttr, parse_fetch_attrs};
use crate::parse::{Cursor, ParseError, Result, SeqSet, err};
use crate::search::{SearchKey, parse_search_key};

/// A parsed command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub tag: String,
    pub body: CommandBody,
}

/// A system flag or keyword (RFC 9051 §2.3.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Flag {
    Seen,
    Answered,
    Flagged,
    Deleted,
    Draft,
    /// `\Recent` (IMAP4rev1 only; never stored).
    Recent,
    Keyword(String),
}

impl Flag {
    fn parse(c: &mut Cursor<'_>) -> Result<Self> {
        if c.eat(b'\\') {
            let name = c.atom()?;
            return Ok(match name.to_ascii_lowercase().as_str() {
                "seen" => Self::Seen,
                "answered" => Self::Answered,
                "flagged" => Self::Flagged,
                "deleted" => Self::Deleted,
                "draft" => Self::Draft,
                "recent" => Self::Recent,
                // RFC 9051 §9 flag-extension: unknown system flags are an error
                // when storing; treat as keyword-free error.
                _ => return err(format!("unknown flag \\{name}")),
            });
        }
        Ok(Self::Keyword(c.atom()?))
    }

    /// The wire form.
    pub fn as_wire(&self) -> String {
        match self {
            Self::Seen => "\\Seen".into(),
            Self::Answered => "\\Answered".into(),
            Self::Flagged => "\\Flagged".into(),
            Self::Deleted => "\\Deleted".into(),
            Self::Draft => "\\Draft".into(),
            Self::Recent => "\\Recent".into(),
            Self::Keyword(k) => k.clone(),
        }
    }
}

/// STATUS data items (RFC 9051 §6.3.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusItem {
    Messages,
    UidNext,
    UidValidity,
    Unseen,
    Deleted,
    Size,
    Recent,
    HighestModSeq,
}

/// LIST selection options (RFC 5258 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListSelect {
    Subscribed,
    Remote,
    RecursiveMatch,
    SpecialUse,
}

/// LIST return options (RFC 5258 §3.2, RFC 5819, RFC 6154).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListReturn {
    Subscribed,
    Children,
    SpecialUse,
    Status(Vec<StatusItem>),
}

/// SEARCH RETURN options (RFC 4731 §3.1, RFC 9051 §6.4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchReturn {
    Min,
    Max,
    All,
    Count,
    Save,
}

/// QRESYNC parameters of SELECT/EXAMINE (RFC 7162 §3.2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QResync {
    pub uidvalidity: u32,
    pub modseq: u64,
    pub known_uids: Option<SeqSet>,
    pub seq_match: Option<(SeqSet, SeqSet)>,
}

/// How STORE changes flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreMode {
    Replace,
    Add,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandBody {
    Capability,
    Noop,
    Logout,
    /// ID with the client's fields (RFC 2971 §3.1); None for NIL.
    Id(Option<Vec<(String, Option<String>)>>),
    Enable(Vec<String>),
    StartTls,
    /// AUTHENTICATE with an optional SASL-IR initial response (base64, or
    /// `=` for empty, RFC 4959 §3).
    Authenticate {
        mechanism: String,
        initial: Option<Vec<u8>>,
    },
    Login {
        user: Vec<u8>,
        password: Vec<u8>,
    },
    Select {
        mailbox: Vec<u8>,
        read_only: bool,
        condstore: bool,
        qresync: Option<QResync>,
    },
    Create(Vec<u8>),
    Delete(Vec<u8>),
    Rename {
        from: Vec<u8>,
        to: Vec<u8>,
    },
    Subscribe(Vec<u8>),
    Unsubscribe(Vec<u8>),
    List {
        reference: Vec<u8>,
        patterns: Vec<Vec<u8>>,
        select: Vec<ListSelect>,
        returns: Vec<ListReturn>,
        /// LSUB (IMAP4rev1): LIST of subscribed mailboxes, old format.
        lsub: bool,
    },
    Namespace,
    Status {
        mailbox: Vec<u8>,
        items: Vec<StatusItem>,
    },
    Append {
        mailbox: Vec<u8>,
        flags: Vec<Flag>,
        date: Option<i64>,
        message: Vec<u8>,
    },
    Idle,
    Check,
    Close,
    Unselect,
    /// EXPUNGE, or UID EXPUNGE with a UID set (RFC 4315 §2.1).
    Expunge(Option<SeqSet>),
    Search {
        uid: bool,
        returns: Option<Vec<SearchReturn>>,
        key: SearchKey,
    },
    Fetch {
        uid: bool,
        set: SeqSet,
        attrs: Vec<FetchAttr>,
        changed_since: Option<u64>,
        vanished: bool,
    },
    Store {
        uid: bool,
        set: SeqSet,
        mode: StoreMode,
        silent: bool,
        flags: Vec<Flag>,
        unchanged_since: Option<u64>,
    },
    Copy {
        uid: bool,
        set: SeqSet,
        mailbox: Vec<u8>,
    },
    Move {
        uid: bool,
        set: SeqSet,
        mailbox: Vec<u8>,
    },
}

/// A parse failure with the tag, if it could be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandError {
    pub tag: Option<String>,
    pub message: String,
}

/// Parses one framed command (as produced by [`crate::frame::Framer`]).
pub fn parse_command(input: &[u8]) -> std::result::Result<Command, CommandError> {
    let mut c = Cursor::new(input);
    let tag = c.tag().map_err(|e| CommandError {
        tag: None,
        message: e.0,
    })?;
    let body = (|| {
        c.sp()?;
        let body = body(&mut c)?;
        c.end()?;
        Ok::<_, ParseError>(body)
    })()
    .map_err(|e| CommandError {
        tag: Some(tag.clone()),
        message: e.0,
    })?;
    Ok(Command { tag, body })
}

fn body(c: &mut Cursor<'_>) -> Result<CommandBody> {
    let name = c.atom()?.to_ascii_uppercase();
    Ok(match name.as_str() {
        "CAPABILITY" => CommandBody::Capability,
        "NOOP" => CommandBody::Noop,
        "LOGOUT" => CommandBody::Logout,
        "STARTTLS" => CommandBody::StartTls,
        "NAMESPACE" => CommandBody::Namespace,
        "IDLE" => CommandBody::Idle,
        "CHECK" => CommandBody::Check,
        "CLOSE" => CommandBody::Close,
        "UNSELECT" => CommandBody::Unselect,
        "EXPUNGE" => CommandBody::Expunge(None),
        "ID" => {
            c.sp()?;
            if c.eat_word("NIL") {
                CommandBody::Id(None)
            } else {
                let items = c.list(|c| {
                    let k = c.string()?;
                    c.sp()?;
                    let v = c.nstring()?;
                    Ok((
                        String::from_utf8_lossy(&k).into_owned(),
                        v.map(|v| String::from_utf8_lossy(&v).into_owned()),
                    ))
                })?;
                if items.len() > 30 {
                    return err("too many ID fields");
                }
                CommandBody::Id(Some(items))
            }
        }
        "ENABLE" => {
            let mut caps = Vec::new();
            while c.eat(b' ') {
                caps.push(c.atom()?.to_ascii_uppercase());
            }
            if caps.is_empty() {
                return err("ENABLE needs a capability");
            }
            CommandBody::Enable(caps)
        }
        "AUTHENTICATE" => {
            c.sp()?;
            let mechanism = c.atom()?.to_ascii_uppercase();
            let initial = if c.eat(b' ') {
                let ir = c.atom()?;
                Some(ir.into_bytes())
            } else {
                None
            };
            CommandBody::Authenticate { mechanism, initial }
        }
        "LOGIN" => {
            c.sp()?;
            let user = c.astring()?;
            c.sp()?;
            let password = c.astring()?;
            CommandBody::Login { user, password }
        }
        "SELECT" | "EXAMINE" => {
            c.sp()?;
            let mailbox = c.astring()?;
            let (mut condstore, mut qresync) = (false, None);
            if c.eat(b' ') {
                c.list(|c| {
                    if c.eat_word("CONDSTORE") {
                        condstore = true;
                    } else if c.eat_word("QRESYNC") {
                        c.sp()?;
                        qresync = Some(parse_qresync(c)?);
                    } else {
                        return err("unknown SELECT parameter");
                    }
                    Ok(())
                })?;
            }
            CommandBody::Select {
                mailbox,
                read_only: name == "EXAMINE",
                condstore,
                qresync,
            }
        }
        "CREATE" => {
            c.sp()?;
            CommandBody::Create(c.astring()?)
        }
        "DELETE" => {
            c.sp()?;
            CommandBody::Delete(c.astring()?)
        }
        "RENAME" => {
            c.sp()?;
            let from = c.astring()?;
            c.sp()?;
            let to = c.astring()?;
            CommandBody::Rename { from, to }
        }
        "SUBSCRIBE" => {
            c.sp()?;
            CommandBody::Subscribe(c.astring()?)
        }
        "UNSUBSCRIBE" => {
            c.sp()?;
            CommandBody::Unsubscribe(c.astring()?)
        }
        "LIST" | "LSUB" => parse_list(c, name == "LSUB")?,
        "STATUS" => {
            c.sp()?;
            let mailbox = c.astring()?;
            c.sp()?;
            let items = c.list(status_item)?;
            CommandBody::Status { mailbox, items }
        }
        "APPEND" => {
            c.sp()?;
            let mailbox = c.astring()?;
            c.sp()?;
            let mut flags = Vec::new();
            if c.peek() == Some(b'(') {
                flags = c.list(Flag::parse)?;
                c.sp()?;
            }
            let mut date = None;
            if c.peek() == Some(b'"') {
                date = Some(c.date_time()?);
                c.sp()?;
            }
            let message = c.string()?;
            CommandBody::Append {
                mailbox,
                flags,
                date,
                message,
            }
        }
        "UID" => {
            c.sp()?;
            let sub = c.atom()?.to_ascii_uppercase();
            match sub.as_str() {
                "FETCH" => fetch(c, true)?,
                "STORE" => store(c, true)?,
                "COPY" | "MOVE" => copy_move(c, true, sub == "MOVE")?,
                "SEARCH" => search(c, true)?,
                "EXPUNGE" => {
                    c.sp()?;
                    CommandBody::Expunge(Some(c.seq_set()?))
                }
                _ => return err("unknown UID command"),
            }
        }
        "FETCH" => fetch(c, false)?,
        "STORE" => store(c, false)?,
        "COPY" => copy_move(c, false, false)?,
        "MOVE" => copy_move(c, false, true)?,
        "SEARCH" => search(c, false)?,
        _ => return err("unknown command"),
    })
}

fn status_item(c: &mut Cursor<'_>) -> Result<StatusItem> {
    let a = c.atom()?.to_ascii_uppercase();
    Ok(match a.as_str() {
        "MESSAGES" => StatusItem::Messages,
        "UIDNEXT" => StatusItem::UidNext,
        "UIDVALIDITY" => StatusItem::UidValidity,
        "UNSEEN" => StatusItem::Unseen,
        "DELETED" => StatusItem::Deleted,
        "SIZE" => StatusItem::Size,
        "RECENT" => StatusItem::Recent,
        "HIGHESTMODSEQ" => StatusItem::HighestModSeq,
        _ => return err("unknown STATUS item"),
    })
}

fn parse_qresync(c: &mut Cursor<'_>) -> Result<QResync> {
    c.expect(b'(')?;
    let uidvalidity = c.nz_number()?;
    c.sp()?;
    let modseq = c.number()?;
    let mut q = QResync {
        uidvalidity,
        modseq,
        known_uids: None,
        seq_match: None,
    };
    if c.eat(b' ') {
        if c.peek() == Some(b'(') {
            q.seq_match = Some(seq_match(c)?);
        } else {
            q.known_uids = Some(c.seq_set()?);
            if c.eat(b' ') {
                q.seq_match = Some(seq_match(c)?);
            }
        }
    }
    c.expect(b')')?;
    Ok(q)
}

fn seq_match(c: &mut Cursor<'_>) -> Result<(SeqSet, SeqSet)> {
    c.expect(b'(')?;
    let a = c.seq_set()?;
    c.sp()?;
    let b = c.seq_set()?;
    c.expect(b')')?;
    Ok((a, b))
}

fn parse_list(c: &mut Cursor<'_>, lsub: bool) -> Result<CommandBody> {
    c.sp()?;
    let mut select = Vec::new();
    if !lsub && c.peek() == Some(b'(') {
        select = c.list(|c| {
            let a = c.atom()?.to_ascii_uppercase();
            Ok(match a.as_str() {
                "SUBSCRIBED" => ListSelect::Subscribed,
                "REMOTE" => ListSelect::Remote,
                "RECURSIVEMATCH" => ListSelect::RecursiveMatch,
                "SPECIAL-USE" => ListSelect::SpecialUse,
                _ => return err("unknown LIST selection option"),
            })
        })?;
        c.sp()?;
    }
    let reference = c.astring()?;
    c.sp()?;
    let patterns = if !lsub && c.peek() == Some(b'(') {
        c.list(Cursor::list_mailbox)?
    } else {
        vec![c.list_mailbox()?]
    };
    let mut returns = Vec::new();
    if !lsub && c.eat(b' ') {
        if !c.eat_word("RETURN") {
            return err("expected RETURN");
        }
        c.sp()?;
        returns = c.list(|c| {
            let a = c.atom()?.to_ascii_uppercase();
            Ok(match a.as_str() {
                "SUBSCRIBED" => ListReturn::Subscribed,
                "CHILDREN" => ListReturn::Children,
                "SPECIAL-USE" => ListReturn::SpecialUse,
                "STATUS" => {
                    c.sp()?;
                    ListReturn::Status(c.list(status_item)?)
                }
                _ => return err("unknown LIST return option"),
            })
        })?;
    }
    if select.contains(&ListSelect::RecursiveMatch) && select.len() == 1 {
        // RFC 5258 §3.1: RECURSIVEMATCH needs another selection option.
        return err("RECURSIVEMATCH alone");
    }
    Ok(CommandBody::List {
        reference,
        patterns,
        select,
        returns,
        lsub,
    })
}

fn fetch(c: &mut Cursor<'_>, uid: bool) -> Result<CommandBody> {
    c.sp()?;
    let set = c.seq_set()?;
    c.sp()?;
    let attrs = parse_fetch_attrs(c)?;
    let (mut changed_since, mut vanished) = (None, false);
    if c.eat(b' ') {
        c.list(|c| {
            if c.eat_word("CHANGEDSINCE") {
                c.sp()?;
                changed_since = Some(c.number()?);
            } else if c.eat_word("VANISHED") {
                vanished = true;
            } else {
                return err("unknown FETCH modifier");
            }
            Ok(())
        })?;
    }
    // RFC 7162 §3.2.6: VANISHED needs UID FETCH and CHANGEDSINCE.
    if vanished && (!uid || changed_since.is_none()) {
        return err("VANISHED needs UID FETCH with CHANGEDSINCE");
    }
    Ok(CommandBody::Fetch {
        uid,
        set,
        attrs,
        changed_since,
        vanished,
    })
}

fn store(c: &mut Cursor<'_>, uid: bool) -> Result<CommandBody> {
    c.sp()?;
    let set = c.seq_set()?;
    c.sp()?;
    let mut unchanged_since = None;
    if c.peek() == Some(b'(') {
        c.list(|c| {
            if c.eat_word("UNCHANGEDSINCE") {
                c.sp()?;
                unchanged_since = Some(c.number()?);
                Ok(())
            } else {
                err("unknown STORE modifier")
            }
        })?;
        c.sp()?;
    }
    let mode = if c.eat(b'+') {
        StoreMode::Add
    } else if c.eat(b'-') {
        StoreMode::Remove
    } else {
        StoreMode::Replace
    };
    let item = c.atom()?.to_ascii_uppercase();
    let silent = match item.as_str() {
        "FLAGS" => false,
        "FLAGS.SILENT" => true,
        _ => return err("expected FLAGS or FLAGS.SILENT"),
    };
    c.sp()?;
    let flags = if c.peek() == Some(b'(') {
        c.list(Flag::parse)?
    } else {
        let mut f = vec![Flag::parse(c)?];
        while c.eat(b' ') {
            f.push(Flag::parse(c)?);
        }
        f
    };
    Ok(CommandBody::Store {
        uid,
        set,
        mode,
        silent,
        flags,
        unchanged_since,
    })
}

fn copy_move(c: &mut Cursor<'_>, uid: bool, is_move: bool) -> Result<CommandBody> {
    c.sp()?;
    let set = c.seq_set()?;
    c.sp()?;
    let mailbox = c.astring()?;
    Ok(if is_move {
        CommandBody::Move { uid, set, mailbox }
    } else {
        CommandBody::Copy { uid, set, mailbox }
    })
}

fn search(c: &mut Cursor<'_>, uid: bool) -> Result<CommandBody> {
    c.sp()?;
    let mut returns = None;
    if c.eat_word("RETURN") {
        c.sp()?;
        returns = Some(c.list(|c| {
            let a = c.atom()?.to_ascii_uppercase();
            Ok(match a.as_str() {
                "MIN" => SearchReturn::Min,
                "MAX" => SearchReturn::Max,
                "ALL" => SearchReturn::All,
                "COUNT" => SearchReturn::Count,
                "SAVE" => SearchReturn::Save,
                _ => return err("unknown SEARCH return option"),
            })
        })?);
        c.sp()?;
    }
    if c.eat_word("CHARSET") {
        c.sp()?;
        let cs = c.astring_utf8()?;
        // RFC 9051 §6.4.4: US-ASCII and UTF-8 must be supported.
        if !cs.eq_ignore_ascii_case("UTF-8") && !cs.eq_ignore_ascii_case("US-ASCII") {
            return err("[BADCHARSET (UTF-8 US-ASCII)] unsupported charset");
        }
        c.sp()?;
    }
    let mut keys = vec![parse_search_key(c, 0)?];
    while c.eat(b' ') {
        keys.push(parse_search_key(c, 0)?);
        if keys.len() > 1000 {
            return err("search too long");
        }
    }
    let key = if keys.len() == 1 {
        keys.pop().unwrap_or(SearchKey::All)
    } else {
        SearchKey::And(keys)
    };
    Ok(CommandBody::Search { uid, returns, key })
}
