//! SEARCH keys (RFC 9051 §6.4.4), plus MODSEQ (RFC 7162 §3.1.5) and
//! OLDER/YOUNGER (RFC 5032).

use crate::parse::{Cursor, Result, SeqSet, err};

/// Deepest nesting of parentheses, NOT and OR.
const MAX_DEPTH: usize = 50;

/// A search criterion. Dates are days since 1970-01-01.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchKey {
    All,
    And(Vec<SearchKey>),
    Or(Box<SearchKey>, Box<SearchKey>),
    Not(Box<SearchKey>),
    SeqSet(SeqSet),
    Uid(SeqSet),
    /// A system flag (by name, upper-case) set or not.
    Flag { name: &'static str, set: bool },
    Keyword { keyword: String, set: bool },
    /// IMAP4rev1 NEW (RECENT UNSEEN) and RECENT/OLD: no message is
    /// \Recent in Idly, so these match nothing / everything.
    Recent(bool),
    Before(i64),
    On(i64),
    Since(i64),
    SentBefore(i64),
    SentOn(i64),
    SentSince(i64),
    Larger(u64),
    Smaller(u64),
    /// HEADER field string; `field` as given.
    Header { field: String, value: String },
    Bcc(String),
    Body(String),
    Cc(String),
    From(String),
    Subject(String),
    Text(String),
    To(String),
    ModSeq(u64),
    /// Seconds: arrived more than / less than this long ago (RFC 5032).
    Older(u64),
    Younger(u64),
}

fn text(c: &mut Cursor<'_>) -> Result<String> {
    c.sp()?;
    Ok(String::from_utf8_lossy(&c.astring()?).into_owned())
}

fn date(c: &mut Cursor<'_>) -> Result<i64> {
    c.sp()?;
    c.date()
}

pub(crate) fn parse_search_key(c: &mut Cursor<'_>, depth: usize) -> Result<SearchKey> {
    if depth > MAX_DEPTH {
        return err("search nested too deeply");
    }
    if c.peek() == Some(b'(') {
        let keys = c.list(|c| parse_search_key(c, depth + 1))?;
        if keys.is_empty() {
            return err("empty search group");
        }
        return Ok(SearchKey::And(keys));
    }
    if matches!(c.peek(), Some(b'0'..=b'9' | b'*' | b'$')) {
        return Ok(SearchKey::SeqSet(c.seq_set()?));
    }
    let word = c.atom()?.to_ascii_uppercase();
    let flag = |name: &'static str, set: bool| SearchKey::Flag { name, set };
    Ok(match word.as_str() {
        "ALL" => SearchKey::All,
        "ANSWERED" => flag("ANSWERED", true),
        "DELETED" => flag("DELETED", true),
        "DRAFT" => flag("DRAFT", true),
        "FLAGGED" => flag("FLAGGED", true),
        "SEEN" => flag("SEEN", true),
        "UNANSWERED" => flag("ANSWERED", false),
        "UNDELETED" => flag("DELETED", false),
        "UNDRAFT" => flag("DRAFT", false),
        "UNFLAGGED" => flag("FLAGGED", false),
        "UNSEEN" => flag("SEEN", false),
        "NEW" | "RECENT" => SearchKey::Recent(true),
        "OLD" => SearchKey::Recent(false),
        "KEYWORD" | "UNKEYWORD" => {
            c.sp()?;
            SearchKey::Keyword {
                keyword: c.atom()?,
                set: word == "KEYWORD",
            }
        }
        "BEFORE" => SearchKey::Before(date(c)?),
        "ON" => SearchKey::On(date(c)?),
        "SINCE" => SearchKey::Since(date(c)?),
        "SENTBEFORE" => SearchKey::SentBefore(date(c)?),
        "SENTON" => SearchKey::SentOn(date(c)?),
        "SENTSINCE" => SearchKey::SentSince(date(c)?),
        "LARGER" => {
            c.sp()?;
            SearchKey::Larger(c.number()?)
        }
        "SMALLER" => {
            c.sp()?;
            SearchKey::Smaller(c.number()?)
        }
        "OLDER" | "YOUNGER" => {
            c.sp()?;
            let n = c.number()?;
            if word == "OLDER" {
                SearchKey::Older(n)
            } else {
                SearchKey::Younger(n)
            }
        }
        "HEADER" => {
            c.sp()?;
            let field = String::from_utf8_lossy(&c.astring()?).into_owned();
            SearchKey::Header {
                field,
                value: text(c)?,
            }
        }
        "BCC" => SearchKey::Bcc(text(c)?),
        "BODY" => SearchKey::Body(text(c)?),
        "CC" => SearchKey::Cc(text(c)?),
        "FROM" => SearchKey::From(text(c)?),
        "SUBJECT" => SearchKey::Subject(text(c)?),
        "TEXT" => SearchKey::Text(text(c)?),
        "TO" => SearchKey::To(text(c)?),
        "UID" => {
            c.sp()?;
            SearchKey::Uid(c.seq_set()?)
        }
        "NOT" => {
            c.sp()?;
            SearchKey::Not(Box::new(parse_search_key(c, depth + 1)?))
        }
        "OR" => {
            c.sp()?;
            let a = parse_search_key(c, depth + 1)?;
            c.sp()?;
            let b = parse_search_key(c, depth + 1)?;
            SearchKey::Or(Box::new(a), Box::new(b))
        }
        "MODSEQ" => {
            c.sp()?;
            // RFC 7162 §3.1.5: optional entry-name and entry-type-req.
            if c.peek() == Some(b'"') {
                let _ = c.astring()?;
                c.sp()?;
                let _ = c.atom()?;
                c.sp()?;
            }
            SearchKey::ModSeq(c.number()?)
        }
        _ => return err(format!("unknown search key {word}")),
    })
}
