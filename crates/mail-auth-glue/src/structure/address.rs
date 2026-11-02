//! Address lists with display names and groups (RFC 5322 §3.4), as IMAP
//! ENVELOPE (RFC 9051 §7.5.2) and JMAP (RFC 8621 §4.1.2.3) present them.
//! Lenient: whatever can't be parsed is skipped, never an error.

use super::words;

/// One entry of an address list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Mailbox(Mailbox),
    /// `name: members;`
    Group { name: String, members: Vec<Mailbox> },
}

/// A mailbox. `name` is as written (encoded-words not decoded, quotes
/// removed); [`Mailbox::display_name`] decodes it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mailbox {
    pub name: Option<String>,
    pub local: String,
    pub domain: Option<String>,
}

impl Mailbox {
    /// The display name with RFC 2047 encoded-words decoded.
    pub fn display_name(&self) -> Option<String> {
        self.name
            .as_ref()
            .map(|n| words::decode(n.as_bytes()))
            .filter(|n| !n.is_empty())
    }

    /// `local@domain`, or just `local`.
    pub fn email(&self) -> String {
        match &self.domain {
            Some(d) => format!("{}@{d}", self.local),
            None => self.local.clone(),
        }
    }
}

/// Lexical tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// An atom or dot-atom.
    Atom(String),
    /// A quoted-string's content.
    Quoted(String),
    /// A comment's content.
    Comment(String),
    /// A domain literal, brackets included.
    Literal(String),
    Special(char),
}

/// Most tokens per field; longer lists are cut (memory safety).
const MAX_TOKENS: usize = 10_000;

fn tokenize(v: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut chars = v.chars().peekable();
    while let Some(&c) = chars.peek() {
        if out.len() >= MAX_TOKENS {
            break;
        }
        match c {
            ' ' | '\t' | '\r' | '\n' => {
                chars.next();
            }
            '"' => {
                chars.next();
                let mut s = String::new();
                while let Some(c) = chars.next() {
                    match c {
                        '"' => break,
                        '\\' => {
                            if let Some(n) = chars.next() {
                                s.push(n);
                            }
                        }
                        '\r' | '\n' => {}
                        _ => s.push(c),
                    }
                }
                out.push(Tok::Quoted(s));
            }
            '(' => {
                chars.next();
                let mut depth = 1u32;
                let mut s = String::new();
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => {
                            if let Some(n) = chars.next() {
                                s.push(n);
                            }
                        }
                        '(' => {
                            depth = depth.saturating_add(1);
                            s.push(c);
                        }
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                            s.push(c);
                        }
                        _ => s.push(c),
                    }
                }
                out.push(Tok::Comment(s.trim().to_owned()));
            }
            '[' => {
                let mut s = String::new();
                for c in chars.by_ref() {
                    s.push(c);
                    if c == ']' {
                        break;
                    }
                }
                out.push(Tok::Literal(s));
            }
            '<' | '>' | '@' | ',' | ';' | ':' | ']' => {
                chars.next();
                out.push(Tok::Special(c));
            }
            _ => {
                let mut s = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() || "\"(<>@,;:[]".contains(c) {
                        break;
                    }
                    s.push(c);
                    chars.next();
                }
                out.push(Tok::Atom(s));
            }
        }
    }
    out
}

/// Parses an address-list field value.
pub fn parse_list(raw: &[u8]) -> Vec<Address> {
    let text = String::from_utf8_lossy(raw);
    let toks = tokenize(&text);
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < toks.len() {
        // A group: display-name ":" ... ";"
        let colon = toks
            .get(i..)
            .unwrap_or_default()
            .iter()
            .position(|t| matches!(t, Tok::Special(':' | ',' | '<' | '@' | ';')));
        if let Some(off) = colon
            && toks.get(i + off) == Some(&Tok::Special(':'))
        {
            let name = phrase(toks.get(i..i + off).unwrap_or_default());
            i += off + 1;
            let mut members = Vec::new();
            loop {
                match toks.get(i) {
                    None => break,
                    Some(Tok::Special(';')) => {
                        i += 1;
                        break;
                    }
                    Some(Tok::Special(',')) => i += 1,
                    _ => {
                        let (m, next) = mailbox(&toks, i, true);
                        members.extend(m);
                        i = next.max(i + 1);
                    }
                }
            }
            out.push(Address::Group {
                name: name.unwrap_or_default(),
                members,
            });
            continue;
        }
        if toks.get(i) == Some(&Tok::Special(',')) {
            i += 1;
            continue;
        }
        let (m, next) = mailbox(&toks, i, false);
        if let Some(m) = m {
            out.push(Address::Mailbox(m));
        }
        i = next.max(i + 1);
    }
    out
}

/// Every mailbox, with group members flattened.
pub fn mailboxes(list: &[Address]) -> Vec<Mailbox> {
    list.iter()
        .flat_map(|a| match a {
            Address::Mailbox(m) => vec![m.clone()],
            Address::Group { members, .. } => members.clone(),
        })
        .collect()
}

/// Words joined by single spaces (quoted-strings included).
fn phrase(toks: &[Tok]) -> Option<String> {
    let words: Vec<&str> = toks
        .iter()
        .filter_map(|t| match t {
            Tok::Atom(s) | Tok::Quoted(s) => Some(s.as_str()),
            Tok::Special('.') => Some("."),
            _ => None,
        })
        .collect();
    (!words.is_empty()).then(|| words.join(" "))
}

/// One mailbox starting at `i`; returns it and the index after it. Stops
/// at `,` (and at `;` inside a group).
fn mailbox(toks: &[Tok], start: usize, in_group: bool) -> (Option<Mailbox>, usize) {
    let mut end = start;
    let mut in_angle = false;
    while let Some(t) = toks.get(end) {
        match t {
            Tok::Special('<') => in_angle = true,
            Tok::Special('>') => in_angle = false,
            Tok::Special(',') if !in_angle => break,
            Tok::Special(';') if in_group && !in_angle => break,
            _ => {}
        }
        end += 1;
    }
    let slice = toks.get(start..end).unwrap_or_default();
    let comment = slice.iter().find_map(|t| match t {
        Tok::Comment(c) if !c.is_empty() => Some(c.clone()),
        _ => None,
    });
    let m = if let Some(open) = slice.iter().position(|t| *t == Tok::Special('<')) {
        // name-addr: [display-name] "<" [route] addr-spec ">"
        let close = slice
            .iter()
            .rposition(|t| *t == Tok::Special('>'))
            .filter(|c| *c > open)
            .unwrap_or(slice.len());
        let inner = slice.get(open + 1..close).unwrap_or_default();
        // RFC 5322 §4.4 obs-route: drop "@a,@b:" before the address.
        let inner = match inner.iter().position(|t| *t == Tok::Special(':')) {
            Some(p) => inner.get(p + 1..).unwrap_or_default(),
            None => inner,
        };
        addr_spec(inner).map(|(local, domain)| Mailbox {
            name: phrase(slice.get(..open).unwrap_or_default()).or(comment),
            local,
            domain,
        })
    } else {
        addr_spec(slice).map(|(local, domain)| Mailbox {
            name: comment,
            local,
            domain,
        })
    };
    (m, end)
}

/// local-part ["@" domain]; None if there is no local part.
fn addr_spec(toks: &[Tok]) -> Option<(String, Option<String>)> {
    let toks: Vec<&Tok> = toks.iter().filter(|t| !matches!(t, Tok::Comment(_))).collect();
    let at = toks.iter().rposition(|t| **t == Tok::Special('@'));
    let (local_toks, domain_toks) = match at {
        Some(a) => (toks.get(..a).unwrap_or_default(), toks.get(a + 1..)),
        None => (toks.as_slice(), None),
    };
    let local: String = local_toks
        .iter()
        .filter_map(|t| match t {
            Tok::Atom(s) | Tok::Quoted(s) => Some(s.as_str()),
            _ => None,
        })
        .collect();
    if local.is_empty() {
        return None;
    }
    let domain: Option<String> = domain_toks
        .map(|d| {
            d.iter()
                .filter_map(|t| match t {
                    Tok::Atom(s) | Tok::Literal(s) => Some(s.as_str()),
                    _ => None,
                })
                .collect::<String>()
        })
        .filter(|d| !d.is_empty());
    Some((local, domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mb(name: Option<&str>, local: &str, domain: &str) -> Address {
        Address::Mailbox(Mailbox {
            name: name.map(String::from),
            local: local.into(),
            domain: Some(domain.into()),
        })
    }

    #[test]
    fn common_forms() {
        let list = parse_list(
            b"\"Doe, John\" <john@example.com>, jane@example.org (Jane Roe),\r\n Pete <pete(his account)@silly.test>, =?UTF-8?Q?Ren=C3=A9?= <r@x.test>",
        );
        assert_eq!(
            list,
            [
                mb(Some("Doe, John"), "john", "example.com"),
                mb(Some("Jane Roe"), "jane", "example.org"),
                mb(Some("Pete"), "pete", "silly.test"),
                mb(Some("=?UTF-8?Q?Ren=C3=A9?="), "r", "x.test"),
            ]
        );
        let Address::Mailbox(rene) = &list[3] else {
            panic!()
        };
        assert_eq!(rene.display_name().as_deref(), Some("Ren\u{e9}"));
        assert_eq!(rene.email(), "r@x.test");
    }

    #[test]
    fn groups_and_routes() {
        // RFC 5322 Appendix A.1.3.
        let list = parse_list(
            b"A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;, Undisclosed recipients:;, <@route.test:x@y.test>",
        );
        assert_eq!(list.len(), 3);
        let Address::Group { name, members } = &list[0] else {
            panic!("{list:?}")
        };
        assert_eq!(name, "A Group");
        assert_eq!(members.len(), 3);
        assert_eq!(members[1].email(), "joe@where.test");
        assert_eq!(
            list[1],
            Address::Group {
                name: "Undisclosed recipients".into(),
                members: vec![]
            }
        );
        assert_eq!(list[2], mb(None, "x", "y.test"));
        assert_eq!(mailboxes(&list).len(), 4);
    }

    #[test]
    fn garbage_never_panics() {
        for v in [&b""[..], b"<", b"<>", b"@", b"a@", b":;", b"\"", b"(((", b"x <y", b";;,,::", b"[a@b"] {
            let _ = parse_list(v);
        }
        assert_eq!(parse_list(b"<>"), []);
        assert_eq!(parse_list(b"undisclosed"), [Address::Mailbox(Mailbox {
            name: None,
            local: "undisclosed".into(),
            domain: None
        })]);
    }
}
