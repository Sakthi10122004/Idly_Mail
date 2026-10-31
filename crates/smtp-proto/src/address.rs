//! Mailboxes, domains, address literals and paths.
//!
//! Grammar: RFC 5321 §4.1.2 and §4.1.3, extended for internationalized
//! addresses by RFC 6531 §3.3. Whether non-ASCII is allowed in a given
//! transaction (the SMTPUTF8 parameter) is the server's decision; see
//! [`Mailbox::is_ascii`].

use core::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::cursor::{Cursor, is_atext, is_ldh, is_let_dig};
use crate::error::Error;
use crate::limits;

/// The part after `@` in a mailbox, or the argument of EHLO.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    /// A domain name, kept exactly as received (case is not changed).
    Domain(String),
    /// `[192.0.2.1]`. RFC 5321 §4.1.3.
    Ipv4(Ipv4Addr),
    /// `[IPv6:2001:db8::1]`. RFC 5321 §4.1.3.
    Ipv6(Ipv6Addr),
    /// `[tag:content]`, a General-address-literal. RFC 5321 §4.1.3.
    General {
        /// The Standardized-tag.
        tag: String,
        /// The literal content after the colon.
        content: String,
    },
}

impl Host {
    /// Parses a domain or address literal, e.g. the argument of EHLO.
    pub fn parse(s: &str) -> Result<Self, Error> {
        let mut c = Cursor::new(s);
        let host = parse_host(&mut c)?;
        if !c.is_empty() {
            return Err(Error::InvalidAddress("unexpected characters after host"));
        }
        Ok(host)
    }

    /// Whether the host is plain ASCII (always true for address literals).
    pub fn is_ascii(&self) -> bool {
        match self {
            Self::Domain(d) => d.is_ascii(),
            Self::Ipv4(_) | Self::Ipv6(_) => true,
            Self::General { tag, content } => tag.is_ascii() && content.is_ascii(),
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(d) => f.write_str(d),
            Self::Ipv4(a) => write!(f, "[{a}]"),
            Self::Ipv6(a) => write!(f, "[IPv6:{a}]"),
            Self::General { tag, content } => write!(f, "[{tag}:{content}]"),
        }
    }
}

/// `Local-part "@" ( Domain / address-literal )`. RFC 5321 §4.1.2.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Mailbox {
    /// The local-part exactly as sent: a Dot-string, or a Quoted-string
    /// with its quotes and backslashes.
    pub local_part: String,
    /// The domain or address literal.
    pub host: Host,
}

impl Mailbox {
    /// Parses a bare mailbox (no angle brackets).
    pub fn parse(s: &str) -> Result<Self, Error> {
        let mut c = Cursor::new(s);
        let mailbox = parse_mailbox(&mut c)?;
        if !c.is_empty() {
            return Err(Error::InvalidAddress("unexpected characters after mailbox"));
        }
        Ok(mailbox)
    }

    /// Whether the mailbox is plain ASCII. A non-ASCII mailbox needs the
    /// SMTPUTF8 parameter on MAIL FROM. RFC 6531 §3.4.
    pub fn is_ascii(&self) -> bool {
        self.local_part.is_ascii() && self.host.is_ascii()
    }
}

impl fmt::Display for Mailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.local_part, self.host)
    }
}

/// The argument of MAIL FROM. RFC 5321 §4.1.2: `Reverse-path = Path / "<>"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReversePath {
    /// `<>`: the null reverse-path, used for bounces. RFC 5321 §4.5.5.
    Null,
    /// A sender mailbox.
    Mailbox(Mailbox),
}

impl fmt::Display for ReversePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("<>"),
            Self::Mailbox(m) => write!(f, "<{m}>"),
        }
    }
}

/// The argument of RCPT TO. RFC 5321 §4.1.1.3.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ForwardPath {
    /// `<Postmaster>` with no domain. RFC 5321 §4.1.1.3, §4.5.1.
    Postmaster,
    /// A recipient mailbox (including `<Postmaster@domain>`).
    Mailbox(Mailbox),
}

impl fmt::Display for ForwardPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postmaster => f.write_str("<Postmaster>"),
            Self::Mailbox(m) => write!(f, "<{m}>"),
        }
    }
}

pub(crate) fn parse_reverse_path(c: &mut Cursor<'_>) -> Result<ReversePath, Error> {
    // RFC 5321 §4.1.2: Reverse-path = Path / "<>"
    if c.eat_ignore_case("<>") {
        return Ok(ReversePath::Null);
    }
    parse_path(c).map(ReversePath::Mailbox)
}

pub(crate) fn parse_forward_path(c: &mut Cursor<'_>) -> Result<ForwardPath, Error> {
    // RFC 5321 §4.1.1.3: "<Postmaster>" is accepted without a domain.
    // RFC 5321 §4.5.1: the name is case-insensitive.
    if c.eat_ignore_case("<postmaster>") {
        return Ok(ForwardPath::Postmaster);
    }
    parse_path(c).map(ForwardPath::Mailbox)
}

/// RFC 5321 §4.1.2: `Path = "<" [ A-d-l ":" ] Mailbox ">"`.
fn parse_path(c: &mut Cursor<'_>) -> Result<Mailbox, Error> {
    if !c.eat('<') {
        return Err(Error::InvalidAddress("path must be enclosed in <>"));
    }
    // RFC 5321 §4.1.2: A-d-l = At-domain *( "," At-domain ).
    // RFC 5321 §4.1.2 (note on A-d-l): a source route "MUST BE accepted,
    // SHOULD NOT be generated, and SHOULD be ignored". See also RFC 5321 §3.3
    // and Appendix C. We parse it and drop it.
    if c.peek() == Some('@') {
        loop {
            if !c.eat('@') {
                return Err(Error::InvalidAddress("malformed source route"));
            }
            parse_domain(c)?;
            if !c.eat(',') {
                break;
            }
        }
        if !c.eat(':') {
            return Err(Error::InvalidAddress("source route must end with ':'"));
        }
    }
    let mailbox = parse_mailbox(c)?;
    if !c.eat('>') {
        return Err(Error::InvalidAddress("path must be enclosed in <>"));
    }
    Ok(mailbox)
}

/// RFC 5321 §4.1.2: `Mailbox = Local-part "@" ( Domain / address-literal )`.
pub(crate) fn parse_mailbox(c: &mut Cursor<'_>) -> Result<Mailbox, Error> {
    let local_part = parse_local_part(c)?.to_owned();
    if !c.eat('@') {
        return Err(Error::InvalidAddress("mailbox has no '@'"));
    }
    let host = parse_host(c)?;
    Ok(Mailbox { local_part, host })
}

/// RFC 5321 §4.1.2: `Local-part = Dot-string / Quoted-string`.
fn parse_local_part<'a>(c: &mut Cursor<'a>) -> Result<&'a str, Error> {
    let start = c.rest();
    if c.eat('"') {
        // RFC 5321 §4.1.2: Quoted-string = DQUOTE *QcontentSMTP DQUOTE
        loop {
            match c.bump() {
                None => return Err(Error::InvalidAddress("unterminated quoted string")),
                Some('"') => break,
                // RFC 5321 §4.1.2: quoted-pairSMTP = %d92 %d32-126
                Some('\\') => match c.bump() {
                    Some(' '..='~') => {}
                    _ => return Err(Error::InvalidAddress("invalid quoted-pair")),
                },
                Some(ch) if is_qtext_smtp(ch) => {}
                Some(_) => return Err(Error::InvalidAddress("invalid character in quoted string")),
            }
        }
    } else {
        // RFC 5321 §4.1.2: Dot-string = Atom *("." Atom); Atom = 1*atext
        loop {
            if c.take_while(is_atext).is_empty() {
                return Err(Error::InvalidAddress("empty atom in local-part"));
            }
            if !c.eat('.') {
                break;
            }
        }
    }
    Ok(c.since(start))
}

/// RFC 5321 §4.1.2 `qtextSMTP = %d32-33 / %d35-91 / %d93-126`, extended by
/// RFC 6531 §3.3 with UTF8-non-ascii.
fn is_qtext_smtp(c: char) -> bool {
    matches!(c, ' '..='!' | '#'..='[' | ']'..='~') || !c.is_ascii()
}

fn parse_host(c: &mut Cursor<'_>) -> Result<Host, Error> {
    if c.peek() == Some('[') {
        parse_address_literal(c)
    } else {
        parse_domain(c).map(Host::Domain)
    }
}

/// RFC 5321 §4.1.2: `Domain = sub-domain *("." sub-domain)`, where
/// `sub-domain = Let-dig [Ldh-str]`, and RFC 6531 §3.3 adds U-labels.
///
/// We do not run full IDNA2008 validation on U-labels. Non-ASCII characters
/// are accepted in the positions of letters and digits, except for control
/// and whitespace characters, which IDNA never allows.
pub(crate) fn parse_domain(c: &mut Cursor<'_>) -> Result<String, Error> {
    let start = c.rest();
    loop {
        let label = c.take_while(|ch| is_ldh(ch) || is_u_label_char(ch));
        let ends_ok = |ch: Option<char>| ch.is_some_and(|ch| is_let_dig(ch) || is_u_label_char(ch));
        if label.is_empty() {
            return Err(Error::InvalidAddress("empty domain label"));
        }
        // RFC 5321 §4.1.2: Ldh-str ends in Let-dig, sub-domain starts with one.
        if !ends_ok(label.chars().next()) || !ends_ok(label.chars().next_back()) {
            return Err(Error::InvalidAddress(
                "domain label starts or ends with '-'",
            ));
        }
        // RFC 1035 §2.3.4: labels are 63 octets or less.
        if label.len() > limits::LABEL {
            return Err(Error::InvalidAddress("domain label longer than 63 octets"));
        }
        if !c.eat('.') {
            break;
        }
    }
    let domain = c.since(start);
    // RFC 5321 §4.5.3.1.2; RFC 1035 §2.3.4.
    if domain.len() > limits::DOMAIN {
        return Err(Error::InvalidAddress("domain longer than 255 octets"));
    }
    Ok(domain.to_owned())
}

fn is_u_label_char(c: char) -> bool {
    !c.is_ascii() && !c.is_control() && !c.is_whitespace()
}

/// RFC 5321 §4.1.2 (alternatives defined in RFC 5321 §4.1.3):
/// `address-literal = "[" ( IPv4-address-literal / IPv6-address-literal /
/// General-address-literal ) "]"`.
fn parse_address_literal(c: &mut Cursor<'_>) -> Result<Host, Error> {
    if !c.eat('[') {
        return Err(Error::InvalidAddress("address literal must start with '['"));
    }
    let inner = c.take_while(|ch| ch != ']');
    if !c.eat(']') {
        return Err(Error::InvalidAddress("unterminated address literal"));
    }
    match inner.split_once(':') {
        // RFC 5321 §4.1.3: IPv6-address-literal = "IPv6:" IPv6-addr
        Some((tag, addr)) if tag.eq_ignore_ascii_case("IPv6") => addr
            .parse::<Ipv6Addr>()
            .map(Host::Ipv6)
            .map_err(|_| Error::InvalidAddress("invalid IPv6 address literal")),
        // RFC 5321 §4.1.3: General-address-literal = Standardized-tag ":" 1*dcontent
        Some((tag, content)) => {
            // Standardized-tag = Ldh-str, which must end in Let-dig.
            if tag.is_empty()
                || !tag.chars().all(is_ldh)
                || !tag.chars().next_back().is_some_and(is_let_dig)
            {
                return Err(Error::InvalidAddress("invalid address literal tag"));
            }
            // dcontent = %d33-90 / %d94-126
            if content.is_empty()
                || !content
                    .chars()
                    .all(|ch| matches!(ch, '!'..='Z' | '^'..='~'))
            {
                return Err(Error::InvalidAddress("invalid address literal content"));
            }
            Ok(Host::General {
                tag: tag.to_owned(),
                content: content.to_owned(),
            })
        }
        None => parse_ipv4_literal(inner).map(Host::Ipv4),
    }
}

/// RFC 5321 §4.1.3: `IPv4-address-literal = Snum 3("." Snum)`, where
/// `Snum = 1*3DIGIT` with a value of 0–255. We parse this ourselves because
/// the ABNF allows leading zeros, which `Ipv4Addr::from_str` rejects.
fn parse_ipv4_literal(s: &str) -> Result<Ipv4Addr, Error> {
    let err = Error::InvalidAddress("invalid IPv4 address literal");
    let mut octets = [0u8; 4];
    let mut parts = s.split('.');
    for octet in &mut octets {
        let part = parts.next().ok_or_else(|| err.clone())?;
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(err);
        }
        *octet = part.parse().map_err(|_| err.clone())?;
    }
    if parts.next().is_some() {
        return Err(err);
    }
    Ok(Ipv4Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mbox(s: &str) -> Result<Mailbox, Error> {
        Mailbox::parse(s)
    }

    fn domain(d: &str) -> Host {
        Host::Domain(d.to_owned())
    }

    #[test]
    fn simple_mailbox() {
        let m = mbox("alice@example.org").unwrap();
        assert_eq!(m.local_part, "alice");
        assert_eq!(m.host, domain("example.org"));
        assert_eq!(m.to_string(), "alice@example.org");
    }

    #[test]
    fn dot_string_local_parts() {
        for ok in ["a.b.c@x", "a+tag@x", "!#$%&'*+-/=?^_`{|}~@x", "1@x"] {
            assert!(mbox(ok).is_ok(), "{ok}");
        }
        for bad in [".a@x", "a.@x", "a..b@x", "@x", "a b@x", "a(b)@x", "a\"b@x"] {
            assert!(mbox(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn quoted_local_parts() {
        let m = mbox(r#""john doe"@example.org"#).unwrap();
        assert_eq!(m.local_part, r#""john doe""#);
        assert!(mbox(r#""a\"b"@x"#).is_ok());
        assert!(mbox(r#""a\\b"@x"#).is_ok());
        assert!(mbox("\"\"@x").is_ok(), "empty quoted string is valid ABNF");
        assert!(mbox(r#""abc@x"#).is_err(), "unterminated");
        assert!(mbox("\"a\tb\"@x").is_err(), "HT is not qtextSMTP");
        assert!(
            mbox("\"a\\\u{1}\"@x").is_err(),
            "quoted-pair must be %d32-126"
        );
    }

    #[test]
    fn domains() {
        for ok in [
            "x",
            "a-b.example",
            "1.2.3",
            "xn--bcher-kva.example",
            "a.b.c.d.e.f",
        ] {
            assert_eq!(Host::parse(ok), Ok(domain(ok)), "{ok}");
        }
        for bad in [
            "", "-a.x", "a-.x", "a..b", "a.", ".a", "a_b.x", "a b", "a.-",
        ] {
            assert!(Host::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn domain_length_limits() {
        let label63 = "a".repeat(63);
        assert!(Host::parse(&label63).is_ok());
        assert!(Host::parse(&"a".repeat(64)).is_err());
        // 4 * 63 + 3 dots = 255 octets: allowed.
        let max = [label63.as_str(); 4].join(".");
        assert_eq!(max.len(), 255);
        assert!(Host::parse(&max).is_ok());
        assert!(Host::parse(&format!("a{max}")).is_err());
    }

    #[test]
    fn internationalized_addresses() {
        // RFC 6531 §3.3
        let m = mbox("用户@例子.广告").unwrap();
        assert!(!m.is_ascii());
        let m = mbox("சக்தி@எடுத்துக்காட்டு.இந்தியா").unwrap();
        assert_eq!(m.local_part, "சக்தி");
        assert!(
            mbox("a@exa\u{a0}mple").is_err(),
            "no whitespace in U-labels"
        );
        assert!(mbox("a@exa\u{85}mple").is_err(), "no controls in U-labels");
        assert!(mbox("alice@example.org").unwrap().is_ascii());
    }

    #[test]
    fn ipv4_literals() {
        assert_eq!(
            Host::parse("[192.0.2.1]"),
            Ok(Host::Ipv4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(
            Host::parse("[001.0.2.1]"),
            Ok(Host::Ipv4(Ipv4Addr::new(1, 0, 2, 1)))
        );
        for bad in [
            "[256.0.0.1]",
            "[1.2.3]",
            "[1.2.3.4.5]",
            "[1..2.3]",
            "[1234.1.1.1]",
            "[]",
        ] {
            assert!(Host::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(
            Host::Ipv4(Ipv4Addr::new(192, 0, 2, 1)).to_string(),
            "[192.0.2.1]"
        );
    }

    #[test]
    fn ipv6_literals() {
        let h = Host::parse("[IPv6:2001:db8::1]").unwrap();
        assert_eq!(h, Host::Ipv6("2001:db8::1".parse().unwrap()));
        assert_eq!(h.to_string(), "[IPv6:2001:db8::1]");
        assert!(Host::parse("[ipv6:::1]").is_ok(), "tag is case-insensitive");
        assert!(Host::parse("[IPv6:::ffff:192.0.2.1]").is_ok());
        assert!(Host::parse("[IPv6:zz::1]").is_err());
        assert!(Host::parse("[IPv6:2001:db8::1").is_err(), "unterminated");
    }

    #[test]
    fn general_literals() {
        let h = Host::parse("[x-tag:some-content]").unwrap();
        assert_eq!(
            h,
            Host::General {
                tag: "x-tag".into(),
                content: "some-content".into()
            }
        );
        assert!(Host::parse("[tag-:x]").is_err(), "tag must end in Let-dig");
        assert!(Host::parse("[tag:]").is_err(), "content must be non-empty");
        assert!(
            Host::parse("[tag:a\\b]").is_err(),
            "backslash is not dcontent"
        );
    }

    #[test]
    fn reverse_paths() {
        let mut c = Cursor::new("<>");
        assert_eq!(parse_reverse_path(&mut c), Ok(ReversePath::Null));
        let mut c = Cursor::new("<a@b>");
        let p = parse_reverse_path(&mut c).unwrap();
        assert_eq!(p.to_string(), "<a@b>");
        for bad in ["a@b", "<a@b", "a@b>", "<a>", "< a@b>", "<a@b >"] {
            let mut c = Cursor::new(bad);
            let r = parse_reverse_path(&mut c);
            assert!(r.is_err() || !c.is_empty(), "{bad}");
        }
    }

    #[test]
    fn source_routes_are_ignored() {
        // RFC 5321 §3.3, Appendix C
        let mut c = Cursor::new("<@relay1.example,@relay2.example:user@example.org>");
        let p = parse_forward_path(&mut c).unwrap();
        assert_eq!(p.to_string(), "<user@example.org>");
        let mut c = Cursor::new("<@relay1.example user@example.org>");
        assert!(parse_forward_path(&mut c).is_err());
        let mut c = Cursor::new("<@relay1.example,relay2:user@example.org>");
        assert!(parse_forward_path(&mut c).is_err());
    }

    #[test]
    fn postmaster() {
        for s in ["<Postmaster>", "<postmaster>", "<POSTMASTER>"] {
            let mut c = Cursor::new(s);
            assert_eq!(
                parse_forward_path(&mut c),
                Ok(ForwardPath::Postmaster),
                "{s}"
            );
        }
        let mut c = Cursor::new("<Postmaster@example.org>");
        assert!(matches!(
            parse_forward_path(&mut c),
            Ok(ForwardPath::Mailbox(_))
        ));
    }
}
