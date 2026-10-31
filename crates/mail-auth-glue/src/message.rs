//! Just enough RFC 5322 to authenticate a message: the header section split
//! into fields (raw bytes kept, for DKIM), the body, and the domains in the
//! From field (for DMARC).

use smtp_proto::Host;
use smtp_proto::address::domain_to_ascii;

/// One header field, exactly as it appears in the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header<'a> {
    /// The field name as written (case preserved).
    pub name: &'a str,
    /// The whole field, `name: value` with any folding, without the final
    /// CRLF. DKIM "simple" canonicalization hashes exactly this.
    pub raw: &'a [u8],
    /// The value: everything after the colon, folding included.
    pub value: &'a [u8],
}

/// A parsed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    /// Header fields in order, top to bottom.
    pub headers: Vec<Header<'a>>,
    /// The body: everything after the empty line (may be empty).
    pub body: &'a [u8],
}

/// The message's header section is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedHeader;

impl<'a> Message<'a> {
    /// Splits a CRLF message into header fields and body.
    ///
    /// RFC 5322 §2.2: a field is a name, a colon and a body, and may be
    /// folded onto continuation lines that start with WSP (§2.2.3). The
    /// header section ends at the first empty line (§2.1).
    pub fn parse(message: &'a [u8]) -> Result<Self, MalformedHeader> {
        let mut headers = Vec::new();
        let mut pos = 0usize;
        loop {
            let rest = message.get(pos..).unwrap_or_default();
            if rest.is_empty() {
                return Ok(Self {
                    headers,
                    body: rest,
                });
            }
            if let Some(body) = rest.strip_prefix(b"\r\n") {
                return Ok(Self { headers, body });
            }
            // Find the end of this field: a CRLF not followed by WSP.
            let mut end = 0usize;
            let field_len = loop {
                match find_crlf(rest.get(end..).unwrap_or_default()) {
                    Some(i) => {
                        let crlf = end + i;
                        match rest.get(crlf + 2) {
                            Some(b' ' | b'\t') => end = crlf + 2,
                            _ => break crlf,
                        }
                    }
                    None => break rest.len(),
                }
            };
            let raw = rest.get(..field_len).ok_or(MalformedHeader)?;
            headers.push(parse_field(raw)?);
            pos += (field_len + 2).min(rest.len());
        }
    }

    /// Header fields named `name` (case-insensitive), top to bottom.
    pub fn headers_named<'s>(
        &'s self,
        name: &'s str,
    ) -> impl DoubleEndedIterator<Item = &'s Header<'a>> + 's {
        self.headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(name))
    }
}

fn find_crlf(b: &[u8]) -> Option<usize> {
    b.windows(2).position(|w| w == b"\r\n")
}

/// RFC 5322 §3.6.8: `field-name = 1*ftext`, `ftext = %d33-57 / %d59-126`.
/// RFC 5322 §4.5.8 (obsolete syntax) allows WSP between name and colon.
fn parse_field(raw: &[u8]) -> Result<Header<'_>, MalformedHeader> {
    let colon = raw.iter().position(|&b| b == b':').ok_or(MalformedHeader)?;
    let name_part = raw.get(..colon).ok_or(MalformedHeader)?;
    let name_len = name_part
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map_or(0, |i| i + 1);
    let name_bytes = name_part.get(..name_len).ok_or(MalformedHeader)?;
    if name_bytes.is_empty()
        || !name_bytes
            .iter()
            .all(|&b| (33..=126).contains(&b) && b != b':')
    {
        return Err(MalformedHeader);
    }
    let name = core::str::from_utf8(name_bytes).map_err(|_| MalformedHeader)?;
    let value = raw.get(colon + 1..).ok_or(MalformedHeader)?;
    Ok(Header { name, raw, value })
}

/// Lexical tokens of an address list (RFC 5322 §3.2, §3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    /// An atom or dot-atom (dots kept), or a quoted-string's contents.
    Word(String),
    /// A domain literal `[...]`.
    Literal,
    /// One of `<>@,;:`.
    Special(u8),
}

/// Tokenizes an address-list value, dropping whitespace and (nested)
/// comments (RFC 5322 §3.2.2). Returns None if it is malformed.
fn tokenize(v: &[u8]) -> Option<Vec<Token>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(&b) = v.get(i) {
        match b {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'(' => {
                let mut depth = 0u32;
                loop {
                    match v.get(i)? {
                        b'\\' => i += 1,
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                i += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
            }
            b'"' => {
                let mut s = Vec::new();
                i += 1;
                loop {
                    match *v.get(i)? {
                        b'"' => break,
                        b'\\' => {
                            i += 1;
                            s.push(*v.get(i)?);
                        }
                        c => s.push(c),
                    }
                    i += 1;
                }
                i += 1;
                out.push(Token::Word(String::from_utf8(s).ok()?));
            }
            b'[' => {
                i += v.get(i..)?.iter().position(|&c| c == b']')? + 1;
                out.push(Token::Literal);
            }
            b'<' | b'>' | b'@' | b',' | b';' | b':' => {
                out.push(Token::Special(b));
                i += 1;
            }
            // Unbalanced closers and stray backslashes are malformed.
            b')' | b']' | b'\\' => return None,
            _ => {
                let start = i;
                while let Some(&c) = v.get(i) {
                    if b" \t\r\n()\"[]<>@,;:\\".contains(&c) {
                        break;
                    }
                    i += 1;
                }
                // Every branch must consume input, or this loop never ends.
                if i == start {
                    return None;
                }
                out.push(Token::Word(
                    String::from_utf8(v.get(start..i)?.to_vec()).ok()?,
                ));
            }
        }
    }
    Some(out)
}

/// The domains of every mailbox in an address-list field such as From
/// (RFC 5322 §3.4 `mailbox-list`, with groups), lower-cased and in
/// A-label form. Returns None if the field can't be parsed or a mailbox
/// has no valid domain: DMARC must then treat the message as unauthenticatable.
pub fn address_domains(value: &[u8]) -> Option<Vec<String>> {
    let tokens = tokenize(value)?;
    let mut domains = Vec::new();
    // Split into mailboxes at top-level commas, and drop group names
    // ("name:" ... ";", RFC 5322 §3.4).
    let mut current: Vec<Token> = Vec::new();
    let mut in_angle = false;
    let flush = |current: &mut Vec<Token>, domains: &mut Vec<String>| -> Option<()> {
        if !current.is_empty() {
            domains.push(mailbox_domain(current)?);
            current.clear();
        }
        Some(())
    };
    for t in tokens {
        match t {
            Token::Special(b'<') => {
                in_angle = true;
                current.push(t);
            }
            Token::Special(b'>') => {
                in_angle = false;
                current.push(t);
            }
            Token::Special(b',' | b';') if !in_angle => flush(&mut current, &mut domains)?,
            // A group name: everything so far was the display name of the group.
            Token::Special(b':') if !in_angle => current.clear(),
            _ => current.push(t),
        }
    }
    flush(&mut current, &mut domains)?;
    Some(domains)
}

/// The domain of one mailbox: `name-addr` (`[display-name] <addr-spec>`)
/// or a bare `addr-spec`.
fn mailbox_domain(tokens: &[Token]) -> Option<String> {
    let spec: &[Token] = match tokens.iter().position(|t| *t == Token::Special(b'<')) {
        Some(open) => {
            let inner = tokens.get(open + 1..)?;
            let close = inner.iter().position(|t| *t == Token::Special(b'>'))?;
            inner.get(..close)?
        }
        None => tokens,
    };
    let at = spec.iter().rposition(|t| *t == Token::Special(b'@'))?;
    let mut domain = String::new();
    for t in spec.get(at + 1..)? {
        match t {
            Token::Word(w) => domain.push_str(w),
            // Address literals have no DNS domain to check.
            _ => return None,
        }
    }
    match Host::parse(&domain).ok()? {
        Host::Domain(d) => domain_to_ascii(&d).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_headers_and_body() {
        let m = Message::parse(b"From: a@b\r\nSubject: hi\r\n there\r\n\r\nbody\r\n").unwrap();
        assert_eq!(m.headers.len(), 2);
        assert_eq!(m.headers[1].name, "Subject");
        assert_eq!(m.headers[1].raw, b"Subject: hi\r\n there");
        assert_eq!(m.headers[1].value, b" hi\r\n there");
        assert_eq!(m.body, b"body\r\n");
    }

    #[test]
    fn no_body_and_obsolete_space_before_colon() {
        let m = Message::parse(b"X-A : 1\r\n").unwrap();
        assert_eq!(m.headers[0].name, "X-A");
        assert_eq!(m.body, b"");
        let m = Message::parse(b"X-A: 1").unwrap();
        assert_eq!(m.headers[0].value, b" 1");
    }

    #[test]
    fn malformed_headers() {
        assert_eq!(
            Message::parse(b"no colon here\r\n\r\n"),
            Err(MalformedHeader)
        );
        assert_eq!(
            Message::parse(b": empty name\r\n\r\n"),
            Err(MalformedHeader)
        );
        assert_eq!(Message::parse(b"Bad Name: x\r\n\r\n"), Err(MalformedHeader));
    }

    #[test]
    fn headers_named_is_case_insensitive() {
        let m = Message::parse(b"From: a\r\nfrom: b\r\nTo: c\r\n\r\n").unwrap();
        assert_eq!(m.headers_named("FROM").count(), 2);
    }

    #[test]
    fn from_domains() {
        let d = |v: &str| address_domains(v.as_bytes());
        assert_eq!(
            d(" Joe SixPack <joe@Football.Example.com>"),
            Some(vec!["football.example.com".into()])
        );
        assert_eq!(d(" joe@example.com"), Some(vec!["example.com".into()]));
        assert_eq!(
            d(" \"Smith, Joe\" (comment (nested)) <joe@example.com>"),
            Some(vec!["example.com".into()])
        );
        assert_eq!(
            d(" a@one.example, B <b@two.example>"),
            Some(vec!["one.example".into(), "two.example".into()])
        );
        assert_eq!(
            d(" Friends: a@one.example, b@two.example;"),
            Some(vec!["one.example".into(), "two.example".into()])
        );
        assert_eq!(
            d(" \"a@fake.example\"@real.example"),
            Some(vec!["real.example".into()])
        );
        assert_eq!(
            d(" Kim <kim@bücher.example>"),
            Some(vec!["xn--bcher-kva.example".into()])
        );
        // Unusable for DMARC:
        for bad in [
            " no-at-sign",
            " a@[192.0.2.1]",
            " <unterminated@x",
            " (open comment a@b",
            " a@b_c.example",
        ] {
            assert_eq!(d(bad), None, "{bad}");
        }
        assert_eq!(d(""), Some(vec![]));
    }

    #[test]
    fn stray_bracket_does_not_loop() {
        // Found by the message_parse fuzzer: a ']' starting a token used to
        // loop forever pushing empty words, until memory ran out.
        assert_eq!(address_domains(b" a] b@example.com"), None);
        assert_eq!(address_domains(b"]"), None);
        let found = include_bytes!("../tests/data/oom-stray-bracket.bin");
        let _ = address_domains(found);
        if let Ok(m) = Message::parse(found) {
            for h in &m.headers {
                let _ = address_domains(h.value);
            }
        }
    }
}
