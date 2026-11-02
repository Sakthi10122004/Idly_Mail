//! Header values with parameters: Content-Type (RFC 2045 §5.1) and
//! Content-Disposition (RFC 2183 §2), including RFC 2231 continuations,
//! charsets and languages.

use super::decode::charset_to_utf8;

/// `value; name=param; ...` as written: the leading value and the
/// parameters with quoted-strings unquoted, names and order kept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parameterized {
    pub value: String,
    pub params: Vec<(String, String)>,
}

impl Parameterized {
    /// Parses a header value. Comments are dropped (RFC 5322 §3.2.2).
    pub fn parse(raw: &[u8]) -> Self {
        let text = String::from_utf8_lossy(raw);
        let mut pieces = split_semicolons(&text).into_iter();
        let value = pieces
            .next()
            .map(|v| v.trim().to_owned())
            .unwrap_or_default();
        let mut params = Vec::new();
        for p in pieces {
            let Some((name, val)) = p.split_once('=') else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() || !name.bytes().all(is_token_char_or_star) {
                continue;
            }
            params.push((name.to_owned(), unquote(val.trim())));
        }
        Self { value, params }
    }

    /// The parameter `name` (case-insensitive), decoded: RFC 2231
    /// continuations joined and `charset'lang'%XX` decoded to UTF-8.
    pub fn param(&self, name: &str) -> Option<String> {
        if let Some((_, v)) = self
            .params
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
        {
            return Some(v.clone());
        }
        // RFC 2231 §4: `name*` alone is an extended (encoded) value.
        let star = format!("{name}*");
        if let Some((_, v)) = self
            .params
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(&star))
        {
            return Some(decode_extended(v, true).0);
        }
        // RFC 2231 §3: continuations `name*0`, `name*1*`, ... in order.
        let mut sections: Vec<(u32, bool, &str)> = Vec::new();
        for (n, v) in &self.params {
            let Some(rest) = strip_prefix_ci(n, name).and_then(|r| r.strip_prefix('*')) else {
                continue;
            };
            let (digits, encoded) = match rest.strip_suffix('*') {
                Some(d) => (d, true),
                None => (rest, false),
            };
            // No leading zeros except "0" itself (RFC 2231 §3).
            if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
                continue;
            }
            if let Ok(i) = digits.parse::<u32>() {
                sections.push((i, encoded, v));
            }
        }
        if sections.is_empty() {
            return None;
        }
        sections.sort_by_key(|s| s.0);
        let mut bytes = Vec::new();
        let mut charset = String::new();
        for (expected, (i, encoded, v)) in (0u32..).zip(&sections) {
            if *i != expected {
                break;
            }
            if *encoded {
                // Only the first section carries charset'lang'.
                let (decoded, cs) = decode_extended_bytes(v, *i == 0);
                if *i == 0 {
                    charset = cs;
                }
                bytes.extend(decoded);
            } else {
                bytes.extend_from_slice(v.as_bytes());
            }
        }
        Some(charset_to_utf8(&bytes, &charset))
    }
}

fn is_token_char_or_star(b: u8) -> bool {
    // RFC 2045 §5.1 token: no specials, no space, no CTLs.
    b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?=".contains(&b)
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| s.get(prefix.len()..))
        .flatten()
}

/// Splits on `;` outside quoted-strings and comments; comments dropped.
fn split_semicolons(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut comment = 0u32;
    for c in v.chars() {
        if escaped {
            if comment == 0 {
                cur.push('\\');
                cur.push(c);
            }
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted || comment > 0 => escaped = true,
            '"' if comment == 0 => {
                quoted = !quoted;
                cur.push(c);
            }
            '(' if !quoted => comment = comment.saturating_add(1),
            ')' if !quoted && comment > 0 => comment -= 1,
            _ if comment > 0 => {}
            ';' if !quoted => out.push(std::mem::take(&mut cur)),
            '\r' | '\n' => cur.push(' '),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// A quoted-string's content (RFC 5322 §3.2.4), or the token as is.
fn unquote(v: &str) -> String {
    let Some(inner) = v.strip_prefix('"') else {
        return v.to_owned();
    };
    let inner = inner.strip_suffix('"').unwrap_or(inner);
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// RFC 2231 §4: `charset'language'percent-encoded`, as UTF-8; also
/// returns the charset.
fn decode_extended(v: &str, first: bool) -> (String, String) {
    let (bytes, charset) = decode_extended_bytes(v, first);
    (charset_to_utf8(&bytes, &charset), charset)
}

fn decode_extended_bytes(v: &str, first: bool) -> (Vec<u8>, String) {
    let (charset, data) = if first {
        let mut it = v.splitn(3, '\'');
        match (it.next(), it.next(), it.next()) {
            (Some(cs), Some(_lang), Some(rest)) => (cs.to_owned(), rest),
            _ => (String::new(), v),
        }
    } else {
        (String::new(), v)
    };
    (percent_decode(data.as_bytes()), charset)
}

fn percent_decode(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        if c == b'%'
            && let (Some(h), Some(l)) = (
                b.get(i + 1).and_then(|x| hex(*x)),
                b.get(i + 2).and_then(|x| hex(*x)),
            )
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

pub(crate) fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_quoted_parameters() {
        let p = Parameterized::parse(
            b"text/plain; charset=\"UTF-8\" (a comment); format=flowed;\r\n\tname=\"a \\\"b\\\";c\"",
        );
        assert_eq!(p.value, "text/plain");
        assert_eq!(p.param("CHARSET").as_deref(), Some("UTF-8"));
        assert_eq!(p.param("format").as_deref(), Some("flowed"));
        assert_eq!(p.param("name").as_deref(), Some("a \"b\";c"));
        assert_eq!(p.params.len(), 3);
    }

    #[test]
    fn rfc2231_examples() {
        // RFC 2231 §3 and §4 examples.
        let p = Parameterized::parse(
            b"message/external-body; access-type=URL;\r\n URL*0=\"ftp://\";\r\n URL*1=\"cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar\"",
        );
        assert_eq!(
            p.param("url").as_deref(),
            Some("ftp://cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar")
        );
        let p = Parameterized::parse(
            b"application/x-stuff; title*=us-ascii'en-us'This%20is%20%2A%2A%2Afun%2A%2A%2A",
        );
        assert_eq!(p.param("title").as_deref(), Some("This is ***fun***"));
        let p = Parameterized::parse(
            b"attachment; filename*0*=utf-8''%E2%82%AC%20rates; filename*1=\".pdf\"",
        );
        assert_eq!(p.param("filename").as_deref(), Some("\u{20ac} rates.pdf"));
        let p = Parameterized::parse(b"attachment; filename*=iso-8859-1''caf%E9.txt");
        assert_eq!(p.param("filename").as_deref(), Some("caf\u{e9}.txt"));
    }

    #[test]
    fn junk_is_tolerated() {
        for v in [
            &b""[..],
            b";;;",
            b"text/plain; =x; a",
            b"x; \"unterminated",
            b"(((",
            b"a; b*00=x",
        ] {
            let p = Parameterized::parse(v);
            let _ = p.param("b");
        }
        assert_eq!(Parameterized::parse(b"a; b*00=x").param("b"), None);
    }
}
