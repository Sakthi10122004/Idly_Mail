//! SMTP replies: parsing (client side) and serialization (server side).
//!
//! RFC 5321 §4.2:
//! ```text
//! Reply-line = *( Reply-code "-" [ textstring ] CRLF )
//!              Reply-code [ SP textstring ] CRLF
//! Reply-code = %x32-35 %x30-35 %x30-39
//! ```
//! The code and the line framing are checked strictly. The text is not:
//! RFC 5321 §4.2 says a client acts only on the reply code, never on the
//! text, so odd text should not make delivery fail. Text that is not UTF-8
//! is decoded lossily.

use crate::error::{EnhancedCode, Error};
use crate::line::split_line;

/// An SMTP reply: a code and one or more lines of text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Reply {
    /// The three-digit reply code, 200–559.
    pub code: u16,
    /// The enhanced status code that prefixes every line, if present.
    /// RFC 2034 §4; RFC 3463 §2.
    pub enhanced: Option<EnhancedCode>,
    /// The text of each line, without the code or enhanced code.
    pub lines: Vec<String>,
}

impl Reply {
    /// Creates a single-line reply.
    pub fn new(code: u16, enhanced: Option<EnhancedCode>, text: impl Into<String>) -> Self {
        Self {
            code,
            enhanced,
            lines: vec![text.into()],
        }
    }

    /// 2yz: positive completion. RFC 5321 §4.2.1.
    pub fn is_positive(&self) -> bool {
        self.code / 100 == 2
    }

    /// 3yz: positive intermediate (e.g. 354 after DATA). RFC 5321 §4.2.1.
    pub fn is_intermediate(&self) -> bool {
        self.code / 100 == 3
    }

    /// 4yz: transient negative completion; retry later. RFC 5321 §4.2.1.
    pub fn is_transient(&self) -> bool {
        self.code / 100 == 4
    }

    /// 5yz: permanent negative completion. RFC 5321 §4.2.1.
    pub fn is_permanent(&self) -> bool {
        self.code / 100 == 5
    }

    /// Parses one complete reply from the front of `buf`.
    ///
    /// Returns `Ok(Some((reply, consumed)))`, or `Ok(None)` if the reply is
    /// not complete yet. Each line may be at most `max_line` octets, CRLF
    /// included ([`crate::limits::REPLY_LINE`] is the RFC 5321 limit). The
    /// caller must also cap how much it buffers while a multi-line reply is
    /// incomplete.
    pub fn parse(buf: &[u8], max_line: usize) -> Result<Option<(Self, usize)>, Error> {
        let mut pos = 0usize;
        let mut code = None;
        let mut lines = Vec::new();
        loop {
            let rest = buf.get(pos..).unwrap_or_default();
            let Some((line, n)) = split_line(rest, max_line)? else {
                return Ok(None);
            };
            pos = pos.saturating_add(n);
            let (c, last, text) = parse_line(line)?;
            match code {
                None => code = Some(c),
                // RFC 5321 §4.2.1: every line of a multiline reply has the same code.
                Some(prev) if prev != c => {
                    return Err(Error::InvalidReply(
                        "reply code changed within a multiline reply",
                    ));
                }
                Some(_) => {}
            }
            lines.push(text);
            if last {
                break;
            }
        }
        let code = code.ok_or(Error::InvalidReply("empty reply"))?;
        let enhanced = strip_enhanced(code, &mut lines);
        Ok(Some((
            Self {
                code,
                enhanced,
                lines,
            },
            pos,
        )))
    }

    /// Serializes the reply, CRLF included.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_to(&mut out);
        out
    }

    /// Appends the reply to `out`. CR and LF inside the text are replaced by
    /// spaces, so text from elsewhere can never inject extra reply lines.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        let empty = [String::new()];
        let lines: &[String] = if self.lines.is_empty() {
            &empty
        } else {
            &self.lines
        };
        let last = lines.len().saturating_sub(1);
        for (i, text) in lines.iter().enumerate() {
            out.extend_from_slice(self.code.to_string().as_bytes());
            let body = match self.enhanced {
                Some(e) if text.is_empty() => e.to_string(),
                Some(e) => format!("{e} {text}"),
                None => text.clone(),
            };
            // RFC 5321 §4.2: "-" on all lines but the last, SP on the last.
            match (i == last, body.is_empty()) {
                (true, true) => {}
                (true, false) => out.push(b' '),
                (false, _) => out.push(b'-'),
            }
            out.extend(
                body.bytes()
                    .map(|b| if b == b'\r' || b == b'\n' { b' ' } else { b }),
            );
            out.extend_from_slice(b"\r\n");
        }
    }
}

/// Parses one reply line (without CRLF) into (code, is_last, text).
fn parse_line(line: &[u8]) -> Result<(u16, bool, String), Error> {
    let (code, rest) = match line {
        // RFC 5321 §4.2: Reply-code = %x32-35 %x30-35 %x30-39
        [a @ b'2'..=b'5', b @ b'0'..=b'5', c @ b'0'..=b'9', rest @ ..] => {
            let code = u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0');
            (code, rest)
        }
        _ => return Err(Error::InvalidReply("invalid reply code")),
    };
    let (last, text) = match rest {
        [] => (true, &[][..]),
        [b' ', text @ ..] => (true, text),
        [b'-', text @ ..] => (false, text),
        _ => {
            return Err(Error::InvalidReply(
                "reply code must be followed by SP or '-'",
            ));
        }
    };
    Ok((code, last, String::from_utf8_lossy(text).into_owned()))
}

/// RFC 2034 §4: with ENHANCEDSTATUSCODES, each line's text starts with
/// `status-code SP`. If every line has the same enhanced code and its class
/// matches the reply code's first digit, strip it and return it.
fn strip_enhanced(code: u16, lines: &mut [String]) -> Option<EnhancedCode> {
    let mut found = None;
    for line in lines.iter() {
        let token = line.split(' ').next().unwrap_or_default();
        let e = parse_enhanced(token)?;
        // The class (RFC 3463 §2) must agree with the reply code's first digit.
        if u16::from(e.class) != code / 100 || found.is_some_and(|f| f != e) {
            return None;
        }
        found = Some(e);
    }
    let e = found?;
    for line in lines.iter_mut() {
        let rest = line.split_once(' ').map_or("", |(_, rest)| rest);
        *line = rest.to_owned();
    }
    Some(e)
}

/// RFC 3463 §2: `class "." subject "." detail`, with class 2, 4 or 5, and
/// subject and detail of 1–3 digits.
pub fn parse_enhanced(s: &str) -> Option<EnhancedCode> {
    let mut parts = s.split('.');
    let (class, subject, detail) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let num = |p: &str| -> Option<u16> {
        if (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()) {
            p.parse().ok()
        } else {
            None
        }
    };
    let class = match class {
        "2" => 2,
        "4" => 4,
        "5" => 5,
        _ => return None,
    };
    Some(EnhancedCode::new(class, num(subject)?, num(detail)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::REPLY_LINE;

    fn parse(s: &str) -> Result<Option<(Reply, usize)>, Error> {
        Reply::parse(s.as_bytes(), REPLY_LINE)
    }

    fn reply(s: &str) -> Reply {
        parse(s).unwrap().unwrap().0
    }

    #[test]
    fn single_line() {
        let r = reply("220 mx.example.org ESMTP ready\r\n");
        assert_eq!(r.code, 220);
        assert_eq!(r.lines, vec!["mx.example.org ESMTP ready"]);
        assert!(r.is_positive());
    }

    #[test]
    fn code_only() {
        // RFC 5321 §4.2: textstring is optional.
        let r = reply("250\r\n");
        assert_eq!(r.lines, vec![""]);
        assert_eq!(r.to_bytes(), b"250\r\n");
    }

    #[test]
    fn multiline() {
        let input = "250-mx.example.org\r\n250-PIPELINING\r\n250 SIZE 1000\r\nNEXT";
        let (r, n) = parse(input).unwrap().unwrap();
        assert_eq!(n, input.len() - 4, "stops after the last line");
        assert_eq!(r.lines, vec!["mx.example.org", "PIPELINING", "SIZE 1000"]);
    }

    #[test]
    fn incomplete() {
        assert_eq!(parse("250-a\r\n250-b\r\n"), Ok(None));
        assert_eq!(parse("25"), Ok(None));
        assert_eq!(parse(""), Ok(None));
    }

    #[test]
    fn invalid_codes() {
        // RFC 5321 §4.2: first digit 2–5, second 0–5.
        for bad in [
            "199 x\r\n",
            "600 x\r\n",
            "260 x\r\n",
            "2x0 x\r\n",
            "25\r\n",
            "250x\r\n",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn mismatched_multiline_codes() {
        assert!(parse("250-a\r\n251 b\r\n").is_err());
    }

    #[test]
    fn bare_line_endings_rejected() {
        assert_eq!(parse("250 ok\n"), Err(Error::BareLf));
        assert_eq!(parse("250 o\rk\r\n"), Err(Error::BareCr));
    }

    #[test]
    fn line_limit() {
        let long = format!("250 {}\r\n", "x".repeat(REPLY_LINE));
        assert!(matches!(parse(&long), Err(Error::LineTooLong { .. })));
        assert!(Reply::parse(long.as_bytes(), 4096).unwrap().is_some());
    }

    #[test]
    fn enhanced_codes() {
        // RFC 2034 §4
        let r = reply("550-5.1.1 No such user\r\n550 5.1.1 Try again\r\n");
        assert_eq!(r.enhanced, Some(EnhancedCode::new(5, 1, 1)));
        assert_eq!(r.lines, vec!["No such user", "Try again"]);
        assert!(r.is_permanent());
        assert_eq!(
            r.to_bytes(),
            b"550-5.1.1 No such user\r\n550 5.1.1 Try again\r\n"
        );
    }

    #[test]
    fn enhanced_code_not_stripped_when_inconsistent() {
        // Class mismatch with the reply code.
        let r = reply("250 5.0.0 odd\r\n");
        assert_eq!((r.enhanced, r.lines[0].as_str()), (None, "5.0.0 odd"));
        // Only some lines carry it.
        let r = reply("250-2.0.0 a\r\n250 b\r\n");
        assert_eq!(r.enhanced, None);
        // Different codes on different lines.
        let r = reply("450-4.2.0 a\r\n450 4.2.1 b\r\n");
        assert_eq!(r.enhanced, None);
        // Not a valid status code.
        let r = reply("250 2.0 ok\r\n");
        assert_eq!(r.enhanced, None);
    }

    #[test]
    fn enhanced_code_alone() {
        let r = reply("250 2.0.0\r\n");
        assert_eq!(r.enhanced, Some(EnhancedCode::new(2, 0, 0)));
        assert_eq!(r.lines, vec![""]);
        assert_eq!(r.to_bytes(), b"250 2.0.0\r\n");
    }

    #[test]
    fn parse_enhanced_codes() {
        assert_eq!(parse_enhanced("5.7.1"), Some(EnhancedCode::new(5, 7, 1)));
        assert_eq!(
            parse_enhanced("4.999.999"),
            Some(EnhancedCode::new(4, 999, 999))
        );
        for bad in [
            "3.0.0", "5.1", "5.1.1.1", "5..1", "5.1000.1", "x.1.1", "5.1.a", "",
        ] {
            assert_eq!(parse_enhanced(bad), None, "{bad}");
        }
    }

    #[test]
    fn serializer_neutralizes_line_breaks() {
        let r = Reply::new(250, None, "ok\r\n250 injected");
        assert_eq!(r.to_bytes(), b"250 ok  250 injected\r\n");
    }

    #[test]
    fn serializer_multiline_with_empty_lines() {
        let r = Reply {
            code: 214,
            enhanced: None,
            lines: vec![String::new(), "end".into()],
        };
        assert_eq!(r.to_bytes(), b"214-\r\n214 end\r\n");
        assert_eq!(reply("214-\r\n214 end\r\n"), r);
    }

    #[test]
    fn non_utf8_text_is_tolerated() {
        // RFC 5321 §4.2: clients act on the code, not the text.
        let (r, _) = Reply::parse(b"250 caf\xe9\r\n", REPLY_LINE)
            .unwrap()
            .unwrap();
        assert_eq!(r.code, 250);
    }
}
