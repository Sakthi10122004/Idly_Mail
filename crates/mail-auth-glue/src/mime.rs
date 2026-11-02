//! Keeping submitted mail within the 998-octet line limit.
//!
//! RFC 5322 §2.1.1 and RFC 2045 §2.8 limit lines to 998 octets. RFC 6409
//! §8.4 lets a submission server "apply transfer encoding to the message
//! according to MIME conventions, if needed and not harmful to the MIME
//! type". Policy (CLAUDE.md): Idly Mail re-encodes over-long lines on
//! submission, before DKIM signing, so it never sends a non-compliant
//! message.
//!
//! The MIME tree is walked part by part:
//! - a text leaf (7bit/8bit/binary or no encoding) with a long line becomes
//!   quoted-printable (RFC 2045 §6.7) and its Content-Transfer-Encoding is
//!   updated;
//! - a base64 leaf with long lines is re-wrapped at 76 characters;
//! - a quoted-printable leaf with long lines gets soft line breaks;
//! - multipart bodies (RFC 2046 §5.1.1) and message/rfc822 bodies are
//!   handled recursively;
//! - a long header line is folded at whitespace (RFC 5322 §2.2.3).
//!
//! A message without long lines is returned unchanged, byte for byte.

use std::borrow::Cow;

use crate::message::Message;

/// RFC 5322 §2.1.1: "Each line ... MUST be no more than 998 characters".
pub const MAX_LINE: usize = 998;
/// RFC 2045 §6.7 rule 5: encoded lines are at most 76 characters.
const QP_LINE: usize = 76;
/// How deeply nested MIME structures may be.
const MAX_DEPTH: usize = 20;

/// Why a message could not be brought within the limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimeError {
    /// A header line is too long and has no whitespace to fold at.
    HeaderLineTooLong,
    /// The structure can't be re-encoded safely (malformed headers, an
    /// unknown transfer encoding, or nesting deeper than 20 levels).
    CannotReencode,
}

/// The physical lines of `b`, without their CRLF.
fn lines(b: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = Some(b);
    std::iter::from_fn(move || {
        let r = rest?;
        match r.windows(2).position(|w| w == b"\r\n") {
            Some(i) => {
                rest = r.get(i + 2..);
                r.get(..i)
            }
            None => {
                rest = None;
                (!r.is_empty()).then_some(r)
            }
        }
    })
}

/// Whether any line of `b` exceeds 998 octets.
pub fn has_long_lines(b: &[u8]) -> bool {
    lines(b).any(|l| l.len() > MAX_LINE)
}

/// Re-encodes `message` so no line exceeds 998 octets. Returns the input
/// unchanged (borrowed) if it already complies.
pub fn fix_long_lines(message: &[u8]) -> Result<Cow<'_, [u8]>, MimeError> {
    if !has_long_lines(message) {
        return Ok(Cow::Borrowed(message));
    }
    let fixed = fix_entity(message, 0, true)?;
    // The whole point: make sure we got it right.
    if has_long_lines(&fixed) {
        return Err(MimeError::CannotReencode);
    }
    Ok(Cow::Owned(fixed))
}

/// Splits an entity into its header section (with its final CRLF) and body.
fn split_entity(e: &[u8]) -> (&[u8], &[u8]) {
    if e.starts_with(b"\r\n") {
        return (&[], e.get(2..).unwrap_or_default());
    }
    match e.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => (
            e.get(..i + 2).unwrap_or(e),
            e.get(i + 4..).unwrap_or_default(),
        ),
        None => (e, &[]),
    }
}

/// The media type (lower-case `type/subtype`) and boundary parameter of a
/// Content-Type value (RFC 2045 §5.1).
fn content_type(value: &[u8]) -> (String, Option<String>) {
    let v = String::from_utf8_lossy(value);
    let mut parts = split_params(&v);
    let media = parts
        .next()
        .map(|t| t.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let mut boundary = None;
    for p in parts {
        if let Some((name, val)) = p.split_once('=')
            && name.trim().eq_ignore_ascii_case("boundary")
        {
            let val = val.trim();
            let val = match val.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
                // RFC 5322 §3.2.4 quoted-string: drop the escaping backslashes.
                Some(q) => q
                    .replace("\\\\", "\u{0}")
                    .replace('\\', "")
                    .replace('\u{0}', "\\"),
                None => val.to_owned(),
            };
            boundary = Some(val);
        }
    }
    (media, boundary)
}

/// Splits on ';' outside quoted strings, dropping (comments) crudely.
fn split_params(v: &str) -> impl Iterator<Item = String> + '_ {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for c in v.chars() {
        match c {
            _ if escaped => {
                cur.push(c);
                escaped = false;
            }
            '\\' if quoted => {
                cur.push(c);
                escaped = true;
            }
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            ';' if !quoted => out.push(std::mem::take(&mut cur)),
            '\r' | '\n' => cur.push(' '),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out.into_iter()
}

/// Folds header lines over 998 octets at whitespace (RFC 5322 §2.2.3: a
/// CRLF may be inserted before any WSP).
fn fold_headers(headers: &[u8]) -> Result<Vec<u8>, MimeError> {
    let mut out = Vec::with_capacity(headers.len() + 16);
    for line in lines(headers) {
        let mut rest = line;
        while rest.len() > MAX_LINE {
            // The last WSP that isn't the first character, within the limit.
            let cut = rest
                .get(1..=MAX_LINE)
                .and_then(|w| w.iter().rposition(|&b| b == b' ' || b == b'\t'))
                .map(|i| i + 1)
                .ok_or(MimeError::HeaderLineTooLong)?;
            out.extend_from_slice(rest.get(..cut).unwrap_or_default());
            out.extend_from_slice(b"\r\n");
            rest = rest.get(cut..).unwrap_or_default();
        }
        out.extend_from_slice(rest);
        out.extend_from_slice(b"\r\n");
    }
    Ok(out)
}

/// Replaces (or adds) the Content-Transfer-Encoding field of a header
/// section, and adds MIME-Version at the top level if missing.
fn set_cte(headers: &[u8], cte: &str, top: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(headers.len() + 48);
    let mut skipping = false;
    let mut has_mime_version = false;
    for line in lines(headers) {
        let continuation = line.first().is_some_and(|b| *b == b' ' || *b == b'\t');
        if continuation && skipping {
            continue;
        }
        let name = line.split(|b| *b == b':').next().unwrap_or_default();
        let name = String::from_utf8_lossy(name).trim().to_ascii_lowercase();
        skipping = !continuation && name == "content-transfer-encoding";
        has_mime_version |= !continuation && name == "mime-version";
        if !skipping {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
    }
    if top && !has_mime_version {
        out.extend_from_slice(b"MIME-Version: 1.0\r\n");
    }
    out.extend_from_slice(format!("Content-Transfer-Encoding: {cte}\r\n").as_bytes());
    out
}

fn fix_entity(entity: &[u8], depth: usize, top: bool) -> Result<Vec<u8>, MimeError> {
    if depth > MAX_DEPTH {
        return Err(MimeError::CannotReencode);
    }
    let (headers, body) = split_entity(entity);
    let parsed = if headers.is_empty() {
        Message {
            headers: Vec::new(),
            body: &[],
        }
    } else {
        Message::parse(headers).map_err(|_| MimeError::CannotReencode)?
    };
    let field = |name: &str| parsed.headers_named(name).next().map(|h| h.value);
    // RFC 2045 §5.2: the default is text/plain; RFC 2046 §5.1.5: inside
    // multipart/digest it would be message/rfc822, handled as text here.
    let (media, boundary) = field("Content-Type")
        .map(content_type)
        .unwrap_or_else(|| ("text/plain".into(), None));
    let cte = field("Content-Transfer-Encoding")
        .map(|v| String::from_utf8_lossy(v).trim().to_ascii_lowercase())
        .unwrap_or_default();
    let mut headers = fold_headers(headers)?;

    let body: Vec<u8> = if media.starts_with("multipart/") && boundary.is_some() {
        fix_multipart(body, boundary.as_deref().unwrap_or_default(), depth)?
    } else if !has_long_lines(body) {
        body.to_vec()
    } else if media == "message/rfc822" || media == "message/global" {
        // RFC 2046 §5.2.1: message/rfc822 can't itself be encoded; fix the
        // message inside it instead.
        fix_entity(body, depth + 1, false)?
    } else {
        match cte.as_str() {
            "base64" => rewrap_base64(body),
            "quoted-printable" => soft_break_qp(body),
            "" | "7bit" | "8bit" | "binary" => {
                headers = set_cte(&headers, "quoted-printable", top);
                encode_qp(body)
            }
            _ => return Err(MimeError::CannotReencode),
        }
    };
    let mut out = headers;
    if !out.is_empty() || entity.starts_with(b"\r\n") || !body.is_empty() {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(&body);
    Ok(out)
}

/// RFC 2046 §5.1.1: parts are separated by lines `--boundary`, ended by
/// `--boundary--`; each part is an entity. Preamble and epilogue are kept
/// (their long lines are simply broken, since readers ignore them).
fn fix_multipart(body: &[u8], boundary: &str, depth: usize) -> Result<Vec<u8>, MimeError> {
    let delim = format!("--{boundary}");
    let is_delim = |l: &[u8]| {
        l.strip_prefix(delim.as_bytes()).is_some_and(|rest| {
            rest.iter().all(|b| *b == b' ' || *b == b'\t') || rest.starts_with(b"--")
        })
    };
    let mut out = Vec::with_capacity(body.len() + 256);
    let mut part: Vec<&[u8]> = Vec::new();
    let mut in_part = false;
    let mut closed = false;
    let flush_part = |part: &mut Vec<&[u8]>, out: &mut Vec<u8>| -> Result<(), MimeError> {
        let mut entity = Vec::new();
        for (i, l) in part.iter().enumerate() {
            if i > 0 {
                entity.extend_from_slice(b"\r\n");
            }
            entity.extend_from_slice(l);
        }
        let fixed = fix_entity(&entity, depth + 1, false)?;
        out.extend_from_slice(&fixed);
        out.extend_from_slice(b"\r\n");
        part.clear();
        Ok(())
    };
    for line in lines(body) {
        if !closed && is_delim(line) {
            if in_part {
                flush_part(&mut part, &mut out)?;
            }
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
            in_part = !line
                .get(delim.len()..)
                .is_some_and(|r| r.starts_with(b"--"));
            closed = !in_part;
            continue;
        }
        if in_part {
            part.push(line);
        } else {
            // Preamble or epilogue: break long lines.
            for chunk in line.chunks(MAX_LINE) {
                out.extend_from_slice(chunk);
                out.extend_from_slice(b"\r\n");
            }
        }
    }
    if in_part {
        // Unterminated multipart: still fix the last part.
        flush_part(&mut part, &mut out)?;
    }
    Ok(out)
}

/// Quoted-printable encoding (RFC 2045 §6.7). Line breaks stay CRLF
/// (rule 4); trailing whitespace is encoded (rule 3); lines are kept to 76
/// characters with soft breaks (rule 5).
pub fn encode_qp(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + body.len() / 8);
    let ends_with_crlf = body.ends_with(b"\r\n");
    let all: Vec<&[u8]> = lines(body).collect();
    for (n, line) in all.iter().enumerate() {
        let mut col = 0usize;
        for (i, &b) in line.iter().enumerate() {
            let last = i + 1 == line.len();
            let literal =
                matches!(b, b'!'..=b'<' | b'>'..=b'~') || ((b == b' ' || b == b'\t') && !last);
            let token_len = if literal { 1 } else { 3 };
            // Leave room for the "=" of a soft line break.
            if col + token_len > QP_LINE - 1 {
                out.extend_from_slice(b"=\r\n");
                col = 0;
            }
            if literal {
                out.push(b);
            } else {
                out.extend_from_slice(format!("={b:02X}").as_bytes());
            }
            col += token_len;
        }
        if n + 1 < all.len() || ends_with_crlf {
            out.extend_from_slice(b"\r\n");
        }
    }
    out
}

/// Inserts soft line breaks into over-long quoted-printable lines, never
/// inside an "=XX" escape (RFC 2045 §6.7 rule 5).
fn soft_break_qp(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + body.len() / 32);
    let ends_with_crlf = body.ends_with(b"\r\n");
    let all: Vec<&[u8]> = lines(body).collect();
    for (n, line) in all.iter().enumerate() {
        let mut col = 0usize;
        let mut i = 0usize;
        while let Some(&b) = line.get(i) {
            let token = if b == b'=' {
                line.get(i..(i + 3).min(line.len())).unwrap_or_default()
            } else {
                line.get(i..=i).unwrap_or_default()
            };
            if col + token.len() > QP_LINE - 1 && line.len() > MAX_LINE {
                out.extend_from_slice(b"=\r\n");
                col = 0;
            }
            out.extend_from_slice(token);
            col += token.len();
            i += token.len().max(1);
        }
        if n + 1 < all.len() || ends_with_crlf {
            out.extend_from_slice(b"\r\n");
        }
    }
    out
}

/// Re-wraps base64 at 76 characters per line (RFC 2045 §6.8).
fn rewrap_base64(body: &[u8]) -> Vec<u8> {
    let chars: Vec<u8> = body
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(chars.len() + chars.len() / 38 + 2);
    for chunk in chars.chunks(QP_LINE) {
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long(n: usize) -> String {
        "x".repeat(n)
    }

    fn max_line(b: &[u8]) -> usize {
        lines(b).map(<[u8]>::len).max().unwrap_or(0)
    }

    #[test]
    fn compliant_messages_are_untouched() {
        let m = b"From: a@b\r\nSubject: hi\r\n\r\nshort\r\n";
        assert!(matches!(fix_long_lines(m), Ok(Cow::Borrowed(_))));
    }

    #[test]
    fn plain_text_becomes_quoted_printable() {
        let m = format!(
            "From: a@b\r\nSubject: hi\r\n\r\n{} end\r\nnext=line \r\n",
            long(2000)
        );
        let out = fix_long_lines(m.as_bytes()).unwrap().into_owned();
        assert!(max_line(&out) <= 76, "{}", max_line(&out));
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains(
                "MIME-Version: 1.0\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
            ),
            "{text}"
        );
        // '=' is escaped, trailing space is encoded, hard breaks stay.
        assert!(text.contains("next=3Dline=20\r\n"), "{text}");
    }

    #[test]
    fn existing_cte_is_replaced() {
        let m = format!(
            "MIME-Version: 1.0\r\nContent-Transfer-Encoding: 8bit\r\nSubject: x\r\n\r\n{}\r\n",
            long(1500)
        );
        let text = String::from_utf8(fix_long_lines(m.as_bytes()).unwrap().into_owned()).unwrap();
        assert_eq!(text.matches("Content-Transfer-Encoding").count(), 1);
        assert_eq!(text.matches("MIME-Version").count(), 1);
        assert!(text.contains("Content-Transfer-Encoding: quoted-printable"));
    }

    #[test]
    fn multipart_parts_fixed_individually() {
        let m = format!(
            "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n\
             preamble\r\n--b1\r\nContent-Type: text/plain\r\n\r\nshort part\r\n\
             --b1\r\nContent-Type: text/html\r\n\r\n{}\r\n--b1--\r\nepilogue\r\n",
            long(3000)
        );
        let text = String::from_utf8(fix_long_lines(m.as_bytes()).unwrap().into_owned()).unwrap();
        assert!(max_line(text.as_bytes()) <= MAX_LINE);
        assert!(
            text.contains("--b1\r\nContent-Type: text/plain\r\n\r\nshort part\r\n--b1\r\n"),
            "first part untouched:\n{text}"
        );
        assert!(
            text.contains(
                "Content-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n"
            ),
            "{text}"
        );
        assert!(text.ends_with("--b1--\r\nepilogue\r\n"));
    }

    #[test]
    fn base64_is_rewrapped() {
        let b64 = "QUJD".repeat(500);
        let m = format!(
            "Content-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\n{b64}\r\n"
        );
        let out = fix_long_lines(m.as_bytes()).unwrap().into_owned();
        assert_eq!(max_line(&out), 76);
        let joined: String = String::from_utf8(out)
            .unwrap()
            .split("\r\n\r\n")
            .nth(1)
            .unwrap()
            .replace("\r\n", "");
        assert_eq!(joined, b64);
    }

    #[test]
    fn long_header_lines_are_folded() {
        let words: Vec<String> = (0..300).map(|i| format!("word{i}")).collect();
        let m = format!("Subject: {}\r\n\r\nbody\r\n", words.join(" "));
        let out = fix_long_lines(m.as_bytes()).unwrap().into_owned();
        assert!(max_line(&out) <= MAX_LINE);
        // Unfolding gives the original header back (RFC 5322 §2.2.3).
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.replace("\r\n ", " "), m);
        let unbreakable = format!("Subject: {}\r\n\r\nbody\r\n", long(1200));
        assert_eq!(
            fix_long_lines(unbreakable.as_bytes()),
            Err(MimeError::HeaderLineTooLong)
        );
    }

    #[test]
    fn unknown_encoding_is_refused() {
        let m = format!(
            "Content-Transfer-Encoding: x-custom\r\n\r\n{}\r\n",
            long(1200)
        );
        assert_eq!(fix_long_lines(m.as_bytes()), Err(MimeError::CannotReencode));
    }

    #[test]
    fn qp_round_trip_shape() {
        let enc = encode_qp(b"caf\xc3\xa9 = ok\t\r\n");
        assert_eq!(enc, b"caf=C3=A9 =3D ok=09\r\n");
    }
}
