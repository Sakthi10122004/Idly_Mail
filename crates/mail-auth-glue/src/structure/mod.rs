//! The MIME structure of a message (RFC 2045, RFC 2046), for IMAP
//! (BODYSTRUCTURE and ENVELOPE, RFC 9051 §7.5.2; section numbers,
//! §6.4.5) and JMAP (bodyStructure, RFC 8621 §4.1.4).
//!
//! [`parse`] never fails: mail in the store must always be readable, so
//! malformed input gives a best-effort tree. Every part records byte
//! ranges into the original message, so any section can be served
//! verbatim. Nesting and the number of parts are bounded.

pub mod address;
pub mod decode;
pub mod params;
pub mod words;

use std::ops::Range;

pub use address::{Address, Mailbox};
pub use params::Parameterized;

/// How deeply multiparts and message/rfc822 may nest.
pub const MAX_DEPTH: usize = 32;
/// The most parts in one message; the rest are not parsed.
pub const MAX_PARTS: usize = 2_000;

/// One header field: the name as written and the raw value (folding
/// included, final line break excluded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub value: Vec<u8>,
}

/// A MIME entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// The header section, including the empty line that ends it.
    pub header: Range<usize>,
    /// The body (as encoded).
    pub body: Range<usize>,
    pub fields: Vec<Field>,
    /// Lower-case media type and subtype; text/plain if absent or broken
    /// (RFC 2045 §5.2).
    pub media_type: String,
    pub media_subtype: String,
    /// Content-Type parameters, as written.
    pub params: Parameterized,
    /// Content-Transfer-Encoding, as written; "7BIT" if absent
    /// (RFC 2045 §6.1).
    pub encoding: String,
    pub id: Option<String>,
    pub description: Option<String>,
    pub disposition: Option<Parameterized>,
    pub language: Vec<String>,
    pub location: Option<String>,
    pub md5: Option<String>,
    /// Lines in the body (RFC 9051 §7.5.2, for text/* and message/rfc822).
    pub lines: usize,
    pub kind: Kind,
}

/// What the part contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Leaf,
    Multipart(Vec<Part>),
    /// message/rfc822 (or message/global, RFC 6532 §3.7): the embedded
    /// message's envelope and structure.
    Message(Box<(Envelope, Part)>),
}

impl Part {
    /// The first field named `name`, case-insensitive.
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name.eq_ignore_ascii_case(name))
    }

    /// `type/subtype`.
    pub fn mime_type(&self) -> String {
        format!("{}/{}", self.media_type, self.media_subtype)
    }

    pub fn is_multipart(&self) -> bool {
        matches!(self.kind, Kind::Multipart(_))
    }

    /// The charset parameter, if any.
    pub fn charset(&self) -> Option<String> {
        self.params.param("charset")
    }

    /// The file name: Content-Disposition `filename`, else Content-Type
    /// `name` (RFC 2183 §2.3), with RFC 2231 and (non-standard but common)
    /// RFC 2047 encodings undone.
    pub fn filename(&self) -> Option<String> {
        self.disposition
            .as_ref()
            .and_then(|d| d.param("filename"))
            .or_else(|| self.params.param("name"))
            .map(|n| words::decode(n.as_bytes()))
            .filter(|n| !n.is_empty())
    }

    /// The body with its transfer encoding undone.
    pub fn decoded_body(&self, message: &[u8]) -> Vec<u8> {
        let raw = message.get(self.body.clone()).unwrap_or_default();
        decode::transfer_decode(raw, &self.encoding)
    }

    /// The body as text: transfer encoding and charset undone.
    pub fn text(&self, message: &[u8]) -> String {
        decode::charset_to_utf8(
            &self.decoded_body(message),
            &self.charset().unwrap_or_default(),
        )
    }

    /// The part at an IMAP section path such as `[1, 2]` (RFC 9051
    /// §6.4.5): numbers index into multiparts, and into the body of an
    /// embedded message.
    pub fn section(&self, path: &[u32]) -> Option<&Part> {
        let Some((&first, rest)) = path.split_first() else {
            return Some(self);
        };
        let idx = usize::try_from(first.checked_sub(1)?).ok()?;
        let child = match &self.kind {
            Kind::Multipart(parts) => parts.get(idx)?,
            Kind::Message(m) => return m.1.section(path),
            // A non-multipart part has only part 1: itself.
            Kind::Leaf if idx == 0 => self,
            Kind::Leaf => return None,
        };
        child.section(rest)
    }

    /// Every part, depth first, the root first.
    pub fn walk(&self) -> Vec<&Part> {
        let mut out = vec![self];
        match &self.kind {
            Kind::Leaf => {}
            Kind::Multipart(parts) => {
                for p in parts {
                    out.extend(p.walk());
                }
            }
            Kind::Message(m) => out.extend(m.1.walk()),
        }
        out
    }
}

/// The ENVELOPE of a message (RFC 9051 §7.5.2): the raw, unfolded values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Envelope {
    pub date: Option<String>,
    pub subject: Option<String>,
    pub from: Vec<Address>,
    /// Sender and Reply-To are the From addresses when absent or empty.
    pub sender: Vec<Address>,
    pub reply_to: Vec<Address>,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub bcc: Vec<Address>,
    pub in_reply_to: Option<String>,
    pub message_id: Option<String>,
}

impl Envelope {
    pub fn from_fields(fields: &[Field]) -> Self {
        let get = |name: &str| {
            fields
                .iter()
                .find(|f| f.name.eq_ignore_ascii_case(name))
                .map(|f| f.value.as_slice())
        };
        let text = |name: &str| get(name).map(words::unfold);
        let list = |name: &str| get(name).map(address::parse_list).unwrap_or_default();
        let from = list("From");
        let or_from = |l: Vec<Address>| if l.is_empty() { from.clone() } else { l };
        Self {
            date: text("Date"),
            subject: text("Subject"),
            sender: or_from(list("Sender")),
            reply_to: or_from(list("Reply-To")),
            to: list("To"),
            cc: list("Cc"),
            bcc: list("Bcc"),
            in_reply_to: text("In-Reply-To"),
            message_id: text("Message-ID"),
            from,
        }
    }
}

/// Parses a whole message.
pub fn parse(message: &[u8]) -> Part {
    let mut budget = MAX_PARTS;
    entity(message, 0..message.len(), 0, false, &mut budget)
}

/// The envelope of a whole message.
pub fn envelope(message: &[u8]) -> Envelope {
    let (_, fields) = split_header(message, 0..message.len());
    Envelope::from_fields(&fields)
}

/// Splits `range` of `msg` into the header end offset and the fields.
/// The header section ends at the first empty line (RFC 5322 §2.1); CRLF
/// and, leniently, bare LF line ends are accepted.
pub fn split_header(msg: &[u8], range: Range<usize>) -> (usize, Vec<Field>) {
    let mut fields: Vec<Field> = Vec::new();
    let mut pos = range.start;
    let end = range.end.min(msg.len());
    while pos < end {
        let line_end = msg
            .get(pos..end)
            .and_then(|r| r.iter().position(|b| *b == b'\n'))
            .map_or(end, |i| pos + i + 1);
        let line = msg.get(pos..line_end).unwrap_or_default();
        let content = line
            .strip_suffix(b"\n")
            .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
            .unwrap_or(line);
        if content.is_empty() {
            return (line_end, fields);
        }
        if matches!(content.first(), Some(b' ' | b'\t')) {
            // A continuation line (RFC 5322 §2.2.3).
            if let Some(last) = fields.last_mut() {
                last.value.extend_from_slice(b"\r\n");
                last.value.extend_from_slice(content);
            }
        } else if let Some(colon) = content.iter().position(|b| *b == b':') {
            let name = content.get(..colon).unwrap_or_default();
            let name = String::from_utf8_lossy(name).trim_end().to_owned();
            if !name.is_empty() && !name.contains(' ') {
                fields.push(Field {
                    name,
                    value: content.get(colon + 1..).unwrap_or_default().to_vec(),
                });
            }
        }
        pos = line_end;
    }
    (end, fields)
}

fn entity(
    msg: &[u8],
    range: Range<usize>,
    depth: usize,
    digest_child: bool,
    budget: &mut usize,
) -> Part {
    *budget = budget.saturating_sub(1);
    let (header_end, fields) = split_header(msg, range.clone());
    let header = range.start..header_end;
    let body = header_end..range.end;
    let field = |name: &str| fields.iter().find(|f| f.name.eq_ignore_ascii_case(name));
    let text = |name: &str| field(name).map(|f| words::unfold(&f.value));

    let mut params = Parameterized::default();
    // RFC 2045 §5.2 / RFC 2046 §5.1.5: defaults.
    let (mut media_type, mut media_subtype) = if digest_child {
        ("message".to_owned(), "rfc822".to_owned())
    } else {
        ("text".to_owned(), "plain".to_owned())
    };
    if let Some(f) = field("Content-Type") {
        let p = Parameterized::parse(&f.value);
        if let Some((t, s)) = p.value.split_once('/') {
            let (t, s) = (t.trim(), s.trim());
            if !t.is_empty() && !s.is_empty() && !t.contains(' ') && !s.contains(' ') {
                media_type = t.to_ascii_lowercase();
                media_subtype = s.to_ascii_lowercase();
                params = p;
            }
        }
    }
    if media_type == "text" && media_subtype == "plain" && params.param("charset").is_none() && !digest_child && field("Content-Type").is_none() {
        params.params.push(("charset".into(), "us-ascii".into()));
    }
    let encoding = text("Content-Transfer-Encoding")
        .filter(|e| !e.is_empty())
        .unwrap_or_else(|| "7BIT".into());
    let disposition = field("Content-Disposition")
        .map(|f| Parameterized::parse(&f.value))
        .filter(|d| !d.value.is_empty());
    let language = text("Content-Language")
        .map(|l| {
            l.split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let body_bytes = msg.get(body.clone()).unwrap_or_default();
    let lines = count_lines(body_bytes);
    let can_nest = depth < MAX_DEPTH && *budget > 0;
    let kind = if media_type == "multipart" && can_nest {
        let digest = media_subtype == "digest";
        match params.param("boundary").filter(|b| !b.is_empty()) {
            Some(boundary) => {
                let ranges = split_multipart(msg, body.clone(), boundary.as_bytes());
                let mut parts = Vec::new();
                for r in ranges {
                    if *budget == 0 {
                        break;
                    }
                    parts.push(entity(msg, r, depth + 1, digest, budget));
                }
                Kind::Multipart(parts)
            }
            None => Kind::Multipart(Vec::new()),
        }
    } else if media_type == "message"
        && (media_subtype == "rfc822" || media_subtype == "global")
        && can_nest
        && !matches!(
            encoding.to_ascii_lowercase().as_str(),
            "base64" | "quoted-printable"
        )
    {
        let inner = entity(msg, body.clone(), depth + 1, false, budget);
        let envelope = Envelope::from_fields(&inner.fields);
        Kind::Message(Box::new((envelope, inner)))
    } else {
        Kind::Leaf
    };

    Part {
        header,
        body,
        media_type,
        media_subtype,
        params,
        encoding,
        id: text("Content-ID"),
        description: text("Content-Description"),
        disposition,
        language,
        location: text("Content-Location"),
        md5: text("Content-MD5"),
        lines,
        kind,
        fields,
    }
}

/// Lines in a body: line breaks, plus one for a final unterminated line.
fn count_lines(b: &[u8]) -> usize {
    let breaks = b.iter().filter(|c| **c == b'\n').count();
    if b.is_empty() || b.ends_with(b"\n") {
        breaks
    } else {
        breaks + 1
    }
}

/// The body parts of a multipart (RFC 2046 §5.1.1). A delimiter line is
/// `--boundary` (closing: `--boundary--`) with optional trailing space;
/// the line break before it belongs to the delimiter. Preamble and
/// epilogue are dropped. A missing close delimiter ends the last part at
/// the end of the body.
fn split_multipart(msg: &[u8], body: Range<usize>, boundary: &[u8]) -> Vec<Range<usize>> {
    let mut delim = Vec::with_capacity(boundary.len() + 2);
    delim.extend_from_slice(b"--");
    delim.extend_from_slice(boundary);
    let mut parts = Vec::new();
    let mut current: Option<usize> = None;
    let mut pos = body.start;
    let end = body.end.min(msg.len());
    while pos < end {
        let line_end = msg
            .get(pos..end)
            .and_then(|r| r.iter().position(|b| *b == b'\n'))
            .map_or(end, |i| pos + i + 1);
        let line = msg.get(pos..line_end).unwrap_or_default();
        if let Some(rest) = line.strip_prefix(delim.as_slice()) {
            let (closing, rest) = match rest.strip_prefix(b"--") {
                Some(r) => (true, r),
                None => (false, rest),
            };
            if rest.iter().all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n')) {
                if let Some(start) = current.take() {
                    // Drop the line break that precedes the delimiter.
                    let mut stop = pos;
                    if stop > start && msg.get(stop - 1) == Some(&b'\n') {
                        stop -= 1;
                        if stop > start && msg.get(stop - 1) == Some(&b'\r') {
                            stop -= 1;
                        }
                    }
                    parts.push(start..stop.max(start));
                }
                if closing {
                    return parts;
                }
                current = Some(line_end);
            }
        }
        pos = line_end;
    }
    if let Some(start) = current {
        parts.push(start..end.max(start));
    }
    parts
}

#[cfg(test)]
mod tests;
