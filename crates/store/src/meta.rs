//! What the store keeps from a message's content: threading ids,
//! subject, addresses, dates and a preview, for listing, sorting and JMAP.

use mail_auth_glue::structure::{self, Kind, Part, address, date, words};

/// Longest preview (RFC 8621 §4.1.4: up to 256 characters).
const PREVIEW: usize = 256;
/// Most Message-IDs taken from References.
const MAX_REFS: usize = 100;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Meta {
    /// The Message-ID without angle brackets.
    pub message_id: Option<String>,
    /// In-Reply-To and References ids, nearest ancestor first.
    pub parents: Vec<String>,
    pub subject: String,
    pub sender: String,
    pub recipients: String,
    pub sent: Option<i64>,
    pub preview: String,
    pub has_attachment: bool,
}

/// `<a@b>` tokens of a msg-id list (RFC 5322 §3.6.4).
pub(crate) fn msg_ids(value: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(value);
    let mut out = Vec::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find('<') {
        let after = rest.get(start + 1..).unwrap_or_default();
        let Some(end) = after.find('>') else { break };
        let id = after.get(..end).unwrap_or_default().trim();
        if !id.is_empty() && !id.contains(char::is_whitespace) && out.len() < MAX_REFS {
            out.push(id.to_owned());
        }
        rest = after.get(end + 1..).unwrap_or_default();
    }
    out
}

pub(crate) fn extract(raw: &[u8]) -> Meta {
    let root = structure::parse(raw);
    let field = |name: &str| root.field(name).map(|f| f.value.as_slice());
    let message_id = field("Message-ID").and_then(|v| msg_ids(v).into_iter().next());
    let mut parents = field("In-Reply-To").map(msg_ids).unwrap_or_default();
    // References lists the oldest first; take the nearest first.
    let mut refs = field("References").map(msg_ids).unwrap_or_default();
    refs.reverse();
    for r in refs {
        if !parents.contains(&r) {
            parents.push(r);
        }
    }
    parents.truncate(MAX_REFS);
    let subject = field("Subject").map(words::decode).unwrap_or_default();
    let names = |name: &str| {
        let list = field(name).map(address::parse_list).unwrap_or_default();
        address::mailboxes(&list)
            .iter()
            .map(|m| match m.display_name() {
                Some(n) => format!("{n} <{}>", m.email()),
                None => m.email(),
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut recipients = names("To");
    let cc = names("Cc");
    if !cc.is_empty() {
        if !recipients.is_empty() {
            recipients.push_str(", ");
        }
        recipients.push_str(&cc);
    }
    Meta {
        message_id,
        parents,
        subject,
        sender: names("From"),
        recipients,
        sent: field("Date").and_then(|v| date::parse(&String::from_utf8_lossy(v))),
        preview: preview(&root, raw),
        has_attachment: root.walk().iter().any(|p| is_attachment(p)),
    }
}

/// An explicit attachment, or a non-text leaf that isn't inline.
pub(crate) fn is_attachment(p: &Part) -> bool {
    if !matches!(p.kind, Kind::Leaf) {
        return false;
    }
    match &p.disposition {
        Some(d) if d.value.eq_ignore_ascii_case("attachment") => true,
        Some(d) if d.value.eq_ignore_ascii_case("inline") => false,
        _ => p.media_type != "text" && p.media_type != "multipart",
    }
}

/// The first text/plain part (or text/html, tags stripped), whitespace
/// collapsed, cut to [`PREVIEW`] characters.
fn preview(root: &Part, raw: &[u8]) -> String {
    let parts = root.walk();
    let pick = parts
        .iter()
        .find(|p| p.mime_type() == "text/plain" && !is_attachment(p))
        .or_else(|| {
            parts
                .iter()
                .find(|p| p.mime_type() == "text/html" && !is_attachment(p))
        });
    let Some(part) = pick else {
        return String::new();
    };
    // Don't decode more than needed.
    let mut text = part.text(raw);
    if part.media_subtype == "html" {
        text = strip_tags(&text);
    }
    let mut out = String::new();
    for word in text.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
        if out.chars().count() >= PREVIEW {
            break;
        }
    }
    out.chars().take(PREVIEW).collect()
}

fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_threading_and_listing_fields() {
        let m = extract(
            b"From: =?utf-8?q?Ren=C3=A9?= <r@x.test>\r\nTo: a@x.test\r\nCc: B <b@x.test>\r\n\
Subject: Re: hello\r\nMessage-ID: <m3@x.test>\r\nIn-Reply-To: <m2@x.test>\r\n\
References: <m1@x.test> <m2@x.test>\r\nDate: Mon, 2 Nov 2026 10:00:00 +0000\r\n\
Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\n  Hello\r\n  there  \r\n--b\r\n\
Content-Type: application/pdf\r\n\r\nx\r\n--b--\r\n",
        );
        assert_eq!(m.message_id.as_deref(), Some("m3@x.test"));
        assert_eq!(m.parents, ["m2@x.test", "m1@x.test"]);
        assert_eq!(m.subject, "Re: hello");
        assert_eq!(m.sender, "Ren\u{e9} <r@x.test>");
        assert_eq!(m.recipients, "a@x.test, B <b@x.test>");
        assert_eq!(m.sent, Some(1_793_613_600));
        assert_eq!(m.preview, "Hello there");
        assert!(m.has_attachment);
    }

    #[test]
    fn html_preview_and_empty_message() {
        let m = extract(b"Content-Type: text/html\r\n\r\n<p>Hi&nbsp;<b>you</b></p>");
        assert_eq!(m.preview, "Hi you");
        assert_eq!(extract(b""), Meta::default());
    }
}
