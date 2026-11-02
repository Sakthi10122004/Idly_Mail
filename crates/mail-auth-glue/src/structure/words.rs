//! Encoded-words in header fields (RFC 2047): `=?charset?B|Q?text?=`.

use super::decode::{base64, charset_to_utf8};
use super::params::hex;

/// Decodes the encoded-words in an unstructured header value (and
/// unfolds it: RFC 5322 §2.2.3). Whitespace between two adjacent
/// encoded-words is dropped (RFC 2047 §6.2); anything malformed stays as
/// written. Raw 8-bit text is read as UTF-8 (RFC 6532).
pub fn decode(raw: &[u8]) -> String {
    let text = unfold(raw);
    let mut out = String::with_capacity(text.len());
    let mut last_was_word = false;
    let mut rest = text.as_str();
    while !rest.is_empty() {
        let ws_len = rest
            .find(|c: char| c != ' ' && c != '\t')
            .unwrap_or(rest.len());
        let (ws, after) = rest.split_at(ws_len);
        if after.is_empty() {
            out.push_str(ws);
            break;
        }
        let word_len = after.find([' ', '\t']).unwrap_or(after.len());
        let (word, tail) = after.split_at(word_len);
        match decode_word(word) {
            Some(decoded) => {
                // RFC 2047 §6.2: drop space between adjacent encoded-words.
                if !last_was_word {
                    out.push_str(ws);
                }
                out.push_str(&decoded);
                last_was_word = true;
            }
            None => {
                out.push_str(ws);
                out.push_str(word);
                last_was_word = false;
            }
        }
        rest = tail;
    }
    out
}

/// RFC 5322 §2.2.3: remove the CRLF of folded lines; also trims.
pub fn unfold(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c != '\r' && c != '\n' {
            out.push(c);
        }
    }
    out.trim().to_owned()
}

/// One `=?charset[*lang]?enc?text?=` (RFC 2047 §2, RFC 2231 §5).
fn decode_word(word: &str) -> Option<String> {
    let inner = word.strip_prefix("=?")?.strip_suffix("?=")?;
    let mut parts = inner.splitn(3, '?');
    let charset = parts.next()?;
    let enc = parts.next()?;
    let text = parts.next()?;
    if charset.is_empty() || text.contains('?') && !enc.eq_ignore_ascii_case("q") {
        return None;
    }
    let charset = charset.split('*').next().unwrap_or(charset);
    let bytes = if enc.eq_ignore_ascii_case("b") {
        base64(text.as_bytes())
    } else if enc.eq_ignore_ascii_case("q") {
        q_decode(text.as_bytes())
    } else {
        return None;
    };
    Some(charset_to_utf8(&bytes, charset))
}

/// RFC 2047 §4.2: "_" is a space, `=XX` an octet.
fn q_decode(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        match c {
            b'_' => out.push(b' '),
            b'=' => {
                if let (Some(h), Some(l)) = (
                    b.get(i + 1).and_then(|x| hex(*x)),
                    b.get(i + 2).and_then(|x| hex(*x)),
                ) {
                    out.push(h << 4 | l);
                    i += 3;
                    continue;
                }
                out.push(c);
            }
            _ => out.push(c),
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc2047_examples() {
        // RFC 2047 §8.
        assert_eq!(decode(b"=?ISO-8859-1?Q?a?="), "a");
        assert_eq!(decode(b"=?ISO-8859-1?Q?a?= b"), "a b");
        assert_eq!(decode(b"=?ISO-8859-1?Q?a?= =?ISO-8859-1?Q?b?="), "ab");
        assert_eq!(
            decode(b"=?ISO-8859-1?Q?a?=  \r\n  =?ISO-8859-1?Q?b?="),
            "ab"
        );
        assert_eq!(decode(b"=?ISO-8859-1?Q?a_b?="), "a b");
        assert_eq!(decode(b"=?ISO-8859-1?Q?a?= =?ISO-8859-2?Q?_b?="), "a b");
        assert_eq!(
            decode(b"=?US-ASCII?Q?Keith_Moore?= <moore@cs.utk.edu>"),
            "Keith Moore <moore@cs.utk.edu>"
        );
        assert_eq!(decode(b"=?UTF-8?B?w6l0w6k=?= ok"), "\u{e9}t\u{e9} ok");
        assert_eq!(decode(b"=?utf-8*en?q?hi?="), "hi");
    }

    #[test]
    fn malformed_words_stay() {
        assert_eq!(decode(b"=?x?y?z?= =?broken"), "=?x?y?z?= =?broken");
        assert_eq!(decode(b"  plain\r\n text  "), "plain text");
        assert_eq!(decode("caf\u{e9}".as_bytes()), "caf\u{e9}");
    }
}
