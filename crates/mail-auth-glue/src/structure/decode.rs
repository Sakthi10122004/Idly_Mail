//! Undoing transfer encodings (RFC 2045 §6) and charsets. All decoders are
//! lenient: mail in the wild is often slightly broken, and a reader should
//! still see what can be seen.

use encoding_rs::Encoding;

use super::params::hex;

/// The body of a part with its Content-Transfer-Encoding undone. Unknown
/// encodings are returned as they are (RFC 2045 §6.4: treat as
/// application/octet-stream).
pub fn transfer_decode(body: &[u8], encoding: &str) -> Vec<u8> {
    if encoding.eq_ignore_ascii_case("base64") {
        base64(body)
    } else if encoding.eq_ignore_ascii_case("quoted-printable") {
        quoted_printable(body)
    } else {
        body.to_vec()
    }
}

/// RFC 2045 §6.8: characters outside the alphabet are ignored, and
/// decoding stops at the pad character.
pub fn base64(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in input {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => continue,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    out
}

/// RFC 2045 §6.7: `=XX` escapes and `=` soft line breaks; a broken escape
/// is kept literally (rule 6 suggests that robustness).
pub fn quoted_printable(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while let Some(&c) = input.get(i) {
        if c != b'=' {
            out.push(c);
            i += 1;
            continue;
        }
        match (input.get(i + 1), input.get(i + 2)) {
            (Some(b'\r'), Some(b'\n')) => i += 3,
            (Some(b'\n'), _) => i += 2,
            (Some(&h), Some(&l)) => match (hex(h), hex(l)) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 3;
                }
                _ => {
                    out.push(c);
                    i += 1;
                }
            },
            _ => {
                // "=" at the very end, or followed by trailing space.
                let rest = input.get(i + 1..).unwrap_or_default();
                if rest.iter().all(|b| *b == b' ' || *b == b'\t') {
                    break;
                }
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Decodes text in `charset` to UTF-8. Unknown or empty charsets are read
/// as UTF-8 with replacement characters (RFC 6532 makes UTF-8 the norm).
pub fn charset_to_utf8(bytes: &[u8], charset: &str) -> String {
    let charset = charset.trim();
    // RFC 2045 §5.2: us-ascii is the default; read it as UTF-8 so stray
    // 8-bit text is still shown.
    if charset.is_empty() || charset.eq_ignore_ascii_case("us-ascii") {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    match Encoding::for_label(charset.as_bytes()) {
        Some(enc) => enc.decode_without_bom_handling(bytes).0.into_owned(),
        None => String::from_utf8_lossy(bytes).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_is_lenient() {
        assert_eq!(base64(b"SGVs\r\nbG8=\r\n"), b"Hello");
        assert_eq!(base64(b"SGVsbG8gd29ybGQ"), b"Hello world");
        assert_eq!(base64(b"!!!S G V s\nbG8"), b"Hello");
        assert!(base64(b"").is_empty());
    }

    #[test]
    fn quoted_printable_rules() {
        assert_eq!(quoted_printable(b"caf=C3=A9 =\r\nok"), "caf\u{e9} ok".as_bytes());
        assert_eq!(quoted_printable(b"a=\nb"), b"ab");
        assert_eq!(quoted_printable(b"100=%"), b"100=%");
        assert_eq!(quoted_printable(b"x=zz"), b"x=zz");
        assert_eq!(quoted_printable(b"end= "), b"end");
        assert_eq!(quoted_printable(b"="), b"");
    }

    #[test]
    fn charsets() {
        assert_eq!(charset_to_utf8(b"caf\xe9", "ISO-8859-1"), "caf\u{e9}");
        assert_eq!(charset_to_utf8(b"\x82\xa0", "shift_jis"), "\u{3042}");
        assert_eq!(charset_to_utf8(b"ok\xff", "x-unknown"), "ok\u{fffd}");
        assert_eq!(charset_to_utf8("é".as_bytes(), ""), "é");
    }
}
