//! Modified UTF-7 mailbox names (RFC 3501 §5.1.3), for IMAP4rev1 clients
//! that haven't enabled UTF-8 (RFC 9051 §5.1 and Appendix E: IMAP4rev2
//! and UTF8=ACCEPT use UTF-8 directly).

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

/// UTF-8 to modified UTF-7.
pub fn encode(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut pending: Vec<u16> = Vec::new();
    let flush = |pending: &mut Vec<u16>, out: &mut String| {
        if pending.is_empty() {
            return;
        }
        out.push('&');
        let bytes: Vec<u8> = pending.iter().flat_map(|u| u.to_be_bytes()).collect();
        let mut acc = 0u32;
        let mut bits = 0u32;
        for b in bytes {
            acc = (acc << 8) | u32::from(b);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                let i = ((acc >> bits) & 0x3f) as usize;
                out.push(char::from(ALPHABET.get(i).copied().unwrap_or(b'A')));
            }
        }
        if bits > 0 {
            let i = ((acc << (6 - bits)) & 0x3f) as usize;
            out.push(char::from(ALPHABET.get(i).copied().unwrap_or(b'A')));
        }
        out.push('-');
        pending.clear();
    };
    for c in name.chars() {
        if (' '..='~').contains(&c) {
            flush(&mut pending, &mut out);
            if c == '&' {
                out.push_str("&-");
            } else {
                out.push(c);
            }
        } else {
            let mut buf = [0u16; 2];
            pending.extend_from_slice(c.encode_utf16(&mut buf));
        }
    }
    flush(&mut pending, &mut out);
    out
}

/// Modified UTF-7 to UTF-8; None if it is malformed.
pub fn decode(name: &[u8]) -> Option<String> {
    let mut out = String::with_capacity(name.len());
    let mut i = 0usize;
    while let Some(&b) = name.get(i) {
        if b != b'&' {
            if !(0x20..=0x7e).contains(&b) {
                return None;
            }
            out.push(char::from(b));
            i += 1;
            continue;
        }
        let end = name.get(i + 1..)?.iter().position(|c| *c == b'-')? + i + 1;
        let chunk = name.get(i + 1..end)?;
        i = end + 1;
        if chunk.is_empty() {
            out.push('&');
            continue;
        }
        let mut acc = 0u32;
        let mut bits = 0u32;
        let mut units = Vec::new();
        let mut bytes = Vec::new();
        for &c in chunk {
            let v = ALPHABET.iter().position(|a| *a == c)? as u32;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                bytes.push(((acc >> bits) & 0xff) as u8);
            }
        }
        if bytes.len() % 2 != 0 {
            return None;
        }
        for pair in bytes.chunks(2) {
            if let [hi, lo] = pair {
                units.push(u16::from_be_bytes([*hi, *lo]));
            }
        }
        let s = String::from_utf16(&units).ok()?;
        // Printable ASCII must not be encoded (RFC 3501 §5.1.3).
        if s.chars().any(|c| (' '..='~').contains(&c)) {
            return None;
        }
        out.push_str(&s);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3501_example_and_round_trips() {
        // RFC 3501 §5.1.3.
        assert_eq!(encode("~peter/mail/台北/日本語"), "~peter/mail/&U,BTFw-/&ZeVnLIqe-");
        assert_eq!(
            decode(b"~peter/mail/&U,BTFw-/&ZeVnLIqe-").as_deref(),
            Some("~peter/mail/台北/日本語")
        );
        for s in ["Entwürfe", "a&b", "Ünïcödé 🎉", "plain", ""] {
            assert_eq!(decode(encode(s).as_bytes()).as_deref(), Some(s), "{s}");
        }
        assert_eq!(encode("a&b"), "a&-b");
    }

    #[test]
    fn malformed() {
        for bad in [&b"&"[..], b"&AGE", b"&!!-", b"&AGEA-", b"\xff", b"&AEE-"] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
    }
}
