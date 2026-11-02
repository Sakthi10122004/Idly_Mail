//! Writing responses: strings in the safest form the data allows
//! (RFC 9051 §4.3), and flag lists.

use crate::command::Flag;

/// Appends `s` as an IMAP string: quoted when it is short, printable and
/// free of CR/LF, otherwise a literal (`{n}` CRLF data).
pub fn string(out: &mut Vec<u8>, s: &[u8]) {
    let quotable = s.len() <= 1024
        && s.iter().all(|b| *b != b'\r' && *b != b'\n' && *b != 0)
        && (std::str::from_utf8(s).is_ok());
    if quotable {
        out.push(b'"');
        for &b in s {
            if b == b'"' || b == b'\\' {
                out.push(b'\\');
            }
            out.push(b);
        }
        out.push(b'"');
    } else {
        literal(out, s);
    }
}

/// A literal, always.
pub fn literal(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(format!("{{{}}}\r\n", s.len()).as_bytes());
    out.extend_from_slice(s);
}

/// `nstring`: NIL or a string.
pub fn nstring(out: &mut Vec<u8>, s: Option<&[u8]>) {
    match s {
        Some(s) => string(out, s),
        None => out.extend_from_slice(b"NIL"),
    }
}

/// An astring: the bare atom when possible, else a string.
pub fn astring(out: &mut Vec<u8>, s: &[u8]) {
    if !s.is_empty() && s.iter().all(|b| crate::parse::is_astring_char(*b)) && !s.eq_ignore_ascii_case(b"NIL") {
        out.extend_from_slice(s);
    } else {
        string(out, s);
    }
}

/// `(\Seen $Label)`.
pub fn flag_list(out: &mut Vec<u8>, flags: &[Flag]) {
    out.push(b'(');
    for (i, f) in flags.iter().enumerate() {
        if i > 0 {
            out.push(b' ');
        }
        out.extend_from_slice(f.as_wire().as_bytes());
    }
    out.push(b')');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(f: impl Fn(&mut Vec<u8>)) -> String {
        let mut v = Vec::new();
        f(&mut v);
        String::from_utf8(v).unwrap()
    }

    #[test]
    fn strings_choose_their_form() {
        assert_eq!(s(|o| string(o, b"a \"b\" \\")), "\"a \\\"b\\\" \\\\\"");
        assert_eq!(s(|o| string(o, b"two\r\nlines")), "{10}\r\ntwo\r\nlines");
        assert_eq!(s(|o| nstring(o, None)), "NIL");
        assert_eq!(s(|o| astring(o, b"INBOX")), "INBOX");
        assert_eq!(s(|o| astring(o, b"My Box")), "\"My Box\"");
        assert_eq!(s(|o| astring(o, b"nil")), "\"nil\"");
        assert_eq!(s(|o| astring(o, b"")), "\"\"");
        assert_eq!(
            s(|o| flag_list(o, &[Flag::Seen, Flag::Keyword("$Fw".into())])),
            "(\\Seen $Fw)"
        );
    }
}
