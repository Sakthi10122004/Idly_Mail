//! Lexical pieces of the IMAP grammar (RFC 9051 §9): atoms, strings,
//! literals, numbers, sequence sets, dates. A [`Cursor`] walks one framed
//! command; nothing here panics or allocates without bound.

use std::fmt;

/// A parse failure; the message goes into a tagged BAD response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub type Result<T> = std::result::Result<T, ParseError>;

pub(crate) fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(ParseError(msg.into()))
}

/// RFC 9051 §9: `atom-specials`, plus CTLs and space.
pub fn is_atom_char(b: u8) -> bool {
    b > 0x20 && b != 0x7f && !b"(){%*\"\\]".contains(&b)
}

/// `ASTRING-CHAR = ATOM-CHAR / resp-specials`.
pub fn is_astring_char(b: u8) -> bool {
    is_atom_char(b) || b == b']'
}

/// `list-char = ATOM-CHAR / list-wildcards / resp-specials`.
fn is_list_char(b: u8) -> bool {
    is_astring_char(b) || b == b'%' || b == b'*'
}

/// A position in a framed command.
#[derive(Debug, Clone)]
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn rest(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or_default()
    }

    pub fn at_end(&self) -> bool {
        self.rest() == b"\r\n" || self.rest().is_empty()
    }

    /// The command must end here (CRLF).
    pub fn end(&mut self) -> Result<()> {
        if self.at_end() {
            self.pos = self.buf.len();
            Ok(())
        } else {
            err("unexpected text at the end of the command")
        }
    }

    pub fn eat(&mut self, b: u8) -> bool {
        if self.peek() == Some(b) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    pub fn expect(&mut self, b: u8) -> Result<()> {
        if self.eat(b) {
            Ok(())
        } else {
            err(format!("expected {:?}", char::from(b)))
        }
    }

    pub fn sp(&mut self) -> Result<()> {
        self.expect(b' ')
    }

    /// Consumes `word` case-insensitively if it comes next (as a whole
    /// word: followed by a non-atom character).
    pub fn eat_word(&mut self, word: &str) -> bool {
        let w = word.as_bytes();
        let Some(next) = self.rest().get(..w.len()) else {
            return false;
        };
        if !next.eq_ignore_ascii_case(w) {
            return false;
        }
        let after = self.rest().get(w.len()).copied();
        if after.is_some_and(|b| is_atom_char(b) && b != b'[' && b != b'<' && b != b'.') {
            return false;
        }
        self.pos += w.len();
        true
    }

    fn take_while(&mut self, f: impl Fn(u8) -> bool) -> &'a [u8] {
        let start = self.pos;
        while self.peek().is_some_and(&f) {
            self.pos += 1;
        }
        self.buf.get(start..self.pos).unwrap_or_default()
    }

    /// An atom (upper-cased by callers when it's a keyword).
    pub fn atom(&mut self) -> Result<String> {
        let a = self.take_while(is_atom_char);
        if a.is_empty() {
            return err("expected an atom");
        }
        Ok(String::from_utf8_lossy(a).into_owned())
    }

    /// The command tag: ASTRING-CHAR except "+".
    pub fn tag(&mut self) -> Result<String> {
        let t = self.take_while(|b| is_astring_char(b) && b != b'+');
        if t.is_empty() || t.len() > 64 {
            return err("bad tag");
        }
        Ok(String::from_utf8_lossy(t).into_owned())
    }

    /// `astring = 1*ASTRING-CHAR / string`.
    pub fn astring(&mut self) -> Result<Vec<u8>> {
        match self.peek() {
            Some(b'"' | b'{' | b'~') => self.string(),
            _ => {
                let a = self.take_while(is_astring_char);
                if a.is_empty() {
                    return err("expected a string");
                }
                Ok(a.to_vec())
            }
        }
    }

    pub fn astring_utf8(&mut self) -> Result<String> {
        String::from_utf8(self.astring()?).or_else(|_| err("not UTF-8"))
    }

    /// `string = quoted / literal` (and literal8 `~{n}`, RFC 9051 §9).
    pub fn string(&mut self) -> Result<Vec<u8>> {
        match self.peek() {
            Some(b'"') => self.quoted(),
            Some(b'{') => self.literal(),
            Some(b'~') => {
                self.pos += 1;
                self.literal()
            }
            _ => err("expected a string"),
        }
    }

    /// `nstring = string / "NIL"`.
    pub fn nstring(&mut self) -> Result<Option<Vec<u8>>> {
        if self.eat_word("NIL") {
            return Ok(None);
        }
        self.string().map(Some)
    }

    fn quoted(&mut self) -> Result<Vec<u8>> {
        self.expect(b'"')?;
        let mut out = Vec::new();
        loop {
            match self.peek() {
                None | Some(b'\r' | b'\n') => return err("unterminated quoted string"),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(c @ (b'"' | b'\\')) => {
                            out.push(c);
                            self.pos += 1;
                        }
                        _ => return err("bad escape in quoted string"),
                    }
                }
                Some(c) => {
                    out.push(c);
                    self.pos += 1;
                }
            }
        }
    }

    fn literal(&mut self) -> Result<Vec<u8>> {
        self.expect(b'{')?;
        let n = self.number()?;
        let _ = self.eat(b'+') || self.eat(b'-');
        self.expect(b'}')?;
        self.expect(b'\r')?;
        self.expect(b'\n')?;
        let n = usize::try_from(n).or_else(|_| err("literal too large"))?;
        let end = self.pos.checked_add(n).filter(|e| *e <= self.buf.len());
        let Some(end) = end else {
            return err("literal shorter than announced");
        };
        let data = self.buf.get(self.pos..end).unwrap_or_default().to_vec();
        self.pos = end;
        Ok(data)
    }

    /// `list-mailbox = 1*list-char / string` (LIST patterns).
    pub fn list_mailbox(&mut self) -> Result<Vec<u8>> {
        match self.peek() {
            Some(b'"' | b'{' | b'~') => self.string(),
            _ => {
                let a = self.take_while(is_list_char);
                if a.is_empty() {
                    return err("expected a mailbox pattern");
                }
                Ok(a.to_vec())
            }
        }
    }

    /// `number64` (RFC 9051 §9): up to 2^63 - 1.
    pub fn number(&mut self) -> Result<u64> {
        let d = self.take_while(|b| b.is_ascii_digit());
        if d.is_empty() || d.len() > 19 {
            return err("expected a number");
        }
        std::str::from_utf8(d)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n <= i64::MAX as u64)
            .map_or_else(|| err("number out of range"), Ok)
    }

    /// `number` (32-bit).
    pub fn number32(&mut self) -> Result<u32> {
        u32::try_from(self.number()?).or_else(|_| err("number out of range"))
    }

    pub fn nz_number(&mut self) -> Result<u32> {
        match self.number32()? {
            0 => err("zero is not allowed here"),
            n => Ok(n),
        }
    }

    /// A sequence set (RFC 9051 §9 `sequence-set`), or `$` (RFC 5182).
    pub fn seq_set(&mut self) -> Result<SeqSet> {
        if self.eat(b'$') {
            return Ok(SeqSet::Saved);
        }
        let mut ranges = Vec::new();
        loop {
            let a = self.seq_number()?;
            let b = if self.eat(b':') { self.seq_number()? } else { a };
            ranges.push((a, b));
            if ranges.len() > 10_000 {
                return err("sequence set too long");
            }
            if !self.eat(b',') {
                return Ok(SeqSet::Ranges(ranges));
            }
        }
    }

    fn seq_number(&mut self) -> Result<SeqNum> {
        if self.eat(b'*') {
            Ok(SeqNum::Last)
        } else {
            Ok(SeqNum::Value(self.nz_number()?))
        }
    }

    /// `date = date-text / DQUOTE date-text DQUOTE`, `d-Mon-yyyy`, as
    /// days since 1970-01-01.
    pub fn date(&mut self) -> Result<i64> {
        let quoted = self.eat(b'"');
        let day = self.number32()?;
        self.expect(b'-')?;
        let month = self.month()?;
        self.expect(b'-')?;
        let year = self.number32()?;
        if quoted {
            self.expect(b'"')?;
        }
        days(year, month, day).map_or_else(|| err("bad date"), Ok)
    }

    fn month(&mut self) -> Result<u32> {
        let m = self.take_while(|b| b.is_ascii_alphabetic());
        const MONTHS: [&str; 12] = [
            "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
        ];
        let m = String::from_utf8_lossy(m).to_ascii_lowercase();
        MONTHS
            .iter()
            .position(|x| *x == m)
            .map(|i| i as u32 + 1)
            .map_or_else(|| err("bad month"), Ok)
    }

    /// `date-time` (RFC 9051 §9) for APPEND: `"dd-Mon-yyyy hh:mm:ss +zzzz"`,
    /// as Unix seconds.
    pub fn date_time(&mut self) -> Result<i64> {
        self.expect(b'"')?;
        let _ = self.eat(b' ');
        let day = self.number32()?;
        self.expect(b'-')?;
        let month = self.month()?;
        self.expect(b'-')?;
        let year = self.number32()?;
        self.sp()?;
        let h = self.number32()?;
        self.expect(b':')?;
        let m = self.number32()?;
        self.expect(b':')?;
        let s = self.number32()?;
        self.sp()?;
        let sign = match self.peek() {
            Some(b'+') => 1i64,
            Some(b'-') => -1,
            _ => return err("bad zone"),
        };
        self.pos += 1;
        let z = self.take_while(|b| b.is_ascii_digit());
        if z.len() != 4 {
            return err("bad zone");
        }
        let z: i64 = std::str::from_utf8(z).ok().and_then(|z| z.parse().ok()).unwrap_or(0);
        self.expect(b'"')?;
        if h > 23 || m > 59 || s > 60 {
            return err("bad time");
        }
        let d = days(year, month, day).map_or_else(|| err("bad date"), Ok)?;
        let offset = sign * ((z / 100) * 3600 + (z % 100) * 60);
        Ok(d * 86_400 + i64::from(h) * 3600 + i64::from(m) * 60 + i64::from(s) - offset)
    }

    /// A parenthesized list of items parsed by `f`, possibly empty.
    pub fn list<T>(&mut self, mut f: impl FnMut(&mut Self) -> Result<T>) -> Result<Vec<T>> {
        self.expect(b'(')?;
        let mut out = Vec::new();
        if self.eat(b')') {
            return Ok(out);
        }
        loop {
            out.push(f(self)?);
            if out.len() > 10_000 {
                return err("list too long");
            }
            if self.eat(b')') {
                return Ok(out);
            }
            self.sp()?;
        }
    }
}

/// A message number or UID, or `*` (the largest in use).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqNum {
    Value(u32),
    Last,
}

/// A set of message numbers or UIDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeqSet {
    Ranges(Vec<(SeqNum, SeqNum)>),
    /// `$`: the saved search result (RFC 5182).
    Saved,
}

impl SeqSet {
    /// Whether `n` is in the set, `*` meaning `largest` (RFC 9051 §9:
    /// ranges may be written in either order).
    pub fn contains(&self, n: u32, largest: u32) -> bool {
        let SeqSet::Ranges(ranges) = self else {
            return false;
        };
        let v = |s: SeqNum| match s {
            SeqNum::Value(v) => v,
            SeqNum::Last => largest,
        };
        ranges.iter().any(|(a, b)| {
            let (lo, hi) = (v(*a).min(v(*b)), v(*a).max(v(*b)));
            (lo..=hi).contains(&n)
        })
    }
}

/// Days since 1970-01-01 for a valid civil date.
pub(crate) fn days(y: u32, m: u32, d: u32) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || !(1..=9999).contains(&y) {
        return None;
    }
    let (y, m, d) = (i64::from(y), i64::from(m), i64::from(d));
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings() {
        let mut c = Cursor::new(b"atom \"q \\\"x\\\\\" {3}\r\nlit NIL ]x");
        assert_eq!(c.astring().unwrap(), b"atom");
        c.sp().unwrap();
        assert_eq!(c.astring().unwrap(), b"q \"x\\");
        c.sp().unwrap();
        assert_eq!(c.astring().unwrap(), b"lit");
        c.sp().unwrap();
        assert_eq!(c.nstring().unwrap(), None);
        c.sp().unwrap();
        assert_eq!(c.astring().unwrap(), b"]x");
        assert!(Cursor::new(b"{9}\r\nshort").astring().is_err());
        assert!(Cursor::new(b"\"open").astring().is_err());
        assert!(Cursor::new(b"\"bad\\x\"").astring().is_err());
        assert!(Cursor::new(b"{99999999999999999999}\r\n").astring().is_err());
    }

    #[test]
    fn sequence_sets() {
        let s = Cursor::new(b"1:3,7,*:9").seq_set().unwrap();
        assert!(s.contains(2, 20) && s.contains(7, 20) && s.contains(15, 20));
        assert!(!s.contains(5, 20) && !s.contains(21, 20));
        assert!(Cursor::new(b"0").seq_set().is_err());
        assert!(Cursor::new(b"1:").seq_set().is_err());
        assert_eq!(Cursor::new(b"$").seq_set().unwrap(), SeqSet::Saved);
    }

    #[test]
    fn dates() {
        assert_eq!(Cursor::new(b"1-Feb-1994").date().unwrap(), 8797);
        assert_eq!(Cursor::new(b"\"01-feb-1994\"").date().unwrap(), 8797);
        assert!(Cursor::new(b"30-Foo-1994").date().is_err());
        assert_eq!(
            Cursor::new(b"\" 7-Feb-1994 21:52:25 -0800\"").date_time().unwrap(),
            760_686_745
        );
        assert!(Cursor::new(b"\"7-Feb-1994 25:52:25 -0800\"").date_time().is_err());
    }

    #[test]
    fn words_are_whole() {
        let mut c = Cursor::new(b"NILS");
        assert!(!c.eat_word("NIL"));
        let mut c = Cursor::new(b"body[");
        assert!(c.eat_word("BODY"));
    }
}
