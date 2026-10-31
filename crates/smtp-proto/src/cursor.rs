//! A small cursor over a `&str`, plus the character classes from the ABNF.
//! Nothing here indexes directly, so it cannot panic on hostile input.

#[derive(Debug, Clone, Copy)]
pub(crate) struct Cursor<'a> {
    rest: &'a str,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(s: &'a str) -> Self {
        Self { rest: s }
    }

    pub(crate) fn rest(&self) -> &'a str {
        self.rest
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    pub(crate) fn peek(&self) -> Option<char> {
        self.rest.chars().next()
    }

    pub(crate) fn bump(&mut self) -> Option<char> {
        let mut chars = self.rest.chars();
        let c = chars.next()?;
        self.rest = chars.as_str();
        Some(c)
    }

    pub(crate) fn eat(&mut self, c: char) -> bool {
        match self.rest.strip_prefix(c) {
            Some(rest) => {
                self.rest = rest;
                true
            }
            None => false,
        }
    }

    /// Consumes `prefix` if the input starts with it, ignoring ASCII case.
    /// RFC 5234 §2.3: ABNF quoted strings are case-insensitive.
    pub(crate) fn eat_ignore_case(&mut self, prefix: &str) -> bool {
        match (self.rest.get(..prefix.len()), self.rest.get(prefix.len()..)) {
            (Some(head), Some(tail)) if head.eq_ignore_ascii_case(prefix) => {
                self.rest = tail;
                true
            }
            _ => false,
        }
    }

    pub(crate) fn take_while(&mut self, f: impl Fn(char) -> bool) -> &'a str {
        let end = self
            .rest
            .char_indices()
            .find(|&(_, c)| !f(c))
            .map_or(self.rest.len(), |(i, _)| i);
        let (head, tail) = self.rest.split_at_checked(end).unwrap_or((self.rest, ""));
        self.rest = tail;
        head
    }

    /// The text consumed since the cursor was at `start`.
    pub(crate) fn since(&self, start: &'a str) -> &'a str {
        start
            .get(..start.len().saturating_sub(self.rest.len()))
            .unwrap_or("")
    }
}

/// RFC 5322 §3.2.3 `atext`, extended by RFC 6531 §3.3 with UTF8-non-ascii.
pub(crate) fn is_atext(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~".contains(c) || !c.is_ascii()
}

/// RFC 5321 §4.1.2 `Let-dig = ALPHA / DIGIT`.
pub(crate) fn is_let_dig(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

/// RFC 5321 §4.1.2 characters of `Ldh-str`.
pub(crate) fn is_ldh(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

/// RFC 5321 §4.1.2 `esmtp-keyword = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")`;
/// RFC 5321 §4.1.1.1 `ehlo-keyword` has the same form.
pub(crate) fn is_keyword(s: &str) -> bool {
    s.chars().next().is_some_and(is_let_dig) && s.chars().all(is_ldh)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eat_ignore_case_handles_short_and_multibyte_input() {
        let mut c = Cursor::new("fr");
        assert!(!c.eat_ignore_case("FROM:"));
        // "é" is two bytes; slicing at byte 1 must not panic.
        let mut c = Cursor::new("éx");
        assert!(!c.eat_ignore_case("e"));
        let mut c = Cursor::new("from:<>");
        assert!(c.eat_ignore_case("FROM:"));
        assert_eq!(c.rest(), "<>");
    }

    #[test]
    fn take_while_and_since() {
        let mut c = Cursor::new("abc.def");
        let start = c.rest();
        assert_eq!(c.take_while(|ch| ch != '.'), "abc");
        assert!(c.eat('.'));
        assert_eq!(c.since(start), "abc.");
    }

    #[test]
    fn keyword_class() {
        assert!(is_keyword("SIZE"));
        assert!(is_keyword("X-FOO1"));
        assert!(!is_keyword("-X"));
        assert!(!is_keyword(""));
        assert!(!is_keyword("A_B"));
    }
}
