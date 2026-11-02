//! Splitting the client's byte stream into commands (RFC 9051 §2.2).
//!
//! A command is a line ending in CRLF, unless the line ends in a literal
//! announcement `{n}` (synchronizing: the server must first send a `+`
//! continuation, RFC 9051 §4.3) or `{n+}` / `{n-}` (non-synchronizing,
//! RFC 7888). Then n octets of literal data follow, and the command
//! continues after them.
//!
//! Strict framing (CLAUDE.md): only CRLF ends a line; a bare CR or LF
//! outside literal data is an error. Lines and literals are bounded.

/// Limits on what a client may send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The command's text without literal data, CRLFs included.
    pub max_line: usize,
    /// One literal's size (APPEND sends whole messages this way).
    pub max_literal: usize,
    /// Non-synchronizing literals (LITERAL-, RFC 7888 §4) larger than this
    /// are refused.
    pub max_nonsync_literal: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_line: 64 * 1024,
            max_literal: 25 * 1024 * 1024,
            max_nonsync_literal: 4096,
        }
    }
}

/// What the framer found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A whole command (text and literal data, as sent).
    Command(Vec<u8>),
    /// A synchronizing literal is announced: send `+ ...` now.
    Continue,
    /// A synchronizing literal is too large. The command so far is
    /// discarded; reply with a tagged NO/BAD naming `tag` (RFC 7888 §4:
    /// the client won't send the data).
    LiteralTooLarge { tag: Vec<u8> },
    /// Unrecoverable: a non-synchronizing literal too large, a line too
    /// long, or a bare CR/LF. The connection must be closed.
    Fatal(FrameError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    LineTooLong,
    LiteralTooLarge,
    /// A CR not followed by LF, or an LF without CR (smuggling-style
    /// framing tricks are refused, as in SMTP).
    BareCrOrLf,
}

/// The command framer. Feed bytes with [`Framer::push`], then call
/// [`Framer::next_event`] until it returns None.
#[derive(Debug, Default)]
pub struct Framer {
    limits: Limits,
    buf: Vec<u8>,
    /// Bytes of `buf` already scanned and belonging to the current command.
    pos: usize,
    /// Text octets of the current command (literal data excluded).
    text: usize,
    /// Literal octets still to come.
    literal_left: usize,
    fatal: bool,
}

impl Framer {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    pub fn push(&mut self, data: &[u8]) {
        if !self.fatal {
            self.buf.extend_from_slice(data);
        }
    }

    /// Bytes received but not yet part of a whole command.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }

    /// Takes one CRLF-terminated line verbatim (for IDLE's DONE and
    /// AUTHENTICATE responses), without the CRLF. None if no whole line is
    /// buffered yet.
    pub fn take_line(&mut self) -> Option<Result<Vec<u8>, FrameError>> {
        let lf = self.buf.iter().position(|b| *b == b'\n')?;
        let line: Vec<u8> = self.buf.drain(..=lf).collect();
        self.pos = 0;
        self.text = 0;
        let Some(body) = line.strip_suffix(b"\r\n") else {
            self.fatal = true;
            return Some(Err(FrameError::BareCrOrLf));
        };
        if body.contains(&b'\r') {
            self.fatal = true;
            return Some(Err(FrameError::BareCrOrLf));
        }
        if body.len() > self.limits.max_line {
            self.fatal = true;
            return Some(Err(FrameError::LineTooLong));
        }
        Some(Ok(body.to_vec()))
    }

    pub fn next_event(&mut self) -> Option<Event> {
        if self.fatal {
            return None;
        }
        loop {
            if self.literal_left > 0 {
                let available = self.buf.len().saturating_sub(self.pos);
                if available < self.literal_left {
                    self.pos += available;
                    self.literal_left -= available;
                    return None;
                }
                self.pos += self.literal_left;
                self.literal_left = 0;
            }
            let rest = self.buf.get(self.pos..).unwrap_or_default();
            let Some(lf) = rest.iter().position(|b| *b == b'\n') else {
                if self.text + rest.len() > self.limits.max_line {
                    return Some(self.fail(FrameError::LineTooLong));
                }
                if rest.contains(&b'\r')
                    && rest.iter().position(|b| *b == b'\r') != Some(rest.len().saturating_sub(1))
                {
                    return Some(self.fail(FrameError::BareCrOrLf));
                }
                return None;
            };
            let line = rest.get(..lf).unwrap_or_default();
            let Some(line) = line.strip_suffix(b"\r") else {
                return Some(self.fail(FrameError::BareCrOrLf));
            };
            if line.contains(&b'\r') {
                return Some(self.fail(FrameError::BareCrOrLf));
            }
            self.text += lf + 1;
            if self.text > self.limits.max_line {
                return Some(self.fail(FrameError::LineTooLong));
            }
            let line_end = self.pos + lf + 1;
            match literal_announcement(line) {
                Some((size, sync)) => {
                    if size > self.limits.max_literal
                        || (!sync && size > self.limits.max_nonsync_literal)
                    {
                        if sync {
                            let tag = self.tag();
                            self.buf.drain(..line_end);
                            self.reset();
                            return Some(Event::LiteralTooLarge { tag });
                        }
                        return Some(self.fail(FrameError::LiteralTooLarge));
                    }
                    self.pos = line_end;
                    self.literal_left = size;
                    if sync {
                        return Some(Event::Continue);
                    }
                }
                None => {
                    let cmd: Vec<u8> = self.buf.drain(..line_end).collect();
                    self.reset();
                    return Some(Event::Command(cmd));
                }
            }
        }
    }

    fn reset(&mut self) {
        self.pos = 0;
        self.text = 0;
        self.literal_left = 0;
    }

    fn tag(&self) -> Vec<u8> {
        self.buf
            .iter()
            .take_while(|b| **b != b' ' && **b != b'\r')
            .take(64)
            .copied()
            .collect()
    }

    fn fail(&mut self, e: FrameError) -> Event {
        self.fatal = true;
        self.buf.clear();
        Event::Fatal(e)
    }
}

/// `{123}` / `{123+}` / `{123-}` at the end of a line: (size, synchronizing).
fn literal_announcement(line: &[u8]) -> Option<(usize, bool)> {
    let inner = line.strip_suffix(b"}")?;
    let open = inner.iter().rposition(|b| *b == b'{')?;
    let spec = inner.get(open + 1..)?;
    let (digits, sync) = match spec.last() {
        Some(b'+' | b'-') => (spec.get(..spec.len() - 1)?, false),
        _ => (spec, true),
    };
    // RFC 9051 §9: number64; ten digits are plenty for our limits.
    if digits.is_empty() || digits.len() > 10 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n = std::str::from_utf8(digits).ok()?.parse::<usize>().ok()?;
    Some((n, sync))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(f: &mut Framer) -> Vec<Event> {
        std::iter::from_fn(|| f.next_event()).collect()
    }

    #[test]
    fn plain_commands() {
        let mut f = Framer::default();
        f.push(b"a1 NOOP\r\na2 CAPA");
        assert_eq!(all(&mut f), [Event::Command(b"a1 NOOP\r\n".to_vec())]);
        f.push(b"BILITY\r\n");
        assert_eq!(all(&mut f), [Event::Command(b"a2 CAPABILITY\r\n".to_vec())]);
        assert_eq!(f.pending(), 0);
    }

    #[test]
    fn synchronizing_literals() {
        let mut f = Framer::default();
        f.push(b"a LOGIN {5}\r\n");
        assert_eq!(all(&mut f), [Event::Continue]);
        f.push(b"al\r\nx {3}\r\n");
        assert_eq!(all(&mut f), [Event::Continue]);
        f.push(b"p\nw\r\n");
        assert_eq!(
            all(&mut f),
            [Event::Command(b"a LOGIN {5}\r\nal\r\nx {3}\r\np\nw\r\n".to_vec())]
        );
    }

    #[test]
    fn non_synchronizing_literals() {
        let mut f = Framer::default();
        f.push(b"a APPEND INBOX {3+}\r\nabc\r\nb NOOP\r\n");
        assert_eq!(
            all(&mut f),
            [
                Event::Command(b"a APPEND INBOX {3+}\r\nabc\r\n".to_vec()),
                Event::Command(b"b NOOP\r\n".to_vec())
            ]
        );
    }

    #[test]
    fn limits() {
        let small = Limits {
            max_line: 20,
            max_literal: 10,
            max_nonsync_literal: 4,
        };
        let mut f = Framer::new(small);
        f.push(b"t1 APPEND x {11}\r\nt2 NOOP\r\n");
        assert_eq!(
            all(&mut f),
            [
                Event::LiteralTooLarge { tag: b"t1".to_vec() },
                Event::Command(b"t2 NOOP\r\n".to_vec())
            ]
        );
        let mut f = Framer::new(small);
        f.push(b"t APPEND x {5+}\r\n");
        assert_eq!(all(&mut f), [Event::Fatal(FrameError::LiteralTooLarge)]);
        let mut f = Framer::new(small);
        f.push(&[b'x'; 30]);
        assert_eq!(all(&mut f), [Event::Fatal(FrameError::LineTooLong)]);
        assert!(f.next_event().is_none(), "nothing after a fatal error");
    }

    #[test]
    fn bare_cr_and_lf_are_fatal() {
        for bad in [&b"a NOOP\n"[..], b"a NO\rOP\r\n", b"a NO\rOP"] {
            let mut f = Framer::default();
            f.push(bad);
            assert_eq!(all(&mut f), [Event::Fatal(FrameError::BareCrOrLf)], "{bad:?}");
        }
        // A CR at the very end may be the first half of CRLF.
        let mut f = Framer::default();
        f.push(b"a NOOP\r");
        assert!(all(&mut f).is_empty());
        f.push(b"\n");
        assert_eq!(all(&mut f), [Event::Command(b"a NOOP\r\n".to_vec())]);
    }

    #[test]
    fn raw_lines() {
        let mut f = Framer::default();
        f.push(b"DONE\r\nAAA");
        assert_eq!(f.take_line(), Some(Ok(b"DONE".to_vec())));
        assert_eq!(f.take_line(), None);
        let mut f = Framer::default();
        f.push(b"DONE\n");
        assert_eq!(f.take_line(), Some(Err(FrameError::BareCrOrLf)));
    }
}
