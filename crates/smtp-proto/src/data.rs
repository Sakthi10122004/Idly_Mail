//! The DATA message body: dot-unstuffing (server) and dot-stuffing (client).
//!
//! RFC 5321 §4.1.1.4: the mail data ends with `CRLF . CRLF`, where the first
//! CRLF ends the last line of the message. RFC 5321 §4.5.2: a leading period
//! on a line is doubled by the sender and removed by the receiver.
//!
//! Smuggling defense: this is the only end-of-data sequence accepted.
//! `LF . LF`, `CR . CR`, `LF . CRLF`, `CRLF . LF` and every other variant are
//! never treated as the end. A bare CR or bare LF anywhere in the data is a
//! hard error (RFC 5321 §2.3.8, §4.1.1.4). Two SMTP implementations that
//! disagree on where a message ends are what make smuggling possible; with
//! no lenient path there is nothing to disagree about.

use crate::error::Error;

/// Result of feeding bytes to a [`DataDecoder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// All input was consumed; the end of data has not been seen yet.
    NeedMore,
    /// The end of data was found after `consumed` bytes of this input. Any
    /// remaining bytes belong to the next command (e.g. with PIPELINING,
    /// RFC 2920).
    Done {
        /// Bytes of this input that belonged to the message data.
        consumed: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    /// At the start of a line.
    LineStart,
    /// After a period at the start of a line.
    Dot,
    /// After `.` CR at the start of a line: only LF may follow (end of data).
    DotCr,
    /// Inside a line.
    InLine,
    /// After a CR inside a line: only LF may follow.
    Cr,
    /// End of data reached.
    Done,
    /// A protocol error occurred; the decoder stays in this state.
    Failed(Error),
}

/// Sans-I/O decoder for the DATA phase.
///
/// Feed it the bytes that follow the 354 reply, in chunks of any size. It
/// writes the dot-unstuffed message, with CRLF line endings, to `out`.
///
/// On error the decoder stays failed. The stream has no safe
/// resynchronization point, so the server should send the error's reply and
/// close the connection.
#[derive(Debug, Clone)]
pub struct DataDecoder {
    state: State,
    /// Octets on the current line so far, as transmitted (stuffing included).
    line_len: usize,
    /// Maximum line length, CRLF included; `None` for no limit.
    max_line: Option<usize>,
}

impl DataDecoder {
    /// Creates a decoder. `max_line` is the line limit including CRLF;
    /// [`crate::limits::TEXT_LINE`] is the RFC 5321 §4.5.3.1.6 limit.
    pub fn new(max_line: Option<usize>) -> Self {
        Self {
            state: State::LineStart,
            line_len: 0,
            max_line,
        }
    }

    /// Whether the end of data has been reached.
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// Decodes `input`, appending message bytes to `out`.
    ///
    /// Message size limits are the caller's job: check `out.len()` after
    /// each call.
    pub fn decode(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<Progress, Error> {
        match &self.state {
            State::Failed(e) => return Err(e.clone()),
            State::Done => return Ok(Progress::Done { consumed: 0 }),
            _ => {}
        }
        for (i, &b) in input.iter().enumerate() {
            match self.step(b, out) {
                Ok(true) => return Ok(Progress::Done { consumed: i + 1 }),
                Ok(false) => {}
                Err(e) => {
                    self.state = State::Failed(e.clone());
                    return Err(e);
                }
            }
        }
        Ok(Progress::NeedMore)
    }

    /// Processes one byte. Returns `Ok(true)` at the end of data.
    fn step(&mut self, b: u8, out: &mut Vec<u8>) -> Result<bool, Error> {
        let state = match (&self.state, b) {
            (State::Failed(e), _) => return Err(e.clone()),
            (State::Done, _) => return Ok(true),

            // RFC 5321 §2.3.8: LF is only valid right after CR.
            (State::LineStart | State::Dot | State::InLine, b'\n') => return Err(Error::BareLf),
            // RFC 5321 §2.3.8: CR is only valid right before LF.
            (State::Cr | State::DotCr, b2) if b2 != b'\n' => return Err(Error::BareCr),

            // RFC 5321 §4.5.2: a period at the start of a line.
            (State::LineStart, b'.') => State::Dot,
            (State::LineStart | State::InLine, b'\r') => State::Cr,
            (State::LineStart | State::InLine, other) => {
                out.push(other);
                State::InLine
            }

            // RFC 5321 §4.1.1.4: "." CRLF on its own line ends the data.
            (State::Dot, b'\r') => State::DotCr,
            // RFC 5321 §4.5.2: "If the first character is a period and there
            // are other characters on the line, the first character is
            // deleted."
            (State::Dot, other) => {
                out.push(other);
                State::InLine
            }

            (State::DotCr, _) => {
                self.state = State::Done;
                return Ok(true);
            }
            (State::Cr, _) => {
                out.extend_from_slice(b"\r\n");
                self.line_len = 0;
                self.state = State::LineStart;
                return Ok(false);
            }
        };
        self.line_len = self.line_len.saturating_add(1);
        // RFC 5321 §4.5.3.1.6: line length includes the CRLF. A line whose
        // content has reached max - 1 octets can't end within the limit.
        if let Some(max) = self.max_line {
            let pending_crlf = if matches!(state, State::Cr | State::DotCr) {
                1
            } else {
                2
            };
            if self.line_len.saturating_add(pending_crlf) > max {
                return Err(Error::LineTooLong { limit: max });
            }
        }
        self.state = state;
        Ok(false)
    }
}

/// Dot-stuffs `message` for transmission after a 354 reply, and appends the
/// end-of-data sequence. RFC 5321 §4.5.2, §4.1.1.4.
///
/// `message` must use CRLF line endings; a bare CR or LF is an error (the
/// client must not send them, RFC 5321 §2.3.8). If the last line has no
/// CRLF, one is added, since the end-of-data sequence must follow a CRLF.
pub fn encode(message: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    let mut at_line_start = true;
    let mut prev_cr = false;
    for &b in message {
        match b {
            b'\n' if !prev_cr => return Err(Error::BareLf),
            _ if prev_cr && b != b'\n' => return Err(Error::BareCr),
            _ => {}
        }
        if at_line_start && b == b'.' {
            // RFC 5321 §4.5.2: double a leading period.
            out.push(b'.');
        }
        out.push(b);
        at_line_start = b == b'\n';
        prev_cr = b == b'\r';
    }
    if prev_cr {
        return Err(Error::BareCr);
    }
    if !at_line_start {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::TEXT_LINE;

    /// Decodes `input` in one piece.
    fn decode(input: &[u8]) -> (Result<Progress, Error>, Vec<u8>) {
        let mut d = DataDecoder::new(Some(TEXT_LINE));
        let mut out = Vec::new();
        let r = d.decode(input, &mut out);
        (r, out)
    }

    #[test]
    fn simple_message() {
        let input = b"Subject: hi\r\n\r\nHello\r\n.\r\n";
        let (r, out) = decode(input);
        assert_eq!(
            r,
            Ok(Progress::Done {
                consumed: input.len()
            })
        );
        assert_eq!(out, b"Subject: hi\r\n\r\nHello\r\n");
    }

    #[test]
    fn empty_message() {
        assert_eq!(
            decode(b".\r\n"),
            (Ok(Progress::Done { consumed: 3 }), vec![])
        );
    }

    #[test]
    fn dot_unstuffing() {
        // RFC 5321 §4.5.2
        let (r, out) = decode(b"..leading\r\n...\r\n..\r\nmid.dle\r\n.\r\n");
        assert!(matches!(r, Ok(Progress::Done { .. })));
        assert_eq!(out, b".leading\r\n..\r\n.\r\nmid.dle\r\n");
        // A single leading period followed by text is deleted (RFC 5321 §4.5.2).
        let (_, out) = decode(b".x\r\n.\r\n");
        assert_eq!(out, b"x\r\n");
    }

    #[test]
    fn pipelined_bytes_after_end_are_left() {
        let input = b"a\r\n.\r\nQUIT\r\n";
        let (r, _) = decode(input);
        assert_eq!(r, Ok(Progress::Done { consumed: 6 }));
    }

    #[test]
    fn incomplete() {
        let (r, out) = decode(b"abc\r\n.\r");
        assert_eq!(r, Ok(Progress::NeedMore));
        assert_eq!(out, b"abc\r\n");
    }

    /// Smuggling regression suite: none of these may end the data, and every
    /// one contains a bare CR or LF, so each must be a hard error.
    #[test]
    fn smuggling_sequences_rejected() {
        let cases: &[(&[u8], Error)] = &[
            (b"a\n.\nMAIL FROM:<x@y>\r\n", Error::BareLf),
            (b"a\r.\rMAIL FROM:<x@y>\r\n", Error::BareCr),
            (b"a\n.\r\nMAIL FROM:<x@y>\r\n", Error::BareLf),
            (b"a\r\n.\nMAIL FROM:<x@y>\r\n", Error::BareLf),
            (b"a\r\n.\rMAIL FROM:<x@y>\r\n", Error::BareCr),
            (b"a\r.\r\nMAIL FROM:<x@y>\r\n", Error::BareCr),
            (b"a\r\n.\r\r\n", Error::BareCr),
            (b"\n.\r\n", Error::BareLf),
            (b"text\nmore\r\n.\r\n", Error::BareLf),
            (b"text\rmore\r\n.\r\n", Error::BareCr),
            (b"text\r\r\n.\r\n", Error::BareCr),
            (b".\n", Error::BareLf),
            (b"..\n", Error::BareLf),
        ];
        for (input, err) in cases {
            let (r, _) = decode(input);
            assert_eq!(r.as_ref(), Err(err), "{:?}", String::from_utf8_lossy(input));
        }
    }

    #[test]
    fn errors_are_sticky() {
        let mut d = DataDecoder::new(None);
        let mut out = Vec::new();
        assert_eq!(d.decode(b"a\nb", &mut out), Err(Error::BareLf));
        assert_eq!(d.decode(b"\r\n.\r\n", &mut out), Err(Error::BareLf));
        assert!(!d.is_done());
    }

    #[test]
    fn end_of_data_split_at_every_boundary() {
        let input = b"Line one\r\n..stuffed\r\nlast\r\n.\r\nNEXT";
        let (whole, whole_out) = decode(input);
        let Ok(Progress::Done { consumed }) = whole else {
            panic!("{whole:?}")
        };
        for split in 0..=input.len() {
            let (a, b) = input.split_at(split);
            let mut d = DataDecoder::new(Some(TEXT_LINE));
            let mut out = Vec::new();
            let total = match d.decode(a, &mut out).unwrap() {
                Progress::Done { consumed } => consumed,
                Progress::NeedMore => match d.decode(b, &mut out).unwrap() {
                    Progress::Done { consumed } => a.len() + consumed,
                    Progress::NeedMore => panic!("not done at split {split}"),
                },
            };
            assert_eq!(total, consumed, "split {split}");
            assert_eq!(out, whole_out, "split {split}");
        }
    }

    #[test]
    fn byte_at_a_time() {
        let input = b"a\r\n..b\r\n.\r\n";
        let mut d = DataDecoder::new(Some(TEXT_LINE));
        let mut out = Vec::new();
        for (i, b) in input.iter().enumerate() {
            let p = d.decode(std::slice::from_ref(b), &mut out).unwrap();
            assert_eq!(p == Progress::NeedMore, i + 1 < input.len());
        }
        assert!(d.is_done());
        assert_eq!(out, b"a\r\n.b\r\n");
        // Further input after the end is not consumed.
        assert_eq!(
            d.decode(b"QUIT\r\n", &mut out),
            Ok(Progress::Done { consumed: 0 })
        );
    }

    #[test]
    fn line_length_limit() {
        // RFC 5321 §4.5.3.1.6: 1000 octets including CRLF.
        let mut ok = vec![b'x'; TEXT_LINE - 2];
        ok.extend_from_slice(b"\r\n.\r\n");
        assert!(matches!(decode(&ok).0, Ok(Progress::Done { .. })));
        let mut long = vec![b'x'; TEXT_LINE - 1];
        long.extend_from_slice(b"\r\n.\r\n");
        assert_eq!(
            decode(&long).0,
            Err(Error::LineTooLong { limit: TEXT_LINE })
        );
        // The stuffed period counts: it is transmitted.
        let mut stuffed = vec![b'.'; 1];
        stuffed.extend(vec![b'x'; TEXT_LINE - 2]);
        stuffed.extend_from_slice(b"\r\n.\r\n");
        assert_eq!(
            decode(&stuffed).0,
            Err(Error::LineTooLong { limit: TEXT_LINE })
        );
        // No limit.
        let mut d = DataDecoder::new(None);
        assert!(d.decode(&long, &mut Vec::new()).is_ok());
    }

    #[test]
    fn encode_stuffs_and_terminates() {
        let mut out = Vec::new();
        encode(b".a\r\nb\r\n.\r\n", &mut out).unwrap();
        assert_eq!(out, b"..a\r\nb\r\n..\r\n.\r\n");
        let mut out = Vec::new();
        encode(b"no final crlf", &mut out).unwrap();
        assert_eq!(out, b"no final crlf\r\n.\r\n");
        let mut out = Vec::new();
        encode(b"", &mut out).unwrap();
        assert_eq!(out, b".\r\n");
    }

    #[test]
    fn encode_rejects_bare_line_endings() {
        for (input, err) in [
            (&b"a\nb"[..], Error::BareLf),
            (b"a\rb", Error::BareCr),
            (b"a\r", Error::BareCr),
            (b"\n", Error::BareLf),
        ] {
            assert_eq!(encode(input, &mut Vec::new()), Err(err));
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        let msg = b"From: a@b\r\n\r\n.\r\n..\r\n.hidden\r\nend\r\n";
        let mut wire = Vec::new();
        encode(msg, &mut wire).unwrap();
        let (r, out) = decode(&wire);
        assert_eq!(
            r,
            Ok(Progress::Done {
                consumed: wire.len()
            })
        );
        assert_eq!(out, msg);
    }
}
