//! Strict CRLF line splitting.
//!
//! RFC 5321 §2.3.8: CR and LF may only appear together, as the CRLF line
//! terminator. RFC 5321 §4.1.1.4: servers MUST NOT accept a bare LF as a line
//! ending. Any bare CR or bare LF is therefore an error here. Accepting either
//! one is what makes SMTP smuggling possible.

use crate::error::Error;

/// Splits the first CRLF-terminated line off the front of `buf`.
///
/// Returns:
/// - `Ok(Some((line, consumed)))`: `line` is the content without the CRLF,
///   and `consumed` is the number of bytes to drop from `buf`, CRLF included.
/// - `Ok(None)`: no complete line yet; read more input and call again.
/// - `Err(_)`: a bare CR or LF was found, or the line (CRLF included) would
///   exceed `max_len` octets.
///
/// After an error the stream can't be resynchronized safely. The caller
/// should send the error reply and close the connection.
pub fn split_line(buf: &[u8], max_len: usize) -> Result<Option<(&[u8], usize)>, Error> {
    for (i, &b) in buf.iter().enumerate() {
        match b {
            // A CR immediately followed by LF is consumed below, so any LF we
            // reach here is bare. RFC 5321 §2.3.8.
            b'\n' => return Err(Error::BareLf),
            b'\r' => {
                return match buf.get(i + 1) {
                    Some(b'\n') => {
                        let consumed = i + 2;
                        if consumed > max_len {
                            return Err(Error::LineTooLong { limit: max_len });
                        }
                        Ok(buf.get(..i).map(|line| (line, consumed)))
                    }
                    // RFC 5321 §2.3.8: CR without LF.
                    Some(_) => Err(Error::BareCr),
                    // The LF still to come makes the line at least i + 2.
                    None if i + 2 > max_len => Err(Error::LineTooLong { limit: max_len }),
                    None => Ok(None),
                };
            }
            _ => {}
        }
    }
    // No CR yet: the shortest possible line is the buffer plus CRLF.
    if buf.len() + 2 > max_len {
        return Err(Error::LineTooLong { limit: max_len });
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: usize = 512;

    #[test]
    fn splits_crlf_line() {
        assert_eq!(
            split_line(b"NOOP\r\nQUIT\r\n", MAX),
            Ok(Some((&b"NOOP"[..], 6)))
        );
    }

    #[test]
    fn empty_line() {
        assert_eq!(split_line(b"\r\n", MAX), Ok(Some((&b""[..], 2))));
    }

    #[test]
    fn incomplete_line_needs_more() {
        assert_eq!(split_line(b"NOO", MAX), Ok(None));
        assert_eq!(split_line(b"NOOP\r", MAX), Ok(None));
        assert_eq!(split_line(b"", MAX), Ok(None));
    }

    #[test]
    fn bare_lf_rejected() {
        assert_eq!(split_line(b"NOOP\n", MAX), Err(Error::BareLf));
        assert_eq!(split_line(b"\n", MAX), Err(Error::BareLf));
        assert_eq!(split_line(b"NO\nOP\r\n", MAX), Err(Error::BareLf));
    }

    #[test]
    fn bare_cr_rejected() {
        assert_eq!(split_line(b"NOOP\rX", MAX), Err(Error::BareCr));
        assert_eq!(split_line(b"NO\rOP\r\n", MAX), Err(Error::BareCr));
        assert_eq!(split_line(b"\r\r\n", MAX), Err(Error::BareCr));
    }

    #[test]
    fn line_at_limit_accepted() {
        let mut line = vec![b'a'; MAX - 2];
        line.extend_from_slice(b"\r\n");
        assert_eq!(split_line(&line, MAX), Ok(Some((&line[..MAX - 2], MAX))));
    }

    #[test]
    fn line_over_limit_rejected() {
        let mut line = vec![b'a'; MAX - 1];
        line.extend_from_slice(b"\r\n");
        assert_eq!(
            split_line(&line, MAX),
            Err(Error::LineTooLong { limit: MAX })
        );
    }

    #[test]
    fn partial_line_over_limit_rejected_early() {
        // RFC 5321 §4.5.3.1.4 limits the line length, so reject as soon as the
        // limit is passed instead of buffering until a CRLF arrives.
        assert_eq!(
            split_line(&[b'a'; MAX - 1], MAX),
            Err(Error::LineTooLong { limit: MAX })
        );
        assert_eq!(split_line(&[b'a'; MAX - 2], MAX), Ok(None));
        let mut cr = vec![b'a'; MAX - 2];
        cr.push(b'\r');
        assert_eq!(split_line(&cr, MAX), Ok(None));
        let mut cr = vec![b'a'; MAX - 1];
        cr.push(b'\r');
        assert_eq!(split_line(&cr, MAX), Err(Error::LineTooLong { limit: MAX }));
    }

    #[test]
    fn default_command_line_cap() {
        use crate::limits::DEFAULT_COMMAND_LINE_CAP as CAP;
        // A command over the RFC 512 octets but under the policy cap passes.
        let mut ok = format!("RCPT TO:<{}@example.org>", "a".repeat(1000)).into_bytes();
        ok.extend_from_slice(b"\r\n");
        assert!(matches!(split_line(&ok, CAP), Ok(Some(_))));
        let mut at = vec![b'a'; CAP - 2];
        at.extend_from_slice(b"\r\n");
        assert!(matches!(split_line(&at, CAP), Ok(Some(_))));
        // One octet over is rejected, even before the CRLF arrives.
        let mut over = vec![b'a'; CAP - 1];
        over.extend_from_slice(b"\r\n");
        assert_eq!(
            split_line(&over, CAP),
            Err(Error::LineTooLong { limit: CAP })
        );
        assert_eq!(
            split_line(&vec![b'a'; CAP], CAP),
            Err(Error::LineTooLong { limit: CAP })
        );
    }
}
