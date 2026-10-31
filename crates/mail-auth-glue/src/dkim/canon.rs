//! DKIM canonicalization (RFC 6376 §3.4).

use ring::digest::{Context, Digest, SHA256};

use crate::message::Header;

/// A canonicalization algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canon {
    /// RFC 6376 §3.4.1 (header) and §3.4.3 (body).
    Simple,
    /// RFC 6376 §3.4.2 (header) and §3.4.4 (body).
    Relaxed,
}

fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Appends the canonical form of `raw` (a whole header field, without its
/// final CRLF) to `out`, without a trailing CRLF.
pub(crate) fn header_raw(canon: Canon, raw: &[u8], out: &mut Vec<u8>) {
    match canon {
        // RFC 6376 §3.4.1: presented exactly as in the message.
        Canon::Simple => out.extend_from_slice(raw),
        Canon::Relaxed => {
            let colon = raw.iter().position(|&b| b == b':').unwrap_or(raw.len());
            let (name, value) = raw.split_at(colon);
            // RFC 6376 §3.4.2: lower-case the name; drop WSP before the colon.
            let name_end = name.iter().rposition(|&b| !is_wsp(b)).map_or(0, |i| i + 1);
            out.extend(name.iter().take(name_end).map(u8::to_ascii_lowercase));
            out.push(b':');
            // Unfold, collapse WSP runs to one SP, drop WSP after the colon
            // and at the end of the value.
            let value = value.get(1..).unwrap_or_default();
            let mut pending_space = false;
            let mut started = false;
            for &b in value {
                match b {
                    b'\r' | b'\n' => {}
                    b' ' | b'\t' => pending_space = started,
                    _ => {
                        if pending_space {
                            out.push(b' ');
                            pending_space = false;
                        }
                        started = true;
                        out.push(b);
                    }
                }
            }
        }
    }
}

/// Appends the canonical form of a header field to `out`.
pub(crate) fn header(canon: Canon, h: &Header<'_>, out: &mut Vec<u8>) {
    header_raw(canon, h.raw, out);
}

/// A hasher that stops counting after an optional length limit (`l=`).
struct Limited {
    ctx: Context,
    limit: Option<u64>,
    written: u64,
    total: u64,
}

impl Limited {
    fn write(&mut self, data: &[u8]) {
        let len = data.len() as u64;
        self.total = self.total.saturating_add(len);
        let take = match self.limit {
            Some(l) => l.saturating_sub(self.written).min(len),
            None => len,
        };
        let take = usize::try_from(take).unwrap_or(data.len());
        if let Some(part) = data.get(..take) {
            self.ctx.update(part);
            self.written = self.written.saturating_add(part.len() as u64);
        }
    }
}

/// The result of hashing a body.
#[derive(Debug, Clone)]
pub(crate) struct BodyHash {
    /// SHA-256 of the canonical body, truncated to `l=` if given.
    pub(crate) digest: Digest,
    /// Length of the whole canonical body (before truncation).
    pub(crate) canonical_len: u64,
}

/// Hashes `body` with SHA-256 after canonicalization (RFC 6376 §3.7 step 1),
/// streaming line by line. Empty lines are held back until a non-empty line
/// follows, since trailing empty lines are dropped (§3.4.3, §3.4.4).
pub(crate) fn body_hash(canon: Canon, body: &[u8], limit: Option<u64>) -> BodyHash {
    let mut h = Limited {
        ctx: Context::new(&SHA256),
        limit,
        written: 0,
        total: 0,
    };
    let mut pending_empty = 0usize;
    let mut any_line = false;
    let mut rest = body;
    let mut line_buf = Vec::new();
    while !rest.is_empty() {
        let (line, next) = match rest.windows(2).position(|w| w == b"\r\n") {
            Some(i) => (
                rest.get(..i).unwrap_or_default(),
                rest.get(i + 2..).unwrap_or_default(),
            ),
            // A final line without CRLF gets one (§3.4.3, §3.4.4 (b)).
            None => (rest, &b""[..]),
        };
        rest = next;
        let line: &[u8] = match canon {
            Canon::Simple => line,
            Canon::Relaxed => {
                // §3.4.4 (a): collapse WSP runs; drop WSP at line end.
                line_buf.clear();
                let mut pending_space = false;
                for &b in line {
                    if is_wsp(b) {
                        pending_space = true;
                    } else {
                        if pending_space {
                            line_buf.push(b' ');
                            pending_space = false;
                        }
                        line_buf.push(b);
                    }
                }
                &line_buf
            }
        };
        if line.is_empty() {
            pending_empty += 1;
            continue;
        }
        for _ in 0..pending_empty {
            h.write(b"\r\n");
        }
        pending_empty = 0;
        h.write(line);
        h.write(b"\r\n");
        any_line = true;
    }
    // §3.4.3: an empty "simple" body is a single CRLF; §3.4.4: an empty
    // "relaxed" body is the null input.
    if !any_line && canon == Canon::Simple {
        h.write(b"\r\n");
    }
    BodyHash {
        digest: h.ctx.finish(),
        canonical_len: h.total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    fn b64(d: &Digest) -> String {
        STANDARD.encode(d.as_ref())
    }

    #[test]
    fn empty_body_hashes_from_rfc() {
        // RFC 6376 §3.4.3 and §3.4.4 give these SHA-256 values.
        assert_eq!(
            b64(&body_hash(Canon::Simple, b"", None).digest),
            "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="
        );
        assert_eq!(
            b64(&body_hash(Canon::Simple, b"\r\n\r\n", None).digest),
            "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="
        );
        assert_eq!(
            b64(&body_hash(Canon::Relaxed, b"", None).digest),
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        );
        assert_eq!(
            b64(&body_hash(Canon::Relaxed, b" \r\n\t\r\n", None).digest),
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        );
    }

    /// Hashes `expected` directly, to compare with a canonicalized body.
    fn sha(expected: &[u8]) -> String {
        b64(&ring::digest::digest(&SHA256, expected))
    }

    #[test]
    fn rfc_6376_section_3_4_5_example() {
        // RFC 6376 §3.4.5, with <SP> and <HTAB> written out.
        let body = b" C \r\nD \t E\r\n\r\n\r\n";
        assert_eq!(
            b64(&body_hash(Canon::Relaxed, body, None).digest),
            sha(b" C\r\nD E\r\n")
        );
        assert_eq!(
            b64(&body_hash(Canon::Simple, body, None).digest),
            sha(b" C \r\nD \t E\r\n")
        );

        let mut out = Vec::new();
        header_raw(Canon::Relaxed, b"A: X", &mut out);
        out.extend_from_slice(b"\r\n");
        header_raw(Canon::Relaxed, b"B : Y\t\r\n\tZ  ", &mut out);
        assert_eq!(out, b"a:X\r\nb:Y Z");
        let mut out = Vec::new();
        header_raw(Canon::Simple, b"B : Y\t\r\n\tZ  ", &mut out);
        assert_eq!(out, b"B : Y\t\r\n\tZ  ");
    }

    #[test]
    fn missing_final_crlf_and_inner_empty_lines() {
        assert_eq!(
            b64(&body_hash(Canon::Simple, b"a\r\n\r\nb", None).digest),
            sha(b"a\r\n\r\nb\r\n")
        );
        assert_eq!(
            b64(&body_hash(Canon::Relaxed, b"a  \r\n\r\nb\t", None).digest),
            sha(b"a\r\n\r\nb\r\n")
        );
    }

    #[test]
    fn length_limit() {
        let h = body_hash(Canon::Simple, b"hello\r\nworld\r\n", Some(5));
        assert_eq!(b64(&h.digest), sha(b"hello"));
        assert_eq!(h.canonical_len, 14);
        let h = body_hash(Canon::Simple, b"hi\r\n", Some(100));
        assert_eq!(b64(&h.digest), sha(b"hi\r\n"));
    }
}
