//! The Authentication-Results header field (RFC 8601).

use crate::dkim::{DkimResult, Verification};
use crate::dmarc::Outcome;
use crate::message::Message;
use crate::spf::SpfResult;

/// Builds an `Authentication-Results:` field, CRLF-terminated (RFC 8601
/// §2.2). `spf` is the result and the MAIL FROM domain that was checked.
pub fn header(
    authserv_id: &str,
    spf: Option<(SpfResult, &str)>,
    dkim: &[Verification],
    dmarc: Option<&Outcome>,
) -> String {
    let mut results: Vec<String> = Vec::new();
    if let Some((r, domain)) = spf {
        // RFC 8601 §2.7.2: ptype "smtp", property "mailfrom".
        results.push(format!(
            "spf={} smtp.mailfrom={}",
            r.name(),
            token_or_quoted(domain)
        ));
    }
    if dkim.is_empty() {
        results.push("dkim=none".into());
    }
    for v in dkim {
        let (name, reason) = match &v.result {
            DkimResult::Pass => ("pass", None),
            DkimResult::Fail(r) => ("fail", Some(*r)),
            DkimResult::Policy(r) => ("policy", Some(*r)),
            DkimResult::TempError(r) => ("temperror", Some(*r)),
            DkimResult::PermError(r) => ("permerror", Some(*r)),
        };
        let mut s = format!("dkim={name}");
        // RFC 8601 §2.2: reasonspec = "reason" "=" value.
        if let Some(r) = reason.filter(|r| !r.is_empty()) {
            s.push_str(&format!(" reason={}", quoted(r)));
        }
        // RFC 8601 §2.7.1: header.d, header.s and header.a.
        if let Some(d) = &v.domain {
            s.push_str(&format!(" header.d={}", token_or_quoted(d)));
        }
        if let Some(sel) = &v.selector {
            s.push_str(&format!(" header.s={}", token_or_quoted(sel)));
        }
        if let Some(a) = v.algorithm {
            s.push_str(&format!(" header.a={}", a.name()));
        }
        results.push(s);
    }
    if let Some(o) = dmarc {
        let mut s = format!("dmarc={}", o.result.name());
        if let Some(d) = &o.author_domain {
            s.push_str(&format!(" header.from={}", token_or_quoted(d)));
        }
        results.push(s);
    }
    let mut out = format!("Authentication-Results: {}", token_or_quoted(authserv_id));
    for r in results {
        out.push_str(";\r\n\t");
        out.push_str(&r);
    }
    out.push_str("\r\n");
    out
}

/// RFC 2045 §5.1 `tspecials`, which a token may not contain.
const TSPECIALS: &[u8] = b"()<>@,;:\\\"/[]?=";

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && !TSPECIALS.contains(&b))
}

/// RFC 5322 §3.2.4 quoted-string, escaping `"` and `\`; CR/LF are dropped
/// so a value can never break the header field.
fn quoted(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars().filter(|&c| c != '\r' && c != '\n') {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// RFC 8601 §2.2 `value`: a token if possible, else a quoted-string.
fn token_or_quoted(s: &str) -> String {
    if is_token(s) { s.to_owned() } else { quoted(s) }
}

/// The authserv-id of an Authentication-Results field value (RFC 8601
/// §2.2: `[CFWS] authserv-id`, where `authserv-id = value`), lower-cased.
pub fn authserv_id(value: &[u8]) -> Option<String> {
    let mut i = 0usize;
    // [CFWS]: whitespace, folding and (nested) comments.
    loop {
        match value.get(i)? {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'(' => {
                let mut depth = 0u32;
                loop {
                    match value.get(i)? {
                        b'\\' => i += 1,
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                i += 1;
            }
            _ => break,
        }
    }
    let rest = value.get(i..)?;
    let id = if rest.first() == Some(&b'"') {
        let mut s = Vec::new();
        let mut j = 1usize;
        loop {
            match *rest.get(j)? {
                b'"' => break,
                b'\\' => {
                    j += 1;
                    s.push(*rest.get(j)?);
                }
                c => s.push(c),
            }
            j += 1;
        }
        s
    } else {
        rest.iter()
            .take_while(|b| b.is_ascii_graphic() && !TSPECIALS.contains(b))
            .copied()
            .collect()
    };
    let id = String::from_utf8(id).ok()?;
    (!id.is_empty()).then(|| id.to_lowercase())
}

/// Removes every Authentication-Results field that claims to come from
/// `our_id` (RFC 8601 §5): only we may say what we checked. Compared in
/// A-label form, which is equivalent to §5's comparison after converting
/// A-labels to U-labels. A message whose header can't be parsed is
/// returned unchanged.
pub fn strip_forged(message: &[u8], our_id: &str) -> Vec<u8> {
    let ours =
        crate::dkim::signature::ascii_domain(our_id).unwrap_or_else(|| our_id.to_lowercase());
    let Ok(msg) = Message::parse(message) else {
        return message.to_vec();
    };
    let mut out = Vec::with_capacity(message.len());
    let mut pos = 0usize;
    for h in &msg.headers {
        // Header fields are contiguous from the start of the message, each
        // followed by CRLF (except possibly a last one at end of input).
        let end = (pos + h.raw.len() + 2).min(message.len());
        let forged = h.name.eq_ignore_ascii_case("Authentication-Results")
            && authserv_id(h.value)
                .is_some_and(|id| crate::dkim::signature::ascii_domain(&id).unwrap_or(id) == ours);
        if !forged {
            out.extend_from_slice(message.get(pos..end).unwrap_or_default());
        }
        pos = end;
    }
    out.extend_from_slice(message.get(pos..).unwrap_or_default());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkim::Algorithm;
    use crate::dmarc::DmarcResult;
    use crate::dmarc::record::Policy;

    #[test]
    fn builds_a_header() {
        let dkim = [
            Verification {
                result: DkimResult::Pass,
                domain: Some("example.com".into()),
                selector: Some("sel".into()),
                algorithm: Some(Algorithm::RsaSha256),
                testing: false,
            },
            Verification {
                result: DkimResult::PermError("no key for signature"),
                domain: None,
                selector: None,
                algorithm: None,
                testing: false,
            },
        ];
        let dmarc = Outcome {
            result: DmarcResult::Fail,
            author_domain: Some("example.com".into()),
            disposition: Policy::Reject,
            testing: false,
        };
        let h = header(
            "mx.example.org",
            Some((SpfResult::Pass, "example.com")),
            &dkim,
            Some(&dmarc),
        );
        assert_eq!(
            h,
            "Authentication-Results: mx.example.org;\r\n\
             \tspf=pass smtp.mailfrom=example.com;\r\n\
             \tdkim=pass header.d=example.com header.s=sel header.a=rsa-sha256;\r\n\
             \tdkim=permerror reason=\"no key for signature\";\r\n\
             \tdmarc=fail header.from=example.com\r\n"
        );
        assert_eq!(
            authserv_id(h.split_once(':').unwrap().1.as_bytes()).as_deref(),
            Some("mx.example.org")
        );
    }

    #[test]
    fn no_signatures() {
        let h = header("mx.example.org", None, &[], None);
        assert_eq!(
            h,
            "Authentication-Results: mx.example.org;\r\n\tdkim=none\r\n"
        );
    }

    #[test]
    fn values_are_escaped() {
        assert_eq!(quoted("a\"b\\c\r\nd"), "\"a\\\"b\\\\cd\"");
        assert_eq!(token_or_quoted("a b"), "\"a b\"");
        assert_eq!(token_or_quoted("example.com"), "example.com");
    }

    #[test]
    fn authserv_ids() {
        assert_eq!(
            authserv_id(b" example.com; spf=pass").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            authserv_id(b" (comment (nested)) Example.COM 1; none").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            authserv_id(b" \"quoted id\"; none").as_deref(),
            Some("quoted id")
        );
        assert_eq!(authserv_id(b"  "), None);
        assert_eq!(authserv_id(b" (unterminated"), None);
        assert_eq!(authserv_id(b" ;none"), None);
    }

    #[test]
    fn forged_results_are_removed() {
        let msg = b"Authentication-Results: MX.example.org; dkim=pass\r\n\
            Received: from x\r\n\
            Authentication-Results: other.example; spf=pass\r\n\
            Authentication-Results:\r\n (forged, folded) mx.example.org; dmarc=pass\r\n\
            Subject: hi\r\n\r\nbody\r\n";
        let out = strip_forged(msg, "mx.example.org");
        assert_eq!(
            out,
            b"Received: from x\r\nAuthentication-Results: other.example; spf=pass\r\nSubject: hi\r\n\r\nbody\r\n"
        );
        // Unparseable messages are left alone.
        assert_eq!(
            strip_forged(b"no colon\r\n", "mx.example.org"),
            b"no colon\r\n"
        );
    }
}
