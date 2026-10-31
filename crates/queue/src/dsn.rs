//! Delivery Status Notifications ("bounces"), RFC 3464 inside a
//! multipart/report (RFC 6522).
//!
//! Loop prevention: a bounce is sent with the null reverse-path, so it can
//! never itself be bounced (RFC 5321 §4.5.5), and nothing is ever bounced
//! to our own MAILER-DAEMON.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use smtp_proto::date::rfc5322;

/// One recipient that could not be delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// The envelope recipient.
    pub recipient: String,
    /// RFC 3463 status code, e.g. `5.1.1`.
    pub status: String,
    /// The remote server's reply or our own explanation.
    pub diagnostic: String,
}

/// Where a bounce for a message from `original_from` should go, or None if
/// no bounce may be sent:
/// - the null reverse-path (RFC 5321 §4.5.5: never bounce a bounce);
/// - our own MAILER-DAEMON, so bounce loops are impossible.
pub fn bounce_recipient(original_from: Option<&str>, hostname: &str) -> Option<String> {
    let from = original_from?;
    let (local, domain) = from.rsplit_once('@')?;
    let is_daemon =
        local.eq_ignore_ascii_case("mailer-daemon") && domain.eq_ignore_ascii_case(hostname);
    (!is_daemon).then(|| from.to_owned())
}

/// Text safe for a 7-bit header field: printable ASCII only, no CR/LF.
fn clean(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// RFC 3464 §2.3.4: `status-code = DIGIT "." 1*3DIGIT "." 1*3DIGIT`,
/// first digit 4 or 5 here. Anything else becomes 5.0.0.
fn status(s: &str) -> String {
    let ok = smtp_proto::reply::parse_enhanced(s).is_some_and(|e| e.class == 4 || e.class == 5);
    if ok { s.to_owned() } else { "5.0.0".to_owned() }
}

/// Builds a complete bounce message (headers and body, CRLF).
///
/// `original_headers` is the header section of the failed message, sent
/// back as text/rfc822-headers so the sender can tell which message failed.
pub fn build(
    hostname: &str,
    to: &str,
    arrival: u64,
    now: u64,
    failures: &[Failure],
    original_headers: Option<&[u8]>,
    unique: &str,
) -> Vec<u8> {
    let at = |secs: u64| rfc5322(UNIX_EPOCH + Duration::from_secs(secs));
    let boundary = format!("=_idly_dsn_{unique}");
    let mut m = String::new();
    m.push_str(&format!(
        "From: Mail Delivery System <MAILER-DAEMON@{hostname}>\r\n"
    ));
    m.push_str(&format!("To: <{}>\r\n", clean(to)));
    m.push_str("Subject: Undelivered Mail Returned to Sender\r\n");
    m.push_str(&format!("Date: {}\r\n", at(now)));
    m.push_str(&format!("Message-ID: <{unique}.dsn@{hostname}>\r\n"));
    // RFC 3834 §3.1.7: automatic responses carry Auto-Submitted: auto-replied.
    m.push_str("Auto-Submitted: auto-replied\r\n");
    m.push_str("MIME-Version: 1.0\r\n");
    // RFC 6522 §3: multipart/report with report-type=delivery-status.
    m.push_str(&format!(
        "Content-Type: multipart/report; report-type=delivery-status;\r\n\tboundary=\"{boundary}\"\r\n\r\n"
    ));
    m.push_str("This is a MIME-encapsulated message.\r\n\r\n");

    // Part 1: human-readable explanation.
    m.push_str(&format!(
        "--{boundary}\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n"
    ));
    m.push_str(&format!(
        "This is the mail system at {hostname}.\r\n\r\n\
         Your message could not be delivered to one or more recipients.\r\n\
         It has been returned to you. The details are below.\r\n\r\n"
    ));
    for f in failures {
        m.push_str(&format!(
            "<{}>: {}\r\n",
            clean(&f.recipient),
            clean(&f.diagnostic)
        ));
    }
    m.push_str("\r\n");

    // Part 2: message/delivery-status, 7bit (RFC 3464 §2.1).
    m.push_str(&format!(
        "--{boundary}\r\nContent-Type: message/delivery-status\r\n\r\n"
    ));
    // RFC 3464 §2.2.2 (required) and §2.2.5.
    m.push_str(&format!(
        "Reporting-MTA: dns; {hostname}\r\nArrival-Date: {}\r\n",
        at(arrival)
    ));
    for f in failures {
        m.push_str("\r\n");
        // RFC 3464 §2.3.2, §2.3.3, §2.3.4 (required) and §2.3.6.
        m.push_str(&format!(
            "Final-Recipient: rfc822; {}\r\n",
            clean(&f.recipient)
        ));
        m.push_str("Action: failed\r\n");
        m.push_str(&format!("Status: {}\r\n", status(&f.status)));
        m.push_str(&format!(
            "Diagnostic-Code: smtp; {}\r\n",
            clean(&f.diagnostic)
        ));
    }
    m.push_str("\r\n");

    // Part 3: the original header section (RFC 6522 §4: text/rfc822-headers).
    m.push_str(&format!(
        "--{boundary}\r\nContent-Type: text/rfc822-headers\r\n\r\n"
    ));
    let mut out = m.into_bytes();
    if let Some(h) = original_headers {
        // Only 7-bit text goes into this part.
        out.extend(h.iter().map(|&b| if b.is_ascii() { b } else { b'?' }));
        if !h.ends_with(b"\r\n") {
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    out
}

/// The header section of a message (up to the first empty line).
pub fn header_section(message: &[u8]) -> &[u8] {
    match message.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => message.get(..i + 2).unwrap_or(message),
        None => message,
    }
}

/// Seconds since the Unix epoch.
pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_bounce_null_sender_or_our_daemon() {
        assert_eq!(bounce_recipient(None, "mx.example.org"), None);
        assert_eq!(
            bounce_recipient(Some("MAILER-DAEMON@mx.example.org"), "mx.example.org"),
            None
        );
        assert_eq!(
            bounce_recipient(Some("mailer-daemon@MX.example.org"), "mx.example.org"),
            None
        );
        assert_eq!(
            bounce_recipient(Some("alice@example.org"), "mx.example.org"),
            Some("alice@example.org".into())
        );
        // Someone else's MAILER-DAEMON is a normal address.
        assert!(bounce_recipient(Some("mailer-daemon@other.example"), "mx.example.org").is_some());
    }

    #[test]
    fn dsn_structure() {
        let original = b"From: alice@example.org\r\nSubject: hello\r\n\r\nbody text\r\n";
        let failures = [Failure {
            recipient: "bob@example.net".into(),
            status: "5.1.1".into(),
            diagnostic: "550 5.1.1 No such user\r\nInjected: header".into(),
        }];
        let dsn = build(
            "mx.example.org",
            "alice@example.org",
            0,
            86_400,
            &failures,
            Some(header_section(original)),
            "abc",
        );
        let text = String::from_utf8(dsn).unwrap();
        for needle in [
            "From: Mail Delivery System <MAILER-DAEMON@mx.example.org>\r\n",
            "To: <alice@example.org>\r\n",
            "Auto-Submitted: auto-replied\r\n",
            "Content-Type: multipart/report; report-type=delivery-status;",
            "Content-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; mx.example.org\r\n",
            "Final-Recipient: rfc822; bob@example.net\r\nAction: failed\r\nStatus: 5.1.1\r\n",
            "Content-Type: text/rfc822-headers\r\n\r\nFrom: alice@example.org\r\nSubject: hello\r\n",
            "--=_idly_dsn_abc--\r\n",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in\n{text}");
        }
        assert!(!text.contains("body text"), "only headers are returned");
        // CR/LF in the diagnostic can't inject header lines.
        assert!(!text.contains("\r\nInjected: header"));
        assert!(text.is_ascii());
        // Every line ends in CRLF (no bare LF).
        assert!(!text.replace("\r\n", "").contains('\n'));
    }

    #[test]
    fn invalid_status_codes_are_replaced() {
        assert_eq!(status("5.7.1"), "5.7.1");
        assert_eq!(status("4.4.7"), "4.4.7");
        assert_eq!(status("2.0.0"), "5.0.0");
        assert_eq!(status("five"), "5.0.0");
    }
}
