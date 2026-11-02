//! Sending SMTP TLS reports (RFC 8460): report mail is DKIM-signed with
//! the reporting domain's keys (RFC 8460 §3) and queued like other mail,
//! as a TLS report so delivery ignores TLS policy failures.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use queue::{Kind, Queue};
use smtp_server::DkimKeys;

/// How often due reports and upload retries are looked for.
pub(crate) const INTERVAL: Duration = Duration::from_secs(600);

/// Signs a report email for `domain` and queues it with the null
/// reverse-path (RFC 3464-style: a report never bounces).
pub(crate) fn mailer(
    queue: Arc<Queue>,
    keys: Arc<DkimKeys>,
    domain: String,
) -> impl Fn(Vec<String>, Vec<u8>) -> Result<(), String> {
    move |to, message| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        // RFC 8460 §3: unsigned reports MUST be ignored; never send one.
        let signed = keys
            .sign_message(&domain, &message, now)
            .ok_or_else(|| format!("cannot DKIM-sign the report for {domain}"))?;
        queue
            .enqueue_kind(None, &to, &signed, Kind::TlsReport)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_auth_glue::dkim::{Signer, SigningKey, keygen};

    #[test]
    fn reports_are_signed_and_queued() {
        let dir = tempfile::tempdir().unwrap();
        let queue = Arc::new(
            Queue::open(
                dir.path(),
                queue::QueueConfig::new("mx.example.org"),
                Arc::new(queue::SystemClock),
                Arc::new(queue::space::Statvfs),
            )
            .unwrap(),
        );
        let key = keygen::ed25519().unwrap();
        let mut keys = DkimKeys::new();
        keys.add(
            "example.org",
            Signer::new(
                SigningKey::from_pkcs8(&key.private_pkcs8).unwrap(),
                "example.org",
                "s",
            )
            .unwrap(),
        );
        let keys = Arc::new(keys);
        let msg =
            b"From: <tlsrpt@example.org>\r\nTLS-Report-Domain: example.net\r\n\r\nx\r\n".to_vec();
        let send = mailer(queue.clone(), keys.clone(), "example.org".into());
        send(vec!["rua@example.net".into()], msg.clone()).unwrap();
        let entries = queue.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sender, None, "null reverse-path");
        let spooled = queue.read_message(&entries[0].message_id).unwrap();
        let text = String::from_utf8(spooled).unwrap();
        assert!(text.starts_with("DKIM-Signature: "));
        assert!(
            text.contains("tls-report-domain"),
            "the report headers are signed"
        );

        // No key for the domain: refused, nothing queued unsigned.
        let unsigned = mailer(queue.clone(), keys, "other.example".into());
        assert!(unsigned(vec!["rua@example.net".into()], msg).is_err());
        assert_eq!(queue.list().unwrap().len(), 1);
    }
}
