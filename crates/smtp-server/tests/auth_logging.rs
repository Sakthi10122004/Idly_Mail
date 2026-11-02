//! Failed logins never log names that aren't accounts. In its own test
//! binary: tracing caches per-call-site interest globally, so a scoped
//! subscriber is unreliable while other tests run in parallel.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use std::sync::{Arc, Mutex};

use common::*;

/// Collects log output for one test.
#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn failed_login_logs_never_contain_unknown_names() {
    let logs = LogBuffer::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let h = start(Setup::default()).await;
    let (mut c, _) = Client::connect_implicit_tls(&h).await;
    c.cmd("EHLO client.example.net").await;
    // A password typed into the user-name field.
    assert_eq!(c.login("Tr0ub4dor&3", "alice@example.org").await.code, 535);
    assert_eq!(c.login("alice@example.org", "wrong").await.code, 535);
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(!text.contains("Tr0ub4dor"), "{text}");
    assert!(text.contains("username=unknown-user"), "{text}");
    assert!(text.contains("username=alice@example.org"), "{text}");
    assert!(!text.contains("wrong"), "passwords never logged");
}
