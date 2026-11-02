//! `kill -9` right after the 250 reply loses nothing: the real `idly`
//! binary takes a submission, is killed with SIGKILL the moment the 250
//! arrives, and the message is still queued afterwards (RFC 5321 §6.1:
//! the server takes responsibility once it says 250).
//!
//! Runs locally: 127.0.0.1 only, test mode on, no DNS or outbound
//! connections (the queue runner's next pass is 30 s away).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const IDLY: &str = env!("CARGO_BIN_EXE_idly");

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn idly(config: &Path, args: &[&str]) -> std::process::Output {
    Command::new(IDLY)
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .unwrap()
}

/// Writes a config, a certificate, a DKIM key and an account.
fn setup(dir: &Path, submission: u16) -> (std::path::PathBuf, rcgen::Certificate) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["mx.example.org".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();

    let mut hash = Command::new(IDLY)
        .args(["user", "hash-password"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    hash.stdin.take().unwrap().write_all(b"secret").unwrap();
    let hash = String::from_utf8(hash.wait_with_output().unwrap().stdout).unwrap();

    let config = dir.join("idly.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[server]
hostname = "mx.example.org"
data_dir = "{data}"
[listen]
smtp = ["127.0.0.1:{smtp}"]
submission = ["127.0.0.1:{submission}"]
submissions = []
metrics = "127.0.0.1:{metrics}"
[[domain]]
name = "example.org"
[[account]]
address = "alice@example.org"
password_hash = "{hash}"
[tls]
cert_file = "{dir}/cert.pem"
key_file = "{dir}/key.pem"
[checks]
reverse_dns = false
port25_probe = false
[test_mode]
enabled = true
allow_domains = ["remote.example"]
[log]
format = "text"
"#,
            data = dir.join("data").display(),
            dir = dir.display(),
            smtp = free_port(),
            metrics = free_port(),
            hash = hash.trim(),
        ),
    )
    .unwrap();
    let out = idly(
        &config,
        &[
            "dkim",
            "generate",
            "--domain",
            "example.org",
            "--selector",
            "s1",
            "--algorithm",
            "ed25519",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    (config, cert)
}

fn serve(config: &Path) -> Child {
    Command::new(IDLY)
        .arg("--config")
        .arg(config)
        .arg("serve")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

async fn connect(port: u16) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(s) = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).await {
            return s;
        }
        assert!(Instant::now() < deadline, "idly did not start");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Reads one (possibly multi-line) reply; returns its last line.
async fn reply<S: AsyncRead + Unpin>(s: &mut BufReader<S>) -> String {
    loop {
        let mut line = String::new();
        s.read_line(&mut line).await.unwrap();
        assert!(line.len() >= 4, "short reply {line:?}");
        if line.as_bytes()[3] == b' ' {
            return line;
        }
    }
}

async fn command<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut BufReader<S>,
    line: &str,
    expect: &str,
) -> String {
    s.get_mut().write_all(line.as_bytes()).await.unwrap();
    let r = reply(s).await;
    assert!(r.starts_with(expect), "{line:?} got {r:?}");
    r
}

#[tokio::test]
async fn kill_9_after_250_keeps_the_message() {
    let dir = tempfile::tempdir().unwrap();
    let submission = free_port();
    let (config, cert) = setup(dir.path(), submission);
    let mut server = serve(&config);

    let mut plain = BufReader::new(connect(submission).await);
    assert!(reply(&mut plain).await.starts_with("220"));
    command(&mut plain, "EHLO client.example\r\n", "250").await;
    command(&mut plain, "STARTTLS\r\n", "220").await;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(
            ServerName::try_from("mx.example.org").unwrap(),
            plain.into_inner(),
        )
        .await
        .unwrap();
    let mut s = BufReader::new(stream);
    command(&mut s, "EHLO client.example\r\n", "250").await;
    let auth = base64::engine::general_purpose::STANDARD.encode(b"\0alice@example.org\0secret");
    command(&mut s, &format!("AUTH PLAIN {auth}\r\n"), "235").await;
    command(&mut s, "MAIL FROM:<alice@example.org>\r\n", "250").await;
    command(&mut s, "RCPT TO:<bob@remote.example>\r\n", "250").await;
    command(&mut s, "DATA\r\n", "354").await;
    s.get_mut()
        .write_all(b"From: <alice@example.org>\r\nTo: <bob@remote.example>\r\nSubject: crash test\r\n\r\nstill here?\r\n.\r\n")
        .await
        .unwrap();
    let accepted = reply(&mut s).await;
    // SIGKILL the moment the 250 is in: no shutdown code runs.
    server.kill().unwrap();
    server.wait().unwrap();
    assert!(accepted.starts_with("250"), "{accepted}");

    // Opening the queue runs crash recovery; the message must survive it.
    let out = idly(&config, &["queue", "list"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert!(text.contains("bob@remote.example"), "{text}");
    assert!(text.contains("<alice@example.org>"), "{text}");
    let spooled: Vec<_> = std::fs::read_dir(dir.path().join("data/queue/spool"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .collect();
    assert_eq!(spooled.len(), 1, "one spool file");
    let message = std::fs::read_to_string(spooled[0].path()).unwrap();
    assert!(message.contains("still here?"));
    assert!(message.contains("DKIM-Signature:"), "signed before queuing");
}
