//! End-to-end tests: a real listener on 127.0.0.1, raw SMTP over TCP, and a
//! Maildir in a temporary directory.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use smtp_proto::{ForwardPath, Host, Reply};
use smtp_server::maildir::Maildir;
use smtp_server::{Directory, InboundConfig, Observer, Recipient, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct TestDirectory;

impl Directory for TestDirectory {
    fn resolve(&self, to: &ForwardPath) -> Recipient {
        match to {
            ForwardPath::Postmaster => Recipient::Local("postmaster@example.org".into()),
            ForwardPath::Mailbox(m) => match &m.host {
                Host::Domain(d) if d.eq_ignore_ascii_case("example.org") => {
                    match m.local_part.to_ascii_lowercase().as_str() {
                        "alice" | "bob" => {
                            Recipient::Local(format!("{}@example.org", m.local_part.to_lowercase()))
                        }
                        "postmaster" => Recipient::Local("postmaster@example.org".into()),
                        _ => Recipient::UnknownUser,
                    }
                }
                _ => Recipient::NotLocal,
            },
        }
    }
}

#[derive(Default)]
struct Counts {
    smuggling: AtomicUsize,
    accepted: AtomicUsize,
}

struct TestObserver(Arc<Counts>);

impl Observer for TestObserver {
    fn smuggling_attempt(&self, _ip: IpAddr) {
        self.0.smuggling.fetch_add(1, Ordering::SeqCst);
    }
    fn message_accepted(&self) {
        self.0.accepted.fetch_add(1, Ordering::SeqCst);
    }
}

struct Harness {
    addr: SocketAddr,
    root: PathBuf,
    counts: Arc<Counts>,
    _dir: tempfile::TempDir,
}

fn config() -> InboundConfig {
    InboundConfig {
        hostname: "mx.example.org".into(),
        command_line_cap: 4096,
        data_line_cap: 65536,
        message_size: 100_000,
        max_recipients: 100,
        idle_timeout: Duration::from_secs(300),
        max_connections: 10,
    }
}

async fn start(config: InboundConfig) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("maildir");
    let counts = Arc::new(Counts::default());
    let server = Server::new(
        config,
        TestDirectory,
        Maildir::new(&root, "mx.example.org"),
        TestObserver(counts.clone()),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server.run(listener));
    Harness {
        addr,
        root,
        counts,
        _dir: dir,
    }
}

/// A minimal raw SMTP client.
struct Client {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Client {
    async fn connect(addr: SocketAddr) -> (Self, Reply) {
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut c = Self {
            stream,
            buf: Vec::new(),
        };
        let greeting = c.reply().await.expect("greeting");
        (c, greeting)
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.unwrap();
    }

    /// The next reply, or None if the server closed the connection.
    async fn reply(&mut self) -> Option<Reply> {
        loop {
            if let Some((r, n)) = Reply::parse(&self.buf, 4096).unwrap() {
                self.buf.drain(..n);
                return Some(r);
            }
            let mut chunk = [0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(5), self.stream.read(&mut chunk))
                .await
                .expect("server did not answer in time")
                .unwrap();
            if n == 0 {
                return None;
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn cmd(&mut self, line: &str) -> Reply {
        self.send(format!("{line}\r\n").as_bytes()).await;
        self.reply().await.expect("reply")
    }

    /// True if the server has closed the connection.
    async fn is_closed(&mut self) -> bool {
        self.reply().await.is_none()
    }
}

fn messages(root: &Path, account: &str) -> Vec<String> {
    let new = root.join(account).join("new");
    let Ok(entries) = std::fs::read_dir(new) else {
        return vec![];
    };
    entries
        .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
        .collect()
}

fn all_messages(root: &Path) -> usize {
    let Ok(accounts) = std::fs::read_dir(root) else {
        return 0;
    };
    accounts
        .map(|a| std::fs::read_dir(a.unwrap().path().join("new")).map_or(0, |d| d.count()))
        .sum()
}

#[tokio::test]
async fn delivers_a_message_to_maildir() {
    let h = start(config()).await;
    let (mut c, greeting) = Client::connect(h.addr).await;
    assert_eq!(greeting.code, 220);
    let ehlo = c.cmd("EHLO client.example.net").await;
    assert_eq!(ehlo.code, 250);
    assert!(ehlo.lines.iter().any(|l| l == "PIPELINING"));
    assert!(ehlo.lines.iter().any(|l| l == "SIZE 100000"));
    assert!(
        !ehlo
            .lines
            .iter()
            .any(|l| l.starts_with("STARTTLS") || l.starts_with("AUTH"))
    );
    assert_eq!(c.cmd("MAIL FROM:<sender@example.net>").await.code, 250);
    assert_eq!(c.cmd("RCPT TO:<alice@example.org>").await.code, 250);
    assert_eq!(c.cmd("DATA").await.code, 354);
    c.send(b"Subject: hi\r\n\r\nHello\r\n..dot\r\n.\r\n").await;
    let r = c.reply().await.unwrap();
    assert_eq!(r.code, 250, "{r:?}");
    assert_eq!(c.cmd("QUIT").await.code, 221);

    let msgs = messages(&h.root, "alice@example.org");
    assert_eq!(msgs.len(), 1);
    let m = &msgs[0];
    assert!(m.starts_with("Return-Path: <sender@example.net>\r\nDelivered-To: alice@example.org\r\nReceived: from client.example.net ([127.0.0.1])\r\n"), "{m}");
    assert!(
        m.contains("by mx.example.org (Idly Mail) with ESMTP id "),
        "{m}"
    );
    assert!(
        m.ends_with("Subject: hi\r\n\r\nHello\r\n.dot\r\n"),
        "dot-unstuffed: {m}"
    );
    assert_eq!(h.counts.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn smuggled_message_is_never_stored() {
    // CLAUDE.md policy: bare CR/LF in DATA -> 5xx 5.5.2, close, discard,
    // count as a smuggling attempt. The smuggled second message must not
    // be delivered either.
    let h = start(config()).await;
    for payload in [
        &b"Subject: a\r\n\r\nbody\n.\nMAIL FROM:<evil@example.net>\r\nRCPT TO:<bob@example.org>\r\nDATA\r\nsmuggled\r\n.\r\n"[..],
        b"Subject: a\r\n\r\nbody\r\n.\nMAIL FROM:<evil@example.net>\r\n",
        b"Subject: a\r\n\r\nbody\r.\r\nQUIT\r\n",
        b"body\n.\r\n",
    ] {
        let (mut c, _) = Client::connect(h.addr).await;
        c.cmd("EHLO client.example.net").await;
        c.cmd("MAIL FROM:<sender@example.net>").await;
        c.cmd("RCPT TO:<alice@example.org>").await;
        assert_eq!(c.cmd("DATA").await.code, 354);
        c.send(payload).await;
        let r = c.reply().await.unwrap();
        assert_eq!(r.code, 500, "{payload:?}");
        assert_eq!(r.enhanced.map(|e| e.to_string()), Some("5.5.2".into()));
        assert!(c.is_closed().await, "connection must be closed");
    }
    assert_eq!(all_messages(&h.root), 0, "nothing may be stored");
    assert_eq!(h.counts.smuggling.load(Ordering::SeqCst), 4);
    assert_eq!(h.counts.accepted.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn bare_lf_in_command_closes_connection() {
    let h = start(config()).await;
    let (mut c, _) = Client::connect(h.addr).await;
    c.send(b"EHLO x.example\nMAIL FROM:<a@b>\r\n").await;
    let r = c.reply().await.unwrap();
    assert_eq!(r.code, 500);
    assert!(c.is_closed().await);
}

#[tokio::test]
async fn never_relays() {
    let h = start(config()).await;
    let (mut c, _) = Client::connect(h.addr).await;
    c.cmd("EHLO client.example.net").await;
    c.cmd("MAIL FROM:<sender@example.net>").await;
    let r = c.cmd("RCPT TO:<someone@gmail.com>").await;
    assert_eq!(
        (r.code, r.enhanced.map(|e| e.to_string())),
        (550, Some("5.7.1".into()))
    );
    let r = c.cmd("RCPT TO:<x@[192.0.2.1]>").await;
    assert_eq!(r.code, 550);
    let r = c.cmd("RCPT TO:<nobody@example.org>").await;
    assert_eq!(
        (r.code, r.enhanced.map(|e| e.to_string())),
        (550, Some("5.1.1".into()))
    );
    // With no valid recipient, DATA is refused.
    assert_eq!(c.cmd("DATA").await.code, 554);
    assert_eq!(all_messages(&h.root), 0);
}

#[tokio::test]
async fn lenient_syntax_policy() {
    let h = start(config()).await;
    let (mut c, _) = Client::connect(h.addr).await;
    // Invalid EHLO name: accepted (recorded, not rejected).
    assert_eq!(c.cmd("EHLO under_score.example").await.code, 250);
    // Space after the colon: accepted.
    assert_eq!(c.cmd("MAIL FROM: <sender@example.net>").await.code, 250);
    assert_eq!(c.cmd("RCPT TO: <Bob@example.org>").await.code, 250);
    assert_eq!(c.cmd("DATA").await.code, 354);
    c.send(b"x\r\n.\r\n").await;
    assert_eq!(c.reply().await.unwrap().code, 250);
    let m = &messages(&h.root, "bob@example.org")[0];
    assert!(m.contains("Received: from unknown ([127.0.0.1])"), "{m}");
}

#[tokio::test]
async fn postmaster_is_always_accepted() {
    // RFC 5321 §4.5.1
    let h = start(config()).await;
    let (mut c, _) = Client::connect(h.addr).await;
    c.cmd("EHLO client.example.net").await;
    c.cmd("MAIL FROM:<>").await;
    assert_eq!(c.cmd("RCPT TO:<Postmaster>").await.code, 250);
}

#[tokio::test]
async fn pipelined_commands() {
    let h = start(config()).await;
    let (mut c, _) = Client::connect(h.addr).await;
    c.cmd("EHLO client.example.net").await;
    c.send(b"MAIL FROM:<s@example.net>\r\nRCPT TO:<alice@example.org>\r\nRCPT TO:<bob@example.org>\r\nDATA\r\n").await;
    for expected in [250, 250, 250, 354] {
        assert_eq!(c.reply().await.unwrap().code, expected);
    }
    c.send(b"one message\r\n.\r\nQUIT\r\n").await;
    assert_eq!(c.reply().await.unwrap().code, 250);
    assert_eq!(c.reply().await.unwrap().code, 221);
    assert_eq!(messages(&h.root, "alice@example.org").len(), 1);
    assert_eq!(messages(&h.root, "bob@example.org").len(), 1);
}

#[tokio::test]
async fn size_limits() {
    let h = start(config()).await;
    let (mut c, _) = Client::connect(h.addr).await;
    c.cmd("EHLO client.example.net").await;
    let r = c.cmd("MAIL FROM:<s@example.net> SIZE=200000").await;
    assert_eq!(r.code, 552);
    c.cmd("MAIL FROM:<s@example.net>").await;
    c.cmd("RCPT TO:<alice@example.org>").await;
    c.cmd("DATA").await;
    let line = format!("{}\r\n", "x".repeat(900));
    for _ in 0..200 {
        c.send(line.as_bytes()).await;
    }
    c.send(b".\r\n").await;
    assert_eq!(c.reply().await.unwrap().code, 552);
    // The session continues after a too-big message.
    assert_eq!(c.cmd("NOOP").await.code, 250);
    assert_eq!(all_messages(&h.root), 0);
}

#[tokio::test]
async fn sequence_errors() {
    let h = start(config()).await;
    let (mut c, _) = Client::connect(h.addr).await;
    assert_eq!(
        c.cmd("MAIL FROM:<a@example.net>").await.code,
        503,
        "before EHLO"
    );
    c.cmd("EHLO client.example.net").await;
    assert_eq!(
        c.cmd("RCPT TO:<alice@example.org>").await.code,
        503,
        "before MAIL"
    );
    c.cmd("MAIL FROM:<a@example.net>").await;
    assert_eq!(
        c.cmd("MAIL FROM:<a@example.net>").await.code,
        503,
        "nested MAIL"
    );
    assert_eq!(c.cmd("STARTTLS").await.code, 502);
    assert_eq!(c.cmd("AUTH PLAIN").await.code, 502);
    assert_eq!(c.cmd("FOO").await.code, 500);
    let r = c.cmd("MAIL FROM:<a@example.net> NOTIFY=NEVER").await;
    assert_eq!(r.code, 503, "still inside the transaction");
    c.cmd("RSET").await;
    assert_eq!(c.cmd("MAIL FROM:<a@example.net> RET=FULL").await.code, 555);
    assert_eq!(
        c.cmd("MAIL FROM:<用户@例子.广告>").await.code,
        550,
        "UTF-8 without SMTPUTF8"
    );
    assert_eq!(c.cmd("MAIL FROM:<用户@例子.广告> SMTPUTF8").await.code, 250);
}

#[tokio::test]
async fn command_line_cap() {
    let mut cfg = config();
    cfg.command_line_cap = 1024;
    let h = start(cfg).await;
    let (mut c, _) = Client::connect(h.addr).await;
    c.cmd("EHLO client.example.net").await;
    // Over 512 octets but under the cap: fine.
    let ok = format!("RCPT TO:<{}@example.org>", "a".repeat(600));
    c.cmd("MAIL FROM:<s@example.net>").await;
    assert_eq!(
        c.cmd(&ok).await.code,
        550,
        "parsed (unknown user), not a line error"
    );
    let long = format!("NOOP {}", "a".repeat(2000));
    let r = c.cmd(&long).await;
    assert_eq!(r.code, 500);
    assert!(c.is_closed().await);
}

#[tokio::test]
async fn connection_limit() {
    let mut cfg = config();
    cfg.max_connections = 1;
    let h = start(cfg).await;
    let (_first, g) = Client::connect(h.addr).await;
    assert_eq!(g.code, 220);
    let (mut second, g) = Client::connect(h.addr).await;
    assert_eq!(g.code, 421);
    assert!(second.is_closed().await);
}
