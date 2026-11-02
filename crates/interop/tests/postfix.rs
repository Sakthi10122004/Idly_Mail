//! Idly Mail against a real Postfix (Docker image from tests/interop/).
//!
//! Idly runs in-process with its real server, queue and delivery code;
//! only DNS (the static test resolver) and the dialer (loopback routes)
//! are test doubles, so no setting of Idly names a delivery host.
//! Postfix reaches Idly through its own transport map.
//!
//! Scenarios:
//! 1. submission (STARTTLS + AUTH) -> queue -> Postfix over STARTTLS; the
//!    DKIM signature verifies after Postfix stored the message;
//! 2. Postfix -> Idly inbound over STARTTLS; SPF passes and the message
//!    lands in the Maildir with Received and Authentication-Results;
//! 3. an unknown user at Postfix -> a bounce (DSN) back to the sender;
//! 4. a bare LF in DATA -> 500 5.5.2, connection closed, nothing stored.
//!
//! Needs Docker: `scripts/interop-test`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use dns::testing::StaticResolver;
use mail_auth_glue::dkim::{DkimResult, Signer, SigningKey, keygen};
use queue::{Queue, QueueConfig, Runner, SystemClock};
use rustls_pki_types::ServerName;
use smtp_client::testing::Loopback;
use smtp_client::{Client, ClientConfig};
use smtp_proto::{ForwardPath, Host};
use smtp_server::maildir::Maildir;
use smtp_server::{Accounts, Delivery, Directory, DkimKeys, Mode, Observer, Recipient, Server};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const IMAGE: &str = "idly-interop-postfix";
const HOSTNAME: &str = "mx.idly.test";
/// What the test resolver hands out for the two MX hosts; the loopback
/// dialer routes them to the real listeners.
const POSTFIX_IP: &str = "45.10.0.25";
const IDLY_IP: &str = "45.10.0.26";

// ------------------------------------------------------------ docker

fn docker(args: &[&str]) -> String {
    let out = Command::new("docker").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "docker {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

struct Container {
    id: String,
    port: u16,
}

impl Container {
    fn start(idly: SocketAddr) -> Self {
        let id = docker(&[
            "run",
            "-d",
            "--rm",
            "-p",
            "127.0.0.1::25",
            "-e",
            &format!("IDLY_ADDR={idly}"),
            IMAGE,
        ])
        .trim()
        .to_owned();
        let mapping = docker(&["port", &id, "25/tcp"]);
        let port = mapping
            .lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        Self { id, port }
    }

    fn exec(&self, script: &str) -> String {
        docker(&["exec", &self.id, "sh", "-c", script])
    }

    fn logs(&self) -> String {
        let out = Command::new("docker")
            .args(["logs", &self.id])
            .output()
            .unwrap();
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.id]).output();
    }
}

/// The docker bridge's gateway: where containers reach the host.
fn bridge_gateway() -> IpAddr {
    docker(&[
        "network",
        "inspect",
        "bridge",
        "-f",
        "{{(index .IPAM.Config 0).Gateway}}",
    ])
    .trim()
    .parse()
    .unwrap()
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}

/// Polls `f` until it returns Some, for up to 60 s.
async fn eventually<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

// ------------------------------------------------------------ idly in-process

struct Dir;

impl Directory for Dir {
    fn resolve(&self, to: &ForwardPath) -> Recipient {
        match to {
            ForwardPath::Postmaster => Recipient::Local("alice@idly.test".into()),
            ForwardPath::Mailbox(m) => match &m.host {
                Host::Domain(d) if d.eq_ignore_ascii_case("idly.test") => {
                    match m.local_part.to_ascii_lowercase().as_str() {
                        "alice" | "postmaster" => Recipient::Local("alice@idly.test".into()),
                        _ => Recipient::UnknownUser,
                    }
                }
                _ => Recipient::NotLocal,
            },
        }
    }
}

struct Users;

impl Accounts for Users {
    fn verify(&self, username: &str, password: &str) -> Option<String> {
        (username == "alice@idly.test" && password == "alice-pw").then(|| username.to_owned())
    }
    fn account_name(&self, username: &str) -> Option<String> {
        (username == "alice@idly.test").then(|| username.to_owned())
    }
    fn may_send_as(&self, account: &str, address: &str) -> bool {
        account.eq_ignore_ascii_case(address)
    }
}

struct Quiet;
impl Observer for Quiet {}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn zone(dkim_txt: &str) -> StaticResolver {
    StaticResolver::new()
        .with_mx("postfix.test", 10, "mx.postfix.test")
        .with_ip("mx.postfix.test", ip(POSTFIX_IP))
        .with_mx("idly.test", 10, HOSTNAME)
        .with_ip(HOSTNAME, ip(IDLY_IP))
        // Postfix connects from the docker network.
        .with_txt("postfix.test", "v=spf1 ip4:172.16.0.0/12 -all")
        .with_txt("s1._domainkey.idly.test", dkim_txt)
}

struct Idly {
    dir: tempfile::TempDir,
    queue: Arc<Queue>,
    runner: Runner<Client<StaticResolver, Loopback>>,
    submission: u16,
    inbound_local: u16,
    cert: rcgen::Certificate,
    dkim_txt: String,
}

impl Idly {
    /// Starts the listeners; `bridge` is where Postfix connects, and
    /// `postfix_port` where Postfix's port 25 is published.
    async fn start(bridge: TcpListener, postfix_port: u16) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![HOSTNAME.into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let tls =
            smtp_server::tls::server_config(cert.pem().as_bytes(), key.serialize_pem().as_bytes())
                .unwrap();
        let generated = keygen::ed25519().unwrap();
        let mut dkim = DkimKeys::new();
        dkim.add(
            "idly.test",
            Signer::new(
                SigningKey::from_pkcs8(&generated.private_pkcs8).unwrap(),
                "idly.test",
                "s1",
            )
            .unwrap(),
        );
        let dkim_txt = generated.dns_record.clone();
        let queue = Arc::new(
            Queue::open(
                &dir.path().join("queue"),
                QueueConfig::new(HOSTNAME),
                Arc::new(SystemClock),
                Arc::new(queue::space::Statvfs),
            )
            .unwrap(),
        );
        let server = Server::new(
            smtp_server::InboundConfig::new(HOSTNAME),
            Dir,
            Delivery {
                maildir: Maildir::new(dir.path().join("maildir"), HOSTNAME),
                queue: queue.clone(),
            },
            Quiet,
            zone(&dkim_txt),
        )
        .with_tls(tls)
        .with_accounts(Arc::new(Users))
        .with_dkim(Arc::new(dkim))
        .shared();
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_local = local.local_addr().unwrap().port();
        let sub = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let submission = sub.local_addr().unwrap().port();
        tokio::spawn(server.clone().run(bridge, Mode::Inbound));
        tokio::spawn(server.clone().run(local, Mode::Inbound));
        tokio::spawn(server.run(sub, Mode::Submission));
        let runner = runner(&queue, &dkim_txt, postfix_port, inbound_local);
        Self {
            dir,
            queue,
            runner,
            submission,
            inbound_local,
            cert,
            dkim_txt,
        }
    }

    fn maildir(&self) -> PathBuf {
        self.dir
            .path()
            .join("maildir")
            .join("alice@idly.test")
            .join("new")
    }
}

fn runner(
    queue: &Arc<Queue>,
    dkim_txt: &str,
    postfix_port: u16,
    idly_port: u16,
) -> Runner<Client<StaticResolver, Loopback>> {
    // Opportunistic TLS (no DANE or MTA-STS for these test domains), so
    // Postfix's self-signed certificate is fine and no roots are needed.
    let config = ClientConfig::new(HOSTNAME, Arc::new(rustls::RootCertStore::empty()));
    let dialer = Loopback::new()
        .route(SocketAddr::new(ip(POSTFIX_IP), 25), postfix_port)
        .route(SocketAddr::new(ip(IDLY_IP), 25), idly_port);
    let client = Client::new(config, zone(dkim_txt), dialer, Arc::new(SystemClock));
    Runner::new(queue.clone(), client, HOSTNAME)
}

fn files(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .collect()
}

// ------------------------------------------------------------ SMTP client

async fn reply<S: AsyncRead + Unpin>(s: &mut BufReader<S>) -> String {
    let mut all = String::new();
    loop {
        let mut line = String::new();
        s.read_line(&mut line).await.unwrap();
        assert!(line.len() >= 4, "short reply {line:?}");
        all.push_str(&line);
        if line.as_bytes()[3] == b' ' {
            return all;
        }
    }
}

async fn cmd<S: AsyncRead + AsyncWrite + Unpin>(s: &mut BufReader<S>, line: &str, code: &str) {
    s.get_mut()
        .write_all(format!("{line}\r\n").as_bytes())
        .await
        .unwrap();
    let r = reply(s).await;
    assert!(r.starts_with(code), "{line:?} got {r:?}");
}

/// Submits one message on port 587 (STARTTLS, AUTH PLAIN).
async fn submit(idly: &Idly, to: &str, message: &str) {
    let tcp = TcpStream::connect(("127.0.0.1", idly.submission))
        .await
        .unwrap();
    let mut plain = BufReader::new(tcp);
    assert!(reply(&mut plain).await.starts_with("220"));
    cmd(&mut plain, "EHLO client.idly.test", "250").await;
    cmd(&mut plain, "STARTTLS", "220").await;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(idly.cert.der().clone()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(HOSTNAME).unwrap(), plain.into_inner())
        .await
        .unwrap();
    let mut s = BufReader::new(tls);
    cmd(&mut s, "EHLO client.idly.test", "250").await;
    let auth = base64::engine::general_purpose::STANDARD.encode(b"\0alice@idly.test\0alice-pw");
    cmd(&mut s, &format!("AUTH PLAIN {auth}"), "235").await;
    cmd(&mut s, "MAIL FROM:<alice@idly.test>", "250").await;
    cmd(&mut s, &format!("RCPT TO:<{to}>"), "250").await;
    cmd(&mut s, "DATA", "354").await;
    s.get_mut()
        .write_all(format!("{message}.\r\n").as_bytes())
        .await
        .unwrap();
    assert!(reply(&mut s).await.starts_with("250"));
    cmd(&mut s, "QUIT", "221").await;
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ------------------------------------------------------------ the test

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Docker and the idly-interop-postfix image; run scripts/interop-test"]
async fn postfix_interop() {
    let gateway = bridge_gateway();
    let bridge = TcpListener::bind((gateway, 0)).await.unwrap();
    let bridge_addr = bridge.local_addr().unwrap();
    let postfix = blocking(move || Container::start(bridge_addr)).await;
    let idly = Idly::start(bridge, postfix.port).await;

    // Postfix is up once it greets.
    let port = postfix.port;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)).await {
            let mut s = BufReader::new(s);
            let mut line = String::new();
            if s.read_line(&mut line).await.is_ok() && line.starts_with("220") {
                break;
            }
        }
        assert!(Instant::now() < deadline, "Postfix did not start");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // 1. Idly -> Postfix, DKIM-signed, over STARTTLS.
    submit(
        &idly,
        "bob@postfix.test",
        "From: Alice <alice@idly.test>\r\nTo: <bob@postfix.test>\r\nSubject: interop one\r\n\r\nHello Postfix.\r\n",
    )
    .await;
    assert_eq!(idly.runner.run_once().await, 1);
    assert!(idly.queue.list().unwrap().is_empty(), "delivered");
    let stored = eventually("bob's mail at Postfix", || {
        let out = postfix.exec("cat /home/bob/Maildir/new/* 2>/dev/null || true");
        out.contains("interop one").then_some(out)
    })
    .await;
    // Postfix stores LF line endings; DKIM is computed over CRLF.
    let crlf = stored.replace("\r\n", "\n").replace('\n', "\r\n");
    let results = mail_auth_glue::dkim::verify(&zone(&idly.dkim_txt), crlf.as_bytes(), now()).await;
    assert!(
        results
            .iter()
            .any(|v| v.result == DkimResult::Pass && v.domain.as_deref() == Some("idly.test")),
        "{results:?}\n{stored}"
    );
    assert!(
        postfix.logs().contains("TLS connection established from"),
        "Idly used STARTTLS:\n{}",
        postfix.logs()
    );

    // 2. Postfix -> Idly over STARTTLS, SPF pass.
    postfix.exec(
        "printf 'From: Bob <bob@postfix.test>\\nTo: alice@idly.test\\nSubject: interop two\\n\\nHello Idly.\\n' | sendmail -f bob@postfix.test alice@idly.test",
    );
    let maildir = idly.maildir();
    let received = eventually("Postfix's mail in Idly's Maildir", || {
        files(&maildir)
            .into_iter()
            .find(|m| m.contains("interop two"))
    })
    .await;
    assert!(
        received.contains("Authentication-Results: mx.idly.test"),
        "{received}"
    );
    assert!(received.contains("spf=pass"), "{received}");
    assert!(
        received.contains("with ESMTPS"),
        "Postfix used STARTTLS:\n{received}\n{}",
        postfix.logs()
    );
    assert!(
        received.contains("Received: from postfix.test"),
        "{received}"
    );

    // 3. An unknown user at Postfix: a DSN back to alice.
    submit(
        &idly,
        "no-such-user@postfix.test",
        "From: <alice@idly.test>\r\nTo: <no-such-user@postfix.test>\r\nSubject: interop three\r\n\r\nAnyone home?\r\n",
    )
    .await;
    assert_eq!(idly.runner.run_once().await, 1);
    // The bounce is queued for alice@idly.test and delivered to our MX.
    let queued = idly.queue.list().unwrap();
    assert_eq!(idly.runner.run_once().await, 1, "{queued:#?}");
    let dsn = eventually("the bounce", || {
        files(&maildir)
            .into_iter()
            .find(|m| m.contains("no-such-user@postfix.test") && m.contains("multipart/report"))
    })
    .await;
    assert!(dsn.contains("Status: 5.1.1"), "{dsn}");
    assert!(dsn.contains("Return-Path: <>"), "null sender:\n{dsn}");
    assert!(idly.queue.list().unwrap().is_empty());

    // 4. Smuggling: bare LF in DATA.
    let before = files(&maildir).len();
    let mut s = BufReader::new(
        TcpStream::connect(("127.0.0.1", idly.inbound_local))
            .await
            .unwrap(),
    );
    assert!(reply(&mut s).await.starts_with("220"));
    cmd(&mut s, "EHLO postfix.test", "250").await;
    cmd(&mut s, "MAIL FROM:<bob@postfix.test>", "250").await;
    cmd(&mut s, "RCPT TO:<alice@idly.test>", "250").await;
    cmd(&mut s, "DATA", "354").await;
    s.get_mut()
        .write_all(b"Subject: smuggled\r\n\r\nhi\n.\r\nMAIL FROM:<x@y.test>\r\n")
        .await
        .unwrap();
    let r = reply(&mut s).await;
    assert!(r.starts_with("500 5.5.2"), "{r}");
    let mut rest = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0, "closed without another reply");
    assert_eq!(files(&maildir).len(), before, "nothing stored");
    assert!(idly.queue.list().unwrap().is_empty(), "nothing queued");
}
