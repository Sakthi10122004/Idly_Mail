//! Milestone 6: TLS, submission with AUTH, sender authorization, the
//! submission pipeline, and inbound authentication policies. Real TLS over
//! loopback, with an rcgen test certificate.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use dns::testing::StaticResolver;
use mail_auth_glue::dkim::{self, DkimResult, Signer, SigningKey};
use smtp_proto::{ForwardPath, Host, Reply};
use smtp_server::{
    Accounts, AuthLimits, Directory, DkimKeys, Envelope, InboundConfig, Mode, Observer, Rcpt,
    Recipient, Server, Sink,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------- fixtures

struct Dir;

impl Directory for Dir {
    fn resolve(&self, to: &ForwardPath) -> Recipient {
        match to {
            ForwardPath::Postmaster => Recipient::Local("alice@example.org".into()),
            ForwardPath::Mailbox(m) => match &m.host {
                Host::Domain(d) if d.eq_ignore_ascii_case("example.org") => {
                    match m.local_part.to_lowercase().as_str() {
                        "alice" | "bob" => {
                            Recipient::Local(format!("{}@example.org", m.local_part.to_lowercase()))
                        }
                        _ => Recipient::UnknownUser,
                    }
                }
                _ => Recipient::NotLocal,
            },
        }
    }
}

/// Plaintext passwords, but `verify` sleeps to make concurrency visible.
#[derive(Default)]
struct TestAccounts {
    running: AtomicUsize,
    max_running: AtomicUsize,
    calls: AtomicUsize,
}

impl Accounts for TestAccounts {
    fn verify(&self, username: &str, password: &str) -> Option<String> {
        let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_running.fetch_max(now, Ordering::SeqCst);
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(40));
        self.running.fetch_sub(1, Ordering::SeqCst);
        let users = [
            ("alice@example.org", "alice-pw"),
            ("bob@example.org", "bob-pw"),
        ];
        users
            .iter()
            .find(|(u, p)| u.eq_ignore_ascii_case(username) && *p == password)
            .map(|(u, _)| (*u).to_owned())
    }

    fn may_send_as(&self, account: &str, address: &str) -> bool {
        account.eq_ignore_ascii_case(address)
    }
}

type Delivered = Vec<(Envelope, Vec<u8>)>;

#[derive(Default, Clone)]
struct Captured(Arc<Mutex<Delivered>>);

impl Captured {
    fn all(&self) -> Delivered {
        self.0.lock().unwrap().clone()
    }
}

struct CaptureSink(Captured);

impl Sink for CaptureSink {
    async fn deliver(&self, envelope: &Envelope, message: &[u8]) -> std::io::Result<()> {
        self.0
            .0
            .lock()
            .unwrap()
            .push((envelope.clone(), message.to_vec()));
        Ok(())
    }
}

#[derive(Default)]
struct Counts {
    auth_failures: AtomicUsize,
}

struct Obs(Arc<Counts>);

impl Observer for Obs {
    fn auth_failure(&self, _: IpAddr) {
        self.0.auth_failures.fetch_add(1, Ordering::SeqCst);
    }
}

/// A self-signed certificate for mx.example.org.
fn certificate() -> (Arc<rustls::ServerConfig>, Vec<u8>) {
    let key = rcgen::generate_simple_self_signed(vec!["mx.example.org".to_owned()]).unwrap();
    let cert_pem = key.cert.pem();
    let key_pem = key.signing_key.serialize_pem();
    let server = smtp_server::tls::server_config(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap();
    (server, key.cert.der().to_vec())
}

struct Harness {
    addrs: HashMap<&'static str, SocketAddr>,
    captured: Captured,
    accounts: Arc<TestAccounts>,
    counts: Arc<Counts>,
    ca: Vec<u8>,
}

struct Setup {
    config: InboundConfig,
    resolver: StaticResolver,
    dkim: Option<DkimKeys>,
}

impl Default for Setup {
    fn default() -> Self {
        let mut config = InboundConfig::new("mx.example.org");
        config.inbound_checks = false;
        Self {
            config,
            resolver: StaticResolver::new(),
            dkim: None,
        }
    }
}

async fn start(setup: Setup) -> Harness {
    let captured = Captured::default();
    let accounts = Arc::new(TestAccounts::default());
    let counts = Arc::new(Counts::default());
    let (tls, ca) = certificate();
    let mut server = Server::new(
        setup.config,
        Dir,
        CaptureSink(captured.clone()),
        Obs(counts.clone()),
        setup.resolver,
    )
    .with_tls(tls)
    .with_accounts(accounts.clone());
    if let Some(k) = setup.dkim {
        server = server.with_dkim(Arc::new(k));
    }
    let server = server.shared();
    let mut addrs = HashMap::new();
    for (name, mode) in [
        ("25", Mode::Inbound),
        ("587", Mode::Submission),
        ("465", Mode::SubmissionImplicitTls),
    ] {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        addrs.insert(name, l.local_addr().unwrap());
        tokio::spawn(server.clone().run(l, mode));
    }
    Harness {
        addrs,
        captured,
        accounts,
        counts,
        ca,
    }
}

// ---------------------------------------------------------------- client

enum Stream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Gone,
}

struct Client {
    stream: Stream,
    buf: Vec<u8>,
    ca: Vec<u8>,
}

fn connector(ca: &[u8]) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(ca.to_vec()))
        .unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

async fn tls_wrap(ca: &[u8], tcp: TcpStream) -> tokio_rustls::client::TlsStream<TcpStream> {
    let name = rustls_pki_types::ServerName::try_from("mx.example.org").unwrap();
    connector(ca).connect(name, tcp).await.unwrap()
}

impl Client {
    async fn connect(h: &Harness, port: &str) -> (Self, Reply) {
        let tcp = TcpStream::connect(h.addrs[port]).await.unwrap();
        let mut c = Self {
            stream: Stream::Plain(tcp),
            buf: Vec::new(),
            ca: h.ca.clone(),
        };
        let g = c.reply().await.expect("greeting");
        (c, g)
    }

    async fn connect_implicit_tls(h: &Harness) -> (Self, Reply) {
        let tcp = TcpStream::connect(h.addrs["465"]).await.unwrap();
        let tls = tls_wrap(&h.ca, tcp).await;
        let mut c = Self {
            stream: Stream::Tls(Box::new(tls)),
            buf: Vec::new(),
            ca: h.ca.clone(),
        };
        let g = c.reply().await.expect("greeting");
        (c, g)
    }

    async fn send(&mut self, b: &[u8]) {
        let r = match &mut self.stream {
            Stream::Plain(s) => s.write_all(b).await,
            Stream::Tls(s) => s.write_all(b).await,
            Stream::Gone => return,
        };
        let _ = r;
    }

    async fn read_some(&mut self) -> usize {
        let mut chunk = [0u8; 8192];
        let fut = async {
            match &mut self.stream {
                Stream::Plain(s) => s.read(&mut chunk).await,
                Stream::Tls(s) => s.read(&mut chunk).await,
                Stream::Gone => Ok(0),
            }
        };
        let n = tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .expect("server did not answer")
            .unwrap_or(0);
        self.buf.extend_from_slice(&chunk[..n]);
        n
    }

    async fn reply(&mut self) -> Option<Reply> {
        loop {
            if let Some((r, n)) = Reply::parse(&self.buf, 4096).unwrap() {
                self.buf.drain(..n);
                return Some(r);
            }
            if self.read_some().await == 0 {
                return None;
            }
        }
    }

    async fn cmd(&mut self, line: &str) -> Reply {
        self.send(format!("{line}\r\n").as_bytes()).await;
        self.reply().await.expect("reply")
    }

    async fn is_closed(&mut self) -> bool {
        self.reply().await.is_none()
    }

    async fn starttls(&mut self) {
        let r = self.cmd("STARTTLS").await;
        assert_eq!(r.code, 220, "{r:?}");
        let Stream::Plain(tcp) = std::mem::replace(&mut self.stream, Stream::Gone) else {
            panic!("already TLS")
        };
        self.stream = Stream::Tls(Box::new(tls_wrap(&self.ca, tcp).await));
    }

    async fn login(&mut self, user: &str, pass: &str) -> Reply {
        let plain = STANDARD.encode(format!("\0{user}\0{pass}"));
        self.cmd(&format!("AUTH PLAIN {plain}")).await
    }

    async fn ehlo_caps(&mut self) -> Vec<String> {
        let r = self.cmd("EHLO client.example.net").await;
        assert_eq!(r.code, 250);
        r.lines
    }
}

fn enhanced(r: &Reply) -> String {
    r.enhanced.map(|e| e.to_string()).unwrap_or_default()
}

// ---------------------------------------------------------------- 1. STARTTLS injection

#[tokio::test]
async fn starttls_injection_never_executes_pipelined_command() {
    for port in ["25", "587"] {
        let h = start(Setup::default()).await;
        let (mut c, _) = Client::connect(&h, port).await;
        c.cmd("EHLO client.example.net").await;
        // CVE-2011-0411 class: the MAIL command rides in the same packet.
        c.send(b"STARTTLS\r\nMAIL FROM:<x@y.example>\r\n").await;
        let r = c.reply().await.unwrap();
        assert_eq!(
            (r.code, enhanced(&r)),
            (554, "5.5.1".into()),
            "port {port}: {r:?}"
        );
        // No 220, no reply to MAIL: the connection is simply closed.
        assert!(c.is_closed().await, "port {port}");
        assert!(h.captured.all().is_empty());
    }
}

// ---------------------------------------------------------------- 2. state reset

#[tokio::test]
async fn tls_resets_all_session_state() {
    let h = start(Setup::default()).await;
    let (mut c, _) = Client::connect(&h, "25").await;
    let caps = c.ehlo_caps().await;
    assert!(caps.iter().any(|l| l == "STARTTLS"));
    // Learned before TLS: an invalid name (a signal) and an open transaction.
    c.cmd("EHLO bad_name.example").await;
    assert_eq!(c.cmd("MAIL FROM:<s@remote.example>").await.code, 250);
    c.starttls().await;
    // RFC 3207 §4.2: all of it is gone; EHLO is required again.
    assert_eq!(
        c.cmd("RCPT TO:<bob@example.org>").await.code,
        503,
        "transaction discarded"
    );
    assert_eq!(
        c.cmd("MAIL FROM:<s@remote.example>").await.code,
        503,
        "EHLO required again"
    );
    let caps = c.ehlo_caps().await;
    assert!(
        !caps.iter().any(|l| l == "STARTTLS"),
        "not offered under TLS"
    );
    assert_eq!(c.cmd("STARTTLS").await.code, 503);
    c.cmd("MAIL FROM:<s@remote.example>").await;
    c.cmd("RCPT TO:<bob@example.org>").await;
    c.cmd("DATA").await;
    c.send(b"Subject: x\r\n\r\nx\r\n.\r\n").await;
    assert_eq!(c.reply().await.unwrap().code, 250);
    let (env, msg) = &h.captured.all()[0];
    assert_eq!(
        env.signals,
        smtp_server::Signals::default(),
        "signals from before TLS discarded"
    );
    assert!(String::from_utf8_lossy(msg).contains("with ESMTPS id"));
}

#[tokio::test]
async fn tls_resets_authentication() {
    // A session authenticated over 465 can't carry AUTH state anywhere: the
    // only way to TLS on 587 is STARTTLS, which resets. Check that AUTH
    // after STARTTLS is required even if attempted before.
    let h = start(Setup::default()).await;
    let (mut c, _) = Client::connect(&h, "587").await;
    c.cmd("EHLO client.example.net").await;
    assert_eq!(
        c.login("alice@example.org", "alice-pw").await.code,
        538,
        "no AUTH before TLS"
    );
    c.starttls().await;
    c.cmd("EHLO client.example.net").await;
    assert_eq!(
        c.cmd("MAIL FROM:<alice@example.org>").await.code,
        530,
        "not authenticated"
    );
}

// ---------------------------------------------------------------- 3. timeouts

#[tokio::test]
async fn tls_handshake_timeout() {
    let mut setup = Setup::default();
    setup.config.tls_handshake_timeout = Duration::from_millis(200);
    let h = start(setup).await;
    let (mut c, _) = Client::connect(&h, "25").await;
    c.cmd("EHLO client.example.net").await;
    assert_eq!(c.cmd("STARTTLS").await.code, 220);
    let started = Instant::now();
    // Never start the handshake: the server gives up.
    assert!(c.is_closed().await);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn command_timeout() {
    let mut setup = Setup::default();
    setup.config.command_timeout = Duration::from_millis(200);
    let h = start(setup).await;
    let (mut c, _) = Client::connect(&h, "25").await;
    let r = c.reply().await.unwrap();
    assert_eq!((r.code, enhanced(&r)), (421, "4.4.2".into()));
    assert!(c.is_closed().await);
}

#[tokio::test]
async fn session_time_cap() {
    let mut setup = Setup::default();
    setup.config.session_timeout = Duration::from_millis(400);
    let h = start(setup).await;
    let (mut c, _) = Client::connect(&h, "25").await;
    // A client that stays busy is still cut off at the cap.
    let mut last = None;
    for _ in 0..20 {
        let r = c.cmd("NOOP").await;
        if r.code != 250 {
            last = Some(r);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let r = last.expect("session was never cut off");
    assert_eq!((r.code, enhanced(&r)), (421, "4.4.2".into()));
    assert!(c.is_closed().await);
}

// ---------------------------------------------------------------- 4. AUTH only with TLS, never on 25

#[tokio::test]
async fn auth_requires_tls_and_never_on_port_25() {
    let h = start(Setup::default()).await;
    // 587 before TLS: STARTTLS offered, AUTH not.
    let (mut c, _) = Client::connect(&h, "587").await;
    let caps = c.ehlo_caps().await;
    assert!(caps.iter().any(|l| l == "STARTTLS"));
    assert!(!caps.iter().any(|l| l.starts_with("AUTH")));
    let r = c.login("alice@example.org", "alice-pw").await;
    assert_eq!((r.code, enhanced(&r)), (538, "5.7.11".into()));
    assert_eq!(c.cmd("MAIL FROM:<alice@example.org>").await.code, 530);
    // After TLS: AUTH offered, STARTTLS not.
    c.starttls().await;
    let caps = c.ehlo_caps().await;
    assert!(caps.iter().any(|l| l == "AUTH PLAIN LOGIN"));
    assert!(!caps.iter().any(|l| l == "STARTTLS"));
    assert_eq!(c.login("alice@example.org", "alice-pw").await.code, 235);
    let caps = c.ehlo_caps().await;
    assert!(
        !caps.iter().any(|l| l.starts_with("AUTH")),
        "not offered again once authenticated"
    );

    // Port 25 never offers or accepts AUTH, even under TLS.
    let (mut c, _) = Client::connect(&h, "25").await;
    c.cmd("EHLO client.example.net").await;
    c.starttls().await;
    let caps = c.ehlo_caps().await;
    assert!(!caps.iter().any(|l| l.starts_with("AUTH")));
    assert_eq!(c.login("alice@example.org", "alice-pw").await.code, 502);

    // 465: TLS from the start.
    let (mut c, g) = Client::connect_implicit_tls(&h).await;
    assert_eq!(g.code, 220);
    let caps = c.ehlo_caps().await;
    assert!(caps.iter().any(|l| l == "AUTH PLAIN LOGIN"));
    assert!(!caps.iter().any(|l| l == "STARTTLS"));
    assert_eq!(c.login("bob@example.org", "bob-pw").await.code, 235);
}

#[tokio::test]
async fn auth_login_and_cancel() {
    let h = start(Setup::default()).await;
    let (mut c, _) = Client::connect_implicit_tls(&h).await;
    c.cmd("EHLO client.example.net").await;
    let r = c.cmd("AUTH LOGIN").await;
    assert_eq!((r.code, r.lines[0].as_str()), (334, "VXNlcm5hbWU6"));
    let r = c.cmd(&STANDARD.encode("alice@example.org")).await;
    assert_eq!((r.code, r.lines[0].as_str()), (334, "UGFzc3dvcmQ6"));
    assert_eq!(c.cmd(&STANDARD.encode("alice-pw")).await.code, 235);
    // RFC 4954 §4: a second AUTH is refused.
    assert_eq!(c.login("alice@example.org", "alice-pw").await.code, 503);
    // Cancelling with "*" gives 501.
    let (mut c, _) = Client::connect_implicit_tls(&h).await;
    c.cmd("EHLO client.example.net").await;
    assert_eq!(c.cmd("AUTH PLAIN").await.code, 334);
    assert_eq!(c.cmd("*").await.code, 501);
    assert_eq!(c.cmd("AUTH CRAM-MD5").await.code, 504);
}

// ---------------------------------------------------------------- 5. brute force

#[tokio::test]
async fn failed_logins_look_the_same_and_slow_down() {
    let mut setup = Setup::default();
    setup.config.auth_limits = AuthLimits {
        free_failures: 1,
        base_delay: Duration::from_millis(150),
        max_delay: Duration::from_secs(2),
        ip_lockout_failures: 5,
        max_attempts_per_session: 3,
        ..AuthLimits::default()
    };
    let h = start(setup).await;
    let (mut c, _) = Client::connect_implicit_tls(&h).await;
    c.cmd("EHLO client.example.net").await;
    // An unknown account and a wrong password get identical replies.
    let unknown = c.login("nobody@example.org", "x").await;
    let started = Instant::now();
    let wrong = c.login("alice@example.org", "wrong").await;
    let second = started.elapsed();
    assert_eq!(
        (unknown.code, enhanced(&unknown), unknown.lines.clone()),
        (
            535,
            "5.7.8".into(),
            vec!["Authentication credentials invalid".into()]
        )
    );
    assert_eq!(
        (wrong.code, enhanced(&wrong), wrong.lines),
        (unknown.code, enhanced(&unknown), unknown.lines)
    );
    assert!(
        second >= Duration::from_millis(150),
        "delay after the free failure: {second:?}"
    );
    // The third failure in one session closes it.
    let r = c.login("alice@example.org", "wrong").await;
    assert_eq!((r.code, enhanced(&r)), (421, "4.7.0".into()));
    assert!(c.is_closed().await);
    // More failures from this IP lock it out (with growing delays).
    let (mut c, _) = Client::connect_implicit_tls(&h).await;
    c.cmd("EHLO client.example.net").await;
    c.login("alice@example.org", "wrong").await;
    c.login("alice@example.org", "wrong").await;
    let (mut c, _) = Client::connect_implicit_tls(&h).await;
    c.cmd("EHLO client.example.net").await;
    let calls = h.accounts.calls.load(Ordering::SeqCst);
    let r = c.login("alice@example.org", "alice-pw").await;
    assert_eq!(
        (r.code, enhanced(&r)),
        (421, "4.7.0".into()),
        "locked out even with the right password"
    );
    assert_eq!(
        h.accounts.calls.load(Ordering::SeqCst),
        calls,
        "no password check while locked out"
    );
    assert_eq!(h.counts.auth_failures.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn password_checks_are_capped() {
    let mut setup = Setup::default();
    setup.config.auth_limits = AuthLimits {
        max_concurrent_verifications: 1,
        ..AuthLimits::default()
    };
    let h = Arc::new(start(setup).await);
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let h = h.clone();
        tasks.push(tokio::spawn(async move {
            let (mut c, _) = Client::connect_implicit_tls(&h).await;
            c.cmd("EHLO client.example.net").await;
            c.login("alice@example.org", "alice-pw").await.code
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), 235);
    }
    assert_eq!(
        h.accounts.max_running.load(Ordering::SeqCst),
        1,
        "never more than one Argon2 check at once"
    );
}

// ---------------------------------------------------------------- 6. sender authorization

async fn logged_in(h: &Harness, user: &str, pass: &str) -> Client {
    let (mut c, _) = Client::connect_implicit_tls(h).await;
    c.cmd("EHLO client.example.net").await;
    assert_eq!(c.login(user, pass).await.code, 235);
    c
}

#[tokio::test]
async fn users_cannot_forge_other_senders() {
    let h = start(Setup::default()).await;
    let mut c = logged_in(&h, "alice@example.org", "alice-pw").await;
    // MAIL FROM someone else.
    let r = c.cmd("MAIL FROM:<bob@example.org>").await;
    assert_eq!(
        (r.code, enhanced(&r), r.lines[0].as_str()),
        (553, "5.7.1".into(), "sender not owned by user")
    );
    assert_eq!(c.cmd("MAIL FROM:<>").await.code, 553);
    // Own MAIL FROM, but someone else's From header.
    assert_eq!(c.cmd("MAIL FROM:<Alice@example.org>").await.code, 250);
    c.cmd("RCPT TO:<bob@example.org>").await;
    c.cmd("DATA").await;
    c.send(b"From: Bob <bob@example.org>\r\nSubject: hi\r\n\r\nx\r\n.\r\n")
        .await;
    let r = c.reply().await.unwrap();
    assert_eq!((r.code, enhanced(&r)), (553, "5.7.1".into()));
    // Two From addresses, one of them not hers.
    c.cmd("MAIL FROM:<alice@example.org>").await;
    c.cmd("RCPT TO:<bob@example.org>").await;
    c.cmd("DATA").await;
    c.send(b"From: alice@example.org, bob@example.org\r\n\r\nx\r\n.\r\n")
        .await;
    assert_eq!(c.reply().await.unwrap().code, 553);
    // Her own address works.
    c.cmd("MAIL FROM:<alice@example.org>").await;
    c.cmd("RCPT TO:<bob@example.org>").await;
    c.cmd("DATA").await;
    c.send(b"From: Alice <alice@example.org>\r\n\r\nx\r\n.\r\n")
        .await;
    assert_eq!(c.reply().await.unwrap().code, 250);
    assert_eq!(h.captured.all().len(), 1);
}

// ---------------------------------------------------------------- 7. submission pipeline

#[tokio::test]
async fn submission_reencodes_signs_and_routes() {
    let key = dkim::keygen::ed25519().unwrap();
    let mut keys = DkimKeys::new();
    keys.add(
        "example.org",
        Signer::new(
            SigningKey::from_pkcs8(&key.private_pkcs8).unwrap(),
            "example.org",
            "ed",
        )
        .unwrap(),
    );
    let mut setup = Setup {
        dkim: Some(keys),
        ..Setup::default()
    };
    setup.config.test_mode_allow = Some(vec!["remote.example".into()]);
    let h = start(setup).await;
    let mut c = logged_in(&h, "alice@example.org", "alice-pw").await;
    c.cmd("MAIL FROM:<alice@example.org>").await;
    assert_eq!(c.cmd("RCPT TO:<bob@example.org>").await.code, 250);
    assert_eq!(c.cmd("RCPT TO:<carol@remote.example>").await.code, 250);
    // Test mode: only allow-listed remote domains.
    let r = c.cmd("RCPT TO:<eve@gmail.com>").await;
    assert_eq!((r.code, enhanced(&r)), (550, "5.7.1".into()));
    assert_eq!(
        c.cmd("RCPT TO:<x@[192.0.2.1]>").await.code,
        550,
        "no address literals"
    );
    c.cmd("DATA").await;
    let long = "y".repeat(1500);
    c.send(format!("From: Alice <alice@example.org>\r\nTo: bob@example.org\r\nSubject: long\r\n\r\n{long}\r\n.\r\n").as_bytes()).await;
    assert_eq!(c.reply().await.unwrap().code, 250);

    let (env, msg) = h.captured.all().remove(0);
    assert_eq!(
        env.recipients,
        vec![
            Rcpt::Local("bob@example.org".into()),
            Rcpt::Remote("carol@remote.example".into())
        ]
    );
    assert_eq!(env.authenticated.as_deref(), Some("alice@example.org"));
    let text = String::from_utf8(msg.clone()).unwrap();
    assert!(text.lines().all(|l| l.len() <= 998), "no over-long lines");
    assert!(text.contains("Content-Transfer-Encoding: quoted-printable"));
    assert!(
        text.contains("\r\nDate: ") && text.contains("\r\nMessage-ID: <"),
        "Date and Message-ID added"
    );
    assert!(text.contains("with ESMTPSA id"));
    assert!(!text.contains("alice-pw"));
    // The DKIM signature verifies (it was made after re-encoding).
    let r = StaticResolver::new().with_txt("ed._domainkey.example.org", &key.dns_record);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let results = dkim::verify(&r, &msg, now).await;
    assert_eq!(
        results.iter().map(|v| v.result.clone()).collect::<Vec<_>>(),
        vec![DkimResult::Pass]
    );
}

// ---------------------------------------------------------------- 8-10. inbound checks and policies

/// example.org and remote domains with SPF and DMARC records.
fn inbound_setup(extra: impl FnOnce(StaticResolver) -> StaticResolver) -> Setup {
    let mut setup = Setup::default();
    setup.config.inbound_checks = true;
    setup.resolver = extra(StaticResolver::new()).with_txt("example.org", "v=spf1 -all");
    setup
}

async fn send_inbound(h: &Harness, from_header: &str, mail_from: &str) -> Reply {
    let (mut c, _) = Client::connect(h, "25").await;
    c.cmd("EHLO mail.sender.example").await;
    c.cmd(&format!("MAIL FROM:<{mail_from}>")).await;
    c.cmd("RCPT TO:<bob@example.org>").await;
    c.cmd("DATA").await;
    c.send(
        format!("Authentication-Results: mx.example.org; dkim=pass header.d=bank.example\r\nFrom: {from_header}\r\nSubject: hi\r\n\r\nbody\r\n.\r\n")
            .as_bytes(),
    )
    .await;
    c.reply().await.unwrap()
}

#[tokio::test]
async fn forged_auth_results_stripped_and_ours_added() {
    let h = start(inbound_setup(|r| r)).await;
    assert_eq!(
        send_inbound(&h, "x@sender.example", "x@sender.example")
            .await
            .code,
        250
    );
    let (_, msg) = h.captured.all().remove(0);
    let text = String::from_utf8(msg).unwrap();
    assert_eq!(text.matches("Authentication-Results:").count(), 1, "{text}");
    assert!(
        !text.contains("header.d=bank.example"),
        "forged result removed"
    );
    assert!(text.contains("Authentication-Results: mx.example.org;\r\n\tspf=none smtp.mailfrom=sender.example;\r\n\tdkim=none;\r\n\tdmarc=none"), "{text}");
}

#[tokio::test]
async fn dmarc_policies() {
    let h = start(inbound_setup(|r| {
        r.with_txt("_dmarc.reject.example", "v=DMARC1; p=reject")
            .with_txt("_dmarc.quarantine.example", "v=DMARC1; p=quarantine")
            .with_txt("_dmarc.testing.example", "v=DMARC1; p=quarantine; t=y")
            .with_txt("_dmarc.none.example", "v=DMARC1; p=none")
            .with_txt("reject.example", "v=spf1 -all")
            .with_txt("none.example", "v=spf1 -all")
            .with_failure(
                "_dmarc.broken.example",
                dns::Error::Temporary("servfail".into()),
            )
    }))
    .await;
    // p=reject: 550 5.7.1, nothing stored.
    let r = send_inbound(&h, "ceo@reject.example", "ceo@reject.example").await;
    assert_eq!((r.code, enhanced(&r)), (550, "5.7.1".into()));
    assert!(h.captured.all().is_empty());
    // p=quarantine: Junk.
    assert_eq!(
        send_inbound(&h, "a@quarantine.example", "a@quarantine.example")
            .await
            .code,
        250
    );
    // t=y downgrades quarantine to none: inbox.
    assert_eq!(
        send_inbound(&h, "a@testing.example", "a@testing.example")
            .await
            .code,
        250
    );
    // SPF fail with p=none: delivered normally (SPF fail alone never rejects).
    assert_eq!(
        send_inbound(&h, "a@none.example", "a@none.example")
            .await
            .code,
        250
    );
    // DNS trouble: fail open, recorded as temperror.
    assert_eq!(
        send_inbound(&h, "a@broken.example", "a@broken.example")
            .await
            .code,
        250
    );
    // permerror (two From domains beyond what we can align): Junk, not rejected.
    assert_eq!(
        send_inbound(
            &h,
            "a@one.example, b@two.example, c@three.example, d@four.example",
            "a@one.example"
        )
        .await
        .code,
        250
    );

    let got: Vec<(bool, String)> = h
        .captured
        .all()
        .into_iter()
        .map(|(e, m)| (e.junk, String::from_utf8(m).unwrap()))
        .collect();
    assert_eq!(got.len(), 5);
    assert!(
        got[0].0
            && got[0]
                .1
                .contains("dmarc=fail header.from=quarantine.example"),
        "quarantine -> junk"
    );
    assert!(
        !got[1].0 && got[1].1.contains("dmarc=fail header.from=testing.example"),
        "t=y -> inbox"
    );
    assert!(
        !got[2].0 && got[2].1.contains("spf=fail") && got[2].1.contains("dmarc=fail"),
        "spf fail + p=none -> inbox"
    );
    assert!(
        !got[3].0 && got[3].1.contains("dmarc=temperror"),
        "temperror -> inbox"
    );
    assert!(
        got[4].0 && got[4].1.contains("dmarc=permerror"),
        "permerror -> junk"
    );
}

#[tokio::test]
async fn spf_fail_alone_never_rejects() {
    // SPF fails and the domain has no DMARC record at all.
    let h = start(inbound_setup(|r| {
        r.with_txt("forwarded.example", "v=spf1 -all")
    }))
    .await;
    assert_eq!(
        send_inbound(&h, "a@forwarded.example", "a@forwarded.example")
            .await
            .code,
        250
    );
    let (env, msg) = h.captured.all().remove(0);
    assert!(!env.junk);
    assert!(
        String::from_utf8(msg).unwrap().contains("spf=fail"),
        "kept as a signal"
    );
}

#[tokio::test]
async fn authenticated_submission_skips_inbound_dmarc() {
    // example.org says p=reject and its SPF allows nobody; a logged-in
    // user's mail must still go through.
    let h = start(inbound_setup(|r| {
        r.with_txt("_dmarc.example.org", "v=DMARC1; p=reject")
    }))
    .await;
    let mut c = logged_in(&h, "alice@example.org", "alice-pw").await;
    c.cmd("MAIL FROM:<alice@example.org>").await;
    c.cmd("RCPT TO:<bob@example.org>").await;
    c.cmd("DATA").await;
    c.send(b"From: alice@example.org\r\n\r\nhello\r\n.\r\n")
        .await;
    assert_eq!(c.reply().await.unwrap().code, 250);
    let (env, _) = h.captured.all().remove(0);
    assert!(!env.junk);
}

#[allow(dead_code)]
fn assert_send<T: AsyncRead + AsyncWrite + Send>() {}
