//! The test harness shared by the milestone 6 test binaries: an SMTP
//! server on loopback with all three listener modes, a test certificate,
//! and a small SMTP/TLS client.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use dns::testing::StaticResolver;
use smtp_proto::{ForwardPath, Host, Reply};
use smtp_server::{
    Accounts, Directory, DkimKeys, Envelope, InboundConfig, Mode, Observer, Recipient, Server, Sink,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------- fixtures

pub(crate) struct Dir;

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
pub(crate) struct TestAccounts {
    pub(crate) running: AtomicUsize,
    pub(crate) max_running: AtomicUsize,
    pub(crate) calls: AtomicUsize,
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

    fn account_name(&self, username: &str) -> Option<String> {
        ["alice@example.org", "bob@example.org"]
            .into_iter()
            .find(|u| u.eq_ignore_ascii_case(username))
            .map(str::to_owned)
    }
}

pub(crate) type Delivered = Vec<(Envelope, Vec<u8>)>;

#[derive(Default, Clone)]
pub(crate) struct Captured(pub(crate) Arc<Mutex<Delivered>>);

impl Captured {
    pub(crate) fn all(&self) -> Delivered {
        self.0.lock().unwrap().clone()
    }
}

pub(crate) struct CaptureSink(pub(crate) Captured);

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
pub(crate) struct Counts {
    pub(crate) auth_failures: AtomicUsize,
}

pub(crate) struct Obs(pub(crate) Arc<Counts>);

impl Observer for Obs {
    fn auth_failure(&self, _: IpAddr) {
        self.0.auth_failures.fetch_add(1, Ordering::SeqCst);
    }
}

/// A self-signed certificate for mx.example.org.
pub(crate) fn certificate() -> (Arc<rustls::ServerConfig>, Vec<u8>) {
    let key = rcgen::generate_simple_self_signed(vec!["mx.example.org".to_owned()]).unwrap();
    let cert_pem = key.cert.pem();
    let key_pem = key.signing_key.serialize_pem();
    let server = smtp_server::tls::server_config(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap();
    (server, key.cert.der().to_vec())
}

pub(crate) struct Harness {
    pub(crate) addrs: HashMap<&'static str, SocketAddr>,
    pub(crate) captured: Captured,
    pub(crate) accounts: Arc<TestAccounts>,
    pub(crate) counts: Arc<Counts>,
    pub(crate) ca: Vec<u8>,
}

pub(crate) struct Setup {
    pub(crate) config: InboundConfig,
    pub(crate) resolver: StaticResolver,
    pub(crate) dkim: Option<DkimKeys>,
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

pub(crate) async fn start(setup: Setup) -> Harness {
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

pub(crate) enum Stream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Gone,
}

pub(crate) struct Client {
    stream: Stream,
    buf: Vec<u8>,
    ca: Vec<u8>,
}

pub(crate) fn connector(ca: &[u8]) -> tokio_rustls::TlsConnector {
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

pub(crate) async fn tls_wrap(
    ca: &[u8],
    tcp: TcpStream,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let name = rustls_pki_types::ServerName::try_from("mx.example.org").unwrap();
    connector(ca).connect(name, tcp).await.unwrap()
}

impl Client {
    pub(crate) async fn connect(h: &Harness, port: &str) -> (Self, Reply) {
        let tcp = TcpStream::connect(h.addrs[port]).await.unwrap();
        let mut c = Self {
            stream: Stream::Plain(tcp),
            buf: Vec::new(),
            ca: h.ca.clone(),
        };
        let g = c.reply().await.expect("greeting");
        (c, g)
    }

    pub(crate) async fn connect_implicit_tls(h: &Harness) -> (Self, Reply) {
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

    pub(crate) async fn send(&mut self, b: &[u8]) {
        let r = match &mut self.stream {
            Stream::Plain(s) => s.write_all(b).await,
            Stream::Tls(s) => s.write_all(b).await,
            Stream::Gone => return,
        };
        let _ = r;
    }

    pub(crate) async fn read_some(&mut self) -> usize {
        let mut chunk = [0u8; 8192];
        let fut = async {
            match &mut self.stream {
                Stream::Plain(s) => s.read(&mut chunk).await,
                Stream::Tls(s) => s.read(&mut chunk).await,
                Stream::Gone => Ok(0),
            }
        };
        let n = tokio::time::timeout(Duration::from_secs(60), fut)
            .await
            .expect("server did not answer")
            .unwrap_or(0);
        self.buf.extend_from_slice(&chunk[..n]);
        n
    }

    pub(crate) async fn reply(&mut self) -> Option<Reply> {
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

    pub(crate) async fn cmd(&mut self, line: &str) -> Reply {
        self.send(format!("{line}\r\n").as_bytes()).await;
        self.reply().await.expect("reply")
    }

    pub(crate) async fn is_closed(&mut self) -> bool {
        self.reply().await.is_none()
    }

    pub(crate) async fn starttls(&mut self) {
        let r = self.cmd("STARTTLS").await;
        assert_eq!(r.code, 220, "{r:?}");
        let Stream::Plain(tcp) = std::mem::replace(&mut self.stream, Stream::Gone) else {
            panic!("already TLS")
        };
        self.stream = Stream::Tls(Box::new(tls_wrap(&self.ca, tcp).await));
    }

    pub(crate) async fn login(&mut self, user: &str, pass: &str) -> Reply {
        let plain = STANDARD.encode(format!("\0{user}\0{pass}"));
        self.cmd(&format!("AUTH PLAIN {plain}")).await
    }

    pub(crate) async fn ehlo_caps(&mut self) -> Vec<String> {
        let r = self.cmd("EHLO client.example.net").await;
        assert_eq!(r.code, 250);
        r.lines
    }
}

pub(crate) fn enhanced(r: &Reply) -> String {
    r.enhanced.map(|e| e.to_string()).unwrap_or_default()
}
