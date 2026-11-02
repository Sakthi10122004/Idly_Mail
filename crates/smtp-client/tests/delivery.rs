//! Outbound delivery against a scripted fake MX and a fake MTA-STS policy
//! host on loopback. DNS is a static zone; the loopback test dialer is the
//! only way to reach 127.0.0.1 (the production dialer refuses it).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use dns::testing::StaticResolver;
use dns::{Answer, Mx, Resolver, Tlsa};
use http_body_util::Full;
use hyper::body::Bytes;
use queue::{Clock, Outcome};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, PublicKeyData,
};
use ring::digest::{SHA256, digest};
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use smtp_client::testing::Loopback;
use smtp_client::{Client, ClientConfig, Dialer, Direct, Families, Sources};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

// ---------------------------------------------------------------- PKI

struct Pki {
    ca: CertifiedIssuer<'static, KeyPair>,
}

impl Pki {
    fn new() -> Self {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name
            .push(DnType::CommonName, "Idly Test CA");
        Self {
            ca: CertifiedIssuer::self_signed(p, KeyPair::generate().unwrap()).unwrap(),
        }
    }

    fn roots(&self) -> Arc<RootCertStore> {
        let mut r = RootCertStore::empty();
        r.add(self.ca.der().clone()).unwrap();
        Arc::new(r)
    }

    /// A server config with a leaf for `names` signed by the CA, the
    /// chain [leaf, CA], and the leaf's SPKI.
    fn server(&self, names: &[&str]) -> (Arc<ServerConfig>, Vec<CertificateDer<'static>>, Vec<u8>) {
        let key = KeyPair::generate().unwrap();
        let params =
            CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
                .unwrap();
        let leaf = params.signed_by(&key, &self.ca).unwrap();
        let chain = vec![leaf.der().clone(), self.ca.der().clone()];
        (
            server_config(chain.clone(), &key),
            chain,
            key.subject_public_key_info(),
        )
    }
}

fn server_config(chain: Vec<CertificateDer<'static>>, key: &KeyPair) -> Arc<ServerConfig> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    Arc::new(
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap(),
    )
}

/// A self-signed certificate nobody trusts.
fn self_signed(names: &[&str]) -> (Arc<ServerConfig>, Vec<u8>) {
    let c = rcgen::generate_simple_self_signed(
        names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>(),
    )
    .unwrap();
    (
        server_config(vec![c.cert.der().clone()], &c.signing_key),
        c.signing_key.subject_public_key_info(),
    )
}

fn sha256(b: &[u8]) -> Vec<u8> {
    digest(&SHA256, b).as_ref().to_vec()
}

// ---------------------------------------------------------------- fake MX

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

#[derive(Clone, Default)]
struct Script {
    /// EHLO keywords (STARTTLS is added when `tls` is set).
    caps: Vec<&'static str>,
    tls: Option<Arc<ServerConfig>>,
    /// Reply to STARTTLS with 220, then send garbage instead of TLS.
    broken_tls: bool,
    /// Replies to RCPT by address (default 250).
    rcpt: HashMap<&'static str, &'static str>,
    /// The reply to MAIL (default 250).
    mail: Option<&'static str>,
}

#[derive(Debug, Clone, Default)]
struct Session {
    peer: Option<SocketAddr>,
    ehlo: Vec<String>,
    tls: bool,
    commands: Vec<String>,
    data: Vec<Vec<u8>>,
    /// Commands that arrived while an earlier one was still unanswered.
    pipelined: usize,
}

impl Session {
    fn count(&self, verb: &str) -> usize {
        self.commands
            .iter()
            .filter(|c| c.to_ascii_uppercase().starts_with(verb))
            .count()
    }
}

type Log = Arc<Mutex<Vec<Session>>>;

async fn fake_mx(script: Script) -> (u16, Log) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: Log = Arc::default();
    let l = log.clone();
    tokio::spawn(async move {
        while let Ok((s, peer)) = listener.accept().await {
            let idx = {
                let mut l = l.lock().unwrap();
                l.push(Session {
                    peer: Some(peer),
                    ..Session::default()
                });
                l.len() - 1
            };
            tokio::spawn(serve_mx(Box::new(s), script.clone(), l.clone(), idx));
        }
    });
    (port, log)
}

async fn read_line(s: &mut Box<dyn Io>, buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    loop {
        if let Some(i) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = buf[..i].to_vec();
            buf.drain(..i + 2);
            return Some(line);
        }
        let mut chunk = [0u8; 4096];
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn serve_mx(mut s: Box<dyn Io>, script: Script, log: Log, idx: usize) {
    let record = |f: &dyn Fn(&mut Session)| f(&mut log.lock().unwrap()[idx]);
    let _ = s.write_all(b"220 mx.example.com ESMTP fake\r\n").await;
    let mut buf = Vec::new();
    let mut tls = false;
    while let Some(line) = read_line(&mut s, &mut buf).await {
        let text = String::from_utf8_lossy(&line).to_string();
        let waiting = buf.windows(2).any(|w| w == b"\r\n");
        record(&|x| {
            x.commands.push(text.clone());
            x.pipelined += usize::from(waiting);
        });
        let upper = text.to_ascii_uppercase();
        let reply: String = if upper.starts_with("EHLO ") {
            record(&|x| x.ehlo.push(text[5..].to_owned()));
            let mut caps = script
                .caps
                .iter()
                .map(|c| (*c).to_owned())
                .collect::<Vec<_>>();
            if (script.tls.is_some() || script.broken_tls) && !tls {
                caps.push("STARTTLS".into());
            }
            let mut r = String::from("250-mx.example.com\r\n");
            for (i, c) in caps.iter().enumerate() {
                let sep = if i + 1 == caps.len() { ' ' } else { '-' };
                r.push_str(&format!("250{sep}{c}\r\n"));
            }
            if caps.is_empty() {
                r = "250 mx.example.com\r\n".into();
            }
            r
        } else if upper == "STARTTLS" && script.broken_tls {
            let _ = s.write_all(b"220 2.0.0 go\r\n").await;
            let _ = s.write_all(b"this is not TLS\r\n").await;
            return;
        } else if upper == "STARTTLS" && !tls && script.tls.is_some() {
            let _ = s.write_all(b"220 2.0.0 go\r\n").await;
            let acceptor = tokio_rustls::TlsAcceptor::from(script.tls.clone().unwrap());
            match acceptor.accept(s).await {
                Ok(t) => {
                    s = Box::new(t);
                    tls = true;
                    buf.clear();
                    record(&|x| x.tls = true);
                    continue;
                }
                Err(_) => return,
            }
        } else if upper.starts_with("MAIL FROM:") && script.mail.is_some() {
            format!("{}\r\n", script.mail.unwrap_or_default())
        } else if upper.starts_with("MAIL FROM:") || upper == "RSET" {
            "250 2.1.0 ok\r\n".into()
        } else if upper.starts_with("RCPT TO:") {
            let addr = text[8..].trim().trim_start_matches('<');
            let addr = addr.split('>').next().unwrap_or_default();
            match script.rcpt.get(addr) {
                Some(r) => format!("{r}\r\n"),
                None => "250 2.1.5 ok\r\n".into(),
            }
        } else if upper == "DATA" {
            let _ = s.write_all(b"354 go ahead\r\n").await;
            loop {
                if buf.starts_with(b".\r\n") {
                    buf.drain(..3);
                    record(&|x| x.data.push(Vec::new()));
                    break;
                }
                if let Some(i) = buf.windows(5).position(|w| w == b"\r\n.\r\n") {
                    let data = buf[..i + 2].to_vec();
                    buf.drain(..i + 5);
                    record(&|x| x.data.push(data.clone()));
                    break;
                }
                let mut chunk = [0u8; 65536];
                match s.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            "250 2.0.0 queued\r\n".into()
        } else if upper == "QUIT" {
            let _ = s.write_all(b"221 2.0.0 bye\r\n").await;
            return;
        } else {
            "502 5.5.1 not implemented\r\n".into()
        };
        if s.write_all(reply.as_bytes()).await.is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------- fake MTA-STS host

#[derive(Clone)]
struct Https {
    port: u16,
    requests: Arc<AtomicUsize>,
    body: Arc<Mutex<(u16, &'static str, String)>>,
}

async fn https(
    tls: Arc<ServerConfig>,
    status: u16,
    content_type: &'static str,
    body: &str,
) -> Https {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let h = Https {
        port: listener.local_addr().unwrap().port(),
        requests: Arc::default(),
        body: Arc::new(Mutex::new((status, content_type, body.to_owned()))),
    };
    let srv = h.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            let acceptor = tokio_rustls::TlsAcceptor::from(tls.clone());
            let srv = srv.clone();
            tokio::spawn(async move {
                let Ok(s) = acceptor.accept(s).await else {
                    return;
                };
                let service = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let srv = srv.clone();
                        async move {
                            assert_eq!(req.uri().path(), "/.well-known/mta-sts.txt");
                            srv.requests.fetch_add(1, Ordering::SeqCst);
                            let (status, ct, body) = srv.body.lock().unwrap().clone();
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .status(status)
                                    .header("content-type", ct)
                                    .header("location", "https://evil.example/")
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap(),
                            )
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(s), service)
                    .await;
            });
        }
    });
    h
}

const POLICY_ENFORCE: &str =
    "version: STSv1\r\nmode: enforce\r\nmx: mx.example.com\r\nmax_age: 86400\r\n";

// ---------------------------------------------------------------- harness

#[derive(Debug, Default)]
struct ManualClock(AtomicU64);

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// example.com -> MX 10 mx.example.com -> 127.0.0.1.
fn zone() -> StaticResolver {
    StaticResolver::new()
        .with_mx("example.com", 10, "mx.example.com")
        .with_ip("mx.example.com", ip("127.0.0.1"))
}

fn client<R: Resolver>(
    resolver: R,
    dialer: Loopback,
    roots: Arc<RootCertStore>,
    clock: Arc<ManualClock>,
    tweak: impl FnOnce(&mut ClientConfig),
) -> Client<R, Loopback> {
    let mut config = ClientConfig::new("out.example.org", roots);
    tweak(&mut config);
    Client::new(config, resolver, dialer, clock)
}

fn simple(resolver: StaticResolver, smtp_port: u16) -> Client<StaticResolver, Loopback> {
    client(
        resolver,
        Loopback::new().map(25, smtp_port),
        Arc::new(RootCertStore::empty()),
        Arc::default(),
        |_| {},
    )
}

const MSG: &[u8] =
    b"From: a@example.org\r\nTo: b@example.com\r\nSubject: hi\r\n\r\nHello.\r\n.leading dot\r\n";

fn rcpts(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

fn status(o: &Outcome) -> String {
    match o {
        Outcome::Delivered => "delivered".into(),
        Outcome::Temporary(_) => "temporary".into(),
        Outcome::Permanent { status, .. } => status.clone(),
    }
}

// ---------------------------------------------------------------- f. one transaction, partial failures

#[tokio::test]
async fn several_recipients_one_transaction_with_partial_failures() {
    let mut script = Script {
        caps: vec!["8BITMIME", "SIZE 1000000"],
        ..Script::default()
    };
    script
        .rcpt
        .insert("bad@example.com", "550 5.1.1 no such user");
    script
        .rcpt
        .insert("later@example.com", "450 4.2.1 mailbox busy");
    let (port, log) = fake_mx(script).await;
    let c = simple(zone(), port);
    let out = c
        .deliver_to(
            "example.com",
            Some("a@example.org"),
            &rcpts(&[
                "one@example.com",
                "bad@example.com",
                "later@example.com",
                "two@example.com",
            ]),
            MSG,
        )
        .await;
    assert_eq!(
        out.iter().map(status).collect::<Vec<_>>(),
        ["delivered", "5.1.1", "temporary", "delivered"]
    );
    let log = log.lock().unwrap();
    assert_eq!(log.len(), 1, "one connection");
    let s = &log[0];
    assert_eq!(
        (s.count("MAIL"), s.count("RCPT"), s.count("DATA")),
        (1, 4, 1)
    );
    let mail = format!("MAIL FROM:<a@example.org> SIZE={}", MSG.len());
    assert!(s.commands.contains(&mail), "{:?}", s.commands);
    // Dot-stuffed on the wire.
    assert!(s.data[0].ends_with(b"\r\n..leading dot\r\n"));
}

#[tokio::test]
async fn no_accepted_recipient_means_no_data() {
    let mut script = Script::default();
    script.rcpt.insert("x@example.com", "550 5.1.1 nope");
    let (port, log) = fake_mx(script).await;
    let out = simple(zone(), port)
        .deliver_to("example.com", None, &rcpts(&["x@example.com"]), MSG)
        .await;
    assert_eq!(status(&out[0]), "5.1.1");
    let log = log.lock().unwrap();
    assert_eq!(log[0].count("DATA"), 0);
    assert!(
        log[0].commands.contains(&"MAIL FROM:<>".to_owned()),
        "null sender for bounces"
    );
}

#[tokio::test]
async fn pipelining_sends_one_group_and_matches_replies_by_count() {
    let mut script = Script {
        caps: vec!["PIPELINING"],
        ..Script::default()
    };
    script.rcpt.insert(
        "bad@example.com",
        "550-5.1.1 no such user\r\n550 5.1.1 really",
    );
    let (port, log) = fake_mx(script).await;
    let out = simple(zone(), port)
        .deliver_to(
            "example.com",
            Some("a@example.org"),
            &rcpts(&["one@example.com", "bad@example.com", "two@example.com"]),
            MSG,
        )
        .await;
    assert_eq!(
        out.iter().map(status).collect::<Vec<_>>(),
        ["delivered", "5.1.1", "delivered"]
    );
    let log = log.lock().unwrap();
    let s = &log[0];
    // RFC 2920 §3.1: MAIL, the RCPTs and DATA in one group, DATA last.
    let verbs: Vec<&str> = s.commands.iter().map(|c| &c[..4]).collect();
    assert_eq!(&verbs[1..6], ["MAIL", "RCPT", "RCPT", "RCPT", "DATA"]);
    assert_eq!(
        s.pipelined, 4,
        "MAIL and every RCPT had a command behind it"
    );
    assert_eq!(s.data.len(), 1);
}

#[tokio::test]
async fn without_pipelining_commands_wait_for_replies() {
    let (port, log) = fake_mx(Script::default()).await;
    let out = simple(zone(), port)
        .deliver_to(
            "example.com",
            None,
            &rcpts(&["one@example.com", "two@example.com"]),
            MSG,
        )
        .await;
    assert!(out.iter().all(|o| *o == Outcome::Delivered));
    assert_eq!(log.lock().unwrap()[0].pipelined, 0);
}

#[tokio::test]
async fn pipelined_data_accepted_without_recipients_sends_a_lone_dot() {
    // The fake MX answers DATA with 354 even when no RCPT was accepted;
    // RFC 2920 §3.1: the client must check, and send a single dot.
    let mut script = Script {
        caps: vec!["PIPELINING"],
        ..Script::default()
    };
    script.rcpt.insert("x@example.com", "550 5.1.1 nope");
    let (port, log) = fake_mx(script).await;
    let out = simple(zone(), port)
        .deliver_to("example.com", None, &rcpts(&["x@example.com"]), MSG)
        .await;
    assert_eq!(status(&out[0]), "5.1.1");
    assert_eq!(
        log.lock().unwrap()[0].data,
        vec![Vec::<u8>::new()],
        "only the dot was sent"
    );

    // A refused MAIL decides every recipient, even with replies pending.
    let (port, log) = fake_mx(Script {
        caps: vec!["PIPELINING"],
        mail: Some("550 5.7.1 sender blocked"),
        ..Script::default()
    })
    .await;
    let out = simple(zone(), port)
        .deliver_to(
            "example.com",
            Some("a@example.org"),
            &rcpts(&["a@example.com", "b@example.com"]),
            MSG,
        )
        .await;
    assert_eq!(
        out.iter().map(status).collect::<Vec<_>>(),
        ["5.7.1", "5.7.1"]
    );
    assert_eq!(log.lock().unwrap()[0].data, vec![Vec::<u8>::new()]);
}

#[tokio::test]
async fn large_pipelined_groups_do_not_deadlock() {
    let (port, log) = fake_mx(Script {
        caps: vec!["PIPELINING"],
        ..Script::default()
    })
    .await;
    let many: Vec<String> = (0..2000)
        .map(|i| format!("recipient-number-{i:05}-{}@example.com", "x".repeat(40)))
        .collect();
    let out = simple(zone(), port)
        .deliver_to("example.com", None, &many, MSG)
        .await;
    assert!(out.iter().all(|o| *o == Outcome::Delivered));
    assert_eq!(log.lock().unwrap()[0].count("RCPT"), 2000);
}

// ---------------------------------------------------------------- a. SSRF guard

#[tokio::test]
async fn never_connects_to_non_public_addresses() {
    let r = StaticResolver::new()
        .with_mx("evil.example", 10, "internal.evil.example")
        .with_mx("evil.example", 20, "metadata.evil.example")
        .with_mx("evil.example", 30, "mapped.evil.example")
        .with_ip("internal.evil.example", ip("10.0.0.5"))
        .with_ip("metadata.evil.example", ip("169.254.169.254"))
        .with_ip("mapped.evil.example", ip("::ffff:127.0.0.1"))
        // The MTA-STS host points inside too.
        .with_txt("_mta-sts.evil.example", "v=STSv1; id=1")
        .with_ip("mta-sts.evil.example", ip("192.168.1.1"));
    let c = simple(r, 9);
    let out = c
        .deliver_to("evil.example", None, &rcpts(&["a@evil.example"]), MSG)
        .await;
    match &out[0] {
        Outcome::Permanent { status, diagnostic } => {
            assert_eq!(status, "5.4.4");
            assert!(diagnostic.contains("non-public"), "{diagnostic}");
        }
        o => panic!("{o:?}"),
    }
    assert!(c.dialer().connected().is_empty(), "no socket was opened");
    assert_eq!(
        c.dialer().attempts().len(),
        4,
        "{:?}",
        c.dialer().attempts()
    );
}

#[tokio::test]
async fn private_mx_is_skipped_for_the_public_one() {
    let (port, log) = fake_mx(Script::default()).await;
    let r = zone()
        .with_mx("example.com", 5, "lan.example.com")
        .with_ip("lan.example.com", ip("192.168.0.10"));
    let c = simple(r, port);
    let out = c
        .deliver_to("example.com", None, &rcpts(&["a@example.com"]), MSG)
        .await;
    assert_eq!(out, vec![Outcome::Delivered]);
    assert_eq!(log.lock().unwrap().len(), 1);
    assert_eq!(c.dialer().connected().len(), 1);
}

#[tokio::test]
async fn production_dialer_refuses_loopback() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    for target in ["127.0.0.1", "::ffff:127.0.0.1", "::1"] {
        let e = Direct
            .connect(SocketAddr::new(ip(target), port), None)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{target}");
    }
    // Nothing reached the listener.
    let accepted =
        tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept()).await;
    assert!(accepted.is_err());
}

// ---------------------------------------------------------------- b. source address and EHLO

#[tokio::test]
async fn binds_the_configured_source_and_says_our_name() {
    let (port, log) = fake_mx(Script::default()).await;
    let r = zone().with_ip("mx.example.com", ip("::1"));
    let c = client(
        r,
        Loopback::new().map(25, port),
        Arc::new(RootCertStore::empty()),
        Arc::default(),
        |cfg| {
            cfg.sources = Sources {
                ipv4: Some("127.0.0.2".parse().unwrap()),
                ipv6: None,
            };
            // No IPv6 source with a PTR: don't deliver over IPv6.
            cfg.families = Families {
                ipv4: true,
                ipv6: false,
            };
        },
    );
    let out = c
        .deliver_to("example.com", None, &rcpts(&["a@example.com"]), MSG)
        .await;
    assert_eq!(out, vec![Outcome::Delivered]);
    let log = log.lock().unwrap();
    assert_eq!(log[0].peer.unwrap().ip(), ip("127.0.0.2"));
    assert_eq!(log[0].ehlo, ["out.example.org"]);
    assert!(
        c.resolver()
            .queries()
            .iter()
            .all(|q| !q.starts_with("AAAA"))
    );
    assert!(c.dialer().attempts().iter().all(SocketAddr::is_ipv4));
}

// ---------------------------------------------------------------- c. TLS policy: DANE

fn dane_zone(tlsa: Tlsa) -> StaticResolver {
    zone()
        .secure(true)
        .with_tlsa("_25._tcp.mx.example.com", tlsa)
}

fn tlsa(usage: u8, selector: u8, data: Vec<u8>) -> Tlsa {
    Tlsa {
        usage,
        selector,
        matching: 1,
        data: sha256(&data),
    }
}

#[tokio::test]
async fn dane_ee_match_delivers_over_tls() {
    let (tls, spki) = self_signed(&["whatever.invalid"]);
    let (port, log) = fake_mx(Script {
        tls: Some(tls),
        ..Script::default()
    })
    .await;
    // DANE-EE: names and the (untrusted) issuer don't matter, the key does.
    let out = simple(dane_zone(tlsa(3, 1, spki)), port)
        .deliver_to("example.com", None, &rcpts(&["a@example.com"]), MSG)
        .await;
    assert_eq!(out, vec![Outcome::Delivered]);
    assert!(log.lock().unwrap()[0].tls);
}

#[tokio::test]
async fn dane_mismatch_never_falls_back_to_plaintext() {
    let (tls, _) = self_signed(&["mx.example.com"]);
    let (port, log) = fake_mx(Script {
        tls: Some(tls),
        ..Script::default()
    })
    .await;
    let out = simple(dane_zone(tlsa(3, 1, vec![1, 2, 3])), port)
        .deliver_to("example.com", None, &rcpts(&["a@example.com"]), MSG)
        .await;
    assert_eq!(status(&out[0]), "temporary");
    let log = log.lock().unwrap();
    assert_eq!(log.len(), 1, "no plaintext retry");
    assert_eq!(log[0].count("MAIL"), 0);
}

#[tokio::test]
async fn dane_requires_starttls() {
    let (port, log) = fake_mx(Script::default()).await;
    let out = simple(dane_zone(tlsa(3, 1, vec![1])), port)
        .deliver_to("example.com", None, &rcpts(&["a@example.com"]), MSG)
        .await;
    match &out[0] {
        Outcome::Temporary(e) => assert!(e.contains("STARTTLS is not offered"), "{e}"),
        o => panic!("{o:?}"),
    }
    assert_eq!(log.lock().unwrap()[0].count("MAIL"), 0);
}

#[tokio::test]
async fn dane_ignored_when_dns_is_insecure() {
    let (tls, _) = self_signed(&["mx.example.com"]);
    let (port, log) = fake_mx(Script {
        tls: Some(tls),
        ..Script::default()
    })
    .await;
    // The same wrong TLSA, but unsigned DNS: RFC 7672 doesn't apply.
    let r = zone().with_tlsa("_25._tcp.mx.example.com", tlsa(3, 1, vec![1]));
    let out = simple(r, port)
        .deliver_to("example.com", None, &rcpts(&["a@example.com"]), MSG)
        .await;
    assert_eq!(out, vec![Outcome::Delivered]);
    assert!(log.lock().unwrap()[0].tls, "opportunistic TLS");
}

#[tokio::test]
async fn dane_ta_validates_the_chain_and_name() {
    let pki = Pki::new();
    let ca = pki.ca.der().to_vec();
    for (names, expect) in [
        (&["mx.example.com"][..], "delivered"),
        (&["other.example.com"][..], "temporary"),
    ] {
        let (tls, _, _) = pki.server(names);
        let (port, _) = fake_mx(Script {
            tls: Some(tls),
            ..Script::default()
        })
        .await;
        let out = simple(dane_zone(tlsa(2, 0, ca.clone())), port)
            .deliver_to("example.com", None, &rcpts(&["a@example.com"]), MSG)
            .await;
        assert_eq!(status(&out[0]), expect, "{names:?}");
    }
}

// ---------------------------------------------------------------- c. TLS policy: MTA-STS

fn sts_zone(id: &str) -> StaticResolver {
    zone()
        .with_txt("_mta-sts.example.com", &format!("v=STSv1; id={id}"))
        .with_ip("mta-sts.example.com", ip("127.0.0.1"))
}

struct Sts {
    pki: Pki,
    https: Https,
}

async fn sts(status: u16, content_type: &'static str, body: &str) -> Sts {
    let pki = Pki::new();
    let (tls, _, _) = pki.server(&["mta-sts.example.com"]);
    let https = https(tls, status, content_type, body).await;
    Sts { pki, https }
}

fn sts_client<R: Resolver>(
    r: R,
    s: &Sts,
    smtp_port: u16,
    clock: Arc<ManualClock>,
) -> Client<R, Loopback> {
    client(
        r,
        Loopback::new().map(25, smtp_port).map(443, s.https.port),
        s.pki.roots(),
        clock,
        |_| {},
    )
}

#[tokio::test]
async fn mta_sts_enforce_with_valid_certificate() {
    let s = sts(200, "text/plain; charset=utf-8", POLICY_ENFORCE).await;
    let (mx_tls, _, _) = s.pki.server(&["mx.example.com"]);
    let (port, log) = fake_mx(Script {
        tls: Some(mx_tls),
        ..Script::default()
    })
    .await;
    let out = sts_client(sts_zone("1"), &s, port, Arc::default())
        .deliver_to("example.com", None, &rcpts(&["a@example.com"]), MSG)
        .await;
    assert_eq!(out, vec![Outcome::Delivered]);
    assert!(log.lock().unwrap()[0].tls);
    assert_eq!(s.https.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn mta_sts_enforce_rejects_untrusted_certificate() {
    let s = sts(200, "text/plain", POLICY_ENFORCE).await;
    let (untrusted, _) = self_signed(&["mx.example.com"]);
    let (port, log) = fake_mx(Script {
        tls: Some(untrusted),
        ..Script::default()
    })
    .await;
    let out = sts_client(sts_zone("1"), &s, port, Arc::default())
        .deliver_to("example.com", None, &rcpts(&["a@example.com"]), MSG)
        .await;
    assert_eq!(status(&out[0]), "temporary");
    let log = log.lock().unwrap();
    assert_eq!(log.len(), 1, "no plaintext retry under enforce");
    assert_eq!(log[0].count("MAIL"), 0);
}

#[tokio::test]
async fn mta_sts_enforce_skips_unlisted_mx() {
    let s = sts(
        200,
        "text/plain",
        &POLICY_ENFORCE.replace("mx.example.com", "*.mail.example.com"),
    )
    .await;
    let (port, log) = fake_mx(Script::default()).await;
    let out = sts_client(sts_zone("1"), &s, port, Arc::default())
        .deliver_to("example.com", None, &rcpts(&["a@example.com"]), MSG)
        .await;
    match &out[0] {
        Outcome::Temporary(e) => assert!(e.contains("not listed in the MTA-STS policy"), "{e}"),
        o => panic!("{o:?}"),
    }
    assert!(log.lock().unwrap().is_empty(), "never connected to the MX");
}

#[tokio::test]
async fn mta_sts_bad_responses_mean_no_policy() {
    // Oversized, wrong media type, and a redirect: each is "no policy", so
    // delivery continues as if the domain had no MTA-STS (RFC 8461 §3.3),
    // here to an MX the (ignored) policy would have rejected.
    let unlisted = POLICY_ENFORCE.replace("mx.example.com", "other.example.com");
    let oversized = format!(
        "{unlisted}{}",
        "x-padding: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n".repeat(2000)
    );
    assert!(oversized.len() > 64 * 1024);
    for (code, ct, body) in [
        (200, "text/plain", oversized.as_str()),
        (200, "text/html", unlisted.as_str()),
        (301, "text/plain", unlisted.as_str()),
    ] {
        let s = sts(code, ct, body).await;
        let (port, _) = fake_mx(Script::default()).await;
        let out = sts_client(sts_zone("1"), &s, port, Arc::default())
            .deliver_to("example.com", None, &rcpts(&["a@example.com"]), MSG)
            .await;
        assert_eq!(out, vec![Outcome::Delivered], "{code} {ct} {}", body.len());
    }
}

/// A resolver whose `_mta-sts` TXT id can change.
struct SwitchTxt {
    inner: StaticResolver,
    id: Mutex<String>,
}

impl Resolver for SwitchTxt {
    async fn mx(&self, n: &str) -> Result<Answer<Mx>, dns::Error> {
        self.inner.mx(n).await
    }
    async fn a(&self, n: &str) -> Result<Answer<IpAddr>, dns::Error> {
        self.inner.a(n).await
    }
    async fn aaaa(&self, n: &str) -> Result<Answer<IpAddr>, dns::Error> {
        self.inner.aaaa(n).await
    }
    async fn txt(&self, n: &str) -> Result<Answer<Vec<u8>>, dns::Error> {
        if n == "_mta-sts.example.com" {
            let id = self.id.lock().unwrap().clone();
            return Ok(Answer {
                records: vec![format!("v=STSv1; id={id}").into_bytes()],
                dnssec: dns::Dnssec::Insecure,
            });
        }
        self.inner.txt(n).await
    }
    async fn tlsa(&self, n: &str) -> Result<Answer<Tlsa>, dns::Error> {
        self.inner.tlsa(n).await
    }
    async fn ptr(&self, ip: IpAddr) -> Result<Answer<String>, dns::Error> {
        self.inner.ptr(ip).await
    }
}

#[tokio::test]
async fn mta_sts_policy_is_cached_by_id_and_max_age() {
    let s = sts(200, "text/plain", POLICY_ENFORCE).await;
    let (mx_tls, _, _) = s.pki.server(&["mx.example.com"]);
    let (port, _) = fake_mx(Script {
        tls: Some(mx_tls),
        ..Script::default()
    })
    .await;
    let clock = Arc::new(ManualClock(AtomicU64::new(1_000)));
    let r = SwitchTxt {
        inner: sts_zone("unused"),
        id: Mutex::new("v1".into()),
    };
    let c = sts_client(r, &s, port, clock.clone());
    let to = rcpts(&["a@example.com"]);
    let send = || c.deliver_to("example.com", None, &to, MSG);
    let fetches = || s.https.requests.load(Ordering::SeqCst);
    assert_eq!(send().await, vec![Outcome::Delivered]);
    assert_eq!(send().await, vec![Outcome::Delivered]);
    assert_eq!(fetches(), 1, "same id: cached");
    // The id changes: fetch the new policy.
    *c.resolver().id.lock().unwrap() = "v2".into();
    send().await;
    assert_eq!(fetches(), 2);
    send().await;
    assert_eq!(fetches(), 2);
    // max_age (86400 s) passes: fetch again even with the same id.
    clock.0.fetch_add(86_400, Ordering::SeqCst);
    send().await;
    assert_eq!(fetches(), 3);
    // The policy host breaks and the id changes: the cached policy stays in
    // force, so an attacker can't strip it by breaking the fetch.
    s.https.body.lock().unwrap().0 = 500;
    *c.resolver().id.lock().unwrap() = "v3".into();
    assert_eq!(
        send().await,
        vec![Outcome::Delivered],
        "old policy still allows mx.example.com"
    );
}

// ---------------------------------------------------------------- opportunistic TLS

#[tokio::test]
async fn opportunistic_tls_and_plaintext_retry() {
    let (tls, _) = self_signed(&["something.else"]);
    let (port, log) = fake_mx(Script {
        tls: Some(tls),
        ..Script::default()
    })
    .await;
    let out = simple(zone(), port)
        .deliver_to("example.com", None, &rcpts(&["a@example.com"]), MSG)
        .await;
    assert_eq!(out, vec![Outcome::Delivered]);
    assert!(
        log.lock().unwrap()[0].tls,
        "encrypted even with an unverifiable certificate"
    );

    // A server whose TLS is broken: one retry without STARTTLS.
    let (port, log) = fake_mx(Script {
        broken_tls: true,
        ..Script::default()
    })
    .await;
    let out = simple(zone(), port)
        .deliver_to("example.com", None, &rcpts(&["a@example.com"]), MSG)
        .await;
    assert_eq!(out, vec![Outcome::Delivered]);
    let log = log.lock().unwrap();
    assert_eq!(log.len(), 2);
    assert_eq!((log[1].count("STARTTLS"), log[1].count("DATA")), (0, 1));
}

// ---------------------------------------------------------------- d. capabilities

const EIGHT_BIT: &[u8] = "From: a@example.org\r\nSubject: hi\r\n\r\nCaf\u{e9}\r\n".as_bytes();

#[tokio::test]
async fn eight_bit_mail_is_downgraded_without_8bitmime() {
    let (port, log) = fake_mx(Script::default()).await;
    let out = simple(zone(), port)
        .deliver_to("example.com", None, &rcpts(&["a@example.com"]), EIGHT_BIT)
        .await;
    assert_eq!(out, vec![Outcome::Delivered]);
    let log = log.lock().unwrap();
    let data = &log[0].data[0];
    assert!(data.iter().all(|b| *b < 0x80), "7-bit on the wire");
    let text = String::from_utf8_lossy(data);
    assert!(
        text.contains("Content-Transfer-Encoding: quoted-printable") && text.contains("Caf=C3=A9")
    );
    assert!(!log[0].commands.iter().any(|c| c.contains("BODY=")));
}

#[tokio::test]
async fn eight_bit_mail_is_sent_as_is_with_8bitmime() {
    let (port, log) = fake_mx(Script {
        caps: vec!["8BITMIME"],
        ..Script::default()
    })
    .await;
    simple(zone(), port)
        .deliver_to("example.com", None, &rcpts(&["a@example.com"]), EIGHT_BIT)
        .await;
    let log = log.lock().unwrap();
    assert!(
        log[0]
            .commands
            .contains(&"MAIL FROM:<> BODY=8BITMIME".to_owned()),
        "{:?}",
        log[0].commands
    );
    assert_eq!(log[0].data[0], EIGHT_BIT);
}

#[tokio::test]
async fn smtputf8_needed_but_not_offered_fails_with_5_6_7() {
    let (port, log) = fake_mx(Script {
        caps: vec!["8BITMIME"],
        ..Script::default()
    })
    .await;
    let out = simple(zone(), port)
        .deliver_to(
            "example.com",
            None,
            &rcpts(&["jos\u{e9}@example.com", "b@example.com"]),
            MSG,
        )
        .await;
    assert_eq!(
        out.iter().map(status).collect::<Vec<_>>(),
        ["5.6.7", "5.6.7"]
    );
    assert_eq!(log.lock().unwrap()[0].count("MAIL"), 0);

    let (port, log) = fake_mx(Script {
        caps: vec!["8BITMIME", "SMTPUTF8"],
        ..Script::default()
    })
    .await;
    let out = simple(zone(), port)
        .deliver_to("example.com", None, &rcpts(&["jos\u{e9}@example.com"]), MSG)
        .await;
    assert_eq!(out, vec![Outcome::Delivered]);
    assert!(
        log.lock().unwrap()[0]
            .commands
            .contains(&"MAIL FROM:<> SMTPUTF8".to_owned())
    );
}

#[tokio::test]
async fn respects_the_peer_size_limit() {
    let (port, log) = fake_mx(Script {
        caps: vec!["SIZE 50"],
        ..Script::default()
    })
    .await;
    let out = simple(zone(), port)
        .deliver_to("example.com", None, &rcpts(&["a@example.com"]), MSG)
        .await;
    assert_eq!(status(&out[0]), "5.3.4");
    assert_eq!(log.lock().unwrap()[0].count("MAIL"), 0);
}

// ---------------------------------------------------------------- e. test mode

#[tokio::test]
async fn test_mode_makes_no_dns_query_and_opens_no_socket() {
    let c = client(
        zone(),
        Loopback::new(),
        Arc::new(RootCertStore::empty()),
        Arc::default(),
        |cfg| cfg.test_mode_allow = Some(vec!["allowed.example".into()]),
    );
    let out = c
        .deliver_to("example.com", None, &rcpts(&["a@example.com"]), MSG)
        .await;
    assert_eq!(status(&out[0]), "temporary");
    assert!(c.resolver().queries().is_empty());
    assert!(c.dialer().attempts().is_empty());
}

#[derive(Debug)]
struct Plenty;

impl queue::space::SpaceProbe for Plenty {
    fn available(&self, _: &std::path::Path) -> std::io::Result<u64> {
        Ok(u64::MAX)
    }
}

#[tokio::test]
async fn test_mode_through_the_queue_runner() {
    let dir = tempfile::tempdir().unwrap();
    let mut qc = queue::QueueConfig::new("out.example.org");
    qc.test_mode_allow = Some(vec!["allowed.example".into()]);
    let q = Arc::new(
        queue::Queue::open(
            dir.path(),
            qc,
            Arc::new(queue::SystemClock),
            Arc::new(Plenty),
        )
        .unwrap(),
    );
    q.enqueue(Some("a@example.org"), &rcpts(&["b@example.com"]), MSG)
        .unwrap();
    let c = client(
        zone(),
        Loopback::new(),
        Arc::new(RootCertStore::empty()),
        Arc::default(),
        |cfg| cfg.test_mode_allow = Some(vec!["allowed.example".into()]),
    );
    let runner = queue::Runner::new(q.clone(), c, "test");
    runner.run_once().await;
    let entries = q.list().unwrap();
    assert_eq!(entries[0].status, "held");
}
