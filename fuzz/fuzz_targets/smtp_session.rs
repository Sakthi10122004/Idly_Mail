//! Fuzzes whole SMTP server sessions: arbitrary client bytes go into an
//! in-memory session. The first byte picks the path:
//!
//! - 0: port 25, plaintext, inbound SPF/DKIM/DMARC checks on.
//! - 1: port 587; the input up to the first `STARTTLS\r\n` is sent in
//!   plaintext, then a real TLS handshake, then the rest over TLS.
//! - 2: port 465, implicit TLS.
//! - 3: port 465, already authenticated (AUTH PLAIN sent by the harness),
//!   so MAIL/DATA reach sender authorization, QP re-encoding and DKIM.
//!
//! Checked on every delivered message: CRLF-only line endings (no
//! smuggling), and on submissions no line over 998 octets.

#![no_main]
#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use dns::testing::StaticResolver;
use libfuzzer_sys::fuzz_target;
use mail_auth_glue::dkim::{Signer, SigningKey, keygen};
use mail_auth_glue::mime::has_long_lines;
use smtp_proto::{ForwardPath, Host};
use smtp_server::{
    Accounts, AuthLimits, Directory, DkimKeys, Envelope, InboundConfig, Mode, Observer, Recipient,
    Server, Sink,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

struct Dir;

impl Directory for Dir {
    fn resolve(&self, to: &ForwardPath) -> Recipient {
        match to {
            ForwardPath::Postmaster => Recipient::Local("user@example.org".into()),
            ForwardPath::Mailbox(m) => match &m.host {
                Host::Domain(d) if d.eq_ignore_ascii_case("example.org") => {
                    if m.local_part.eq_ignore_ascii_case("user") {
                        Recipient::Local("user@example.org".into())
                    } else {
                        Recipient::UnknownUser
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
        (username.eq_ignore_ascii_case("user@example.org") && password == "pw")
            .then(|| "user@example.org".to_owned())
    }
    fn may_send_as(&self, account: &str, address: &str) -> bool {
        account.eq_ignore_ascii_case(address)
    }
}

/// Discards mail after checking the invariants.
struct Check;

impl Sink for Check {
    async fn deliver(&self, envelope: &Envelope, message: &[u8]) -> std::io::Result<()> {
        for (i, &b) in message.iter().enumerate() {
            match b {
                b'\r' => assert_eq!(message.get(i + 1), Some(&b'\n'), "bare CR delivered"),
                b'\n' => assert_eq!(
                    i.checked_sub(1).and_then(|j| message.get(j)),
                    Some(&b'\r'),
                    "bare LF delivered"
                ),
                _ => {}
            }
        }
        if envelope.authenticated.is_some() {
            assert!(
                !has_long_lines(message),
                "submission sent a line over 998 octets"
            );
        }
        Ok(())
    }
}

struct Quiet;

impl Observer for Quiet {}

struct Fixture {
    server_tls: Arc<rustls::ServerConfig>,
    client_tls: tokio_rustls::TlsConnector,
    dkim: Arc<DkimKeys>,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let key = rcgen::generate_simple_self_signed(vec!["mx.example.org".to_owned()])
            .expect("test certificate");
        let server_tls = smtp_server::tls::server_config(
            key.cert.pem().as_bytes(),
            key.signing_key.serialize_pem().as_bytes(),
        )
        .expect("server TLS config");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(key.cert.der().clone()).expect("root certificate");
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        let ed = keygen::ed25519().expect("DKIM key");
        let mut dkim = DkimKeys::new();
        dkim.add(
            "example.org",
            Signer::new(
                SigningKey::from_pkcs8(&ed.private_pkcs8).expect("DKIM key"),
                "example.org",
                "fz",
            )
            .expect("DKIM signer"),
        );
        Fixture {
            server_tls,
            client_tls: tokio_rustls::TlsConnector::from(Arc::new(client)),
            dkim: Arc::new(dkim),
        }
    })
}

/// Writes `data`, closes the write side, and reads until the server closes.
async fn talk<S: AsyncRead + AsyncWrite>(stream: S, data: &[u8]) {
    let (mut rd, mut wr) = tokio::io::split(stream);
    let write = async {
        let _ = wr.write_all(data).await;
        let _ = wr.shutdown().await;
    };
    let read = async {
        let mut sink = Vec::new();
        let _ = rd.read_to_end(&mut sink).await;
    };
    tokio::join!(write, read);
}

/// Reads replies until `marker` arrives or the stream ends.
async fn read_until<S: AsyncRead + Unpin>(stream: &mut S, marker: &[u8]) -> bool {
    let mut seen = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return false,
            Ok(n) => seen.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
        }
        if seen.windows(marker.len()).any(|w| w == marker) {
            return true;
        }
    }
}

async fn client(f: &Fixture, mut stream: tokio::io::DuplexStream, path: u8, data: &[u8]) {
    let name = rustls::pki_types::ServerName::try_from("mx.example.org").expect("name");
    match path {
        1 => {
            let marker = b"STARTTLS\r\n";
            let Some(at) = data.windows(marker.len()).position(|w| w == marker) else {
                return talk(stream, data).await;
            };
            let (before, after) = data.split_at(at + marker.len());
            if stream.write_all(before).await.is_err()
                || !read_until(&mut stream, b"220 2.0.0 Ready to start TLS\r\n").await
            {
                return;
            }
            if let Ok(tls) = f.client_tls.connect(name, stream).await {
                talk(tls, after).await;
            }
        }
        2 | 3 => {
            let Ok(mut tls) = f.client_tls.connect(name, stream).await else {
                return;
            };
            if path == 3 {
                // base64("\0user@example.org\0pw")
                let login = b"EHLO client.example\r\nAUTH PLAIN AHVzZXJAZXhhbXBsZS5vcmcAcHc=\r\n";
                if tls.write_all(login).await.is_err() || !read_until(&mut tls, b"235 ").await {
                    return;
                }
            }
            talk(tls, data).await;
        }
        _ => talk(stream, data).await,
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&selector, data)) = input.split_first() else {
        return;
    };
    let path = selector % 4;
    let f = fixture();
    let mut config = InboundConfig::new("mx.example.org");
    config.command_timeout = Duration::from_secs(2);
    config.data_timeout = Duration::from_secs(2);
    config.tls_handshake_timeout = Duration::from_secs(2);
    config.session_timeout = Duration::from_secs(10);
    config.message_size = 64 * 1024;
    // No sleeping in the fuzzer; the limits themselves are still applied.
    config.auth_limits = AuthLimits {
        base_delay: Duration::ZERO,
        max_delay: Duration::ZERO,
        ..AuthLimits::default()
    };
    let resolver = StaticResolver::new()
        .with_txt("example.org", "v=spf1 -all")
        .with_txt("_dmarc.example.org", "v=DMARC1; p=reject");
    let server = Server::new(config, Dir, Check, Quiet, resolver)
        .with_tls(f.server_tls.clone())
        .with_accounts(Arc::new(Users))
        .with_dkim(f.dkim.clone())
        .shared();
    let mode = match path {
        0 => Mode::Inbound,
        1 => Mode::Submission,
        _ => Mode::SubmissionImplicitTls,
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let (server_side, client_side) = tokio::io::duplex(1 << 20);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let session = server.handle(server_side, ip, mode);
        let run = async { tokio::join!(session, client(f, client_side, path, data)) };
        // A session must always end once the client has closed.
        tokio::time::timeout(Duration::from_secs(30), run)
            .await
            .expect("session hung");
    });
});
