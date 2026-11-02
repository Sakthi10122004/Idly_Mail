//! The fast companion to `smtp_session`: arbitrary bytes into a session
//! with no client-side TLS, so it runs many times faster. The first byte
//! picks port 25 or 587. A certificate is configured, so after STARTTLS
//! the remaining bytes go to the server's TLS handshake as they are.
//!
//! Checked on every delivered message: CRLF-only line endings.

#![no_main]
#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use dns::testing::StaticResolver;
use libfuzzer_sys::fuzz_target;
use smtp_proto::{ForwardPath, Host};
use smtp_server::{
    Accounts, AuthLimits, Directory, Envelope, InboundConfig, Mode, Observer, Recipient, Server,
    Sink,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    fn account_name(&self, username: &str) -> Option<String> {
        username
            .eq_ignore_ascii_case("user@example.org")
            .then(|| "user@example.org".to_owned())
    }
    fn may_send_as(&self, account: &str, address: &str) -> bool {
        account.eq_ignore_ascii_case(address)
    }
}

struct Check;

impl Sink for Check {
    async fn deliver(&self, _envelope: &Envelope, message: &[u8]) -> std::io::Result<()> {
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
        Ok(())
    }
}

struct Quiet;

impl Observer for Quiet {}

fn server_tls() -> Arc<rustls::ServerConfig> {
    static TLS: OnceLock<Arc<rustls::ServerConfig>> = OnceLock::new();
    TLS.get_or_init(|| {
        let key = rcgen::generate_simple_self_signed(vec!["mx.example.org".to_owned()])
            .expect("test certificate");
        smtp_server::tls::server_config(
            key.cert.pem().as_bytes(),
            key.signing_key.serialize_pem().as_bytes(),
        )
        .expect("server TLS config")
    })
    .clone()
}

fuzz_target!(|input: &[u8]| {
    let Some((&selector, data)) = input.split_first() else {
        return;
    };
    let mode = if selector % 2 == 0 {
        Mode::Inbound
    } else {
        Mode::Submission
    };
    let mut config = InboundConfig::new("mx.example.org");
    config.command_timeout = Duration::from_secs(2);
    config.data_timeout = Duration::from_secs(2);
    config.tls_handshake_timeout = Duration::from_secs(2);
    config.session_timeout = Duration::from_secs(10);
    config.message_size = 64 * 1024;
    config.auth_limits = AuthLimits {
        base_delay: Duration::ZERO,
        max_delay: Duration::ZERO,
        ..AuthLimits::default()
    };
    let resolver = StaticResolver::new()
        .with_txt("example.org", "v=spf1 -all")
        .with_txt("_dmarc.example.org", "v=DMARC1; p=reject");
    let server = Server::new(config, Dir, Check, Quiet, resolver)
        .with_tls(server_tls())
        .with_accounts(Arc::new(Users))
        .shared();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let (server_side, client_side) = tokio::io::duplex(1 << 20);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let session = server.handle(server_side, ip, mode);
        let client = async {
            let (mut rd, mut wr) = tokio::io::split(client_side);
            let write = async {
                let _ = wr.write_all(data).await;
                let _ = wr.shutdown().await;
            };
            let read = async {
                let mut sink = Vec::new();
                let _ = rd.read_to_end(&mut sink).await;
            };
            tokio::join!(write, read);
        };
        tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(session, client)
        })
        .await
        .expect("session hung");
    });
});
