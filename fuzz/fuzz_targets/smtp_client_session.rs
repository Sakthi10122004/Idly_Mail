//! Fuzzes the outbound SMTP client: arbitrary bytes play the server's side
//! of a whole conversation. The first byte picks the TLS mode and message
//! (8-bit body, non-ASCII recipient). Every run must end with exactly one
//! outcome per recipient and must never hang.

#![no_main]
#![forbid(unsafe_code)]

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use rustls::{ClientConfig, RootCertStore};
use smtp_client::session::{End, Tls, Transaction, run};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn tls_config() -> Arc<ClientConfig> {
    static C: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    C.get_or_init(|| {
        Arc::new(
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("protocol versions")
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        )
    })
    .clone()
}

fuzz_target!(|input: &[u8]| {
    let Some((&flags, server)) = input.split_first() else {
        return;
    };
    let tls = match flags % 3 {
        0 => Tls::Never,
        1 => Tls::Opportunistic(tls_config()),
        _ => Tls::Required(tls_config()),
    };
    let message: &[u8] = if flags & 0x10 != 0 {
        "From: a@example.org\r\n\r\nCaf\u{e9}\r\n.dot\r\n".as_bytes()
    } else {
        b"From: a@example.org\r\n\r\nhello\r\n"
    };
    let recipients: Vec<String> = if flags & 0x20 != 0 {
        vec!["jos\u{e9}@example.com".into(), "b@example.com".into()]
    } else {
        vec![
            "a@example.com".into(),
            "b@example.com".into(),
            "c@example.com".into(),
        ]
    };
    let sender = (flags & 0x40 != 0).then_some("s@example.org");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let (client_side, server_side) = tokio::io::duplex(1 << 20);
        let tx = Transaction {
            sender,
            recipients: &recipients,
            message,
        };
        let client = run(client_side, "mx.example.com", "out.example.org", tls, &tx);
        let fake_server = async {
            let (mut rd, mut wr) = tokio::io::split(server_side);
            let write = async {
                let _ = wr.write_all(server).await;
                let _ = wr.shutdown().await;
            };
            let read = async {
                let mut sink = Vec::new();
                let _ = rd.read_to_end(&mut sink).await;
            };
            tokio::join!(write, read);
        };
        let ((end, _tls), ()) = tokio::time::timeout(Duration::from_secs(60), async {
            tokio::join!(client, fake_server)
        })
        .await
        .expect("client session hung");
        if let End::Done(outcomes) = end {
            assert_eq!(outcomes.len(), recipients.len());
        }
    });
});
