//! Milestone 6: TLS, submission with AUTH, sender authorization, the
//! submission pipeline, and inbound authentication policies. Real TLS over
//! loopback, with an rcgen test certificate.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use dns::testing::StaticResolver;
use mail_auth_glue::dkim::{self, DkimResult, Signer, SigningKey};
use smtp_proto::Reply;
use smtp_server::{AuthLimits, DkimKeys, Rcpt};

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

#[tokio::test]
async fn eight_bit_submissions_are_converted_before_signing() {
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
    let h = start(Setup {
        dkim: Some(keys),
        ..Setup::default()
    })
    .await;
    let mut c = logged_in(&h, "alice@example.org", "alice-pw").await;
    c.cmd("MAIL FROM:<alice@example.org> BODY=8BITMIME").await;
    c.cmd("RCPT TO:<bob@example.org>").await;
    c.cmd("DATA").await;
    c.send(
        "From: alice@example.org\r\nSubject: =?utf-8?q?caf=C3=A9?=\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nUn café, s'il vous plaît.\r\n.\r\n"
            .as_bytes(),
    )
    .await;
    assert_eq!(c.reply().await.unwrap().code, 250);
    let (_, msg) = h.captured.all().remove(0);
    // RFC 6376 §5.3: signed in 7-bit form, so a downgrade for a server
    // without 8BITMIME changes nothing and the signature survives.
    assert!(msg.is_ascii(), "converted to 7 bits");
    assert!(matches!(
        mail_auth_glue::mime::to_seven_bit(&msg).unwrap(),
        std::borrow::Cow::Borrowed(_)
    ));
    let text = String::from_utf8(msg.clone()).unwrap();
    assert!(text.contains("Content-Transfer-Encoding: quoted-printable"));
    assert!(text.contains("caf=C3=A9"));
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

    // 8-bit header fields (SMTPUTF8 mail) are signed as they are.
    c.cmd("MAIL FROM:<alice@example.org> SMTPUTF8").await;
    c.cmd("RCPT TO:<bob@example.org>").await;
    c.cmd("DATA").await;
    c.send("From: alice@example.org\r\nSubject: café\r\n\r\nUn café.\r\n.\r\n".as_bytes())
        .await;
    assert_eq!(c.reply().await.unwrap().code, 250);
    let (_, msg) = h.captured.all().remove(1);
    assert!(
        String::from_utf8(msg)
            .unwrap()
            .contains("\r\n\r\nUn café.\r\n")
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

#[tokio::test]
async fn slow_attacker_dns_cannot_defeat_dmarc_reject() {
    // A spoofed From of a p=reject domain. The attacker signs with its own
    // valid key for attacker.example and makes that domain's DMARC Tree
    // Walk hang; a second signature's key lookup hangs too. Neither may turn
    // the DMARC fail into a fail-open temperror.
    let key = dkim::keygen::ed25519().unwrap();
    let signer = Signer::new(
        SigningKey::from_pkcs8(&key.private_pkcs8).unwrap(),
        "attacker.example",
        "s",
    )
    .unwrap();
    let body = "From: CEO <ceo@bank.example>\r\nTo: bob@example.org\r\nSubject: wire the money\r\n\r\nnow\r\n";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signature = signer.sign(body.as_bytes(), now).unwrap();
    let slow =
        "DKIM-Signature: v=1; a=ed25519-sha256; d=slow.example; s=x; h=from; bh=AAAA; b=AAAA\r\n";
    let message = format!("{slow}{signature}{body}");

    let h = start(inbound_setup(|r| {
        r.with_txt("_dmarc.bank.example", "v=DMARC1; p=reject")
            .with_txt("s._domainkey.attacker.example", &key.dns_record)
            .with_hang("_dmarc.attacker.example")
            .with_hang("x._domainkey.slow.example")
            .with_hang("attacker.example")
    }))
    .await;
    let (mut c, _) = Client::connect(&h, "25").await;
    c.cmd("EHLO mail.attacker.example").await;
    c.cmd("MAIL FROM:<ceo@attacker.example>").await;
    c.cmd("RCPT TO:<bob@example.org>").await;
    c.cmd("DATA").await;
    let started = Instant::now();
    c.send(format!("{message}.\r\n").as_bytes()).await;
    let r = c.reply().await.unwrap();
    assert_eq!((r.code, enhanced(&r)), (550, "5.7.1".into()), "{r:?}");
    assert!(h.captured.all().is_empty(), "never delivered");
    // Bounded by the per-lookup budgets, not the backstop.
    // SPF (20 s, RFC 7208 §4.6.4) and DKIM run together, then one 3 s walk.
    assert!(
        started.elapsed() < Duration::from_secs(40),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn port_25_flood_does_not_lock_out_submission() {
    let mut setup = Setup::default();
    setup.config.max_connections = 2;
    setup.config.max_submission_connections = 1;
    let h = start(setup).await;
    // Fill the inbound pool.
    let (_a, g1) = Client::connect(&h, "25").await;
    let (_b, g2) = Client::connect(&h, "25").await;
    assert_eq!((g1.code, g2.code), (220, 220));
    let (mut c, g) = Client::connect(&h, "25").await;
    assert_eq!(g.code, 421, "inbound pool full");
    assert!(c.is_closed().await);
    // Submission still works, on both ports, from its own pool.
    let (mut s, g) = Client::connect(&h, "587").await;
    assert_eq!(g.code, 220);
    s.cmd("QUIT").await;
    drop(s);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut s = logged_in(&h, "alice@example.org", "alice-pw").await;
    assert_eq!(s.cmd("NOOP").await.code, 250);
    // ...and that pool has its own limit.
    let (_, g) = Client::connect(&h, "587").await;
    assert_eq!(g.code, 421, "submission pool full");
}
