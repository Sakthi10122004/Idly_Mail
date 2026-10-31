//! RFC 8463 Appendix A test vectors, plus tampering and round-trip tests.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use dns::testing::StaticResolver;
use ring::signature::Ed25519KeyPair;

use super::*;
use crate::message::Message;

/// RFC 8463 Appendix A.3, with CRLF line endings. Continuation lines of the
/// DKIM-Signature fields start with a single space; a blank line follows
/// "Joe.".
const MESSAGE: &str = "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;\r
 d=football.example.com; i=@football.example.com;\r
 q=dns/txt; s=brisbane; t=1528637909; h=from : to :\r
 subject : date : message-id : from : subject : date;\r
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r
 b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus\r
 Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==\r
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r
 d=football.example.com; i=@football.example.com;\r
 q=dns/txt; s=test; t=1528637909; h=from : to : subject :\r
 date : message-id : from : subject : date;\r
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r
 b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3\r
 DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz\r
 dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=\r
From: Joe SixPack <joe@football.example.com>\r
To: Suzie Q <suzie@shopping.example.net>\r
Subject: Is dinner ready?\r
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r
Message-ID: <20030712040037.46341.5F8J@football.example.com>\r
\r
Hi.\r
\r
We lost the game.  Are you hungry yet?\r
\r
Joe.\r
\r
";

/// RFC 8463 Appendix A.2.
fn resolver() -> StaticResolver {
    StaticResolver::new()
        .with_txt(
            "brisbane._domainkey.football.example.com",
            "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
        )
        .with_txt(
            "test._domainkey.football.example.com",
            "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB",
        )
}

const T: u64 = 1_528_637_909;

#[tokio::test]
async fn rfc_8463_both_signatures_verify() {
    let results = verify(&resolver(), MESSAGE.as_bytes(), T + 60).await;
    assert_eq!(results.len(), 2);
    assert_eq!(
        results[0].result,
        DkimResult::Pass,
        "ed25519: {:?}",
        results[0]
    );
    assert_eq!(results[0].algorithm, Some(Algorithm::Ed25519Sha256));
    assert_eq!(results[1].result, DkimResult::Pass, "rsa: {:?}", results[1]);
    assert_eq!(results[1].domain.as_deref(), Some("football.example.com"));
}

#[test]
fn rfc_8463_ed25519_signature_reproduced() {
    // RFC 8463 A.1: the secret key is RFC 8032 §7.1 Test 1's seed.
    let seed = STANDARD
        .decode("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=")
        .unwrap();
    let key = SigningKey::Ed25519(Ed25519KeyPair::from_seed_unchecked(&seed).unwrap());
    let msg = Message::parse(MESSAGE.as_bytes()).unwrap();
    let field = msg.headers_named("DKIM-Signature").next().unwrap();
    let sig = Signature::parse(field.value).unwrap();
    let data = signed_data(
        &msg,
        &sig.headers,
        sig.header_canon,
        &signature::without_b_value(field.raw),
    );
    // Ed25519 is deterministic, so we must produce exactly the RFC's b=.
    assert_eq!(
        STANDARD.encode(key.sign(&data).unwrap()),
        STANDARD.encode(&sig.signature)
    );
}

async fn result_of(message: &str, resolver: &StaticResolver) -> Vec<DkimResult> {
    verify(resolver, message.as_bytes(), T + 60)
        .await
        .into_iter()
        .map(|v| v.result)
        .collect()
}

#[tokio::test]
async fn tampering_is_detected() {
    let r = resolver();
    let body = MESSAGE.replace("Are you hungry yet?", "Are you hungry now?");
    assert_eq!(
        result_of(&body, &r).await,
        vec![DkimResult::Fail("body hash did not verify"); 2]
    );
    let subject = MESSAGE.replace("Is dinner ready?", "Is lunch ready?");
    assert_eq!(
        result_of(&subject, &r).await,
        vec![DkimResult::Fail("signature did not verify"); 2]
    );
    // Adding a second Subject is caught: h= lists "subject" twice, so the
    // new (bottom-most) one is signed in place of the original.
    let added = MESSAGE.replace("\r\n\r\nHi.", "\r\nSubject: Win a prize\r\n\r\nHi.");
    assert_eq!(
        result_of(&added, &r).await,
        vec![DkimResult::Fail("signature did not verify"); 2]
    );
    // Relaxed canonicalization tolerates whitespace changes.
    let spaced = MESSAGE.replace(
        "Subject: Is dinner ready?",
        "SUBJECT:   Is dinner   ready?  ",
    );
    assert_eq!(result_of(&spaced, &r).await, vec![DkimResult::Pass; 2]);
}

#[tokio::test]
async fn key_problems() {
    let none = StaticResolver::new();
    assert_eq!(
        result_of(MESSAGE, &none).await,
        vec![DkimResult::PermError("no key for signature"); 2]
    );
    let broken = StaticResolver::new()
        .with_failure(
            "brisbane._domainkey.football.example.com",
            dns::Error::Temporary("timeout".into()),
        )
        .with_txt("test._domainkey.football.example.com", "v=DKIM1; k=rsa; p=");
    assert_eq!(
        result_of(MESSAGE, &broken).await,
        vec![
            DkimResult::TempError("key unavailable"),
            DkimResult::PermError("key revoked")
        ]
    );
}

fn signed_with(key: SigningKey, selector: &str) -> String {
    let message =
        "From: Kim <kim@example.org>\r\nTo: bob@example.net\r\nSubject: hello\r\n\r\nHi Bob.\r\n";
    let signer = Signer::new(key, "example.org", selector).unwrap();
    format!("{}{message}", signer.sign(message.as_bytes(), T).unwrap())
}

#[tokio::test]
async fn generated_keys_round_trip() {
    let ed = keygen::ed25519().unwrap();
    let rsa = keygen::rsa().unwrap();
    let r = StaticResolver::new()
        .with_txt("ed._domainkey.example.org", &ed.dns_record)
        .with_txt("rsa._domainkey.example.org", &rsa.dns_record);
    for (key, sel) in [(&ed, "ed"), (&rsa, "rsa")] {
        let signed = signed_with(SigningKey::from_pkcs8(&key.private_pkcs8).unwrap(), sel);
        assert_eq!(
            result_of(&signed, &r).await,
            vec![DkimResult::Pass],
            "{sel}:\n{signed}"
        );
        // Oversigning: adding another To breaks the signature.
        let added = signed.replace("\r\n\r\nHi Bob.", "\r\nTo: eve@example.com\r\n\r\nHi Bob.");
        assert_eq!(
            result_of(&added, &r).await,
            vec![DkimResult::Fail("signature did not verify")],
            "{sel}"
        );
    }
}

#[tokio::test]
async fn partial_body_signature_is_policy() {
    // An l= signature that doesn't cover appended content is not trusted.
    let ed = keygen::ed25519().unwrap();
    let r = StaticResolver::new().with_txt("ed._domainkey.example.org", &ed.dns_record);
    let key = SigningKey::from_pkcs8(&ed.private_pkcs8).unwrap();
    let message = "From: kim@example.org\r\n\r\nHi.\r\n";
    let msg = Message::parse(message.as_bytes()).unwrap();
    let names = vec!["from".to_owned()];
    let bh = STANDARD.encode(
        canon::body_hash(Canon::Simple, msg.body, Some(5))
            .digest
            .as_ref(),
    );
    let field = format!(
        "DKIM-Signature: v=1; a=ed25519-sha256; d=example.org; s=ed; h=from; l=5; bh={bh}; b="
    );
    let data = signed_data(&msg, &names, Canon::Simple, field.as_bytes());
    let sig = STANDARD.encode(key.sign(&data).unwrap());
    let signed = format!("{field}{sig}\r\n{message}");
    assert_eq!(
        result_of(&signed, &r).await,
        vec![DkimResult::Pass],
        "l= covering the whole body"
    );
    let appended = format!("{signed}Click here!\r\n");
    assert_eq!(
        result_of(&appended, &r).await,
        vec![DkimResult::Policy("signature covers only part of the body")]
    );
}

#[tokio::test]
async fn expired_signature() {
    let late = MESSAGE.replace("t=1528637909;", "t=1528637909; x=1528637999;");
    let results = verify(&resolver(), late.as_bytes(), T + 1000).await;
    assert_eq!(
        results[0].result,
        DkimResult::PermError("signature expired")
    );
}
