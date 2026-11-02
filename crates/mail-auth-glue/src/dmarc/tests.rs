//! DMARC tests, built on the RFC 9989 examples.

use dns::testing::StaticResolver;

use super::*;
use crate::dkim::Algorithm;

fn dkim_pass(domain: &str) -> Verification {
    Verification {
        result: DkimResult::Pass,
        domain: Some(domain.to_owned()),
        selector: Some("s".into()),
        algorithm: Some(Algorithm::Ed25519Sha256),
        testing: false,
    }
}

fn msg(from: &str) -> String {
    format!("From: {from}\r\nTo: receiver@example.org\r\nSubject: here's a sample\r\n\r\nbody\r\n")
}

async fn run(
    r: &StaticResolver,
    from: &str,
    spf: (SpfResult, &str),
    dkim: &[Verification],
) -> Outcome {
    evaluate(r, msg(from).as_bytes(), &Inputs { spf, dkim }).await
}

fn example_com(record: &str) -> StaticResolver {
    StaticResolver::new()
        .with_txt("_dmarc.example.com", record)
        .with_ip("example.com", "192.0.2.1".parse().unwrap())
        .with_ip("child.example.com", "192.0.2.2".parse().unwrap())
}

#[test]
fn rfc_9989_walk_targets() {
    // RFC 9989 §4.10: the eight queries for a 13-label Author Domain.
    let t = walk_targets("a.b.c.d.e.f.g.h.i.j.mail.example.com", true);
    assert_eq!(
        t,
        [
            "a.b.c.d.e.f.g.h.i.j.mail.example.com",
            "g.h.i.j.mail.example.com",
            "h.i.j.mail.example.com",
            "i.j.mail.example.com",
            "j.mail.example.com",
            "mail.example.com",
            "example.com",
            "com"
        ]
    );
    assert_eq!(
        walk_targets("a.mail.example.com", false),
        ["mail.example.com", "example.com", "com"]
    );
}

#[tokio::test]
async fn rfc_9989_section_4_10_2_org_domain_examples() {
    let mut w = Walker {
        resolver: &StaticResolver::new(),
        cache: HashMap::new(),
    };
    // Records at mail.example.com and example.com: example.com.
    let r = StaticResolver::new()
        .with_txt("_dmarc.mail.example.com", "v=DMARC1; p=none")
        .with_txt("_dmarc.example.com", "v=DMARC1; p=none");
    w.resolver = &r;
    assert_eq!(
        w.org_domain("a.mail.example.com").await,
        Ok("example.com".into())
    );
    // psd=n at mail.example.com: mail.example.com.
    let r = StaticResolver::new()
        .with_txt("_dmarc.mail.example.com", "v=DMARC1; p=none; psd=n")
        .with_txt("_dmarc.example.com", "v=DMARC1; p=none");
    let mut w = Walker {
        resolver: &r,
        cache: HashMap::new(),
    };
    assert_eq!(
        w.org_domain("a.mail.example.com").await,
        Ok("mail.example.com".into())
    );
    // Only _dmarc.com with psd=y: example.com.
    let r = StaticResolver::new().with_txt("_dmarc.com", "v=DMARC1; p=none; psd=y");
    let mut w = Walker {
        resolver: &r,
        cache: HashMap::new(),
    };
    assert_eq!(
        w.org_domain("a.mail.example.com").await,
        Ok("example.com".into())
    );
    // No records at all: the domain itself.
    let r = StaticResolver::new();
    let mut w = Walker {
        resolver: &r,
        cache: HashMap::new(),
    };
    assert_eq!(
        w.org_domain("a.mail.example.com").await,
        Ok("a.mail.example.com".into())
    );
}

#[tokio::test]
async fn rfc_9989_appendix_b1_spf_alignment() {
    let r = example_com("v=DMARC1; p=reject");
    // Example 1: strict alignment.
    assert_eq!(
        run(
            &r,
            "sender@example.com",
            (SpfResult::Pass, "example.com"),
            &[]
        )
        .await
        .result,
        DmarcResult::Pass
    );
    // Example 2: relaxed alignment (child.example.com and example.com).
    assert_eq!(
        run(
            &r,
            "sender@example.com",
            (SpfResult::Pass, "child.example.com"),
            &[]
        )
        .await
        .result,
        DmarcResult::Pass
    );
    // Example 3: no alignment.
    let o = run(
        &r,
        "sender@child.example.com",
        (SpfResult::Pass, "example.net"),
        &[],
    )
    .await;
    assert_eq!(
        (o.result, o.disposition),
        (DmarcResult::Fail, Policy::Reject)
    );
    // Relaxed alignment is not enough under aspf=s.
    let r = example_com("v=DMARC1; p=reject; aspf=s");
    assert_eq!(
        run(
            &r,
            "sender@example.com",
            (SpfResult::Pass, "child.example.com"),
            &[]
        )
        .await
        .result,
        DmarcResult::Fail
    );
    // Only an SPF pass counts.
    let r = example_com("v=DMARC1; p=reject");
    assert_eq!(
        run(
            &r,
            "sender@example.com",
            (SpfResult::SoftFail, "example.com"),
            &[]
        )
        .await
        .result,
        DmarcResult::Fail
    );
}

#[tokio::test]
async fn rfc_9989_appendix_b1_dkim_alignment() {
    let r = example_com("v=DMARC1; p=quarantine");
    let none = (SpfResult::None, "unrelated.example");
    assert_eq!(
        run(&r, "sender@example.com", none, &[dkim_pass("example.com")])
            .await
            .result,
        DmarcResult::Pass
    );
    assert_eq!(
        run(
            &r,
            "sender@child.example.com",
            none,
            &[dkim_pass("example.com")]
        )
        .await
        .result,
        DmarcResult::Pass
    );
    let o = run(
        &r,
        "sender@child.example.com",
        none,
        &[dkim_pass("example.net")],
    )
    .await;
    assert_eq!(
        (o.result, o.disposition),
        (DmarcResult::Fail, Policy::Quarantine)
    );
    // A failing signature never aligns.
    let mut bad = dkim_pass("example.com");
    bad.result = DkimResult::Fail("signature did not verify");
    assert_eq!(
        run(&r, "sender@example.com", none, &[bad]).await.result,
        DmarcResult::Fail
    );
    // adkim=s
    let r = example_com("v=DMARC1; p=quarantine; adkim=s");
    assert_eq!(
        run(
            &r,
            "sender@child.example.com",
            none,
            &[dkim_pass("example.com")]
        )
        .await
        .result,
        DmarcResult::Fail
    );
}

#[tokio::test]
async fn subdomain_policies() {
    let none = (SpfResult::None, "x.example");
    let r = example_com("v=DMARC1; p=reject; sp=quarantine; np=none");
    // An existing subdomain uses sp; a non-existent one uses np.
    assert_eq!(
        run(&r, "a@child.example.com", none, &[]).await.disposition,
        Policy::Quarantine
    );
    assert_eq!(
        run(&r, "a@ghost.example.com", none, &[]).await.disposition,
        Policy::None
    );
    // The Organizational Domain itself uses p.
    assert_eq!(
        run(&r, "a@example.com", none, &[]).await.disposition,
        Policy::Reject
    );
    // Without sp/np, p applies to subdomains.
    let r = example_com("v=DMARC1; p=reject");
    assert_eq!(
        run(&r, "a@child.example.com", none, &[]).await.disposition,
        Policy::Reject
    );
}

#[tokio::test]
async fn testing_flag_downgrades() {
    let r = example_com("v=DMARC1; p=reject; t=y");
    let o = run(&r, "a@example.com", (SpfResult::Fail, "example.com"), &[]).await;
    assert_eq!(
        (o.result, o.disposition, o.testing),
        (DmarcResult::Fail, Policy::Quarantine, true)
    );
}

#[tokio::test]
async fn no_record_and_bad_records() {
    let none = (SpfResult::None, "x.example");
    // No record anywhere: DMARC does not apply (RFC 9989 §5.3.2).
    assert_eq!(
        run(&StaticResolver::new(), "a@example.com", none, &[])
            .await
            .result,
        DmarcResult::None
    );
    // Two records: both discarded (RFC 9989 §4.10 step 2).
    let r = example_com("v=DMARC1; p=reject").with_txt("_dmarc.example.com", "v=DMARC1; p=none");
    assert_eq!(
        run(&r, "a@example.com", none, &[]).await.result,
        DmarcResult::None
    );
    // Invalid p: p=none with a valid rua, otherwise no processing.
    let r = example_com("v=DMARC1; p=bogus; rua=mailto:r@example.com");
    let o = run(&r, "a@example.com", none, &[]).await;
    assert_eq!((o.result, o.disposition), (DmarcResult::Fail, Policy::None));
    let r = example_com("v=DMARC1; p=bogus");
    assert_eq!(
        run(&r, "a@example.com", none, &[]).await.result,
        DmarcResult::None
    );
}

#[tokio::test]
async fn dns_errors_give_temperror() {
    let r = StaticResolver::new().with_failure(
        "_dmarc.example.com",
        dns::Error::Temporary("timeout".into()),
    );
    assert_eq!(
        run(&r, "a@example.com", (SpfResult::Pass, "example.com"), &[])
            .await
            .result,
        DmarcResult::TempError
    );
}

#[tokio::test]
async fn from_field_problems() {
    let r = example_com("v=DMARC1; p=reject");
    let spf = (SpfResult::Pass, "example.com");
    let two_fields = "From: a@example.com\r\nFrom: b@evil.example\r\n\r\nx\r\n";
    assert_eq!(
        evaluate(&r, two_fields.as_bytes(), &Inputs { spf, dkim: &[] })
            .await
            .result,
        DmarcResult::PermError
    );
    let no_field = "To: a@example.com\r\n\r\nx\r\n";
    assert_eq!(
        evaluate(&r, no_field.as_bytes(), &Inputs { spf, dkim: &[] })
            .await
            .result,
        DmarcResult::PermError
    );
    assert_eq!(
        run(&r, "undisclosed-recipients:;", spf, &[]).await.result,
        DmarcResult::PermError
    );
    assert_eq!(
        run(&r, "a@b@", spf, &[]).await.result,
        DmarcResult::PermError
    );
}

#[tokio::test]
async fn multiple_author_domains_cannot_bypass() {
    // RFC 9989 §11.5: adding a second From address must not escape the
    // spoofed domain's policy.
    let r = example_com("v=DMARC1; p=reject").with_txt("_dmarc.evil.example", "v=DMARC1; p=none");
    let o = run(
        &r,
        "boss@example.com, me@evil.example",
        (SpfResult::Pass, "evil.example"),
        &[],
    )
    .await;
    assert_eq!(
        (o.result, o.disposition),
        (DmarcResult::Fail, Policy::Reject)
    );
    assert_eq!(o.author_domain.as_deref(), Some("example.com"));
    let many = "a@one.example, b@two.example, c@three.example, d@four.example";
    assert_eq!(
        run(&r, many, (SpfResult::Pass, "one.example"), &[])
            .await
            .result,
        DmarcResult::PermError
    );
}

#[tokio::test]
async fn international_author_domain() {
    let r = StaticResolver::new().with_txt("_dmarc.xn--bcher-kva.example", "v=DMARC1; p=reject");
    let o = run(
        &r,
        "kim@bücher.example",
        (SpfResult::Pass, "bücher.example"),
        &[],
    )
    .await;
    assert_eq!(o.result, DmarcResult::Pass);
}

// Attacker-controlled DNS (CLAUDE.md, inbound rule 6): slow lookups for
// SPF/DKIM identifiers can never turn a DMARC fail into temperror.

#[tokio::test(start_paused = true)]
async fn hanging_identifier_walk_is_not_aligned() {
    // The attacker signs with its own valid key, then makes the Tree Walk
    // for its d= domain hang, hoping for a fail-open temperror.
    let r = example_com("v=DMARC1; p=reject")
        .with_hang("_dmarc.attacker.example")
        .with_hang("_dmarc.example");
    let o = run(
        &r,
        "ceo@example.com",
        (SpfResult::Pass, "attacker.example"),
        &[dkim_pass("attacker.example")],
    )
    .await;
    assert_eq!(o.result, DmarcResult::Fail);
    assert_eq!(o.disposition, Policy::Reject);
}

#[tokio::test(start_paused = true)]
async fn failing_identifier_walk_is_not_aligned() {
    let r = example_com("v=DMARC1; p=reject").with_failure(
        "_dmarc.attacker.example",
        dns::Error::Temporary("servfail".into()),
    );
    let o = run(
        &r,
        "ceo@example.com",
        (SpfResult::None, "attacker.example"),
        &[dkim_pass("attacker.example")],
    )
    .await;
    assert_eq!(
        (o.result, o.disposition),
        (DmarcResult::Fail, Policy::Reject)
    );
}

#[tokio::test(start_paused = true)]
async fn hanging_identifier_does_not_hide_an_aligned_one() {
    // A slow attacker signature listed first doesn't stop the real
    // signature from aligning.
    let r = example_com("v=DMARC1; p=reject").with_hang("_dmarc.attacker.example");
    let o = run(
        &r,
        "ceo@example.com",
        (SpfResult::None, ""),
        &[dkim_pass("attacker.example"), dkim_pass("mail.example.com")],
    )
    .await;
    assert_eq!(o.result, DmarcResult::Pass);
}

#[tokio::test(start_paused = true)]
async fn author_discovery_timeout_is_temperror() {
    // The Author Domain's own policy discovery is the only temperror source.
    let r = StaticResolver::new().with_hang("_dmarc.example.com");
    let started = tokio::time::Instant::now();
    let o = run(&r, "ceo@example.com", (SpfResult::Pass, "example.com"), &[]).await;
    assert_eq!(o.result, DmarcResult::TempError);
    assert!(started.elapsed() <= AUTHOR_TIMEOUT + Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn attacker_author_domain_cannot_mask_a_victim() {
    // Two Author Domains: the victim's p=reject fail beats the attacker
    // domain's temperror.
    let r = example_com("v=DMARC1; p=reject").with_hang("_dmarc.attacker.example");
    let o = run(
        &r,
        "ceo@example.com, x@attacker.example",
        (SpfResult::None, ""),
        &[],
    )
    .await;
    assert_eq!(
        (o.result, o.disposition),
        (DmarcResult::Fail, Policy::Reject)
    );
}
