//! check_host() tests, built on RFC 7208 Appendix A.

use std::net::IpAddr;

use dns::testing::StaticResolver;

use super::*;

/// The RFC 7208 Appendix A zone, with `example.com`'s TXT record supplied.
fn zone(example_com_spf: &str) -> StaticResolver {
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    StaticResolver::new()
        .with_mx("example.com", 10, "mail-a.example.com")
        .with_mx("example.com", 20, "mail-b.example.com")
        .with_ip("example.com", ip("192.0.2.10"))
        .with_ip("example.com", ip("192.0.2.11"))
        .with_txt("example.com", example_com_spf)
        .with_ip("amy.example.com", ip("192.0.2.65"))
        .with_ip("bob.example.com", ip("192.0.2.66"))
        .with_ip("mail-a.example.com", ip("192.0.2.129"))
        .with_ip("mail-b.example.com", ip("192.0.2.130"))
        .with_mx("example.org", 10, "mail-c.example.org")
        .with_ip("mail-c.example.org", ip("192.0.2.140"))
        .with_ptr(ip("192.0.2.10"), "example.com")
        .with_ptr(ip("192.0.2.11"), "example.com")
        .with_ptr(ip("192.0.2.65"), "amy.example.com")
        .with_ptr(ip("192.0.2.66"), "bob.example.com")
        .with_ptr(ip("192.0.2.129"), "mail-a.example.com")
        .with_ptr(ip("192.0.2.130"), "mail-b.example.com")
        .with_ptr(ip("192.0.2.140"), "mail-c.example.org")
        // A rogue reverse mapping that claims to be bob.example.com.
        .with_ptr(ip("10.0.0.4"), "bob.example.com")
}

async fn check(r: &StaticResolver, ip: &str, domain: &str, sender: &str) -> SpfResult {
    check_host(r, ip.parse().unwrap(), domain, sender, "client.example.net").await
}

/// The client IPs that pass for `record`, out of every host in the zone.
async fn passing(record: &str) -> Vec<&'static str> {
    let r = zone(record);
    let mut out = Vec::new();
    for ip in [
        "192.0.2.10",
        "192.0.2.11",
        "192.0.2.65",
        "192.0.2.66",
        "192.0.2.129",
        "192.0.2.130",
        "192.0.2.131",
        "192.0.2.140",
        "192.0.2.141",
        "10.0.0.4",
    ] {
        if check(&r, ip, "example.com", "user@example.com").await == SpfResult::Pass {
            out.push(ip);
        }
    }
    out
}

#[tokio::test]
async fn rfc_7208_appendix_a1_simple_examples() {
    let all = [
        "192.0.2.10",
        "192.0.2.11",
        "192.0.2.65",
        "192.0.2.66",
        "192.0.2.129",
        "192.0.2.130",
        "192.0.2.131",
        "192.0.2.140",
        "192.0.2.141",
        "10.0.0.4",
    ];
    assert_eq!(passing("v=spf1 +all").await, all);
    assert_eq!(passing("v=spf1 a -all").await, ["192.0.2.10", "192.0.2.11"]);
    assert_eq!(
        passing("v=spf1 a:example.org -all").await,
        Vec::<&str>::new()
    );
    assert_eq!(
        passing("v=spf1 mx -all").await,
        ["192.0.2.129", "192.0.2.130"]
    );
    assert_eq!(passing("v=spf1 mx:example.org -all").await, ["192.0.2.140"]);
    assert_eq!(
        passing("v=spf1 mx mx:example.org -all").await,
        ["192.0.2.129", "192.0.2.130", "192.0.2.140"]
    );
    assert_eq!(
        passing("v=spf1 mx/30 mx:example.org/30 -all").await,
        [
            "192.0.2.129",
            "192.0.2.130",
            "192.0.2.131",
            "192.0.2.140",
            "192.0.2.141"
        ]
    );
    // ptr: .65 passes (valid reverse DNS in example.com); .140 fails
    // (valid, but in example.org); 10.0.0.4 fails (reverse DNS not valid).
    let ptr = passing("v=spf1 ptr -all").await;
    assert!(ptr.contains(&"192.0.2.65"));
    assert!(!ptr.contains(&"192.0.2.140") && !ptr.contains(&"10.0.0.4"));
    // ip4:192.0.2.128/28: .65 fails, .129 passes.
    let r = zone("v=spf1 ip4:192.0.2.128/28 -all");
    assert_eq!(
        check(&r, "192.0.2.65", "example.com", "u@example.com").await,
        SpfResult::Fail
    );
    assert_eq!(
        check(&r, "192.0.2.129", "example.com", "u@example.com").await,
        SpfResult::Pass
    );
}

#[tokio::test]
async fn rfc_7208_appendix_a2_include_and_redirect() {
    let r = zone("v=spf1 a -all")
        .with_txt(
            "example.org",
            "v=spf1 include:example.com include:example.net -all",
        )
        .with_txt("la.example.org", "v=spf1 redirect=example.org");
    // Matched by the first include.
    assert_eq!(
        check(&r, "192.0.2.10", "example.org", "u@example.org").await,
        SpfResult::Pass
    );
    assert_eq!(
        check(&r, "192.0.2.10", "la.example.org", "u@la.example.org").await,
        SpfResult::Pass
    );
    // Not matched there, so example.net is tried: it has no SPF record,
    // which RFC 7208 §5.2 turns into permerror.
    assert_eq!(
        check(&r, "192.0.2.65", "example.org", "u@example.org").await,
        SpfResult::PermError
    );
}

#[tokio::test]
async fn rfc_7208_appendix_a3_dnsbl_style() {
    let lo = "127.0.0.2".parse::<IpAddr>().unwrap();
    let r = zone("v=spf1 mx include:mobile-users._spf.%{d} include:remote-users._spf.%{d} -all")
        .with_txt(
            "mobile-users._spf.example.com",
            "v=spf1 exists:%{l1r+}.%{d}",
        )
        .with_txt(
            "remote-users._spf.example.com",
            "v=spf1 exists:%{ir}.%{l1r+}.%{d}",
        )
        .with_ip("mary.mobile-users._spf.example.com", lo)
        .with_ip("fred.mobile-users._spf.example.com", lo)
        .with_ip("15.15.168.192.joel.remote-users._spf.example.com", lo)
        .with_ip("16.15.168.192.joel.remote-users._spf.example.com", lo);
    assert_eq!(
        check(&r, "203.0.113.9", "example.com", "mary@example.com").await,
        SpfResult::Pass
    );
    assert_eq!(
        check(&r, "203.0.113.9", "example.com", "fred+lists@example.com").await,
        SpfResult::Pass
    );
    assert_eq!(
        check(&r, "192.168.15.15", "example.com", "joel@example.com").await,
        SpfResult::Pass
    );
    assert_eq!(
        check(&r, "192.168.15.17", "example.com", "joel@example.com").await,
        SpfResult::Fail
    );
    assert_eq!(
        check(&r, "192.0.2.129", "example.com", "anyone@example.com").await,
        SpfResult::Pass
    );
}

// RFC 7208 Appendix A.4 is not tested: a bare `ptr` in
// ptr._spf.example.com targets that domain itself, so it never matches and
// the example as written fails every sender.

#[tokio::test]
async fn record_selection() {
    // RFC 7208 §4.5: no record is none; two records are permerror.
    let r = StaticResolver::new().with_txt("example.com", "some other text");
    assert_eq!(
        check(&r, "192.0.2.1", "example.com", "u@example.com").await,
        SpfResult::None
    );
    let r = StaticResolver::new()
        .with_txt("example.com", "v=spf1 -all")
        .with_txt("example.com", "v=spf1 +all");
    assert_eq!(
        check(&r, "192.0.2.1", "example.com", "u@example.com").await,
        SpfResult::PermError
    );
    // RFC 7208 §4.3: NXDOMAIN and single-label domains give none.
    assert_eq!(
        check(
            &StaticResolver::new(),
            "192.0.2.1",
            "example.com",
            "u@example.com"
        )
        .await,
        SpfResult::None
    );
    assert_eq!(
        check(
            &StaticResolver::new(),
            "192.0.2.1",
            "localhost",
            "u@localhost"
        )
        .await,
        SpfResult::None
    );
    // RFC 7208 §4.4: a DNS failure gives temperror.
    let r =
        StaticResolver::new().with_failure("example.com", dns::Error::Temporary("servfail".into()));
    assert_eq!(
        check(&r, "192.0.2.1", "example.com", "u@example.com").await,
        SpfResult::TempError
    );
    // RFC 7208 §4.6: syntax errors give permerror.
    let r = StaticResolver::new().with_txt("example.com", "v=spf1 ip4:300.0.0.1 -all");
    assert_eq!(
        check(&r, "192.0.2.1", "example.com", "u@example.com").await,
        SpfResult::PermError
    );
    // No match and no redirect: neutral (RFC 7208 §4.7).
    let r = StaticResolver::new().with_txt("example.com", "v=spf1 ip4:192.0.2.99");
    assert_eq!(
        check(&r, "192.0.2.1", "example.com", "u@example.com").await,
        SpfResult::Neutral
    );
}

#[tokio::test]
async fn qualifiers() {
    for (rec, want) in [
        ("v=spf1 -all", SpfResult::Fail),
        ("v=spf1 ~all", SpfResult::SoftFail),
        ("v=spf1 ?all", SpfResult::Neutral),
        ("v=spf1 +all", SpfResult::Pass),
    ] {
        let r = StaticResolver::new().with_txt("example.com", rec);
        assert_eq!(
            check(&r, "192.0.2.1", "example.com", "u@example.com").await,
            want,
            "{rec}"
        );
    }
}

#[tokio::test]
async fn dns_term_limit() {
    // RFC 7208 §4.6.4: the 11th DNS-querying term is permerror.
    let mut r = StaticResolver::new();
    for i in 0..11 {
        r = r.with_txt(
            &format!("d{i}.example.com"),
            &format!("v=spf1 include:d{}.example.com", i + 1),
        );
    }
    r = r.with_txt("d11.example.com", "v=spf1 +all");
    assert_eq!(
        check(&r, "192.0.2.1", "d0.example.com", "u@d0.example.com").await,
        SpfResult::PermError
    );
    assert_eq!(
        check(&r, "192.0.2.1", "d2.example.com", "u@d2.example.com").await,
        SpfResult::Pass,
        "9 terms is fine"
    );
}

#[tokio::test]
async fn void_lookup_limit() {
    // RFC 7208 §4.6.4: more than two void lookups is permerror.
    let r = StaticResolver::new().with_txt(
        "example.com",
        "v=spf1 a:none1.example.com a:none2.example.com +all",
    );
    assert_eq!(
        check(&r, "192.0.2.1", "example.com", "u@example.com").await,
        SpfResult::Pass
    );
    let r = StaticResolver::new().with_txt(
        "example.com",
        "v=spf1 a:n1.example.com a:n2.example.com a:n3.example.com +all",
    );
    assert_eq!(
        check(&r, "192.0.2.1", "example.com", "u@example.com").await,
        SpfResult::PermError
    );
}

#[tokio::test]
async fn redirect_rules() {
    // RFC 7208 §6.1: redirect to a domain with no record is permerror.
    let r = StaticResolver::new().with_txt("example.com", "v=spf1 redirect=nothing.example.org");
    assert_eq!(
        check(&r, "192.0.2.1", "example.com", "u@example.com").await,
        SpfResult::PermError
    );
    // Ignored when the record has "all".
    let r =
        StaticResolver::new().with_txt("example.com", "v=spf1 ?all redirect=nothing.example.org");
    assert_eq!(
        check(&r, "192.0.2.1", "example.com", "u@example.com").await,
        SpfResult::Neutral
    );
}

#[tokio::test]
async fn ipv6_and_mapped_clients() {
    let r = StaticResolver::new().with_txt(
        "example.com",
        "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all",
    );
    assert_eq!(
        check(&r, "2001:db8::1", "example.com", "u@example.com").await,
        SpfResult::Pass
    );
    assert_eq!(
        check(&r, "2001:db9::1", "example.com", "u@example.com").await,
        SpfResult::Fail
    );
    // RFC 7208 §5: an IPv4-mapped IPv6 client is checked as IPv4.
    assert_eq!(
        check(&r, "::ffff:192.0.2.7", "example.com", "u@example.com").await,
        SpfResult::Pass
    );
}

#[tokio::test]
async fn too_many_mx_records() {
    let mut r = StaticResolver::new().with_txt("example.com", "v=spf1 mx -all");
    for i in 0..11 {
        r = r.with_mx("example.com", i, &format!("mx{i}.example.com"));
    }
    assert_eq!(
        check(&r, "192.0.2.1", "example.com", "u@example.com").await,
        SpfResult::PermError
    );
}

#[tokio::test]
async fn mail_from_identity() {
    let r = StaticResolver::new()
        .with_txt("example.com", "v=spf1 ip4:192.0.2.1 -all")
        .with_txt("mx.example.net", "v=spf1 ip4:192.0.2.2 -all");
    let ip = "192.0.2.1".parse().unwrap();
    assert_eq!(
        check_mail_from(&r, ip, Some("u@example.com"), "mx.example.net").await,
        (SpfResult::Pass, "example.com".into())
    );
    // RFC 7208 §2.4: the null reverse-path checks postmaster@<helo>.
    assert_eq!(
        check_mail_from(&r, ip, None, "mx.example.net").await,
        (SpfResult::Fail, "mx.example.net".into())
    );
}
