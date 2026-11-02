//! `idly dns`: the DNS records a domain needs for its mail to be accepted,
//! and, with `--check`, what our own resolver currently finds for each.

use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::Path;

use dns::{Dnssec, Resolver};
use mail_auth_glue::spf::{SpfResult, check_host};
use smtp_proto::address::domain_to_ascii;

use crate::config::Config;

/// What to look for when checking a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expect {
    /// `host` among the domain's MX records.
    Mx { host: String },
    /// `ip` among the name's A or AAAA records.
    Address { ip: IpAddr },
    /// The name resolves to one of `ips` (through a CNAME or not).
    AnyOf { ips: Vec<IpAddr> },
    /// The PTR of `ip` names the host.
    Ptr { ip: IpAddr, host: String },
    /// An SPF record that passes each of `ips` (RFC 7208 §4).
    Spf { ips: Vec<IpAddr>, helo: String },
    /// A TXT record equal to the value, ignoring white space.
    TxtEqual,
    /// A TXT record starting with this tag.
    TxtTag(&'static str),
    /// An `_mta-sts` record with this id (RFC 8461 §3.1).
    StsId(String),
    /// TLSA `3 1 1` with this SHA-256, in a DNSSEC-signed zone.
    Tlsa(Vec<u8>),
}

/// One record to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Record {
    /// Owner name with the trailing dot, or an IP for PTR.
    pub(crate) name: String,
    pub(crate) rtype: &'static str,
    pub(crate) value: String,
    pub(crate) note: Option<String>,
    pub(crate) expect: Expect,
}

/// A titled group of records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Section {
    pub(crate) title: String,
    /// The zone whose DNSSEC status is shown with `--check`.
    pub(crate) zone: Option<String>,
    pub(crate) records: Vec<Record>,
}

/// What a check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Status {
    Ok,
    Missing,
    Mismatch(String),
    /// The lookup failed; nothing is known.
    Unknown(String),
}

impl Status {
    fn label(&self) -> String {
        match self {
            Self::Ok => "OK".into(),
            Self::Missing => "MISSING".into(),
            Self::Mismatch(m) => format!("MISMATCH: {m}"),
            Self::Unknown(m) => format!("UNKNOWN: {m}"),
        }
    }
}

/// Everything `idly dns` reports on.
#[derive(Debug, Clone)]
pub(crate) struct Inputs {
    /// Our public addresses (may be empty if unknown).
    pub(crate) ips: Vec<IpAddr>,
    /// SHA-256 of the certificate's public key, for TLSA.
    pub(crate) tlsa: Option<Vec<u8>>,
    /// Why there is no TLSA value, or a caveat about it.
    pub(crate) tlsa_note: Option<String>,
    /// `(domain, selector, record)` for every DKIM key on disk.
    pub(crate) dkim: Vec<(String, String, String)>,
}

/// The records for `domains` (A-labels) and for our host.
pub(crate) fn plan(config: &Config, domains: &[String], inputs: &Inputs) -> Vec<Section> {
    let host = ascii(&config.server.hostname);
    let fqdn = |n: &str| format!("{n}.");
    let mut sections = Vec::new();

    for domain in domains {
        let mut records = vec![
            Record {
                name: fqdn(domain),
                rtype: "MX",
                value: format!("10 {host}."),
                note: None,
                expect: Expect::Mx { host: host.clone() },
            },
            // RFC 7208 §5.4: "mx" authorizes the addresses of our MX host.
            Record {
                name: fqdn(domain),
                rtype: "TXT",
                value: "v=spf1 mx -all".into(),
                note: None,
                expect: Expect::Spf {
                    ips: inputs.ips.clone(),
                    helo: host.clone(),
                },
            },
        ];
        let keys: Vec<_> = inputs.dkim.iter().filter(|(d, _, _)| d == domain).collect();
        if keys.is_empty() {
            records.push(Record {
                name: fqdn(&format!("<selector>._domainkey.{domain}")),
                rtype: "TXT",
                value: "(no key yet)".into(),
                note: Some(format!(
                    "run `idly dkim generate --domain {domain} --selector <name>`"
                )),
                expect: Expect::TxtTag("v=DKIM1"),
            });
        }
        for (_, selector, record) in keys {
            records.push(Record {
                name: fqdn(&format!("{selector}._domainkey.{domain}")),
                rtype: "TXT",
                value: record.clone(),
                note: None,
                expect: Expect::TxtEqual,
            });
        }
        // Strict alignment: our mail always passes both (RFC 9989 §4.4).
        records.push(Record {
            name: fqdn(&format!("_dmarc.{domain}")),
            rtype: "TXT",
            value: "v=DMARC1; p=quarantine; adkim=s; aspf=s".into(),
            note: Some("any valid DMARC policy is fine; this one is a safe start".into()),
            expect: Expect::TxtTag("v=DMARC1"),
        });
        // RFC 8460 §3: where other servers send reports about TLS with us.
        records.push(Record {
            name: fqdn(&format!("_smtp._tls.{domain}")),
            rtype: "TXT",
            value: format!("v=TLSRPTv1; rua=mailto:postmaster@{domain}"),
            note: None,
            expect: Expect::TxtTag("v=TLSRPTv1"),
        });
        if config.mta_sts.enabled {
            let id = crate::mta_sts::policy_id(&crate::mta_sts::policy(config));
            records.push(Record {
                name: fqdn(&format!("_mta-sts.{domain}")),
                rtype: "TXT",
                value: format!("v=STSv1; id={id}"),
                note: Some(format!(
                    "policy: mode {}, max_age {}",
                    config.mta_sts.mode.as_str(),
                    config.mta_sts.max_age
                )),
                expect: Expect::StsId(id),
            });
            records.push(Record {
                name: fqdn(&format!("mta-sts.{domain}")),
                rtype: "CNAME",
                value: fqdn(&host),
                note: Some("or A/AAAA records with this server's addresses".into()),
                expect: Expect::AnyOf {
                    ips: inputs.ips.clone(),
                },
            });
        }
        sections.push(Section {
            title: format!("domain {domain}"),
            zone: Some(domain.clone()),
            records,
        });
    }

    let mut records = Vec::new();
    if inputs.ips.is_empty() {
        records.push(Record {
            name: fqdn(&host),
            rtype: "A",
            value: "<this server's public IPv4 address>".into(),
            note: Some("no public address found; set server.public_ips".into()),
            expect: Expect::AnyOf { ips: vec![] },
        });
    }
    for ip in &inputs.ips {
        records.push(Record {
            name: fqdn(&host),
            rtype: if ip.is_ipv4() { "A" } else { "AAAA" },
            value: ip.to_string(),
            note: None,
            expect: Expect::Address { ip: *ip },
        });
    }
    match &inputs.tlsa {
        // RFC 7672 §3.1.1: DANE-EE(3) SPKI(1) SHA2-256(1) is recommended.
        Some(hash) => records.push(Record {
            name: fqdn(&format!("_25._tcp.{host}")),
            rtype: "TLSA",
            value: format!("3 1 1 {}", hex(hash)),
            note: Some(inputs.tlsa_note.clone().unwrap_or_else(|| {
                "only in a DNSSEC-signed zone; senders ignore it otherwise".into()
            })),
            expect: Expect::Tlsa(hash.clone()),
        }),
        None => records.push(Record {
            name: fqdn(&format!("_25._tcp.{host}")),
            rtype: "TLSA",
            value: "(no key yet)".into(),
            note: inputs.tlsa_note.clone(),
            expect: Expect::Tlsa(Vec::new()),
        }),
    }
    sections.push(Section {
        title: format!("mail host {host}"),
        zone: None,
        records,
    });

    if !inputs.ips.is_empty() {
        sections.push(Section {
            title: "reverse DNS: set these at your hosting provider".into(),
            zone: None,
            records: inputs
                .ips
                .iter()
                .map(|ip| Record {
                    name: ip.to_string(),
                    rtype: "PTR",
                    value: fqdn(&host),
                    note: None,
                    expect: Expect::Ptr {
                        ip: *ip,
                        host: host.clone(),
                    },
                })
                .collect(),
        });
    }
    sections
}

/// Looks the record up and compares.
pub(crate) async fn check<R: Resolver>(resolver: &R, record: &Record) -> Status {
    let name = record.name.trim_end_matches('.');
    match &record.expect {
        Expect::Mx { host } => match resolver.mx(name).await {
            Ok(a) if a.records.iter().any(|m| m.exchange == *host) => Status::Ok,
            Ok(a) => Status::Mismatch(format!(
                "found {}",
                a.records
                    .iter()
                    .map(|m| format!("{} {}", m.preference, m.exchange))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            Err(e) => not_found(&e),
        },
        Expect::Address { ip } => match addresses(resolver, name).await {
            Ok(found) if found.contains(ip) => Status::Ok,
            Ok(found) if found.is_empty() => Status::Missing,
            Ok(found) => Status::Mismatch(format!("found {}", list(&found))),
            Err(s) => s,
        },
        Expect::AnyOf { ips } => match addresses(resolver, name).await {
            Ok(found) if found.is_empty() => Status::Missing,
            Ok(found) if ips.is_empty() || found.iter().any(|f| ips.contains(f)) => Status::Ok,
            Ok(found) => Status::Mismatch(format!("found {}", list(&found))),
            Err(s) => s,
        },
        Expect::Ptr { ip, host } => match resolver.ptr(*ip).await {
            Ok(a) if a.records.iter().any(|n| n.trim_end_matches('.') == host) => Status::Ok,
            Ok(a) => Status::Mismatch(format!("found {}", a.records.join(", "))),
            Err(e) => not_found(&e),
        },
        Expect::Spf { ips, helo } => {
            let txt = match txt(resolver, name, "v=spf1").await {
                Ok(t) => t,
                Err(s) => return s,
            };
            let mut failing = Vec::new();
            for ip in ips {
                let result =
                    check_host(resolver, *ip, name, &format!("postmaster@{name}"), helo).await;
                if result != SpfResult::Pass {
                    failing.push(format!("{} for {ip}", result.name()));
                }
            }
            if failing.is_empty() {
                Status::Ok
            } else {
                Status::Mismatch(format!("{:?} gives {}", txt, failing.join(", ")))
            }
        }
        Expect::TxtEqual => match txt(resolver, name, "").await {
            Ok(found) if squash(&found) == squash(&record.value) => Status::Ok,
            Ok(found) => Status::Mismatch(format!("found {found:?}")),
            Err(s) => s,
        },
        Expect::TxtTag(tag) => match txt(resolver, name, tag).await {
            Ok(_) => Status::Ok,
            Err(s) => s,
        },
        Expect::StsId(id) => match resolver.txt(name).await {
            Ok(a) => match smtp_client::mta_sts::parse_txt(&a.records) {
                Some(found) if found == *id => Status::Ok,
                Some(found) => Status::Mismatch(format!(
                    "id={found}; senders keep the old policy until it matches"
                )),
                None => Status::Mismatch("no valid v=STSv1 record".into()),
            },
            Err(e) => not_found(&e),
        },
        Expect::Tlsa(hash) => match resolver.tlsa(name).await {
            Ok(a) => {
                let ours = a
                    .records
                    .iter()
                    .any(|t| t.usage == 3 && t.selector == 1 && t.matching == 1 && t.data == *hash);
                if !ours {
                    Status::Mismatch("no TLSA record for the current key".into())
                } else if a.dnssec != Dnssec::Secure {
                    Status::Mismatch("found, but the zone is not DNSSEC-signed".into())
                } else {
                    Status::Ok
                }
            }
            Err(e) => not_found(&e),
        },
    }
}

/// The DNSSEC status of a zone, from its MX answer.
pub(crate) async fn dnssec<R: Resolver>(resolver: &R, zone: &str) -> String {
    match resolver.mx(zone).await {
        Ok(a) => match a.dnssec {
            Dnssec::Secure => "signed (DNSSEC)".into(),
            _ => "not DNSSEC-signed".into(),
        },
        Err(dns::Error::Bogus) => "DNSSEC validation FAILS".into(),
        Err(_) => "unknown".into(),
    }
}

/// Zone-file style output; `statuses` (one per record) adds the results.
pub(crate) fn render(
    sections: &[Section],
    statuses: Option<&[Vec<Status>]>,
    zones: &[(String, String)],
) -> String {
    let mut out = String::new();
    for (i, section) in sections.iter().enumerate() {
        let _ = write!(out, "; {}", section.title);
        if let Some(zone) = &section.zone
            && let Some((_, state)) = zones.iter().find(|(z, _)| z == zone)
        {
            let _ = write!(out, " ({state})");
        }
        out.push('\n');
        for (j, r) in section.records.iter().enumerate() {
            if let Some(s) = statuses.and_then(|s| s.get(i)).and_then(|s| s.get(j)) {
                let _ = write!(out, "[{}]\n  ", s.label());
            }
            let value = match r.rtype {
                "TXT" if !r.value.starts_with('(') => quote(&r.value),
                _ => r.value.clone(),
            };
            let _ = writeln!(out, "{:<40} {:<6} {value}", r.name, r.rtype);
            if let Some(note) = &r.note {
                let _ = writeln!(out, "  ; {note}");
            }
        }
        out.push('\n');
    }
    out
}

/// TXT data as zone-file strings of at most 255 octets each
/// (RFC 1035 §3.3.14); DKIM RSA keys need several.
fn quote(value: &str) -> String {
    value
        .as_bytes()
        .chunks(255)
        .map(|c| format!("\"{}\"", String::from_utf8_lossy(c)))
        .collect::<Vec<_>>()
        .join(" ")
}

async fn addresses<R: Resolver>(resolver: &R, name: &str) -> Result<Vec<IpAddr>, Status> {
    let mut found = Vec::new();
    let mut error = None;
    for result in [resolver.a(name).await, resolver.aaaa(name).await] {
        match result {
            Ok(a) => found.extend(a.records),
            Err(e) if e.is_not_found() => {}
            Err(e) => error = Some(e),
        }
    }
    match error {
        Some(e) if found.is_empty() => Err(Status::Unknown(e.to_string())),
        _ => Ok(found),
    }
}

/// The TXT record at `name` starting with `tag` (any, for "").
async fn txt<R: Resolver>(resolver: &R, name: &str, tag: &str) -> Result<String, Status> {
    let a = resolver.txt(name).await.map_err(|e| not_found(&e))?;
    a.records
        .iter()
        .map(|r| String::from_utf8_lossy(r).into_owned())
        .find(|t| t.starts_with(tag))
        .ok_or(Status::Missing)
}

fn not_found(e: &dns::Error) -> Status {
    if e.is_not_found() {
        Status::Missing
    } else {
        Status::Unknown(e.to_string())
    }
}

fn squash(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn list(ips: &[IpAddr]) -> String {
    ips.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn ascii(name: &str) -> String {
    domain_to_ascii(name).unwrap_or_else(|_| name.to_ascii_lowercase())
}

/// DKIM records written by `idly dkim generate` (`<selector>.txt`).
pub(crate) fn dkim_records(data_dir: &Path, domains: &[String]) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for domain in domains {
        let dir = data_dir.join("dkim").join(domain);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut found: Vec<_> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "txt"))
            .filter_map(|p| {
                let selector = p.file_stem()?.to_str()?.to_owned();
                let record = std::fs::read_to_string(&p).ok()?.trim().to_owned();
                Some((domain.clone(), selector, record))
            })
            .collect();
        found.sort();
        out.extend(found);
    }
    out
}

/// The TLSA value: SHA-256 of the certificate's public key. With ACME
/// it comes from the key file, which never changes; with `[tls]` files,
/// from the certificate, whose key may change at renewal.
pub(crate) fn tlsa(config: &Config) -> (Option<Vec<u8>>, Option<String>) {
    let sha = |spki: &[u8]| {
        ring::digest::digest(&ring::digest::SHA256, spki)
            .as_ref()
            .to_vec()
    };
    if config.acme.is_some() {
        let path = config.server.data_dir.join("acme").join("tls.key");
        return match std::fs::read_to_string(&path) {
            Ok(pem) => match acme::store::public_key(&pem) {
                Ok(spki) => (Some(sha(&spki)), None),
                Err(_) => (None, Some(format!("{} is not a valid key", path.display()))),
            },
            Err(_) => (
                None,
                Some("start idly once to create the certificate key, then run this again".into()),
            ),
        };
    }
    if let Some(files) = &config.tls {
        return match crate::certificates::load_files(files) {
            Ok((_, info)) => (
                Some(sha(&info.spki)),
                Some(
                    "only in a DNSSEC-signed zone; keep the key when renewing (certbot --reuse-key) or this record breaks"
                        .into(),
                ),
            ),
            Err(e) => (None, Some(e)),
        };
    }
    (
        None,
        Some("no certificate configured ([acme] or [tls])".into()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::testing::StaticResolver;

    fn config(extra: &str) -> Config {
        Config::parse(&format!(
            r#"
            [server]
            hostname = "mx.example.org"
            data_dir = "/var/lib/idly"
            [[domain]]
            name = "example.org"
            [[account]]
            address = "a@example.org"
            password_hash = "$argon2id$v=19$m=19456,t=2,p=1$ZGVtb2RlbW9kZW1v$ZGVtby1vbmx5LW5vdC1hLXJlYWwtaGFzaA"
            {extra}
            "#
        ))
        .unwrap()
    }

    fn ip() -> IpAddr {
        "203.0.113.5".parse().unwrap()
    }

    fn inputs() -> Inputs {
        Inputs {
            ips: vec![ip()],
            tlsa: Some(vec![0xab; 32]),
            tlsa_note: None,
            dkim: vec![(
                "example.org".into(),
                "s1-ed25519".into(),
                "v=DKIM1; k=ed25519; p=AAAA".into(),
            )],
        }
    }

    #[test]
    fn plan_lists_every_record() {
        let c = config("[acme]\naccept_terms = true\n[mta_sts]\nenabled = true\n");
        let sections = plan(&c, &["example.org".into()], &inputs());
        let text = render(&sections, None, &[]);
        let id = crate::mta_sts::policy_id(&crate::mta_sts::policy(&c));
        for line in [
            "example.org.                             MX     10 mx.example.org.",
            "example.org.                             TXT    \"v=spf1 mx -all\"",
            "s1-ed25519._domainkey.example.org.       TXT    \"v=DKIM1; k=ed25519; p=AAAA\"",
            "_dmarc.example.org.                      TXT    \"v=DMARC1; p=quarantine; adkim=s; aspf=s\"",
            "_smtp._tls.example.org.                  TXT    \"v=TLSRPTv1; rua=mailto:postmaster@example.org\"",
            &format!("_mta-sts.example.org.                    TXT    \"v=STSv1; id={id}\""),
            "mta-sts.example.org.                     CNAME  mx.example.org.",
            "mx.example.org.                          A      203.0.113.5",
            &format!(
                "_25._tcp.mx.example.org.                 TLSA   3 1 1 {}",
                "ab".repeat(32)
            ),
            "203.0.113.5                              PTR    mx.example.org.",
        ] {
            assert!(text.contains(line), "missing {line:?} in\n{text}");
        }
    }

    #[test]
    fn long_txt_values_are_split() {
        let long = "p=".to_owned() + &"A".repeat(400);
        let q = quote(&long);
        assert_eq!(q.matches('"').count(), 4, "{q}");
        assert!(q.starts_with("\"p=AAA"));
    }

    #[tokio::test]
    async fn check_finds_ok_missing_and_mismatch() {
        let c = config("[acme]\naccept_terms = true\n[mta_sts]\nenabled = true\n");
        let id = crate::mta_sts::policy_id(&crate::mta_sts::policy(&c));
        let sections = plan(&c, &["example.org".into()], &inputs());
        let resolver = StaticResolver::new()
            .with_mx("example.org", 10, "mx.example.org")
            .with_ip("mx.example.org", ip())
            .with_txt("example.org", "v=spf1 mx -all")
            .with_txt(
                "s1-ed25519._domainkey.example.org",
                "v=DKIM1;  k=ed25519; p=AAAA",
            )
            .with_txt("_dmarc.example.org", "v=DMARC1; p=reject")
            .with_txt("_mta-sts.example.org", "v=STSv1; id=old1")
            .with_ip("mta-sts.example.org", ip())
            .with_ptr(ip(), "mx.example.org.");
        let mut results = Vec::new();
        for s in &sections {
            for r in &s.records {
                results.push((r.name.clone(), r.rtype, check(&resolver, r).await));
            }
        }
        let status = |name: &str, rtype: &str| {
            results
                .iter()
                .find(|(n, t, _)| n == name && *t == rtype)
                .map(|(_, _, s)| s.clone())
                .unwrap()
        };
        assert_eq!(status("example.org.", "MX"), Status::Ok);
        assert_eq!(
            status("example.org.", "TXT"),
            Status::Ok,
            "SPF passes our IP"
        );
        assert_eq!(
            status("s1-ed25519._domainkey.example.org.", "TXT"),
            Status::Ok
        );
        assert_eq!(status("_dmarc.example.org.", "TXT"), Status::Ok);
        assert_eq!(status("_smtp._tls.example.org.", "TXT"), Status::Missing);
        assert!(
            matches!(status("_mta-sts.example.org.", "TXT"), Status::Mismatch(m) if m.contains("id=old1")),
            "{id}"
        );
        assert_eq!(status("mta-sts.example.org.", "CNAME"), Status::Ok);
        assert_eq!(status("mx.example.org.", "A"), Status::Ok);
        assert_eq!(status("_25._tcp.mx.example.org.", "TLSA"), Status::Missing);
        assert_eq!(status("203.0.113.5", "PTR"), Status::Ok);

        // SPF that doesn't cover us, a TLSA record in an unsigned zone.
        let tlsa = dns::Tlsa {
            usage: 3,
            selector: 1,
            matching: 1,
            data: vec![0xab; 32],
        };
        let wrong = StaticResolver::new()
            .with_txt("example.org", "v=spf1 ip4:192.0.2.1 -all")
            .with_tlsa("_25._tcp.mx.example.org", tlsa.clone());
        let spf = &sections[0].records[1];
        assert!(
            matches!(check(&wrong, spf).await, Status::Mismatch(m) if m.contains("fail for 203.0.113.5"))
        );
        let tlsa_record = sections[1]
            .records
            .iter()
            .find(|r| r.rtype == "TLSA")
            .unwrap();
        assert!(
            matches!(check(&wrong, tlsa_record).await, Status::Mismatch(m) if m.contains("not DNSSEC"))
        );
        let signed = StaticResolver::new()
            .secure(true)
            .with_tlsa("_25._tcp.mx.example.org", tlsa);
        assert_eq!(check(&signed, tlsa_record).await, Status::Ok);
    }

    #[test]
    fn dkim_records_come_from_the_key_directory() {
        let dir = tempfile::tempdir().unwrap();
        crate::dkim::generate(
            dir.path(),
            "example.org",
            "s1",
            crate::dkim::Algorithm::Ed25519,
        )
        .unwrap();
        let found = dkim_records(dir.path(), &["example.org".into(), "other.example".into()]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, "s1");
        assert!(found[0].2.starts_with("v=DKIM1; k=ed25519; p="));
    }
}
