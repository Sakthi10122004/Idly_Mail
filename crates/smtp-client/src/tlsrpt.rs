//! SMTP TLS Reporting (RFC 8460): the `_smtp._tls` TXT record, what is
//! recorded per session, the JSON report, and the email it travels in.
//! This module does no I/O; sending is in `lib.rs`.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};
use smtp_proto::{Host, Mailbox};

/// Report destinations used per policy domain; more `rua` URIs than this
/// are ignored (RFC 8460 §3: a reporter MAY use only one).
pub const MAX_RUA: usize = 4;
/// Failure reason codes are cut to this many characters.
const MAX_REASON: usize = 200;

/// Where a report goes (RFC 8460 §3 `rua`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rua {
    /// `mailto:` an address.
    Mailto(String),
    /// `https://host/path`, port 443.
    Https { host: String, path: String },
}

/// Parses the `_smtp._tls` TXT records (RFC 8460 §3). Returns the usable
/// report destinations, or None if the domain doesn't (validly) ask for
/// reports.
pub fn parse_txt(records: &[Vec<u8>]) -> Option<Vec<Rua>> {
    // "Records that do not begin with v=TLSRPTv1; are discarded"; exactly
    // one must remain.
    let found: Vec<&[u8]> = records
        .iter()
        .map(Vec::as_slice)
        .filter(|r| r.starts_with(b"v=TLSRPTv1"))
        .collect();
    let [record] = found.as_slice() else {
        return None;
    };
    let text = std::str::from_utf8(record).ok()?;
    let wsp = [' ', '\t'];
    let mut fields = text.split(';').map(|f| f.trim_matches(wsp));
    if fields.next()? != "v=TLSRPTv1" {
        return None;
    }
    let mut rua = None;
    let mut seen_any = false;
    for field in fields {
        if field.is_empty() {
            // tlsrpt-record ends with an optional field-delim.
            continue;
        }
        seen_any = true;
        let (name, value) = field.split_once('=')?;
        if name == "rua" {
            if rua.is_some() {
                return None;
            }
            rua = Some(
                value
                    .split(',')
                    .map(|u| u.trim_matches(wsp))
                    .filter_map(parse_uri)
                    .take(MAX_RUA)
                    .collect::<Vec<_>>(),
            );
        } else {
            // tlsrpt-extension: syntax only, the meaning is ignored.
            let name_ok = (1..=32).contains(&name.len())
                && name
                    .bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_alphanumeric())
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b));
            let value_ok = !value.is_empty()
                && value
                    .bytes()
                    .all(|b| (0x21..=0x7e).contains(&b) && b != b';' && b != b'=');
            if !name_ok || !value_ok {
                return None;
            }
        }
    }
    // "the tlsrpt-rua record is required".
    if !seen_any {
        return None;
    }
    rua.filter(|r| !r.is_empty())
}

/// One `rua` URI, if it is a usable mailto or https URI.
fn parse_uri(uri: &str) -> Option<Rua> {
    let (scheme, rest) = uri.split_once(':')?;
    if scheme.eq_ignore_ascii_case("mailto") {
        // RFC 6068: header fields after '?' are ignored.
        let addr = percent_decode(rest.split('?').next()?)?;
        let mailbox = Mailbox::parse(&addr).ok()?;
        // Reports go to domains (found through MX), never address literals.
        if !matches!(mailbox.host, Host::Domain(_)) {
            return None;
        }
        return Some(Rua::Mailto(mailbox.to_string()));
    }
    if scheme.eq_ignore_ascii_case("https") {
        let rest = rest.strip_prefix("//")?;
        let rest = rest.split('#').next()?;
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) => (rest.get(..i)?, rest.get(i..)?),
            None => (rest, "/"),
        };
        let path = if path.starts_with('?') {
            format!("/{path}")
        } else {
            path.to_owned()
        };
        if authority.contains('@') || !path.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return None;
        }
        // Only the default port: a report is never sent to another
        // service on a host.
        let host = match authority.rsplit_once(':') {
            Some((h, "443")) => h,
            Some(_) => return None,
            None => authority,
        };
        // A DNS name, not an address literal.
        if host.parse::<IpAddr>().is_ok() || host.starts_with('[') {
            return None;
        }
        let host = smtp_proto::address::domain_to_ascii(host).ok()?;
        return Some(Rua::Https { host, path });
    }
    None
}

/// Decodes %XX escapes; None for a malformed escape or non-UTF-8 result.
fn percent_decode(s: &str) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = char::from(bytes.next()?).to_digit(16)?;
            let lo = char::from(bytes.next()?).to_digit(16)?;
            out.push(u8::try_from(hi * 16 + lo).ok()?);
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out).ok()
}

/// The kind of policy applied to a session (RFC 8460 §4.4 policy-type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyType {
    Tlsa,
    Sts,
    NoPolicy,
}

/// The policy applied to a session, as the report's "policy" object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Applied {
    pub(crate) kind: PolicyType,
    /// TLSA records in presentation form, or the MTA-STS policy lines.
    pub(crate) strings: Vec<String>,
    /// For MTA-STS, the policy's MX patterns; for DANE, the MX host.
    pub(crate) mx: Vec<String>,
}

impl Applied {
    pub(crate) fn none() -> Self {
        Self {
            kind: PolicyType::NoPolicy,
            strings: Vec::new(),
            mx: Vec::new(),
        }
    }

    /// The "policy" object (RFC 8460 §4.4), serialized; keys are sorted,
    /// so equal policies give equal strings.
    pub(crate) fn to_json(&self, domain: &str) -> String {
        let mut p = Map::new();
        let kind = match self.kind {
            PolicyType::Tlsa => "tlsa",
            PolicyType::Sts => "sts",
            PolicyType::NoPolicy => "no-policy-found",
        };
        p.insert("policy-type".into(), kind.into());
        if self.kind != PolicyType::NoPolicy {
            p.insert("policy-string".into(), self.strings.clone().into());
        }
        p.insert("policy-domain".into(), domain.into());
        match self.kind {
            PolicyType::Sts => {
                p.insert("mx-host".into(), self.mx.clone().into());
            }
            PolicyType::Tlsa => {
                if let Some(h) = self.mx.first() {
                    p.insert("mx-host".into(), h.clone().into());
                }
            }
            PolicyType::NoPolicy => {}
        }
        Value::Object(p).to_string()
    }
}

/// A TLSA record in presentation form (RFC 8460 §4.5).
pub(crate) fn tlsa_string(t: &dns::Tlsa) -> String {
    use std::fmt::Write as _;
    let mut s = format!("{} {} {} ", t.usage, t.selector, t.matching);
    for b in &t.data {
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// One failed session's details (RFC 8460 §4.4 failure-details).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Failure {
    pub(crate) result_type: &'static str,
    pub(crate) sending_ip: Option<IpAddr>,
    pub(crate) mx_host: Option<String>,
    pub(crate) receiving_ip: Option<IpAddr>,
    pub(crate) reason: Option<String>,
}

impl Failure {
    pub(crate) fn new(result_type: &'static str) -> Self {
        Self {
            result_type,
            sending_ip: None,
            mx_host: None,
            receiving_ip: None,
            reason: None,
        }
    }

    pub(crate) fn to_json(&self) -> String {
        let mut f = Map::new();
        f.insert("result-type".into(), self.result_type.into());
        if let Some(ip) = self.sending_ip {
            f.insert("sending-mta-ip".into(), ip.to_string().into());
        }
        if let Some(h) = &self.mx_host {
            f.insert("receiving-mx-hostname".into(), h.clone().into());
        }
        if let Some(ip) = self.receiving_ip {
            f.insert("receiving-ip".into(), ip.to_string().into());
        }
        if let Some(r) = &self.reason {
            let r: String = r
                .chars()
                .filter(|c| !c.is_control())
                .take(MAX_REASON)
                .collect();
            f.insert("failure-reason-code".into(), r.into());
        }
        Value::Object(f).to_string()
    }
}

/// The UTC day (days since 1970-01-01) of a Unix time.
pub(crate) fn day_of(unix: u64) -> u64 {
    unix / 86_400
}

/// (year, month, day) of a day number (Howard Hinnant's algorithm).
fn civil(day: u64) -> (i64, u32, u32) {
    let z = i64::try_from(day).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// What identifies a report and its sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reporter {
    /// "organization-name".
    pub organization: String,
    /// "contact-info", also the From address of report mail.
    pub contact: String,
    /// The Sending MTA's host name: report-id and file names.
    pub hostname: String,
}

impl Reporter {
    /// The contact's domain, the TLS-Report-Submitter (RFC 8460 §5.3).
    pub fn submitter(&self) -> &str {
        self.contact.rsplit_once('@').map_or("", |(_, d)| d)
    }
}

/// One built report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub domain: String,
    pub report_id: String,
    /// RFC 8460 §5.1 file name.
    pub filename: String,
    /// The gzipped JSON (RFC 8460 §5.2).
    pub gzip: Vec<u8>,
}

/// Builds the report for `domain` on `day` from its recorded rows
/// (policy JSON, failure JSON or "" for a success, count).
pub(crate) fn build(
    reporter: &Reporter,
    day: u64,
    domain: &str,
    rows: &[(String, String, u64)],
) -> Option<Report> {
    let (y, m, d) = civil(day);
    let date = format!("{y:04}-{m:02}-{d:02}");
    // RFC 8460 §4.1: a full UTC day.
    let start = day.checked_mul(86_400)?;
    let end = start.checked_add(86_399)?;
    let report_id = format!(
        "{y:04}{m:02}{d:02}.{domain}@{}",
        reporter.hostname.trim_end_matches('.')
    );

    struct Totals {
        policy: Value,
        ok: u64,
        failed: u64,
        details: Vec<Value>,
    }
    let mut by_policy: BTreeMap<&str, Totals> = BTreeMap::new();
    for (policy, failure, count) in rows {
        let t = match by_policy.entry(policy) {
            std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::btree_map::Entry::Vacant(e) => e.insert(Totals {
                policy: serde_json::from_str(policy).ok()?,
                ok: 0,
                failed: 0,
                details: Vec::new(),
            }),
        };
        if failure.is_empty() {
            t.ok = t.ok.saturating_add(*count);
        } else {
            t.failed = t.failed.saturating_add(*count);
            let mut detail: Value = serde_json::from_str(failure).ok()?;
            if let Some(o) = detail.as_object_mut() {
                o.insert("failed-session-count".into(), (*count).into());
            }
            t.details.push(detail);
        }
    }
    let policies: Vec<Value> = by_policy
        .into_values()
        .map(|t| {
            let mut p = json!({
                "policy": t.policy,
                "summary": {
                    "total-successful-session-count": t.ok,
                    "total-failure-session-count": t.failed,
                },
            });
            if !t.details.is_empty()
                && let Some(o) = p.as_object_mut()
            {
                o.insert("failure-details".into(), t.details.into());
            }
            p
        })
        .collect();
    let report = json!({
        "organization-name": reporter.organization,
        "date-range": {
            "start-datetime": format!("{date}T00:00:00Z"),
            "end-datetime": format!("{date}T23:59:59Z"),
        },
        "contact-info": reporter.contact,
        "report-id": report_id,
        "policies": policies,
    });
    let gzip = gzip(report.to_string().as_bytes()).ok()?;
    Some(Report {
        domain: domain.to_owned(),
        filename: format!("{}!{domain}!{start}!{end}.json.gz", reporter.submitter()),
        report_id,
        gzip,
    })
}

fn gzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data)?;
    e.finish()
}

/// The report as an email (RFC 8460 §5.3), unsigned; the caller signs it
/// with the submitter domain's DKIM keys. `date` is an RFC 5322 date.
pub fn message(reporter: &Reporter, report: &Report, to: &[String], date: &str) -> Vec<u8> {
    let submitter = reporter.submitter();
    let boundary = format!("----=_tlsrpt_{}", report.filename.len());
    let mut m = String::new();
    m.push_str(&format!("From: <{}>\r\n", reporter.contact));
    m.push_str(&format!(
        "To: {}\r\n",
        to.iter()
            .map(|a| format!("<{a}>"))
            .collect::<Vec<_>>()
            .join(",\r\n ")
    ));
    m.push_str(&format!("Date: {date}\r\n"));
    m.push_str(&format!(
        "Subject: Report Domain: {}\r\n Submitter: {submitter}\r\n Report-ID: <{}>\r\n",
        report.domain, report.report_id
    ));
    m.push_str(&format!("Message-ID: <tlsrpt.{}>\r\n", report.report_id));
    m.push_str(&format!("TLS-Report-Domain: {}\r\n", report.domain));
    m.push_str(&format!("TLS-Report-Submitter: {submitter}\r\n"));
    // RFC 3834 §5: an automatic message; no auto-replies.
    m.push_str("Auto-Submitted: auto-generated\r\n");
    m.push_str("MIME-Version: 1.0\r\n");
    m.push_str(&format!(
        "Content-Type: multipart/report; report-type=\"tlsrpt\";\r\n boundary=\"{boundary}\"\r\n\r\n"
    ));
    m.push_str("This is a multipart message in MIME format.\r\n\r\n");
    m.push_str(&format!("--{boundary}\r\n"));
    m.push_str("Content-Type: text/plain; charset=\"us-ascii\"\r\n");
    m.push_str("Content-Transfer-Encoding: 7bit\r\n\r\n");
    m.push_str(&format!(
        "This is an aggregate TLS report from {} for {}.\r\n\r\n",
        reporter.hostname, report.domain
    ));
    m.push_str(&format!("--{boundary}\r\n"));
    m.push_str("Content-Type: application/tlsrpt+gzip\r\n");
    m.push_str("Content-Transfer-Encoding: base64\r\n");
    m.push_str(&format!(
        "Content-Disposition: attachment;\r\n filename=\"{}\"\r\n\r\n",
        report.filename
    ));
    let b64 = STANDARD.encode(&report.gzip);
    for chunk in b64.as_bytes().chunks(76) {
        m.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        m.push_str("\r\n");
    }
    m.push_str(&format!("--{boundary}--\r\n"));
    m.into_bytes()
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use super::*;

    fn txt(records: &[&str]) -> Option<Vec<Rua>> {
        let r: Vec<Vec<u8>> = records.iter().map(|s| s.as_bytes().to_vec()).collect();
        parse_txt(&r)
    }

    fn https(host: &str, path: &str) -> Rua {
        Rua::Https {
            host: host.into(),
            path: path.into(),
        }
    }

    #[test]
    fn txt_records() {
        // RFC 8460 §3.1.1 and §3.1.2.
        assert_eq!(
            txt(&["v=TLSRPTv1;rua=mailto:reports@example.com"]),
            Some(vec![Rua::Mailto("reports@example.com".into())])
        );
        assert_eq!(
            txt(&["v=TLSRPTv1; rua=https://reporting.example.com/v1/tlsrpt"]),
            Some(vec![https("reporting.example.com", "/v1/tlsrpt")])
        );
        assert_eq!(
            txt(&[
                "v=spf1 -all",
                "v=TLSRPTv1; rua=mailto:a@example.com , https://r.example:443?x=1, ftp://x.example; ext=1;"
            ]),
            Some(vec![
                Rua::Mailto("a@example.com".into()),
                https("r.example", "/?x=1")
            ])
        );
        assert_eq!(
            txt(&["v=TLSRPTv1; rua=mailto:a%40b@example.com?subject=x"]),
            None,
            "an encoded @ makes a bad address"
        );
        for bad in [
            "v=TLSRPTv1;",
            "v=TLSRPTv1; ext=1",
            "v=TLSRPTv2; rua=mailto:a@example.com",
            "v=TLSRPTv1; rua=ftp://example.com/",
            "v=TLSRPTv1; rua=https://10.0.0.1/r",
            "v=TLSRPTv1; rua=https://[::1]/r",
            "v=TLSRPTv1; rua=https://r.example:8443/r",
            "v=TLSRPTv1; rua=https://user@r.example/r",
            "v=TLSRPTv1; rua=mailto:not-an-address",
            "v=TLSRPTv1; rua=mailto:a@[192.0.2.1]",
            "v=TLSRPTv1; rua=mailto:a@example.com; rua=mailto:b@example.com",
            "v=TLSRPTv1; rua=mailto:a@example.com; bad ext=1",
        ] {
            assert_eq!(txt(&[bad]), None, "{bad}");
        }
        assert_eq!(
            txt(&[
                "v=TLSRPTv1; rua=mailto:a@x.example",
                "v=TLSRPTv1; rua=mailto:b@x.example"
            ]),
            None,
            "two records"
        );
        let many = format!(
            "v=TLSRPTv1; rua={}",
            (0..10)
                .map(|i| format!("mailto:r{i}@example.com"))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(txt(&[&many]).unwrap().len(), MAX_RUA);
    }

    #[test]
    fn dates() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(day_of(951_782_400)), (2000, 2, 29));
        assert_eq!(civil(day_of(1_793_491_200)), (2026, 11, 1));
    }

    fn gunzip(b: &[u8]) -> Value {
        let mut s = String::new();
        flate2::read::GzDecoder::new(b)
            .read_to_string(&mut s)
            .unwrap();
        serde_json::from_str(&s).unwrap()
    }

    #[test]
    fn report_follows_the_schema() {
        let reporter = Reporter {
            organization: "Example Org".into(),
            contact: "tlsrpt@example.org".into(),
            hostname: "mx.example.org".into(),
        };
        let sts = Applied {
            kind: PolicyType::Sts,
            strings: vec!["version: STSv1".into(), "mode: testing".into()],
            mx: vec!["*.example.net".into()],
        }
        .to_json("example.net");
        let mut f = Failure::new("certificate-expired");
        f.sending_ip = Some("192.0.2.1".parse().unwrap());
        f.mx_host = Some("mx1.example.net".into());
        f.receiving_ip = Some("2001:db8::25".parse().unwrap());
        f.reason = Some("expired\r\ncertificate".into());
        let rows = vec![
            (sts.clone(), String::new(), 7),
            (sts, f.to_json(), 2),
            (Applied::none().to_json("example.net"), String::new(), 1),
        ];
        let day = day_of(1_793_491_200);
        let r = build(&reporter, day, "example.net", &rows).unwrap();
        assert_eq!(r.report_id, "20261101.example.net@mx.example.org");
        assert_eq!(
            r.filename,
            "example.org!example.net!1793491200!1793577599.json.gz"
        );
        let v = gunzip(&r.gzip);
        assert_eq!(v["organization-name"], "Example Org");
        assert_eq!(v["contact-info"], "tlsrpt@example.org");
        assert_eq!(v["date-range"]["start-datetime"], "2026-11-01T00:00:00Z");
        assert_eq!(v["date-range"]["end-datetime"], "2026-11-01T23:59:59Z");
        let policies = v["policies"].as_array().unwrap();
        assert_eq!(policies.len(), 2);
        let of_type = |t: &str| {
            policies
                .iter()
                .find(|p| p["policy"]["policy-type"] == t)
                .unwrap()
        };
        let none = of_type("no-policy-found");
        assert_eq!(none["summary"]["total-successful-session-count"], 1);
        assert!(none.get("failure-details").is_none());
        let p = of_type("sts");
        assert_eq!(p["policy"]["policy-string"][1], "mode: testing");
        assert_eq!(p["policy"]["mx-host"][0], "*.example.net");
        assert_eq!(p["summary"]["total-successful-session-count"], 7);
        assert_eq!(p["summary"]["total-failure-session-count"], 2);
        let d = &p["failure-details"][0];
        assert_eq!(d["result-type"], "certificate-expired");
        assert_eq!(d["sending-mta-ip"], "192.0.2.1");
        assert_eq!(d["receiving-ip"], "2001:db8::25");
        assert_eq!(d["receiving-mx-hostname"], "mx1.example.net");
        assert_eq!(d["failure-reason-code"], "expiredcertificate");
        assert_eq!(d["failed-session-count"], 2);

        let msg = message(
            &reporter,
            &r,
            &["rua@example.net".into()],
            "Mon, 2 Nov 2026 03:00:00 +0000",
        );
        let text = String::from_utf8(msg).unwrap();
        assert!(text.contains("\r\nTLS-Report-Domain: example.net\r\n"));
        assert!(text.contains("\r\nTLS-Report-Submitter: example.org\r\n"));
        assert!(text.contains("Subject: Report Domain: example.net\r\n Submitter: example.org\r\n Report-ID: <20261101.example.net@mx.example.org>\r\n"));
        assert!(text.contains("report-type=\"tlsrpt\""));
        assert!(text.contains("Content-Type: application/tlsrpt+gzip"));
        assert!(text.lines().all(|l| l.len() <= 998) && text.is_ascii());
        // The attachment decodes back to the report.
        let b64: String = text
            .split("filename=\"example.org!example.net!1793491200!1793577599.json.gz\"\r\n\r\n")
            .nth(1)
            .unwrap()
            .split("--")
            .next()
            .unwrap()
            .split_whitespace()
            .collect();
        assert_eq!(STANDARD.decode(b64).unwrap(), r.gzip);
    }

    #[test]
    fn tlsa_strings() {
        let t = dns::Tlsa {
            usage: 3,
            selector: 1,
            matching: 1,
            data: vec![0x1f, 0x85, 0x0a],
        };
        assert_eq!(tlsa_string(&t), "3 1 1 1F850A");
    }
}
