//! The configuration file: one TOML file, parsed strictly (unknown keys are
//! errors) and validated as a whole, so every problem is reported at once
//! with the path of the offending key. See `idly.example.toml`.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use smtp_proto::{Host, Mailbox, address::domain_to_ascii, limits};

/// The whole configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) server: Server,
    #[serde(default)]
    pub(crate) listen: Listen,
    #[serde(default)]
    pub(crate) limits: Limits,
    #[serde(default, rename = "domain")]
    pub(crate) domains: Vec<Domain>,
    #[serde(default, rename = "account")]
    pub(crate) accounts: Vec<Account>,
    #[serde(default)]
    pub(crate) tls: Option<Tls>,
    #[serde(default)]
    pub(crate) acme: Option<Acme>,
    #[serde(default)]
    pub(crate) mta_sts: MtaSts,
    #[serde(default)]
    pub(crate) test_mode: TestMode,
    #[serde(default)]
    pub(crate) tls_reporting: TlsReporting,
    #[serde(default)]
    pub(crate) log: Log,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Server {
    /// The server's fully qualified host name, used in EHLO and banners.
    pub(crate) hostname: String,
    /// Where queue, spool, Maildir and keys live. Must be absolute.
    pub(crate) data_dir: PathBuf,
    /// Public IP addresses, for PTR checks. Auto-detected when empty.
    #[allow(dead_code)] // read by the startup checks (milestone 9)
    #[serde(default)]
    pub(crate) public_ips: Vec<IpAddr>,
    /// Addresses outbound mail is sent from: at most one IPv4 and one IPv6,
    /// each with a PTR record naming `hostname`. When set, mail is only
    /// delivered over the families listed here. When empty, the system
    /// picks the source address and both families are used.
    #[serde(default)]
    pub(crate) outbound_ips: Vec<IpAddr>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Listen {
    /// Inbound SMTP (port 25).
    #[serde(default = "default_smtp")]
    pub(crate) smtp: Vec<SocketAddr>,
    /// Submission with STARTTLS (port 587).
    #[serde(default = "default_submission")]
    pub(crate) submission: Vec<SocketAddr>,
    /// Submission with implicit TLS (port 465).
    #[serde(default = "default_submissions")]
    pub(crate) submissions: Vec<SocketAddr>,
    /// Prometheus metrics endpoint; omit to disable.
    #[serde(default = "default_metrics")]
    pub(crate) metrics: Option<SocketAddr>,
}

impl Default for Listen {
    fn default() -> Self {
        Self {
            smtp: default_smtp(),
            submission: default_submission(),
            submissions: default_submissions(),
            metrics: default_metrics(),
        }
    }
}

fn addrs(list: &[&str]) -> Vec<SocketAddr> {
    list.iter().filter_map(|a| a.parse().ok()).collect()
}
fn default_smtp() -> Vec<SocketAddr> {
    addrs(&["0.0.0.0:25", "[::]:25"])
}
fn default_submission() -> Vec<SocketAddr> {
    addrs(&["0.0.0.0:587", "[::]:587"])
}
fn default_submissions() -> Vec<SocketAddr> {
    addrs(&["0.0.0.0:465", "[::]:465"])
}
fn default_metrics() -> Option<SocketAddr> {
    "127.0.0.1:9100".parse().ok()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Limits {
    /// Hard cap on a command line, CRLF included (policy, CLAUDE.md).
    #[serde(default = "default_command_line")]
    pub(crate) command_line: usize,
    /// Hard cap on an inbound DATA line, CRLF included (policy, CLAUDE.md).
    #[serde(default = "default_inbound_line")]
    pub(crate) inbound_line: usize,
    /// Maximum message size in octets, announced with SIZE (RFC 1870).
    #[serde(default = "default_message_size")]
    pub(crate) message_size: u64,
    /// Maximum RCPT commands per transaction.
    #[serde(default = "default_max_recipients")]
    pub(crate) max_recipients: usize,
    /// Refuse new mail (452 4.3.1) when the data directory's filesystem
    /// has fewer free bytes than this.
    #[serde(default = "default_min_free_space")]
    pub(crate) min_free_space: u64,
    /// Seconds to wait for the next command (RFC 5321 §4.5.3.2.7).
    #[serde(default = "default_command_timeout")]
    pub(crate) command_timeout: u64,
    /// Seconds to wait for more message data.
    #[serde(default = "default_data_timeout")]
    pub(crate) data_timeout: u64,
    /// Seconds a TLS handshake may take.
    #[serde(default = "default_tls_handshake_timeout")]
    pub(crate) tls_handshake_timeout: u64,
    /// Seconds a whole SMTP session may last.
    #[serde(default = "default_session_timeout")]
    pub(crate) session_timeout: u64,
    /// Simultaneous inbound connections (port 25).
    #[serde(default = "default_max_connections")]
    pub(crate) max_connections: usize,
    /// Simultaneous submission connections (587 and 465), a separate pool
    /// so a flood on port 25 can't lock users out.
    #[serde(default = "default_max_submission_connections")]
    pub(crate) max_submission_connections: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            command_line: default_command_line(),
            inbound_line: default_inbound_line(),
            message_size: default_message_size(),
            max_recipients: default_max_recipients(),
            min_free_space: default_min_free_space(),
            command_timeout: default_command_timeout(),
            data_timeout: default_data_timeout(),
            tls_handshake_timeout: default_tls_handshake_timeout(),
            session_timeout: default_session_timeout(),
            max_connections: default_max_connections(),
            max_submission_connections: default_max_submission_connections(),
        }
    }
}

fn default_command_line() -> usize {
    limits::DEFAULT_COMMAND_LINE_CAP
}
fn default_inbound_line() -> usize {
    limits::DEFAULT_INBOUND_TEXT_LINE_CAP
}
fn default_message_size() -> u64 {
    25 * 1024 * 1024
}
fn default_max_recipients() -> usize {
    100
}
fn default_min_free_space() -> u64 {
    1024 * 1024 * 1024
}
fn default_command_timeout() -> u64 {
    300
}
fn default_data_timeout() -> u64 {
    300
}
fn default_tls_handshake_timeout() -> u64 {
    30
}
fn default_session_timeout() -> u64 {
    30 * 60
}
fn default_max_connections() -> usize {
    100
}
fn default_max_submission_connections() -> usize {
    50
}

/// A TLS certificate from files managed outside Idly. The files are
/// re-read when they change, so a renewal needs no restart.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Tls {
    /// PEM certificate chain, leaf first.
    pub(crate) cert_file: PathBuf,
    /// PEM private key (PKCS #8, PKCS #1 or SEC1).
    pub(crate) key_file: PathBuf,
}

/// Certificates from an ACME CA (RFC 8555), as an alternative to [tls].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Acme {
    /// `letsencrypt`, `letsencrypt-staging`, or a directory URL (https).
    #[serde(default = "default_acme_directory")]
    pub(crate) directory: String,
    /// Given to the CA for expiry and problem notices.
    #[serde(default)]
    pub(crate) contact: Option<String>,
    /// Must be true: you have read and accept the CA's terms of service.
    #[serde(default)]
    pub(crate) accept_terms: bool,
    /// The HTTP-01 challenge server; the CA connects to port 80.
    #[serde(default = "default_http")]
    pub(crate) listen: Vec<SocketAddr>,
}

impl Acme {
    /// The directory URL, with the shortcuts expanded.
    pub(crate) fn directory_url(&self) -> &str {
        match self.directory.as_str() {
            "letsencrypt" => acme::LETS_ENCRYPT,
            "letsencrypt-staging" => acme::LETS_ENCRYPT_STAGING,
            url => url,
        }
    }
}

fn default_acme_directory() -> String {
    "letsencrypt".to_owned()
}
fn default_http() -> Vec<SocketAddr> {
    addrs(&["0.0.0.0:80", "[::]:80"])
}
fn default_https() -> Vec<SocketAddr> {
    addrs(&["0.0.0.0:443", "[::]:443"])
}

/// Publishing an MTA-STS policy (RFC 8461 §3.2) for every domain at
/// `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MtaSts {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) mode: StsMode,
    /// Seconds senders may cache the policy (RFC 8461 §3.2).
    #[serde(default = "default_max_age")]
    pub(crate) max_age: u64,
    #[serde(default = "default_https")]
    pub(crate) listen: Vec<SocketAddr>,
}

impl Default for MtaSts {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: StsMode::default(),
            max_age: default_max_age(),
            listen: default_https(),
        }
    }
}

fn default_max_age() -> u64 {
    7 * 86_400
}

/// RFC 8461 §5: the policy modes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum StsMode {
    /// Failures are reported (RFC 8460) but mail is still delivered.
    #[default]
    Testing,
    /// Senders deliver only over validated TLS to our host name.
    Enforce,
    /// Withdraws a published policy.
    None,
}

impl StsMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Testing => "testing",
            Self::Enforce => "enforce",
            Self::None => "none",
        }
    }
}

/// A domain this server receives and sends mail for.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Domain {
    pub(crate) name: String,
    /// Start even though this domain has no DKIM key, sending its mail
    /// unsigned. Off by default: unsigned mail fails DMARC at most
    /// receivers, so a missing key is normally a startup error.
    #[serde(default)]
    pub(crate) allow_unsigned: bool,
}

/// A mail account that can authenticate for submission.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Account {
    pub(crate) address: String,
    /// An Argon2id hash in PHC string format (`$argon2id$...`).
    pub(crate) password_hash: String,
}

/// Restricts outbound delivery to an allow-list of domains. It can only
/// restrict delivery, never redirect it (CLAUDE.md: no relays).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TestMode {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) allow_domains: Vec<String>,
}

/// Daily SMTP TLS reports (RFC 8460) to domains that ask for them.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TlsReporting {
    #[serde(default)]
    pub(crate) enabled: bool,
    /// The reports' contact address and the From of report mail. Its
    /// domain must be a [[domain]] with a DKIM key (RFC 8460 §3: report
    /// mail must be DKIM-signed by the reporting domain).
    #[serde(default)]
    pub(crate) from: Option<String>,
    /// The "organization-name" in reports (default: server.hostname).
    #[serde(default)]
    pub(crate) organization: Option<String>,
}

impl TlsReporting {
    /// The From address's domain (A-label), when reporting is on.
    pub(crate) fn report_domain(&self) -> Option<String> {
        let from = self.from.as_ref().filter(|_| self.enabled)?;
        let (_, domain) = from.rsplit_once('@')?;
        domain_ascii(domain)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Log {
    #[serde(default)]
    pub(crate) format: LogFormat,
    /// A tracing filter such as `info` or `info,smtp_server=debug`.
    #[serde(default = "default_log_level")]
    pub(crate) level: String,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            format: LogFormat::default(),
            level: default_log_level(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_owned()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum LogFormat {
    /// One JSON object per line (CLAUDE.md: logs are JSON).
    #[default]
    Json,
    /// Human-readable, for running in a terminal.
    Text,
}

/// One validation problem, located by its key path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Problem {
    pub(crate) path: String,
    pub(crate) message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// Why a configuration could not be loaded.
#[derive(Debug)]
pub(crate) enum LoadError {
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, String),
    Invalid(PathBuf, Vec<Problem>),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(p, e) => write!(f, "cannot read {}: {e}", p.display()),
            Self::Parse(p, e) => write!(f, "{}: {e}", p.display()),
            Self::Invalid(p, problems) => {
                write!(f, "{} has {} problem(s):", p.display(), problems.len())?;
                for problem in problems {
                    write!(f, "\n  - {problem}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for LoadError {}

impl Config {
    /// Reads, parses and validates a configuration file.
    pub(crate) fn load(path: &Path) -> Result<Self, LoadError> {
        let text = std::fs::read_to_string(path).map_err(|e| LoadError::Io(path.into(), e))?;
        let config = Self::parse(&text).map_err(|e| LoadError::Parse(path.into(), e))?;
        config
            .validate()
            .map_err(|p| LoadError::Invalid(path.into(), p))?;
        Ok(config)
    }

    /// Parses TOML without validating.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| e.to_string())
    }

    /// The names our certificate must cover: the host name, and
    /// `mta-sts.<domain>` for each domain when MTA-STS is published.
    pub(crate) fn certificate_names(&self) -> Vec<String> {
        let mut names: Vec<String> = domain_ascii(&self.server.hostname).into_iter().collect();
        if self.mta_sts.enabled {
            for d in &self.domains {
                if let Some(d) = domain_ascii(&d.name) {
                    let name = format!("mta-sts.{d}");
                    if !names.contains(&name) {
                        names.push(name);
                    }
                }
            }
        }
        names
    }

    /// Whether `domain` (any case, U-label or A-label) is one of ours.
    pub(crate) fn is_local_domain(&self, domain: &str) -> bool {
        let Ok(domain) = domain_to_ascii(domain) else {
            return false;
        };
        self.domains
            .iter()
            .any(|d| domain_to_ascii(&d.name).is_ok_and(|n| n == domain))
    }

    /// Checks everything that the types alone can't, returning every problem.
    pub(crate) fn validate(&self) -> Result<(), Vec<Problem>> {
        let mut p = Vec::new();
        let mut bad = |path: String, message: &str| {
            p.push(Problem {
                path,
                message: message.into(),
            })
        };

        if !is_fqdn(&self.server.hostname) {
            bad(
                "server.hostname".into(),
                "must be a fully qualified domain name, e.g. mx.example.org",
            );
        }
        if !self.server.data_dir.is_absolute() {
            bad("server.data_dir".into(), "must be an absolute path");
        }

        let v4 = self
            .server
            .outbound_ips
            .iter()
            .filter(|ip| ip.is_ipv4())
            .count();
        let v6 = self.server.outbound_ips.len() - v4;
        if v4 > 1 || v6 > 1 {
            bad(
                "server.outbound_ips".into(),
                "at most one IPv4 and one IPv6 address",
            );
        }
        for (i, ip) in self.server.outbound_ips.iter().enumerate() {
            if let Some(why) = smtp_client::guard::forbidden(*ip) {
                bad(
                    format!("server.outbound_ips[{i}]"),
                    &format!("{ip} is not a public address ({why})"),
                );
            }
        }

        if self.domains.is_empty() {
            bad("domain".into(), "at least one [[domain]] is required");
        }
        let mut seen = HashSet::new();
        for (i, d) in self.domains.iter().enumerate() {
            match domain_ascii(&d.name) {
                Some(ascii) if !seen.insert(ascii.clone()) => {
                    bad(format!("domain[{i}].name"), "duplicate domain");
                }
                Some(_) => {}
                None => bad(format!("domain[{i}].name"), "not a valid domain name"),
            }
        }

        if self.accounts.is_empty() {
            // RFC 5321 §4.5.1: mail to postmaster must be deliverable.
            bad(
                "account".into(),
                "at least one [[account]] is required (postmaster mail goes to it)",
            );
        }
        let mut seen = HashSet::new();
        for (i, a) in self.accounts.iter().enumerate() {
            match Mailbox::parse(&a.address) {
                Ok(m) => {
                    let local = match &m.host {
                        Host::Domain(d) => self.is_local_domain(d),
                        _ => false,
                    };
                    if !local {
                        bad(
                            format!("account[{i}].address"),
                            "domain is not one of the [[domain]] entries",
                        );
                    }
                    if !seen.insert(a.address.to_lowercase()) {
                        bad(format!("account[{i}].address"), "duplicate account");
                    }
                }
                Err(_) => bad(format!("account[{i}].address"), "not a valid email address"),
            }
            if !a.password_hash.starts_with("$argon2id$")
                || argon2::password_hash::phc::PasswordHash::new(&a.password_hash).is_err()
            {
                bad(
                    format!("account[{i}].password_hash"),
                    "must be an Argon2id PHC string ($argon2id$...); generate one with `idly user hash-password`",
                );
            }
        }

        let l = &self.limits;
        // RFC 5321 §4.5.3.1.4: command lines of 512 octets must be accepted.
        if !(limits::COMMAND_LINE..=64 * 1024).contains(&l.command_line) {
            bad(
                "limits.command_line".into(),
                "must be between 512 and 65536",
            );
        }
        // RFC 5321 §4.5.3.1.6: text lines of 1000 octets must be accepted.
        if !(limits::TEXT_LINE..=1024 * 1024).contains(&l.inbound_line) {
            bad(
                "limits.inbound_line".into(),
                "must be between 1000 and 1048576",
            );
        }
        // RFC 5321 §4.5.3.1.7: messages of at least 64K octets must be accepted.
        if l.message_size < 64 * 1024 {
            bad("limits.message_size".into(), "must be at least 65536");
        }
        // RFC 5321 §4.5.3.1.8: at least 100 recipients must be buffered.
        if l.max_recipients < 100 {
            bad("limits.max_recipients".into(), "must be at least 100");
        }
        // RFC 5321 §4.5.3.2.7: the server should wait at least 5 minutes.
        if l.command_timeout < 300 {
            bad(
                "limits.command_timeout".into(),
                "must be at least 300 seconds",
            );
        }
        // RFC 5321 §4.5.3.2.6: clients wait 10 minutes after DATA ends, and
        // send blocks within 3 minutes (§4.5.3.2.5).
        if l.data_timeout < 180 {
            bad("limits.data_timeout".into(), "must be at least 180 seconds");
        }
        if !(5..=300).contains(&l.tls_handshake_timeout) {
            bad(
                "limits.tls_handshake_timeout".into(),
                "must be between 5 and 300 seconds",
            );
        }
        if l.session_timeout < l.command_timeout.max(l.data_timeout) {
            bad(
                "limits.session_timeout".into(),
                "must be at least the command and data timeouts",
            );
        }
        if l.max_connections == 0 {
            bad("limits.max_connections".into(), "must be at least 1");
        }
        if l.max_submission_connections == 0 {
            bad(
                "limits.max_submission_connections".into(),
                "must be at least 1",
            );
        }

        if let Some(tls) = &self.tls {
            for (key, path) in [
                ("tls.cert_file", &tls.cert_file),
                ("tls.key_file", &tls.key_file),
            ] {
                if !path.is_absolute() {
                    bad(key.into(), "must be an absolute path");
                }
            }
        }

        if let Some(a) = &self.acme {
            if self.tls.is_some() {
                bad(
                    "acme".into(),
                    "use either [tls] certificate files or [acme], not both",
                );
            }
            if !a.accept_terms {
                bad(
                    "acme.accept_terms".into(),
                    "must be true: read the CA's terms of service first",
                );
            }
            let url = a.directory_url();
            let parsed = url.parse::<hyper::Uri>();
            if !url.starts_with("https://") || parsed.map_or(true, |u| u.host().is_none()) {
                bad(
                    "acme.directory".into(),
                    "must be letsencrypt, letsencrypt-staging or an https:// URL",
                );
            }
            if let Some(c) = &a.contact
                && Mailbox::parse(c).map_or(true, |m| !matches!(m.host, Host::Domain(_)))
            {
                bad("acme.contact".into(), "not a valid email address");
            }
            if a.listen.is_empty() {
                bad(
                    "acme.listen".into(),
                    "needs an address; the CA connects to port 80",
                );
            }
        }

        let sts = &self.mta_sts;
        if sts.enabled {
            if self.tls.is_none() && self.acme.is_none() {
                bad(
                    "mta_sts".into(),
                    "needs a certificate for mta-sts.<domain>: set up [acme] or [tls]",
                );
            }
            if sts.listen.is_empty() {
                bad("mta_sts.listen".into(), "needs an address (port 443)");
            }
        }
        // RFC 8461 §3.2: at most 31557600; a day at least, so senders
        // actually benefit from caching.
        if !(86_400..=31_557_600).contains(&sts.max_age) {
            bad(
                "mta_sts.max_age".into(),
                "must be between 86400 and 31557600 seconds",
            );
        }

        if self.test_mode.enabled && self.test_mode.allow_domains.is_empty() {
            bad(
                "test_mode.allow_domains".into(),
                "test mode needs at least one allowed domain",
            );
        }
        for (i, d) in self.test_mode.allow_domains.iter().enumerate() {
            if domain_ascii(d).is_none() {
                bad(
                    format!("test_mode.allow_domains[{i}]"),
                    "not a valid domain name",
                );
            }
        }

        let r = &self.tls_reporting;
        if r.enabled {
            match &r.from {
                None => bad(
                    "tls_reporting.from".into(),
                    "required when TLS reporting is enabled",
                ),
                Some(from) => match Mailbox::parse(from) {
                    Ok(m) if matches!(&m.host, Host::Domain(d) if self.is_local_domain(d)) => {}
                    Ok(_) => bad(
                        "tls_reporting.from".into(),
                        "domain is not one of the [[domain]] entries",
                    ),
                    Err(_) => bad("tls_reporting.from".into(), "not a valid email address"),
                },
            }
        }
        if r.organization.as_ref().is_some_and(|o| {
            o.trim().is_empty() || o.len() > 200 || o.chars().any(char::is_control)
        }) {
            bad(
                "tls_reporting.organization".into(),
                "must be a non-empty name of at most 200 characters",
            );
        }

        if tracing_subscriber::EnvFilter::try_new(&self.log.level).is_err() {
            bad(
                "log.level".into(),
                "not a valid log filter (try \"info\" or \"debug\")",
            );
        }

        if p.is_empty() { Ok(()) } else { Err(p) }
    }
}

impl Config {
    /// Extra rules for `idly serve --demo`: every listener must be on
    /// 127.0.0.1 exactly, so the demo can never be reached from outside.
    pub(crate) fn validate_demo(&self) -> Result<(), Vec<Problem>> {
        let loopback = |a: &SocketAddr| a.ip() == IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let mut p = Vec::new();
        if self.listen.smtp.is_empty() {
            p.push(Problem {
                path: "listen.smtp".into(),
                message: "demo mode needs a listener, e.g. [\"127.0.0.1:2525\"]".into(),
            });
        }
        for (i, a) in self.listen.smtp.iter().enumerate() {
            if !loopback(a) {
                p.push(Problem {
                    path: format!("listen.smtp[{i}]"),
                    message: format!("demo mode only listens on 127.0.0.1, not {a}"),
                });
            }
        }
        if let Some(a) = self.listen.metrics
            && !loopback(&a)
        {
            p.push(Problem {
                path: "listen.metrics".into(),
                message: format!("demo mode only listens on 127.0.0.1, not {a}"),
            });
        }
        if p.is_empty() { Ok(()) } else { Err(p) }
    }
}

/// The A-label form of a domain, if it is a valid domain name (no literals).
fn domain_ascii(name: &str) -> Option<String> {
    match Host::parse(name) {
        Ok(Host::Domain(d)) => domain_to_ascii(&d).ok(),
        _ => None,
    }
}

fn is_fqdn(name: &str) -> bool {
    domain_ascii(name).is_some_and(|d| d.contains('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [server]
        hostname = "mx.example.org"
        data_dir = "/var/lib/idly"

        [[domain]]
        name = "example.org"

        [[account]]
        address = "alice@example.org"
        password_hash = "$argon2id$v=19$m=19456,t=2,p=1$ZGVtb2RlbW9kZW1v$ZGVtby1vbmx5LW5vdC1hLXJlYWwtaGFzaA"
    "#;

    fn problems(text: &str) -> Vec<String> {
        match Config::parse(text).unwrap().validate() {
            Ok(()) => vec![],
            Err(p) => p.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let c = Config::parse(MINIMAL).unwrap();
        c.validate().unwrap();
        assert_eq!(c.limits.command_line, 4096);
        assert_eq!(c.limits.inbound_line, 65536);
        assert_eq!(c.listen.smtp.len(), 2);
        assert_eq!(c.listen.metrics, "127.0.0.1:9100".parse().ok());
        assert_eq!(c.log.format, LogFormat::Json);
        assert!(!c.test_mode.enabled);
    }

    #[test]
    fn example_config_is_valid() {
        let text = include_str!("../../../idly.example.toml");
        Config::parse(text).unwrap().validate().unwrap();
    }

    #[test]
    fn unknown_keys_rejected() {
        let e = Config::parse(&format!("{MINIMAL}\n[server2]\nx = 1\n")).unwrap_err();
        assert!(e.contains("server2"), "{e}");
        let e = Config::parse(&MINIMAL.replace("hostname", "hostnme")).unwrap_err();
        assert!(e.contains("hostnme"), "{e}");
    }

    #[test]
    fn no_relay_option_exists() {
        // CLAUDE.md hard constraint 1: there is no key that names a
        // delivery host. Any such attempt is an unknown key.
        for key in ["relay", "smarthost", "relayhost", "transport"] {
            let text = format!("{MINIMAL}\n[{key}]\nhost = \"smtp.example.com\"\n");
            assert!(Config::parse(&text).is_err(), "{key}");
        }
    }

    #[test]
    fn all_problems_reported_at_once() {
        let text = r#"
            [server]
            hostname = "localhost"
            data_dir = "relative/dir"

            [[domain]]
            name = "example.org"
            [[domain]]
            name = "EXAMPLE.org"
            [[domain]]
            name = "bad_domain"

            [[account]]
            address = "alice@other.example"
            password_hash = "plaintext"

            [limits]
            command_line = 100
            max_recipients = 10

            [test_mode]
            enabled = true
        "#;
        let p = problems(text);
        for expected in [
            "server.hostname",
            "server.data_dir",
            "domain[1].name: duplicate",
            "domain[2].name",
            "account[0].address: domain is not one",
            "account[0].password_hash",
            "limits.command_line",
            "limits.max_recipients",
            "test_mode.allow_domains",
        ] {
            assert!(
                p.iter()
                    .any(|x| x.starts_with(expected) || x.contains(expected)),
                "missing {expected} in {p:#?}"
            );
        }
        assert_eq!(p.len(), 9, "{p:#?}");
    }

    #[test]
    fn accounts_required() {
        let text = MINIMAL.split("[[account]]").next().unwrap();
        assert!(problems(text).iter().any(|p| p.starts_with("account:")));
    }

    #[test]
    fn demo_config_is_valid() {
        let c = Config::parse(include_str!("../../../idly.demo.toml")).unwrap();
        c.validate().unwrap();
        c.validate_demo().unwrap();
    }

    #[test]
    fn demo_refuses_non_loopback_binds() {
        let mut c = Config::parse(MINIMAL).unwrap();
        // Defaults listen on 0.0.0.0 and [::].
        let p = c.validate_demo().unwrap_err();
        assert_eq!(p.len(), 2, "{p:?}");
        for bad in [
            "0.0.0.0:2525",
            "[::1]:2525",
            "192.168.1.5:2525",
            "127.0.0.2:2525",
        ] {
            c.listen.smtp = vec![bad.parse().unwrap()];
            assert!(c.validate_demo().is_err(), "{bad}");
        }
        c.listen.smtp = vec!["127.0.0.1:2525".parse().unwrap()];
        c.validate_demo().unwrap();
        c.listen.metrics = Some("0.0.0.0:9100".parse().unwrap());
        assert!(c.validate_demo().is_err());
    }

    #[test]
    fn local_domains_match_any_case_and_idn_form() {
        let c = Config::parse(&MINIMAL.replace("example.org\"", "bücher.example\"")).unwrap();
        assert!(c.is_local_domain("BÜCHER.example"));
        assert!(c.is_local_domain("xn--bcher-kva.example"));
        assert!(!c.is_local_domain("example.org"));
    }

    #[test]
    fn tls_reporting_needs_a_local_from_address() {
        let on = |from: &str| format!("{MINIMAL}\n[tls_reporting]\nenabled = true\n{from}");
        assert_eq!(
            problems(&on("")),
            ["tls_reporting.from: required when TLS reporting is enabled"]
        );
        assert_eq!(
            problems(&on("from = \"tlsrpt@other.example\"")),
            ["tls_reporting.from: domain is not one of the [[domain]] entries"]
        );
        assert_eq!(
            problems(&on("from = \"nope\"")),
            ["tls_reporting.from: not a valid email address"]
        );
        let c = Config::parse(&on("from = \"tlsrpt@Example.ORG\"")).unwrap();
        c.validate().unwrap();
        assert_eq!(
            c.tls_reporting.report_domain().as_deref(),
            Some("example.org")
        );
        // Off by default, and then the address isn't needed.
        let c = Config::parse(MINIMAL).unwrap();
        assert!(!c.tls_reporting.enabled && c.tls_reporting.report_domain().is_none());
    }

    #[test]
    fn acme_and_mta_sts() {
        let acme = "[acme]\naccept_terms = true\ncontact = \"postmaster@example.org\"\n";
        let c = Config::parse(&format!("{MINIMAL}\n{acme}")).unwrap();
        c.validate().unwrap();
        let a = c.acme.as_ref().unwrap();
        assert_eq!(a.directory_url(), acme::LETS_ENCRYPT);
        assert_eq!(a.listen.len(), 2);
        assert_eq!(c.certificate_names(), ["mx.example.org"]);

        let sts = "[mta_sts]\nenabled = true\nmode = \"enforce\"\n";
        let c = Config::parse(&format!(
            "{MINIMAL}\n[[domain]]\nname = \"Example.NET\"\n{acme}{sts}"
        ))
        .unwrap();
        c.validate().unwrap();
        assert_eq!(c.mta_sts.mode, StsMode::Enforce);
        assert_eq!(c.mta_sts.max_age, 604_800);
        assert_eq!(
            c.certificate_names(),
            [
                "mx.example.org",
                "mta-sts.example.org",
                "mta-sts.example.net"
            ]
        );

        assert_eq!(
            problems(&format!("{MINIMAL}\n[acme]\n")),
            ["acme.accept_terms: must be true: read the CA's terms of service first"]
        );
        let p = problems(&format!(
            "{MINIMAL}\n[acme]\naccept_terms = true\ndirectory = \"http://ca.example/dir\"\ncontact = \"x\"\n"
        ));
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(p[0].starts_with("acme.directory") && p[1].starts_with("acme.contact"));
        let both =
            format!("{MINIMAL}\n{acme}[tls]\ncert_file = \"/c.pem\"\nkey_file = \"/k.pem\"\n");
        assert_eq!(
            problems(&both),
            ["acme: use either [tls] certificate files or [acme], not both"]
        );
        assert_eq!(
            problems(&format!("{MINIMAL}\n{sts}")),
            ["mta_sts: needs a certificate for mta-sts.<domain>: set up [acme] or [tls]"]
        );
        assert_eq!(
            problems(&format!("{MINIMAL}\n{acme}{sts}max_age = 60\n")),
            ["mta_sts.max_age: must be between 86400 and 31557600 seconds"]
        );
    }
}
