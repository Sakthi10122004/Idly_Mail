//! Direct-to-MX delivery (CLAUDE.md, hard constraint 1: no relays). For each
//! domain: MX lookup (RFC 5321 §5.1, RFC 7505), the TLS policy per host
//! (DANE, then MTA-STS, then opportunistic STARTTLS), and one SMTP
//! transaction carrying every recipient of that domain.
//!
//! Delivery targets come only from DNS; there is no relay setting. Every
//! connection goes through a [`Dialer`]; the production [`Direct`] dialer
//! refuses non-public addresses (see [`guard`]).
//!
//! With a [`State`] attached, MTA-STS policies survive restarts, and with
//! `tls_reporting` on, every session's TLS result is counted for the daily
//! TLS reports (RFC 8460), sent by [`Client::send_tls_reports`].

#![forbid(unsafe_code)]

pub mod dialer;
mod fetch;
pub mod guard;
pub mod mta_sts;
mod route;
pub mod session;
pub mod state;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
mod tls;
pub mod tlsrpt;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dns::{Dnssec, Resolver, Tlsa};
use queue::{Clock, Kind, Outcome};
use rustls::RootCertStore;
use tokio::time::timeout;

pub use dialer::{Dialer, Direct};
pub use route::Families;
use route::{Host, Route, RouteError};
use session::{End, Tls, TlsSeen, Transaction};
pub use state::State;
use tlsrpt::{Applied, Failure, PolicyType, Reporter, Rua};

/// Connection attempts (addresses tried) per delivery.
const MAX_ATTEMPTS: usize = 5;
/// The `_mta-sts` and `_smtp._tls` TXT lookups.
const TXT_TIMEOUT: Duration = Duration::from_secs(10);
/// RFC 8460 §5.5: report uploads are retried for up to 24 hours, with
/// exponential back-off starting here.
const UPLOAD_RETRY: u64 = 300;
const UPLOAD_GIVE_UP: u64 = 86_400;
/// Results older than this many days are dropped unreported (the server
/// was down, or the policy domain's DNS kept failing).
const MAX_REPORT_AGE_DAYS: u64 = 3;

/// The local addresses outbound connections come from: one per family,
/// each with a PTR record naming our host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sources {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

impl Sources {
    /// The source address for a connection to `ip`.
    pub fn for_ip(&self, ip: IpAddr) -> Option<IpAddr> {
        match ip {
            IpAddr::V4(_) => self.ipv4.map(IpAddr::V4),
            IpAddr::V6(_) => self.ipv6.map(IpAddr::V6),
        }
    }
}

/// Settings for outbound delivery.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Our host name, sent with EHLO.
    pub hostname: String,
    pub sources: Sources,
    /// Which address families to deliver over.
    pub families: Families,
    /// Test mode: deliver only to these domains (lower-case A-labels).
    pub test_mode_allow: Option<Vec<String>>,
    /// Trusted CAs for MTA-STS (the system's roots in production).
    pub roots: Arc<RootCertStore>,
    /// How long to wait for a TCP connection.
    pub connect_timeout: Duration,
    /// Count TLS results for TLS reports (RFC 8460); needs a [`State`].
    pub tls_reporting: bool,
}

impl ClientConfig {
    /// Both families, no source binding, 30-second connects.
    pub fn new(hostname: &str, roots: Arc<RootCertStore>) -> Self {
        Self {
            hostname: hostname.to_owned(),
            sources: Sources::default(),
            families: Families {
                ipv4: true,
                ipv6: true,
            },
            test_mode_allow: None,
            roots,
            connect_timeout: Duration::from_secs(30),
            tls_reporting: false,
        }
    }
}

/// The operating system's trusted root certificates, for MTA-STS.
pub fn system_roots() -> Result<RootCertStore, String> {
    let found = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(found.certs);
    if added == 0 {
        return Err(match found.errors.first() {
            Some(e) => format!("no trusted root certificates found: {e}"),
            None => "no trusted root certificates found".into(),
        });
    }
    Ok(roots)
}

/// Delivers mail directly to each domain's MX hosts.
pub struct Client<R, D> {
    config: ClientConfig,
    resolver: R,
    dialer: D,
    sts: mta_sts::Cache,
    clock: Arc<dyn Clock>,
    state: Option<Arc<State>>,
}

impl<R, D> std::fmt::Debug for Client<R, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("hostname", &self.config.hostname)
            .finish_non_exhaustive()
    }
}

/// What one connection attempt saw: the result, TLS, and our address.
struct Tried {
    attempt: Attempt,
    tls: TlsSeen,
    local: Option<IpAddr>,
}

/// The result of one connection attempt.
enum Attempt {
    Done(Vec<Outcome>),
    /// The guard refused the address: a permanent failure for this host.
    Refused(String),
    Failed(String),
    TlsFailed(String),
}

impl<R: Resolver, D: Dialer> Client<R, D> {
    pub fn new(config: ClientConfig, resolver: R, dialer: D, clock: Arc<dyn Clock>) -> Self {
        Self {
            config,
            resolver,
            dialer,
            sts: mta_sts::Cache::new(),
            clock,
            state: None,
        }
    }

    /// Keeps MTA-STS policies (and TLS report data) in `state`, and loads
    /// the policies saved there that are still valid.
    pub fn with_state(mut self, state: Arc<State>) -> Self {
        let now = self.clock.now();
        match state.policies() {
            Ok(saved) => {
                for (domain, id, text, fetched) in saved {
                    if let Some(p) = mta_sts::parse_policy(&text) {
                        self.sts.restore(&domain, &id, p, fetched, now);
                    }
                }
            }
            Err(e) => tracing::error!(error = %e, "cannot read saved MTA-STS policies"),
        }
        // Policies live at most a year (RFC 8461 §3.2).
        if let Err(e) = state.forget_policies(now.saturating_sub(31_557_600)) {
            tracing::warn!(error = %e, "cannot clean up saved MTA-STS policies");
        }
        self.state = Some(state);
        self
    }

    /// Runs `f` on the state database off the async threads.
    async fn with_db<T: Send + 'static>(
        &self,
        f: impl FnOnce(&State) -> rusqlite::Result<T> + Send + 'static,
    ) -> Option<T> {
        let state = self.state.clone()?;
        match tokio::task::spawn_blocking(move || f(&state)).await {
            Ok(Ok(v)) => Some(v),
            Ok(Err(e)) => {
                tracing::error!(error = %e, "outbound state database error");
                None
            }
            Err(_) => None,
        }
    }

    /// Counts one session for `domain`'s TLS report.
    async fn note(&self, report: bool, domain: &str, applied: &Applied, result: Option<Failure>) {
        if !report {
            return;
        }
        let day = tlsrpt::day_of(self.clock.now());
        let domain = domain.to_owned();
        let policy = applied.to_json(&domain);
        let failure = result.map(|f| f.to_json()).unwrap_or_default();
        self.with_db(move |s| s.count(day, &domain, &policy, &failure))
            .await;
    }

    /// The resolver (for inspection in tests).
    pub fn resolver(&self) -> &R {
        &self.resolver
    }

    /// The dialer (for inspection in tests).
    pub fn dialer(&self) -> &D {
        &self.dialer
    }

    /// Delivers `message` to `recipients`, all at `domain`, in one
    /// transaction. Returns one outcome per recipient, in order.
    pub async fn deliver_to(
        &self,
        domain: &str,
        sender: Option<&str>,
        recipients: &[String],
        message: &[u8],
    ) -> Vec<Outcome> {
        self.deliver_kind(domain, sender, recipients, message, Kind::Mail)
            .await
    }

    /// Like [`Client::deliver_to`], for a message of a given kind. A TLS
    /// report is delivered despite TLS policy failures, opportunistically,
    /// and isn't counted in the next report (RFC 8460 §3, §5.3).
    pub async fn deliver_kind(
        &self,
        domain: &str,
        sender: Option<&str>,
        recipients: &[String],
        message: &[u8],
        kind: Kind,
    ) -> Vec<Outcome> {
        let n = recipients.len();
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        // Test mode, checked before any DNS query or connection. The queue
        // checks it first too; this is the second line of defence.
        if let Some(allow) = &self.config.test_mode_allow
            && !allow.iter().any(|d| d.eq_ignore_ascii_case(&domain))
        {
            tracing::error!(%domain, "test mode: not delivering to a domain outside the allow-list");
            return vec![Outcome::Temporary("held: test mode".into()); n];
        }
        let relaxed = kind == Kind::TlsReport;
        let report = self.config.tls_reporting && self.state.is_some() && !relaxed;
        let tx = Transaction {
            sender,
            recipients,
            message,
        };
        let sts = if relaxed {
            None
        } else {
            self.mta_sts(&domain, report).await
        };
        let sts = sts.filter(|p| p.mode != mta_sts::Mode::None);
        let enforce = sts
            .as_ref()
            .is_some_and(|p| p.mode == mta_sts::Mode::Enforce);
        let route = match route::route(&self.resolver, &domain, self.config.families).await {
            Ok(r) => r,
            Err(RouteError::Permanent { status, diagnostic }) => {
                tracing::info!(%domain, %diagnostic, "undeliverable domain");
                let o = Outcome::Permanent {
                    status: status.to_owned(),
                    diagnostic,
                };
                return vec![o; n];
            }
            Err(RouteError::Temporary(e)) => {
                tracing::warn!(%domain, error = %e, "cannot find MX hosts; will retry");
                return vec![Outcome::Temporary(e); n];
            }
        };

        let mut last_error = String::from("no MX host could be tried");
        let mut attempts = 0usize;
        let mut only_refused = true;
        'hosts: for host in &route.hosts {
            // RFC 8461 §4.1, §5: with an enforced policy, only listed MX
            // hosts; in testing mode the mismatch is only reported.
            if let Some(p) = &sts
                && !p.mx.iter().any(|pat| mta_sts::mx_matches(pat, &host.name))
            {
                let mut f = Failure::new("validation-failure");
                f.mx_host = Some(host.name.clone());
                f.reason = Some("MX host not listed in the MTA-STS policy".into());
                self.note(report, &domain, &sts_applied(p), Some(f)).await;
                if enforce {
                    tracing::warn!(%domain, mx = %host.name, "MX host not allowed by the MTA-STS policy; skipping");
                    last_error = format!(
                        "{} is not listed in the MTA-STS policy of {domain}",
                        host.name
                    );
                    only_refused = false;
                    continue;
                }
            }
            let (policy, applied) = if relaxed {
                (tls::Policy::Opportunistic, Applied::none())
            } else {
                match self.tls_policy(&route, host, sts.as_ref()).await {
                    Ok(p) => p,
                    Err((e, failure)) => {
                        if let Some(b) = failure {
                            let (applied, f) = *b;
                            self.note(report, &domain, &applied, Some(f)).await;
                        }
                        tracing::warn!(%domain, mx = %host.name, error = %e, "skipping MX host");
                        last_error = e;
                        only_refused = false;
                        continue;
                    }
                }
            };
            let (config, witness) = match tls::client_config(&policy, &self.config.roots) {
                Ok(c) => c,
                Err(e) => {
                    last_error = format!("TLS setup: {e}");
                    only_refused = false;
                    continue;
                }
            };
            for &ip in &host.addrs {
                if attempts >= MAX_ATTEMPTS {
                    break 'hosts;
                }
                attempts += 1;
                let tls = if policy.required() {
                    Tls::Required(config.clone())
                } else {
                    Tls::Opportunistic(config.clone())
                };
                let tried = self.attempt(host, ip, tls, &tx, policy.label()).await;
                if report {
                    let result = session_result(&tried, &policy, witness.take());
                    if let Some(result) = result {
                        let failure = result.err().map(|mut f| {
                            f.sending_ip = tried.local;
                            f.mx_host = Some(host.name.clone());
                            f.receiving_ip = Some(ip);
                            f
                        });
                        self.note(report, &domain, &applied, failure).await;
                    }
                }
                match tried.attempt {
                    Attempt::Done(outcomes) => return outcomes,
                    Attempt::Refused(e) => last_error = e,
                    Attempt::Failed(e) => {
                        only_refused = false;
                        last_error = e;
                    }
                    Attempt::TlsFailed(e) => {
                        // RFC 7435: opportunistic TLS that fails may fall back to
                        // plaintext. Retry this address once without STARTTLS.
                        tracing::info!(%domain, mx = %host.name, %ip, error = %e, "opportunistic TLS failed; retrying without TLS");
                        only_refused = false;
                        match self
                            .attempt(host, ip, Tls::Never, &tx, "none")
                            .await
                            .attempt
                        {
                            Attempt::Done(outcomes) => return outcomes,
                            Attempt::Refused(e) | Attempt::Failed(e) | Attempt::TlsFailed(e) => {
                                last_error = e;
                            }
                        }
                    }
                }
            }
        }
        if only_refused && attempts > 0 {
            // Every address was refused by the guard: retrying won't help.
            let o = Outcome::Permanent {
                status: "5.4.4".into(),
                diagnostic: format!(
                    "every MX address of {domain} is a non-public address ({last_error})"
                ),
            };
            return vec![o; n];
        }
        tracing::warn!(%domain, error = %last_error, "delivery failed; will retry");
        vec![Outcome::Temporary(last_error); n]
    }

    async fn attempt(
        &self,
        host: &Host,
        ip: IpAddr,
        tls: Tls,
        tx: &Transaction<'_>,
        label: &str,
    ) -> Tried {
        let addr = SocketAddr::new(ip, 25);
        let source = self.config.sources.for_ip(ip);
        let failed = |attempt| Tried {
            attempt,
            tls: TlsSeen::NotTried,
            local: None,
        };
        let stream = match timeout(
            self.config.connect_timeout,
            self.dialer.connect(addr, source),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) if e.kind() == io::ErrorKind::PermissionDenied => {
                tracing::warn!(mx = %host.name, %ip, error = %e, "refusing to connect to a non-public address");
                return failed(Attempt::Refused(format!("{}: {e}", host.name)));
            }
            Ok(Err(e)) => return failed(Attempt::Failed(format!("{} [{ip}]: {e}", host.name))),
            Err(_) => {
                return failed(Attempt::Failed(format!(
                    "{} [{ip}]: connection timed out",
                    host.name
                )));
            }
        };
        let local = stream.local_addr().ok().map(|a| a.ip());
        let (end, seen) = session::run(stream, &host.name, &self.config.hostname, tls, tx).await;
        let attempt = match end {
            End::Done(outcomes) => {
                let delivered = outcomes
                    .iter()
                    .filter(|o| **o == Outcome::Delivered)
                    .count();
                tracing::info!(mx = %host.name, %ip, tls = label, delivered, recipients = outcomes.len(), "SMTP transaction finished");
                Attempt::Done(outcomes)
            }
            End::HostFailed(e) => Attempt::Failed(format!("{} [{ip}]: {e}", host.name)),
            End::TlsFailed(e) => Attempt::TlsFailed(format!("{} [{ip}]: {e}", host.name)),
        };
        Tried {
            attempt,
            tls: seen,
            local,
        }
    }

    /// The TLS policy for one MX host, and the policy to report it under:
    /// DANE, then MTA-STS, then opportunistic (RFC 8461 §2: DANE takes
    /// precedence over MTA-STS). `sts` is an enforce or testing policy.
    #[allow(clippy::type_complexity)]
    async fn tls_policy(
        &self,
        route: &Route,
        host: &Host,
        sts: Option<&mta_sts::Policy>,
    ) -> Result<(tls::Policy, Applied), (String, Option<Box<(Applied, Failure)>>)> {
        // RFC 7672 §2.2.1, §2.2.2: DANE needs a secure MX RRset and secure
        // address records; only then are TLSA records looked up.
        if route.mx_secure && host.addrs_secure {
            let tlsa_applied = |records: &[Tlsa]| Applied {
                kind: PolicyType::Tlsa,
                strings: records.iter().map(tlsrpt::tlsa_string).collect(),
                mx: vec![host.name.clone()],
            };
            match self.resolver.tlsa(&format!("_25._tcp.{}", host.name)).await {
                Ok(a) if a.dnssec == Dnssec::Secure && !a.records.is_empty() => {
                    let applied = tlsa_applied(&a.records);
                    let usable: Vec<Tlsa> = a.records.into_iter().filter(tls::usable).collect();
                    // RFC 7672 §2.2: TLSA records that are all unusable still
                    // make TLS mandatory, just unauthenticated.
                    let policy = if usable.is_empty() {
                        tls::Policy::EncryptOnly
                    } else {
                        tls::Policy::Dane(usable)
                    };
                    return Ok((policy, applied));
                }
                Ok(_) => {}
                Err(e) if e.is_not_found() => {}
                // A secure host whose TLSA lookup fails can't be used safely now.
                Err(e) => {
                    let failure = (e == dns::Error::Bogus).then(|| {
                        let mut f = Failure::new("dnssec-invalid");
                        f.mx_host = Some(host.name.clone());
                        Box::new((tlsa_applied(&[]), f))
                    });
                    return Err((format!("TLSA lookup for {}: {e}", host.name), failure));
                }
            }
        }
        Ok(match sts {
            Some(p) if p.mode == mta_sts::Mode::Enforce => (tls::Policy::WebPki, sts_applied(p)),
            Some(p) => (tls::Policy::StsTesting, sts_applied(p)),
            None => (tls::Policy::Opportunistic, Applied::none()),
        })
    }

    /// The MTA-STS policy of `domain`, from the cache or fetched
    /// (RFC 8461 §5.1). A failed fetch is counted for the TLS report.
    async fn mta_sts(&self, domain: &str, report: bool) -> Option<mta_sts::Policy> {
        let now = self.clock.now();
        let txt = timeout(
            TXT_TIMEOUT,
            self.resolver.txt(&format!("_mta-sts.{domain}")),
        )
        .await;
        let id = match txt {
            Ok(Ok(a)) => mta_sts::parse_txt(&a.records),
            _ => None,
        };
        match self.sts.decide(domain, id.as_deref(), now) {
            mta_sts::Decision::Use(p) => p,
            mta_sts::Decision::Fetch { id, fallback } => {
                match fetch::fetch(self.net(), domain).await {
                    Ok(p) => {
                        tracing::info!(%domain, %id, mode = ?p.mode, "MTA-STS policy fetched");
                        self.sts.store(domain, &id, p.clone(), now);
                        let (d, i, text) = (domain.to_owned(), id.clone(), p.lines.join("\n"));
                        self.with_db(move |s| s.save_policy(&d, &i, &text, now))
                            .await;
                        Some(p)
                    }
                    Err(e) => {
                        tracing::warn!(%domain, %id, error = %e, "MTA-STS policy fetch failed");
                        self.sts.failed(domain, &id, now);
                        let applied = Applied {
                            kind: PolicyType::Sts,
                            strings: Vec::new(),
                            mx: Vec::new(),
                        };
                        let mut f = Failure::new(e.result_type);
                        f.reason = Some(e.detail);
                        self.note(report, domain, &applied, Some(f)).await;
                        fallback
                    }
                }
            }
        }
    }

    fn net(&self) -> fetch::Net<'_, R, D> {
        fetch::Net {
            resolver: &self.resolver,
            dialer: &self.dialer,
            roots: &self.config.roots,
            families: self.config.families,
            sources: self.config.sources,
        }
    }

    /// Sends the TLS reports that are due (RFC 8460 §4.1: each covers one
    /// UTC day and goes out a few hours after it ends), and retries failed
    /// uploads. `mail` signs and queues a report email: (recipients,
    /// message). Call it periodically; it does nothing without a [`State`].
    pub async fn send_tls_reports(
        &self,
        reporter: &Reporter,
        mail: impl Fn(Vec<String>, Vec<u8>) -> Result<(), String>,
    ) {
        if self.state.is_none() {
            return;
        }
        let now = self.clock.now();
        let today = tlsrpt::day_of(now);
        let keys = self
            .with_db(move |s| s.report_keys_before(today))
            .await
            .unwrap_or_default();
        for (day, domain) in keys {
            let forget = |d: String| self.with_db(move |s| s.forget_results(day, &d));
            if day.saturating_add(MAX_REPORT_AGE_DAYS) < today {
                tracing::warn!(%domain, day, "dropping an old unsent TLS report");
                forget(domain).await;
                continue;
            }
            // RFC 8460 §4.1: a delay of up to four hours after the day.
            let due = day
                .saturating_add(1)
                .saturating_mul(86_400)
                .saturating_add(report_delay(day, &self.config.hostname));
            if now < due {
                continue;
            }
            let txt = timeout(
                TXT_TIMEOUT,
                self.resolver.txt(&format!("_smtp._tls.{domain}")),
            )
            .await;
            let destinations = match txt {
                Ok(Ok(a)) => tlsrpt::parse_txt(&a.records),
                Ok(Err(e)) if e.is_not_found() => None,
                // DNS trouble: try again on the next pass.
                _ => continue,
            };
            let Some(destinations) = destinations else {
                // The domain doesn't want reports.
                forget(domain).await;
                continue;
            };
            let d = domain.clone();
            let rows = self
                .with_db(move |s| s.results(day, &d))
                .await
                .unwrap_or_default();
            let Some(report) = tlsrpt::build(reporter, day, &domain, &rows) else {
                tracing::error!(%domain, "cannot build TLS report");
                forget(domain).await;
                continue;
            };
            let mailto: Vec<String> = destinations
                .iter()
                .filter_map(|r| match r {
                    Rua::Mailto(a) => Some(a.clone()),
                    Rua::Https { .. } => None,
                })
                .collect();
            if !mailto.is_empty() {
                let date =
                    smtp_proto::date::rfc5322(std::time::UNIX_EPOCH + Duration::from_secs(now));
                let message = tlsrpt::message(reporter, &report, &mailto, &date);
                if let Err(e) = mail(mailto, message) {
                    // Not queued (e.g. the disk is full): next pass.
                    tracing::warn!(%domain, error = %e, "cannot queue TLS report");
                    continue;
                }
            }
            for r in &destinations {
                if let Rua::Https { host, path } = r {
                    self.upload(host, path, &report.gzip, now, None).await;
                }
            }
            tracing::info!(%domain, report_id = %report.report_id, destinations = destinations.len(), "TLS report sent");
            forget(domain).await;
        }
        let retries = self
            .with_db(move |s| s.due_uploads(now))
            .await
            .unwrap_or_default();
        for up in retries {
            let id = up.id;
            if now >= up.created.saturating_add(UPLOAD_GIVE_UP) {
                tracing::warn!(host = %up.host, "giving up on a TLS report upload");
                self.with_db(move |s| s.remove_upload(id)).await;
                continue;
            }
            self.upload(&up.host, &up.path, &up.body, now, Some(&up))
                .await;
        }
    }

    /// POSTs a report (RFC 8460 §5.4); a failure is kept for a retry.
    async fn upload(
        &self,
        host: &str,
        path: &str,
        body: &[u8],
        now: u64,
        retry: Option<&state::Upload>,
    ) {
        let r = fetch::post(
            self.net(),
            host,
            path,
            "application/tlsrpt+gzip",
            body.to_vec(),
        )
        .await;
        match (r, retry) {
            (Ok(()), None) => {}
            (Ok(()), Some(up)) => {
                let id = up.id;
                self.with_db(move |s| s.remove_upload(id)).await;
            }
            (Err(e), None) => {
                tracing::warn!(%host, error = %e, "TLS report upload failed; will retry");
                let (h, p, b) = (host.to_owned(), path.to_owned(), body.to_vec());
                self.with_db(move |s| {
                    s.add_upload(&h, &p, &b, now, now.saturating_add(UPLOAD_RETRY))
                })
                .await;
            }
            (Err(e), Some(up)) => {
                tracing::warn!(%host, error = %e, tries = up.tries, "TLS report upload failed again");
                // Exponential back-off (RFC 8460 §5.5).
                let wait = UPLOAD_RETRY.saturating_mul(1u64 << up.tries.min(8));
                let id = up.id;
                self.with_db(move |s| s.retry_upload(id, now.saturating_add(wait)))
                    .await;
            }
        }
    }
}

/// The report entry for an MTA-STS policy (RFC 8460 §4.5).
fn sts_applied(p: &mta_sts::Policy) -> Applied {
    Applied {
        kind: PolicyType::Sts,
        strings: p.lines.clone(),
        mx: p.mx.clone(),
    }
}

/// How a session counts in the TLS report: None if it doesn't (no TLS
/// attempt, or transient trouble), Ok for a success.
fn session_result(
    tried: &Tried,
    policy: &tls::Policy,
    let_through: Option<rustls::Error>,
) -> Option<Result<(), Failure>> {
    let failure = |result_type, reason: Option<String>| {
        let mut f = Failure::new(result_type);
        f.reason = reason;
        Some(Err(f))
    };
    match &tried.tls {
        TlsSeen::NotTried => None,
        TlsSeen::NotOffered => failure("starttls-not-supported", None),
        TlsSeen::Refused(reply) => failure("starttls-not-supported", Some(reply.clone())),
        TlsSeen::Failed {
            result_type,
            reason,
        } => failure(result_type, Some(reason.clone())),
        TlsSeen::Established => match (let_through, policy) {
            (Some(e), _) => failure(tls::result_type(&e), Some(e.to_string())),
            (None, tls::Policy::EncryptOnly) => failure(
                "tlsa-invalid",
                Some("no usable TLSA record; encrypted without authentication".into()),
            ),
            (None, _) => Some(Ok(())),
        },
    }
}

/// When a day's reports go out: 1 s to 4 h after midnight UTC (RFC 8460
/// §4.1), different per host and day, so reporters don't all send at once.
fn report_delay(day: u64, hostname: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::hash::DefaultHasher::new();
    (day, hostname).hash(&mut h);
    1 + h.finish() % 14_400
}

impl<R: Resolver + 'static, D: Dialer> queue::Connector for Client<R, D> {
    fn deliver(
        &self,
        domain: &str,
        sender: Option<&str>,
        recipients: &[String],
        message: &[u8],
        kind: Kind,
    ) -> impl std::future::Future<Output = Vec<Outcome>> + Send {
        self.deliver_kind(domain, sender, recipients, message, kind)
    }
}
