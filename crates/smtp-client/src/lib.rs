//! Direct-to-MX delivery (CLAUDE.md, hard constraint 1: no relays). For each
//! domain: MX lookup (RFC 5321 §5.1, RFC 7505), the TLS policy per host
//! (DANE, then MTA-STS, then opportunistic STARTTLS), and one SMTP
//! transaction carrying every recipient of that domain.
//!
//! Delivery targets come only from DNS; there is no relay setting. Every
//! connection goes through a [`Dialer`]; the production [`Direct`] dialer
//! refuses non-public addresses (see [`guard`]).

#![forbid(unsafe_code)]

pub mod dialer;
mod fetch;
pub mod guard;
pub mod mta_sts;
mod route;
pub mod session;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
mod tls;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dns::{Dnssec, Resolver, Tlsa};
use queue::{Clock, Outcome};
use rustls::RootCertStore;
use tokio::time::timeout;

pub use dialer::{Dialer, Direct};
pub use route::Families;
use route::{Host, Route, RouteError};
use session::{End, Tls, Transaction};

/// Connection attempts (addresses tried) per delivery.
const MAX_ATTEMPTS: usize = 5;
/// The `_mta-sts` TXT lookup.
const TXT_TIMEOUT: Duration = Duration::from_secs(10);

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
}

impl<R, D> std::fmt::Debug for Client<R, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("hostname", &self.config.hostname)
            .finish_non_exhaustive()
    }
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
        }
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
        let tx = Transaction {
            sender,
            recipients,
            message,
        };
        let sts = self.mta_sts(&domain).await;
        let enforce = sts.filter(|p| p.mode == mta_sts::Mode::Enforce);
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
            // RFC 8461 §4.1, §5: with an enforced policy, only listed MX hosts.
            if let Some(p) = &enforce
                && !p.mx.iter().any(|pat| mta_sts::mx_matches(pat, &host.name))
            {
                tracing::warn!(%domain, mx = %host.name, "MX host not allowed by the MTA-STS policy; skipping");
                last_error = format!(
                    "{} is not listed in the MTA-STS policy of {domain}",
                    host.name
                );
                only_refused = false;
                continue;
            }
            let policy = match self.tls_policy(&route, host, enforce.is_some()).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(%domain, mx = %host.name, error = %e, "skipping MX host");
                    last_error = e;
                    only_refused = false;
                    continue;
                }
            };
            let config = match tls::client_config(&policy, &self.config.roots) {
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
                match self.attempt(host, ip, tls, &tx, policy.label()).await {
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
                        match self.attempt(host, ip, Tls::Never, &tx, "none").await {
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
    ) -> Attempt {
        let addr = SocketAddr::new(ip, 25);
        let source = self.config.sources.for_ip(ip);
        let stream = match timeout(
            self.config.connect_timeout,
            self.dialer.connect(addr, source),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) if e.kind() == io::ErrorKind::PermissionDenied => {
                tracing::warn!(mx = %host.name, %ip, error = %e, "refusing to connect to a non-public address");
                return Attempt::Refused(format!("{}: {e}", host.name));
            }
            Ok(Err(e)) => return Attempt::Failed(format!("{} [{ip}]: {e}", host.name)),
            Err(_) => {
                return Attempt::Failed(format!("{} [{ip}]: connection timed out", host.name));
            }
        };
        match session::run(stream, &host.name, &self.config.hostname, tls, tx).await {
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
        }
    }

    /// The TLS policy for one MX host: DANE, then MTA-STS, then
    /// opportunistic (RFC 8461 §2: DANE takes precedence over MTA-STS).
    async fn tls_policy(
        &self,
        route: &Route,
        host: &Host,
        enforce: bool,
    ) -> Result<tls::Policy, String> {
        // RFC 7672 §2.2.1, §2.2.2: DANE needs a secure MX RRset and secure
        // address records; only then are TLSA records looked up.
        if route.mx_secure && host.addrs_secure {
            match self.resolver.tlsa(&format!("_25._tcp.{}", host.name)).await {
                Ok(a) if a.dnssec == Dnssec::Secure && !a.records.is_empty() => {
                    let usable: Vec<Tlsa> = a.records.into_iter().filter(tls::usable).collect();
                    // RFC 7672 §2.2: TLSA records that are all unusable still
                    // make TLS mandatory, just unauthenticated.
                    return Ok(if usable.is_empty() {
                        tls::Policy::EncryptOnly
                    } else {
                        tls::Policy::Dane(usable)
                    });
                }
                Ok(_) => {}
                Err(e) if e.is_not_found() => {}
                // A secure host whose TLSA lookup fails can't be used safely now.
                Err(e) => return Err(format!("TLSA lookup for {}: {e}", host.name)),
            }
        }
        Ok(if enforce {
            tls::Policy::WebPki
        } else {
            tls::Policy::Opportunistic
        })
    }

    /// The MTA-STS policy of `domain`, from the cache or fetched
    /// (RFC 8461 §5.1).
    async fn mta_sts(&self, domain: &str) -> Option<mta_sts::Policy> {
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
                match fetch::fetch(
                    &self.resolver,
                    &self.dialer,
                    &self.config.roots,
                    self.config.families,
                    self.config.sources,
                    domain,
                )
                .await
                {
                    Ok(p) => {
                        tracing::info!(%domain, %id, mode = ?p.mode, "MTA-STS policy fetched");
                        self.sts.store(domain, &id, p.clone(), now);
                        Some(p)
                    }
                    Err(e) => {
                        tracing::warn!(%domain, %id, error = %e, "MTA-STS policy fetch failed");
                        self.sts.failed(domain, &id, now);
                        fallback
                    }
                }
            }
        }
    }
}

impl<R: Resolver + 'static, D: Dialer> queue::Connector for Client<R, D> {
    fn deliver(
        &self,
        domain: &str,
        sender: Option<&str>,
        recipients: &[String],
        message: &[u8],
    ) -> impl std::future::Future<Output = Vec<Outcome>> + Send {
        self.deliver_to(domain, sender, recipients, message)
    }
}
