//! SPF: the check_host() function of RFC 7208.

mod macros;
pub mod record;

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

use dns::Resolver;

use record::{Directive, Mechanism, Qualifier, Record, is_spf_record};

/// The result of an SPF check (RFC 7208 §2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfResult {
    /// No SPF record, or no usable domain.
    None,
    /// The domain makes no assertion about this client.
    Neutral,
    /// The client is authorized.
    Pass,
    /// The client is not authorized.
    Fail,
    /// The client is probably not authorized.
    SoftFail,
    /// A transient DNS error.
    TempError,
    /// The record is broken, or a limit was exceeded.
    PermError,
}

impl SpfResult {
    /// The name used in Received-SPF and Authentication-Results.
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Neutral => "neutral",
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::SoftFail => "softfail",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
        }
    }
}

/// RFC 7208 §4.6.4: at most 10 terms that cause DNS queries.
const MAX_DNS_TERMS: u32 = 10;
/// RFC 7208 §4.6.4: void lookups SHOULD be limited to two.
const MAX_VOID_LOOKUPS: u32 = 2;
/// RFC 7208 §4.6.4: at most 10 MX records, and 10 address lookups per
/// MX or PTR evaluation.
const MAX_MX_OR_PTR: usize = 10;
/// RFC 7208 §4.6.4: limit the time for check_host(); at least 20 seconds.
pub const TIMEOUT: Duration = Duration::from_secs(20);

/// Checks the MAIL FROM identity (RFC 7208 §2.4). `mail_from` is None for
/// the null reverse-path, in which case `postmaster@<helo>` is checked.
/// Returns the result and the domain that was checked.
pub async fn check_mail_from<R: Resolver>(
    resolver: &R,
    ip: IpAddr,
    mail_from: Option<&str>,
    helo: &str,
) -> (SpfResult, String) {
    let sender = match mail_from {
        Some(s) => s.to_owned(),
        None => format!("postmaster@{helo}"),
    };
    let domain = sender.rsplit_once('@').map_or(helo, |(_, d)| d).to_owned();
    (
        check_host(resolver, ip, &domain, &sender, helo).await,
        domain,
    )
}

/// check_host(<ip>, <domain>, <sender>) of RFC 7208 §4, with `helo` for
/// the `%{h}` macro.
pub async fn check_host<R: Resolver>(
    resolver: &R,
    ip: IpAddr,
    domain: &str,
    sender: &str,
    helo: &str,
) -> SpfResult {
    // RFC 7208 §5: an IPv4-mapped IPv6 client is treated as IPv4.
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    let mut eval = Eval {
        resolver,
        ip,
        sender,
        helo,
        dns_terms: 0,
        voids: 0,
    };
    match tokio::time::timeout(TIMEOUT, eval.check(domain.to_ascii_lowercase())).await {
        Ok(r) => r,
        // RFC 7208 §4.6.4: over the time limit, the result SHOULD be temperror.
        Err(_) => SpfResult::TempError,
    }
}

/// Why a mechanism could not be evaluated: check_host() stops with this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    Temp,
    Perm,
}

impl From<Stop> for SpfResult {
    fn from(s: Stop) -> Self {
        match s {
            Stop::Temp => Self::TempError,
            Stop::Perm => Self::PermError,
        }
    }
}

struct Eval<'a, R> {
    resolver: &'a R,
    ip: IpAddr,
    sender: &'a str,
    helo: &'a str,
    /// Shared by the whole evaluation, includes and redirects too.
    dns_terms: u32,
    voids: u32,
}

/// RFC 7208 §4.3: <domain> must be a well-formed, multi-label DNS name
/// ("label longer than 63 characters, zero-length label not at the end"
/// are its examples of malformed). These are DNS names, not host names:
/// labels like `_spf` are fine. RFC 1035 §2.3.4 bounds the lengths.
fn valid_domain(d: &str) -> bool {
    let d = d.strip_suffix('.').unwrap_or(d);
    let labels: Vec<&str> = d.split('.').collect();
    d.len() <= 253
        && labels.len() > 1
        && labels
            .iter()
            .all(|l| (1..=63).contains(&l.len()) && l.bytes().all(|b| b.is_ascii_graphic()))
}

fn in_network(ip: IpAddr, net: IpAddr, len: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

type BoxFuture<'f, T> = Pin<Box<dyn Future<Output = T> + Send + 'f>>;

impl<R: Resolver> Eval<'_, R> {
    /// RFC 7208 §4.6.4: count a term that causes DNS queries.
    fn count_term(&mut self) -> Result<(), Stop> {
        self.dns_terms += 1;
        if self.dns_terms > MAX_DNS_TERMS {
            Err(Stop::Perm)
        } else {
            Ok(())
        }
    }

    /// RFC 7208 §4.6.4: count a lookup that returned no answer.
    fn count_void(&mut self) -> Result<(), Stop> {
        self.voids += 1;
        if self.voids > MAX_VOID_LOOKUPS {
            Err(Stop::Perm)
        } else {
            Ok(())
        }
    }

    /// check_host() proper (RFC 7208 §4), boxed for recursion.
    fn check(&mut self, domain: String) -> BoxFuture<'_, SpfResult> {
        Box::pin(async move {
            // RFC 7208 §4.3: a malformed domain gives "none".
            if !valid_domain(&domain) {
                return SpfResult::None;
            }
            // RFC 7208 §4.4: errors other than NXDOMAIN give "temperror".
            let txts = match self.resolver.txt(&domain).await {
                Ok(a) => a.records,
                Err(e) if e.is_not_found() || e == dns::Error::InvalidName => {
                    return SpfResult::None;
                }
                Err(_) => return SpfResult::TempError,
            };
            // RFC 7208 §4.5: exactly one record starting with "v=spf1".
            let mut spf = txts.iter().filter(|t| is_spf_record(t));
            let (Some(txt), None) = (spf.next(), spf.next()) else {
                return if txts.iter().any(|t| is_spf_record(t)) {
                    SpfResult::PermError
                } else {
                    SpfResult::None
                };
            };
            // RFC 7208 §4.6: a syntax error gives "permerror".
            let Some(record) = core::str::from_utf8(txt)
                .ok()
                .and_then(|t| Record::parse(t).ok())
            else {
                return SpfResult::PermError;
            };
            match self.evaluate(&record, &domain).await {
                Ok(r) => r,
                Err(stop) => stop.into(),
            }
        })
    }

    async fn evaluate(&mut self, record: &Record, domain: &str) -> Result<SpfResult, Stop> {
        // RFC 7208 §4.6.2: the first matching mechanism decides.
        for Directive {
            qualifier,
            mechanism,
        } in &record.directives
        {
            if self.matches(mechanism, domain).await? {
                return Ok(match qualifier {
                    Qualifier::Pass => SpfResult::Pass,
                    Qualifier::Fail => SpfResult::Fail,
                    Qualifier::SoftFail => SpfResult::SoftFail,
                    Qualifier::Neutral => SpfResult::Neutral,
                });
            }
        }
        // RFC 7208 §6.1: with no match, follow redirect (ignored if the
        // record has "all"). No SPF record there is "permerror".
        if let Some(target) = &record.redirect
            && !record.has_all()
        {
            self.count_term()?;
            let target = self.expand(target, domain).await?;
            return Ok(match self.check(target).await {
                SpfResult::None => SpfResult::PermError,
                r => r,
            });
        }
        // RFC 7208 §4.7: no match and no redirect gives "neutral".
        Ok(SpfResult::Neutral)
    }

    /// Expands a domain-spec to a query name, doing the PTR work for
    /// `%{p}` if needed.
    async fn expand(&mut self, spec: &record::MacroString, domain: &str) -> Result<String, Stop> {
        let ptr = if spec.uses('p') {
            self.validated_ptr(domain).await?
        } else {
            None
        };
        let ctx = macros::Context {
            sender: self.sender,
            domain,
            ip: self.ip,
            helo: self.helo,
            ptr: ptr.as_deref(),
        };
        Ok(macros::query_name(&macros::expand(spec, &ctx)).to_ascii_lowercase())
    }

    /// A or AAAA records of `name`, matching the client's family (RFC 7208
    /// §5). Void answers are counted; other errors stop with "temperror".
    async fn addresses(&mut self, name: &str, count_void: bool) -> Result<Vec<IpAddr>, Stop> {
        let answer = if self.ip.is_ipv4() {
            self.resolver.a(name).await
        } else {
            self.resolver.aaaa(name).await
        };
        match answer {
            Ok(a) => Ok(a.records),
            // RFC 7208 §5: NXDOMAIN is treated like an empty answer.
            Err(e) if e.is_not_found() || e == dns::Error::InvalidName => {
                if count_void {
                    self.count_void()?;
                }
                Ok(Vec::new())
            }
            Err(_) => Err(Stop::Temp),
        }
    }

    /// RFC 7208 §5.5: the PTR names of the client that resolve back to it.
    /// DNS errors here never stop evaluation; at most 10 names are tried.
    async fn validated_names(&mut self) -> Vec<String> {
        let Ok(ptr) = self.resolver.ptr(self.ip).await else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for name in ptr.records.iter().take(MAX_MX_OR_PTR) {
            if let Ok(addrs) = self.addresses(name, false).await
                && addrs.contains(&self.ip)
            {
                out.push(name.clone());
            }
        }
        out
    }

    /// `%{p}`: a validated name in `domain` if any, else any validated
    /// name (RFC 7208 §7.3). Counts as a DNS term (RFC 7208 §4.6.4).
    async fn validated_ptr(&mut self, domain: &str) -> Result<Option<String>, Stop> {
        self.count_term()?;
        let names = self.validated_names().await;
        let in_domain = names
            .iter()
            .find(|n| *n == domain || n.ends_with(&format!(".{domain}")));
        Ok(in_domain.or(names.first()).cloned())
    }

    async fn matches(&mut self, mechanism: &Mechanism, domain: &str) -> Result<bool, Stop> {
        match mechanism {
            Mechanism::All => Ok(true),
            Mechanism::Ip4(net, len) => Ok(in_network(self.ip, IpAddr::V4(*net), *len)),
            Mechanism::Ip6(net, len) => Ok(in_network(self.ip, IpAddr::V6(*net), *len)),
            Mechanism::Include(spec) => {
                self.count_term()?;
                let target = self.expand(spec, domain).await?;
                // RFC 7208 §5.2: pass matches; fail, softfail and neutral
                // don't; temperror and permerror propagate; none is permerror.
                match self.check(target).await {
                    SpfResult::Pass => Ok(true),
                    SpfResult::Fail | SpfResult::SoftFail | SpfResult::Neutral => Ok(false),
                    SpfResult::TempError => Err(Stop::Temp),
                    SpfResult::PermError | SpfResult::None => Err(Stop::Perm),
                }
            }
            Mechanism::A {
                domain: spec,
                cidr4,
                cidr6,
            } => {
                self.count_term()?;
                let target = match spec {
                    Some(s) => self.expand(s, domain).await?,
                    None => domain.to_owned(),
                };
                let len = if self.ip.is_ipv4() { *cidr4 } else { *cidr6 };
                let addrs = self.addresses(&target, true).await?;
                Ok(addrs.iter().any(|a| in_network(self.ip, *a, len)))
            }
            Mechanism::Mx {
                domain: spec,
                cidr4,
                cidr6,
            } => {
                self.count_term()?;
                let target = match spec {
                    Some(s) => self.expand(s, domain).await?,
                    None => domain.to_owned(),
                };
                // RFC 7208 §5.4: no implicit MX (A fallback) here.
                let mxs = match self.resolver.mx(&target).await {
                    Ok(a) => a.records,
                    Err(e) if e.is_not_found() || e == dns::Error::InvalidName => {
                        self.count_void()?;
                        return Ok(false);
                    }
                    Err(_) => return Err(Stop::Temp),
                };
                // RFC 7208 §4.6.4: more than 10 MX records is permerror.
                if mxs.len() > MAX_MX_OR_PTR {
                    return Err(Stop::Perm);
                }
                let len = if self.ip.is_ipv4() { *cidr4 } else { *cidr6 };
                for mx in mxs.iter().filter(|m| !m.is_null()) {
                    let addrs = self.addresses(&mx.exchange, false).await?;
                    if addrs.iter().any(|a| in_network(self.ip, *a, len)) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Mechanism::Ptr(spec) => {
                self.count_term()?;
                let target = match spec {
                    Some(s) => self.expand(s, domain).await?,
                    None => domain.to_owned(),
                };
                // RFC 7208 §5.5: a validated name equal to or under the target.
                let names = self.validated_names().await;
                Ok(names
                    .iter()
                    .any(|n| *n == target || n.ends_with(&format!(".{target}"))))
            }
            Mechanism::Exists(spec) => {
                self.count_term()?;
                let target = self.expand(spec, domain).await?;
                // RFC 7208 §5.7: always an A query, whatever the client family.
                match self.resolver.a(&target).await {
                    Ok(_) => Ok(true),
                    Err(e) if e.is_not_found() || e == dns::Error::InvalidName => {
                        self.count_void()?;
                        Ok(false)
                    }
                    Err(_) => Err(Stop::Temp),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod domain_tests {
    use super::valid_domain;

    #[test]
    fn dns_names_not_host_names() {
        for ok in [
            "example.com",
            "mobile-users._spf.example.com",
            "example.com.",
            "a.b",
        ] {
            assert!(valid_domain(ok), "{ok}");
        }
        let long_label = format!("{}.com", "a".repeat(64));
        for bad in ["localhost", "", ".", "a..b", &long_label, "exa mple.com"] {
            assert!(!valid_domain(bad), "{bad:?}");
        }
    }
}
