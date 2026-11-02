//! Checks of the things outside Idly that decide whether its mail gets
//! delivered: is outbound port 25 open, do our addresses have PTR records
//! naming our host, is the certificate about to expire. They only warn
//! (logs, metrics, `idly dns --check`); they never stop the server.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dns::Resolver;
use smtp_client::{Dialer, Sources};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;

use crate::config::Config;
use crate::metrics::Metrics;

/// How long one port-25 probe may take (connect plus banner).
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
/// Warn this long before the certificate expires.
pub(crate) const CERT_WARNING: u64 = 14 * 86_400;

/// What the port-25 probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Port25 {
    /// A remote MX answered with its banner.
    Open(String),
    /// Every connection timed out: the provider most likely filters
    /// outbound port 25.
    Blocked,
    /// Connections were refused or reset, or no MX could be found.
    Unknown(String),
}

/// Connects to port 25 of the first MX of each domain, as a delivery
/// would, reads the banner and says QUIT. Stops at the first success.
pub(crate) async fn probe_port25<R: Resolver, D: Dialer>(
    resolver: &R,
    dialer: &D,
    sources: Sources,
    domains: &[String],
    limit: Duration,
) -> Port25 {
    let mut timeouts = 0;
    let mut problems = Vec::new();
    for domain in domains {
        let target = match first_mx_address(resolver, domain).await {
            Ok(t) => t,
            Err(e) => {
                problems.push(format!("{domain}: {e}"));
                continue;
            }
        };
        let addr = SocketAddr::new(target, 25);
        let attempt = async {
            let stream = dialer.connect(addr, sources.for_ip(target)).await?;
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await?;
            // RFC 5321 §3.1: the greeting is a 220 reply (possibly
            // multi-line); the first line is enough here.
            let _ = stream.get_mut().write_all(b"QUIT\r\n").await;
            Ok::<_, std::io::Error>(line)
        };
        match timeout(limit, attempt).await {
            Ok(Ok(line)) if line.starts_with("220") => {
                return Port25::Open(format!("{domain} ({addr})"));
            }
            Ok(Ok(line)) => {
                problems.push(format!("{addr}: unexpected greeting {:?}", line.trim_end()))
            }
            Ok(Err(e)) => problems.push(format!("{addr}: {e}")),
            Err(_) => timeouts += 1,
        }
    }
    if timeouts > 0 && problems.is_empty() {
        Port25::Blocked
    } else if problems.is_empty() {
        Port25::Unknown("no domains to probe".into())
    } else {
        Port25::Unknown(problems.join("; "))
    }
}

async fn first_mx_address<R: Resolver>(resolver: &R, domain: &str) -> Result<IpAddr, String> {
    let mx = resolver.mx(domain).await.map_err(|e| e.to_string())?;
    let mut hosts: Vec<_> = mx.records.into_iter().filter(|m| !m.is_null()).collect();
    hosts.sort_by_key(|m| m.preference);
    let host = hosts.first().ok_or("null MX")?;
    let a = resolver
        .a(&host.exchange)
        .await
        .map_err(|e| format!("{}: {e}", host.exchange))?;
    a.records
        .first()
        .copied()
        .ok_or_else(|| format!("{}: no address", host.exchange))
}

/// Our public addresses: `public_ips` and `outbound_ips` from the
/// configuration, else the addresses the system would send from. Private
/// addresses (behind NAT) are left out.
pub(crate) fn public_ips(config: &Config) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    for ip in config
        .server
        .public_ips
        .iter()
        .chain(&config.server.outbound_ips)
    {
        if !ips.contains(ip) {
            ips.push(*ip);
        }
    }
    if ips.is_empty() {
        ips = detect_source_ips();
    }
    ips.retain(|ip| smtp_client::guard::forbidden(*ip).is_none());
    ips
}

/// The local address the system picks to reach the internet, per family.
/// A connected UDP socket sends nothing; it only selects a route.
fn detect_source_ips() -> Vec<IpAddr> {
    // a.root-servers.net, which every resolver reaches anyway.
    let targets = [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)), 53),
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 2, 0x30)),
            53,
        ),
    ];
    targets
        .iter()
        .filter_map(|t| {
            let bind = if t.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let s = std::net::UdpSocket::bind(bind).ok()?;
            s.connect(t).ok()?;
            s.local_addr().ok().map(|a| a.ip())
        })
        .collect()
}

/// Problems with the reverse DNS of `ips`: each needs a PTR naming
/// `hostname`, and `hostname` must resolve back to it (FCrDNS). Most
/// receivers reject or junk mail from addresses without this.
pub(crate) async fn reverse_dns<R: Resolver>(
    resolver: &R,
    hostname: &str,
    ips: &[IpAddr],
) -> Vec<String> {
    let hostname = hostname.trim_end_matches('.');
    let mut problems = Vec::new();
    for &ip in ips {
        match resolver.ptr(ip).await {
            Ok(a) => {
                if !a
                    .records
                    .iter()
                    .any(|n| n.trim_end_matches('.').eq_ignore_ascii_case(hostname))
                {
                    problems.push(format!(
                        "the PTR record of {ip} is {:?}, not {hostname}; ask your provider to change it",
                        a.records
                    ));
                    continue;
                }
            }
            Err(e) if e.is_not_found() => {
                problems.push(format!(
                    "{ip} has no PTR record; ask your provider to set it to {hostname}"
                ));
                continue;
            }
            Err(e) => {
                problems.push(format!("could not look up the PTR record of {ip}: {e}"));
                continue;
            }
        }
        let forward = if ip.is_ipv4() {
            resolver.a(hostname).await
        } else {
            resolver.aaaa(hostname).await
        };
        if !forward.is_ok_and(|a| a.records.contains(&ip)) {
            problems.push(format!(
                "{hostname} does not resolve to {ip}; add an {} record",
                if ip.is_ipv4() { "A" } else { "AAAA" }
            ));
        }
    }
    problems
}

/// A warning when the certificate expires within [`CERT_WARNING`].
pub(crate) fn certificate_expiry(not_after: u64, now: u64) -> Option<String> {
    if not_after <= now {
        Some("the TLS certificate has expired".into())
    } else if not_after - now < CERT_WARNING {
        Some(format!(
            "the TLS certificate expires in {} day(s)",
            (not_after - now) / 86_400
        ))
    } else {
        None
    }
}

/// How often the checks run while serving.
const INTERVAL: Duration = Duration::from_secs(6 * 3600);

/// Runs every check now and then every 6 hours, logging problems and
/// updating the metrics.
pub(crate) async fn run<R: Resolver>(
    config: Config,
    resolver: R,
    sources: Sources,
    metrics: Arc<Metrics>,
    certs: Option<Arc<acme::Certs>>,
) {
    let mut tick = tokio::time::interval(INTERVAL);
    loop {
        tick.tick().await;
        if config.checks.reverse_dns {
            let ips = public_ips(&config);
            if ips.is_empty() {
                tracing::warn!(
                    "no public IP address found for the PTR check; set server.public_ips"
                );
            }
            let problems = reverse_dns(&resolver, &config.server.hostname, &ips).await;
            for p in &problems {
                tracing::warn!(problem = %p, "reverse DNS: receivers may reject our mail");
            }
            metrics
                .reverse_dns_problems
                .set(i64::try_from(problems.len()).unwrap_or(i64::MAX));
        }

        if config.checks.port25_probe {
            let found = probe_port25(
                &resolver,
                &smtp_client::Direct,
                sources,
                &config.checks.probe_domains,
                PROBE_TIMEOUT,
            )
            .await;
            match &found {
                Port25::Open(via) => tracing::info!(via = %via, "outbound port 25 is open"),
                Port25::Blocked => tracing::warn!(
                    "outbound port 25 seems BLOCKED: every probe timed out; most hosting providers filter it until you ask them to open it"
                ),
                Port25::Unknown(why) => {
                    tracing::warn!(detail = %why, "could not tell whether outbound port 25 is open")
                }
            }
            metrics.port25_open.set(match found {
                Port25::Open(_) => 1,
                Port25::Blocked => 0,
                Port25::Unknown(_) => -1,
            });
        }

        if let Some(certs) = &certs
            && let Some(leaf) = certs.current().cert.first()
            && let Ok(info) = acme::cert::inspect(leaf)
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            if let Some(warning) = certificate_expiry(info.not_after, now) {
                tracing::warn!(not_after = info.not_after, "{warning}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::testing::StaticResolver;
    use smtp_client::testing::Loopback;

    fn lo() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    #[tokio::test]
    async fn port25_open_blocked_or_unknown() {
        use tokio::io::AsyncReadExt;
        // A server that greets.
        let greeter = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let greeter_port = greeter.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = greeter.accept().await.unwrap();
            s.write_all(b"220 mx.example.com ESMTP\r\n").await.unwrap();
            let mut quit = [0u8; 6];
            s.read_exact(&mut quit).await.unwrap();
            assert_eq!(&quit, b"QUIT\r\n");
        });
        let resolver = || {
            StaticResolver::new()
                .with_mx("example.com", 10, "mx.example.com")
                .with_ip("mx.example.com", lo())
        };
        let domains = vec!["example.com".to_owned()];
        let open = probe_port25(
            &resolver(),
            &Loopback::new().map(25, greeter_port),
            Sources::default(),
            &domains,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(open, Port25::Open("example.com (127.0.0.1:25)".into()));

        // A server that accepts but never speaks looks like a filter.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent_port = silent.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _keep = silent.accept().await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let blocked = probe_port25(
            &resolver(),
            &Loopback::new().map(25, silent_port),
            Sources::default(),
            &domains,
            Duration::from_millis(200),
        )
        .await;
        assert_eq!(blocked, Port25::Blocked);

        // No MX at all.
        let unknown = probe_port25(
            &StaticResolver::new(),
            &Loopback::new(),
            Sources::default(),
            &domains,
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(unknown, Port25::Unknown(_)), "{unknown:?}");
    }

    #[tokio::test]
    async fn reverse_dns_problems() {
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let good = StaticResolver::new()
            .with_ptr(ip, "mx.example.org.")
            .with_ip("mx.example.org", ip);
        assert!(reverse_dns(&good, "mx.example.org", &[ip]).await.is_empty());
        let none = StaticResolver::new().with_ip("mx.example.org", ip);
        let p = reverse_dns(&none, "mx.example.org", &[ip]).await;
        assert!(p[0].contains("no PTR"), "{p:?}");
        let other = StaticResolver::new()
            .with_ptr(ip, "vps-1.provider.example")
            .with_ip("mx.example.org", ip);
        let p = reverse_dns(&other, "mx.example.org", &[ip]).await;
        assert!(p[0].contains("not mx.example.org"), "{p:?}");
        let one_way = StaticResolver::new().with_ptr(ip, "mx.example.org");
        let p = reverse_dns(&one_way, "mx.example.org", &[ip]).await;
        assert!(p[0].contains("does not resolve to"), "{p:?}");
    }

    #[test]
    fn certificate_warnings() {
        let day = 86_400;
        assert_eq!(certificate_expiry(100 * day, 50 * day), None);
        assert_eq!(
            certificate_expiry(60 * day, 50 * day).as_deref(),
            Some("the TLS certificate expires in 10 day(s)")
        );
        assert!(
            certificate_expiry(day, 2 * day)
                .unwrap()
                .contains("expired")
        );
    }

    #[test]
    fn configured_addresses_win_and_private_ones_are_dropped() {
        let c = Config::parse(
            r#"
            [server]
            hostname = "mx.example.org"
            data_dir = "/var/lib/idly"
            public_ips = ["46.4.10.5", "10.0.0.2"]
            outbound_ips = ["46.4.10.5", "2001:db8::5"]
            [[domain]]
            name = "example.org"
            [[account]]
            address = "a@example.org"
            password_hash = "$argon2id$v=19$m=19456,t=2,p=1$ZGVtb2RlbW9kZW1v$ZGVtby1vbmx5LW5vdC1hLXJlYWwtaGFzaA"
            "#,
        )
        .unwrap();
        // 2001:db8::/32 is documentation space, so it's dropped too.
        assert_eq!(public_ips(&c), ["46.4.10.5".parse::<IpAddr>().unwrap()]);
    }
}
