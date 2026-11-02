//! Outbound delivery settings: which address families and source addresses
//! to use, and the startup check that each source address is ours and has
//! a PTR record naming our host (receivers reject mail without one).

use std::net::{IpAddr, SocketAddr};

use dns::Resolver;
use smtp_client::{Families, Sources};

use crate::config::Config;

/// The families and source addresses for outbound connections. With
/// `outbound_ips` set, only the families listed there are used: a
/// connection from an address without our PTR would be rejected anyway.
pub(crate) fn families_and_sources(config: &Config) -> (Families, Sources) {
    let ips = &config.server.outbound_ips;
    let mut sources = Sources::default();
    for ip in ips {
        match ip {
            IpAddr::V4(v4) => sources.ipv4 = Some(*v4),
            IpAddr::V6(v6) => sources.ipv6 = Some(*v6),
        }
    }
    let families = if ips.is_empty() {
        Families {
            ipv4: true,
            ipv6: true,
        }
    } else {
        Families {
            ipv4: sources.ipv4.is_some(),
            ipv6: sources.ipv6.is_some(),
        }
    };
    (families, sources)
}

/// Checks every `outbound_ips` address: it must be assigned to this machine
/// and its PTR must name `hostname`, confirmed by the forward lookup. A
/// temporary DNS failure only warns; a wrong or missing PTR is an error.
pub(crate) async fn check<R: Resolver>(config: &Config, resolver: &R) -> Result<(), String> {
    let hostname = config.server.hostname.trim_end_matches('.');
    for &ip in &config.server.outbound_ips {
        let socket = if ip.is_ipv4() {
            tokio::net::TcpSocket::new_v4()
        } else {
            tokio::net::TcpSocket::new_v6()
        };
        socket
            .and_then(|s| s.bind(SocketAddr::new(ip, 0)))
            .map_err(|e| format!("cannot send from {ip}: {e} (is it assigned to this server?)"))?;
        let names = match resolver.ptr(ip).await {
            Ok(a) => a.records,
            Err(e) if e.is_not_found() => {
                return Err(format!(
                    "{ip} has no PTR record; ask your provider to set it to {hostname}"
                ));
            }
            Err(e) => {
                tracing::warn!(%ip, error = %e, "could not check the PTR record of an outbound address");
                continue;
            }
        };
        if !names
            .iter()
            .any(|n| n.trim_end_matches('.').eq_ignore_ascii_case(hostname))
        {
            return Err(format!(
                "the PTR record of {ip} is {names:?}, not {hostname}; receivers will reject our mail"
            ));
        }
        // Forward-confirmed reverse DNS: the host name must point back.
        let forward = if ip.is_ipv4() {
            resolver.a(hostname).await
        } else {
            resolver.aaaa(hostname).await
        };
        match forward {
            Ok(a) if a.records.contains(&ip) => {}
            Ok(_) => return Err(format!("{hostname} does not resolve to {ip}")),
            Err(e) if e.is_not_found() => {
                return Err(format!("{hostname} does not resolve to {ip}"));
            }
            Err(e) => {
                tracing::warn!(%ip, error = %e, "could not confirm the forward DNS of our host name")
            }
        }
        tracing::info!(%ip, %hostname, "outbound address and its PTR record match");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use dns::testing::StaticResolver;

    use super::*;

    fn config(ips: &str) -> Config {
        Config::parse(&format!(
            r#"
            [server]
            hostname = "mx.example.org"
            data_dir = "/var/lib/idly"
            outbound_ips = [{ips}]
            [[domain]]
            name = "example.org"
            [[account]]
            address = "a@example.org"
            password_hash = "$argon2id$v=19$m=19456,t=2,p=1$ZGVtb2RlbW9kZW1v$ZGVtby1vbmx5LW5vdC1hLXJlYWwtaGFzaA"
            "#
        ))
        .unwrap()
    }

    #[test]
    fn families_follow_outbound_ips() {
        let (f, s) = families_and_sources(&config(""));
        assert!(f.ipv4 && f.ipv6 && s == Sources::default());
        let (f, s) = families_and_sources(&config("\"192.0.2.1\""));
        assert!(f.ipv4 && !f.ipv6);
        assert_eq!(s.ipv4, Some("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn outbound_ips_must_be_public_and_one_per_family() {
        let problems = |ips: &str| config(ips).validate().err().unwrap_or_default();
        assert!(problems("\"203.0.114.1\", \"2a00:1450::1\"").is_empty());
        assert_eq!(problems("\"10.0.0.1\"").len(), 1);
        assert_eq!(problems("\"8.8.8.8\", \"1.1.1.1\"").len(), 1);
    }

    #[tokio::test]
    async fn ptr_must_match() {
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let c = config("\"127.0.0.1\"");
        let good = StaticResolver::new()
            .with_ptr(lo, "mx.example.org.")
            .with_ip("mx.example.org", lo);
        assert_eq!(check(&c, &good).await, Ok(()));
        let wrong = StaticResolver::new()
            .with_ptr(lo, "host-1.provider.example")
            .with_ip("mx.example.org", lo);
        assert!(
            check(&c, &wrong)
                .await
                .unwrap_err()
                .contains("not mx.example.org")
        );
        let none = StaticResolver::new().with_ip("mx.example.org", lo);
        assert!(check(&c, &none).await.unwrap_err().contains("no PTR"));
        let unconfirmed = StaticResolver::new().with_ptr(lo, "mx.example.org");
        assert!(
            check(&c, &unconfirmed)
                .await
                .unwrap_err()
                .contains("does not resolve")
        );
        let flaky =
            StaticResolver::new().with_failure("ptr:127.0.0.1", dns::Error::Temporary("x".into()));
        assert_eq!(check(&c, &flaky).await, Ok(()), "DNS trouble only warns");
        // An address this machine doesn't have.
        let foreign = config("\"192.0.2.77\"");
        assert!(
            check(&foreign, &good)
                .await
                .unwrap_err()
                .contains("cannot send from")
        );
    }
}
