//! Where mail for a domain goes: MX records (RFC 5321 §5.1), the implicit
//! MX when there are none, and the null MX (RFC 7505). This is the only
//! source of delivery targets: there is no relay or smarthost setting
//! (CLAUDE.md, hard constraint 1).

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::net::IpAddr;

use dns::{Dnssec, Error, Resolver};

/// The most MX hosts considered for one delivery.
const MAX_HOSTS: usize = 10;

/// Which address families may be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Families {
    pub ipv4: bool,
    pub ipv6: bool,
}

/// The delivery route for a domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Route {
    /// The MX RRset was DNSSEC-secure (or, for an implicit MX, the
    /// domain's own address records were), so DANE may apply
    /// (RFC 7672 §2.2.1).
    pub(crate) mx_secure: bool,
    /// MX hosts in the order to try them.
    pub(crate) hosts: Vec<Host>,
}

/// One MX host and its addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Host {
    pub(crate) name: String,
    /// IPv4 first: our IPv4 reverse DNS is the more commonly checked one.
    pub(crate) addrs: Vec<IpAddr>,
    /// All address lookups were DNSSEC-secure (RFC 7672 §2.2.2).
    pub(crate) addrs_secure: bool,
}

/// Why no route could be found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteError {
    Permanent {
        status: &'static str,
        diagnostic: String,
    },
    Temporary(String),
}

/// Finds the MX hosts of `domain` (lower-case A-label) and their addresses.
pub(crate) async fn route<R: Resolver>(
    resolver: &R,
    domain: &str,
    families: Families,
) -> Result<Route, RouteError> {
    let (mut names, mx_secure, implicit) = match resolver.mx(domain).await {
        Ok(answer) => {
            // RFC 7505 §3: a null MX means the domain accepts no mail. It
            // must be the only record; if it isn't, we still honour it
            // rather than guess.
            if answer.records.iter().any(dns::Mx::is_null) {
                return Err(RouteError::Permanent {
                    status: "5.1.10",
                    diagnostic: format!("{domain} does not accept mail (null MX, RFC 7505)"),
                });
            }
            let mut mx = answer.records;
            shuffle_equal_preferences(&mut mx);
            (
                mx.into_iter().map(|m| m.exchange).collect::<Vec<_>>(),
                answer.dnssec == Dnssec::Secure,
                false,
            )
        }
        // RFC 5321 §5.1: without MX records, the domain itself is the host.
        Err(Error::NoRecords) => (vec![domain.to_owned()], false, true),
        Err(Error::NxDomain | Error::InvalidName) => {
            return Err(RouteError::Permanent {
                status: "5.1.2",
                diagnostic: format!("{domain} does not exist"),
            });
        }
        Err(e) => {
            return Err(RouteError::Temporary(format!(
                "MX lookup for {domain}: {e}"
            )));
        }
    };
    let mut seen = std::collections::HashSet::new();
    names.retain(|n| seen.insert(n.to_ascii_lowercase()));
    names.truncate(MAX_HOSTS);

    let mut hosts = Vec::new();
    let mut temporary = None;
    // A Bogus address answer is accepted as insecure only for the hosts
    // of an explicit MX RRset that was itself insecure.
    let tolerate_bogus = !implicit && !mx_secure;
    for name in names {
        match addresses(resolver, &name, families, tolerate_bogus).await {
            Ok((addrs, secure)) if !addrs.is_empty() => hosts.push(Host {
                name,
                addrs,
                addrs_secure: secure,
            }),
            Ok(_) => {}
            Err(e) => temporary = Some(format!("address lookup for {name}: {e}")),
        }
    }
    if hosts.is_empty() {
        return Err(match temporary {
            Some(e) => RouteError::Temporary(e),
            None if implicit => RouteError::Permanent {
                status: "5.1.2",
                diagnostic: format!("{domain} has no MX and no address records"),
            },
            None => RouteError::Permanent {
                status: "5.4.4",
                diagnostic: format!("no MX host of {domain} has a usable address"),
            },
        });
    }
    // RFC 7672 §2.2.2: for an implicit MX the address records decide.
    let mx_secure = if implicit {
        hosts.iter().all(|h| h.addrs_secure)
    } else {
        mx_secure
    };
    Ok(Route { mx_secure, hosts })
}

/// A and AAAA records of `name` for the enabled families. Not-found is an
/// empty list; other failures are errors.
///
/// With `tolerate_bogus`, a Bogus answer is used as insecure. That is only
/// passed for the hosts of an MX RRset that was not DNSSEC-secure: whoever
/// could forge these addresses could forge that unsigned MX RRset just as
/// well, so nothing is lost, and DANE never applies without a secure MX
/// (RFC 7672 §2.2.1). It works around hickory-resolver 0.26.3 calling
/// some unsigned delegations Bogus, such as l.google.com, where Gmail's
/// MX hosts live. Secure MX RRsets and implicit MX (the domain's own
/// address records) stay strict.
async fn addresses<R: Resolver>(
    resolver: &R,
    name: &str,
    families: Families,
    tolerate_bogus: bool,
) -> Result<(Vec<IpAddr>, bool), Error> {
    let mut addrs = Vec::new();
    let mut secure = true;
    let mut any = false;
    for (enabled, v6) in [(families.ipv4, false), (families.ipv6, true)] {
        if !enabled {
            continue;
        }
        let mut result = if v6 {
            resolver.aaaa(name).await
        } else {
            resolver.a(name).await
        };
        if tolerate_bogus && result == Err(Error::Bogus) {
            tracing::warn!(
                host = name,
                "DNSSEC validation failed for an MX host of an unsigned MX RRset; using its addresses as unsigned"
            );
            result = resolver.addresses_despite_bogus(name, v6).await;
        }
        match result {
            Ok(answer) => {
                any = true;
                secure &= answer.dnssec == Dnssec::Secure;
                addrs.extend(answer.records);
            }
            Err(e) if e.is_not_found() => {}
            Err(e) => return Err(e),
        }
    }
    Ok((addrs, secure && any))
}

/// RFC 5321 §5.1: sort by preference, and randomize hosts of equal
/// preference to spread the load.
fn shuffle_equal_preferences(mx: &mut [dns::Mx]) {
    let seed = RandomState::new();
    mx.sort_by_key(|m| (m.preference, seed.hash_one(&m.exchange)));
}

#[cfg(test)]
mod tests {
    use dns::testing::StaticResolver;

    use super::*;

    const BOTH: Families = Families {
        ipv4: true,
        ipv6: true,
    };

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn mx_in_preference_order() {
        let r = StaticResolver::new()
            .with_mx("example.com", 20, "b.example.com")
            .with_mx("example.com", 10, "a.example.com")
            .with_ip("a.example.com", ip("192.0.2.1"))
            .with_ip("a.example.com", ip("2001:db8::1"))
            .with_ip("b.example.com", ip("192.0.2.2"));
        let route = route(&r, "example.com", BOTH).await.unwrap();
        let names: Vec<_> = route.hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["a.example.com", "b.example.com"]);
        assert_eq!(route.hosts[0].addrs, [ip("192.0.2.1"), ip("2001:db8::1")]);
        assert!(!route.mx_secure);
    }

    #[tokio::test]
    async fn equal_preferences_are_shuffled() {
        let mut r = StaticResolver::new();
        for i in 0..8 {
            r = r
                .with_mx("example.com", 10, &format!("mx{i}.example.com"))
                .with_ip(&format!("mx{i}.example.com"), ip("192.0.2.1"));
        }
        let mut orders = std::collections::HashSet::new();
        for _ in 0..20 {
            let route = route(&r, "example.com", BOTH).await.unwrap();
            orders.insert(
                route
                    .hosts
                    .iter()
                    .map(|h| h.name.clone())
                    .collect::<Vec<_>>(),
            );
        }
        assert!(orders.len() > 1);
    }

    #[tokio::test]
    async fn implicit_mx_null_mx_and_nxdomain() {
        let r = StaticResolver::new()
            .with_ip("nomx.example", ip("192.0.2.5"))
            .with_mx("null.example", 0, "")
            .with_ip("null.example", ip("192.0.2.6"));
        let implicit = route(&r, "nomx.example", BOTH).await.unwrap();
        assert_eq!(implicit.hosts[0].name, "nomx.example");
        assert!(matches!(
            route(&r, "null.example", BOTH).await,
            Err(RouteError::Permanent {
                status: "5.1.10",
                ..
            })
        ));
        assert!(matches!(
            route(&r, "missing.example", BOTH).await,
            Err(RouteError::Permanent {
                status: "5.1.2",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn families_are_respected() {
        let r = StaticResolver::new()
            .with_ip("example.com", ip("192.0.2.1"))
            .with_ip("example.com", ip("2001:db8::1"));
        let v4 = Families {
            ipv4: true,
            ipv6: false,
        };
        let route = route(&r, "example.com", v4).await.unwrap();
        assert_eq!(route.hosts[0].addrs, [ip("192.0.2.1")]);
        assert_eq!(
            r.queries().iter().filter(|q| q.starts_with("AAAA")).count(),
            0
        );
    }

    #[tokio::test]
    async fn dns_failures_are_temporary() {
        let r =
            StaticResolver::new().with_failure("example.com", Error::Temporary("servfail".into()));
        assert!(matches!(
            route(&r, "example.com", BOTH).await,
            Err(RouteError::Temporary(_))
        ));
    }

    #[tokio::test]
    async fn bogus_hosts_of_an_unsigned_mx_are_used_as_unsigned() {
        let r = StaticResolver::new()
            .with_mx("gmail.example", 5, "mx.l.google.example")
            .with_ip("mx.l.google.example", ip("192.0.2.9"))
            .with_bogus_addresses("mx.l.google.example");
        let route = route(&r, "gmail.example", BOTH).await.unwrap();
        assert_eq!(route.hosts[0].addrs, [ip("192.0.2.9")]);
        assert!(!route.mx_secure && !route.hosts[0].addrs_secure);
    }

    #[tokio::test]
    async fn bogus_stays_fatal_for_a_secure_mx_and_implicit_mx() {
        // A signed MX RRset pointing at a Bogus host: possibly an attack
        // on DANE, so the host is not used.
        let signed = StaticResolver::new()
            .secure(true)
            .with_mx("signed.example", 10, "mx.signed.example")
            .with_ip("mx.signed.example", ip("192.0.2.10"))
            .with_bogus_addresses("mx.signed.example");
        assert!(matches!(
            route(&signed, "signed.example", BOTH).await,
            Err(RouteError::Temporary(e)) if e.contains("DNSSEC")
        ));
        assert!(!signed.queries().iter().any(|q| q.contains('!')));
        // No MX: the domain's own addresses decide DANE, so Bogus stays
        // fatal there too.
        let implicit = StaticResolver::new()
            .with_ip("nomx.example", ip("192.0.2.11"))
            .with_bogus_addresses("nomx.example");
        assert!(route(&implicit, "nomx.example", BOTH).await.is_err());
        assert!(!implicit.queries().iter().any(|q| q.contains('!')));
    }

    #[tokio::test]
    async fn dnssec_status() {
        let r = StaticResolver::new()
            .secure(true)
            .with_mx("example.com", 10, "mx.example.com")
            .with_ip("mx.example.com", ip("192.0.2.1"));
        let route = route(&r, "example.com", BOTH).await.unwrap();
        assert!(route.mx_secure && route.hosts[0].addrs_secure);
    }
}
