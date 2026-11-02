//! The real resolver: iterative resolution from the root servers with DNSSEC
//! validation against the built-in root trust anchor, via hickory-resolver's
//! `recursor` feature.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::dnssec::Proof;
use hickory_resolver::proto::op::Query;
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::recursor::{DnssecConfig, DnssecPolicy, Recursor, RecursorOptions};

use crate::{Answer, Dnssec, Error, Mx, Resolver, Tlsa, normalize_name, roots};

/// Response cache entries. Bounded for a 1 GB VPS (CLAUDE.md); the default
/// of hickory-resolver is 1,048,576.
const RESPONSE_CACHE_SIZE: u64 = 32_768;

/// A recursive, DNSSEC-validating resolver. Cloning is cheap and shares the
/// cache.
#[derive(Clone)]
pub struct Recursive {
    inner: Arc<Recursor<TokioRuntimeProvider>>,
}

impl core::fmt::Debug for Recursive {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Recursive").finish_non_exhaustive()
    }
}

impl Recursive {
    /// Creates a resolver that starts from the IANA root servers and
    /// validates DNSSEC with the built-in root trust anchor.
    pub fn new() -> Result<Self, Error> {
        let options = RecursorOptions {
            response_cache_size: RESPONSE_CACHE_SIZE,
            // Randomize query-name case over UDP to make spoofing harder.
            case_randomization: true,
            ..RecursorOptions::default()
        };
        // `trust_anchor: None` selects the built-in root trust anchor.
        let policy = DnssecPolicy::ValidateWithStaticKey(DnssecConfig::default());
        let recursor = Recursor::new(
            &roots::ROOT_HINTS,
            policy,
            None,
            options,
            TokioRuntimeProvider::new(),
        )
        .map_err(|e| Error::Temporary(e.to_string()))?;
        Ok(Self {
            inner: Arc::new(recursor),
        })
    }

    async fn query(&self, name: Name, rtype: RecordType) -> Result<(Vec<RData>, Dnssec), Error> {
        self.query_with(name, rtype, false).await
    }

    /// With `allow_bogus`, records that failed validation are returned
    /// as Insecure instead of failing the lookup.
    async fn query_with(
        &self,
        name: Name,
        rtype: RecordType,
        allow_bogus: bool,
    ) -> Result<(Vec<RData>, Dnssec), Error> {
        let query = Query::query(name, rtype);
        let message = match self.inner.resolve(query, Instant::now(), true).await {
            Ok(m) => m,
            Err(e) if e.is_nx_domain() => return Err(Error::NxDomain),
            Err(e) if e.is_no_records_found() => return Err(Error::NoRecords),
            Err(e) => return Err(Error::Temporary(e.to_string())),
        };
        match classify(&message.answers, rtype) {
            Err(Error::Bogus) if allow_bogus => {
                let data: Vec<RData> = message
                    .answers
                    .iter()
                    .filter(|r| r.record_type() == rtype)
                    .map(|r| r.data.clone())
                    .collect();
                if data.is_empty() {
                    return Err(Error::Bogus);
                }
                Ok((data, Dnssec::Insecure))
            }
            other => other,
        }
    }
}

/// Picks the records of `rtype` from an answer section and works out its
/// DNSSEC status from the data RRsets only: the requested type and any
/// CNAMEs followed on the way. An answer is Secure only if that whole chain
/// is. RRSIG records are ignored here: "An RRset MAY have multiple RRSIG
/// RRs" (RFC 4035 §2.2), and the resolver marks each RRSIG it did not use
/// as Indeterminate, which says nothing about the data. The proof on the
/// data records themselves is the validation result.
fn classify(answers: &[Record], rtype: RecordType) -> Result<(Vec<RData>, Dnssec), Error> {
    let chain: Vec<&Record> = answers
        .iter()
        .filter(|r| r.record_type() == rtype || r.record_type() == RecordType::CNAME)
        .collect();
    if chain.iter().any(|r| r.proof == Proof::Bogus) {
        return Err(Error::Bogus);
    }
    let secure = chain.iter().all(|r| r.proof == Proof::Secure);
    let data: Vec<RData> = chain
        .iter()
        .filter(|r| r.record_type() == rtype)
        .map(|r| r.data.clone())
        .collect();
    if data.is_empty() {
        return Err(Error::NoRecords);
    }
    Ok((
        data,
        if secure {
            Dnssec::Secure
        } else {
            Dnssec::Insecure
        },
    ))
}

fn fqdn(name: &str) -> Result<Name, Error> {
    let mut name = Name::from_ascii(name).map_err(|_| Error::InvalidName)?;
    name.set_fqdn(true);
    Ok(name)
}

fn answer<T>(
    (data, dnssec): (Vec<RData>, Dnssec),
    f: impl Fn(RData) -> Option<T>,
) -> Result<Answer<T>, Error> {
    let records: Vec<T> = data.into_iter().filter_map(f).collect();
    if records.is_empty() {
        return Err(Error::NoRecords);
    }
    Ok(Answer { records, dnssec })
}

impl Resolver for Recursive {
    async fn mx(&self, name: &str) -> Result<Answer<Mx>, Error> {
        let r = self.query(fqdn(name)?, RecordType::MX).await?;
        answer(r, |d| match d {
            RData::MX(mx) => Some(Mx {
                preference: mx.preference,
                exchange: normalize_name(&mx.exchange.to_ascii()),
            }),
            _ => None,
        })
    }

    async fn a(&self, name: &str) -> Result<Answer<IpAddr>, Error> {
        let r = self.query(fqdn(name)?, RecordType::A).await?;
        answer(r, |d| match d {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            _ => None,
        })
    }

    async fn aaaa(&self, name: &str) -> Result<Answer<IpAddr>, Error> {
        let r = self.query(fqdn(name)?, RecordType::AAAA).await?;
        answer(r, |d| match d {
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
    }

    async fn txt(&self, name: &str) -> Result<Answer<Vec<u8>>, Error> {
        let r = self.query(fqdn(name)?, RecordType::TXT).await?;
        answer(r, |d| match d {
            RData::TXT(txt) => Some(
                txt.txt_data
                    .iter()
                    .flat_map(|s| s.iter().copied())
                    .collect(),
            ),
            _ => None,
        })
    }

    async fn tlsa(&self, name: &str) -> Result<Answer<Tlsa>, Error> {
        let r = self.query(fqdn(name)?, RecordType::TLSA).await?;
        answer(r, |d| match d {
            RData::TLSA(t) => Some(Tlsa {
                usage: t.cert_usage.into(),
                selector: t.selector.into(),
                matching: t.matching.into(),
                data: t.cert_data,
            }),
            _ => None,
        })
    }

    async fn addresses_despite_bogus(&self, name: &str, v6: bool) -> Result<Answer<IpAddr>, Error> {
        let rtype = if v6 { RecordType::AAAA } else { RecordType::A };
        let r = self.query_with(fqdn(name)?, rtype, true).await?;
        answer(r, |d| match d {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
    }

    async fn ptr(&self, ip: IpAddr) -> Result<Answer<String>, Error> {
        // RFC 1035 §3.5 (in-addr.arpa) and RFC 3596 §2.5 (ip6.arpa).
        let r = self.query(Name::from(ip), RecordType::PTR).await?;
        answer(r, |d| match d {
            RData::PTR(p) => Some(normalize_name(&p.0.to_ascii())),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Live tests against the real DNS. They need outbound UDP/TCP 53, so
    // they are ignored by default: `cargo test -p dns -- --ignored`.

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    #[ignore = "needs network"]
    fn live_mx_insecure_zone() {
        rt().block_on(async {
            let r = Recursive::new().unwrap();
            let a = r.mx("gmail.com").await.unwrap();
            assert!(a.records.iter().any(|m| m.exchange.ends_with("google.com")));
            // gmail.com is not DNSSEC-signed.
            assert_eq!(a.dnssec, Dnssec::Insecure);
        });
    }

    #[test]
    #[ignore = "needs network"]
    fn live_signed_zone_is_secure() {
        rt().block_on(async {
            let r = Recursive::new().unwrap();
            // ietf.org is DNSSEC-signed.
            let a = r.mx("ietf.org").await.unwrap();
            assert_eq!(a.dnssec, Dnssec::Secure);
        });
    }

    #[test]
    #[ignore = "needs network"]
    fn live_bogus_zone_rejected() {
        rt().block_on(async {
            let r = Recursive::new().unwrap();
            // dnssec-failed.org is deliberately mis-signed by Comcast for testing.
            let e = r.a("www.dnssec-failed.org").await.unwrap_err();
            assert!(matches!(e, Error::Bogus | Error::Temporary(_)), "{e:?}");
        });
    }

    #[test]
    #[ignore = "needs network"]
    fn live_negative_answers() {
        rt().block_on(async {
            let r = Recursive::new().unwrap();
            assert_eq!(
                r.a("no-such-name.invalid-idly-test.org").await,
                Err(Error::NxDomain)
            );
            // example.org exists but has no MX… it publishes a null MX.
            let mx = r.mx("example.org").await;
            assert!(
                matches!(&mx, Ok(a) if a.records.iter().any(Mx::is_null))
                    || mx == Err(Error::NoRecords)
            );
            let ptr = r.ptr("8.8.8.8".parse().unwrap()).await.unwrap();
            assert_eq!(ptr.records, vec!["dns.google".to_owned()]);
        });
    }

    #[test]
    #[ignore = "needs network"]
    fn live_gmail_mx_hosts_despite_hickory_bogus() {
        rt().block_on(async {
            let r = Recursive::new().unwrap();
            // hickory 0.26.3 calls names under the unsigned l.google.com
            // delegation Bogus. If this starts passing as Insecure, the
            // upstream bug is fixed and the route workaround is unused.
            let host = "gmail-smtp-in.l.google.com";
            match r.a(host).await {
                Err(Error::Bogus) => {}
                Ok(a) => assert_eq!(a.dnssec, Dnssec::Insecure),
                Err(e) => panic!("{e:?}"),
            }
            let a = r.addresses_despite_bogus(host, false).await.unwrap();
            assert!(!a.records.is_empty());
            assert_eq!(a.dnssec, Dnssec::Insecure);
        });
    }

    #[test]
    #[ignore = "needs network"]
    fn live_tlsa_secure() {
        rt().block_on(async {
            let r = Recursive::new().unwrap();
            // A long-standing DANE-enabled MX (the Debian mail relay).
            let t = r.tlsa("_25._tcp.mailly.debian.org").await.unwrap();
            assert_eq!(t.dnssec, Dnssec::Secure);
            assert!(t.records.iter().all(|t| t.usage == 3 || t.usage == 2));
        });
    }
}
