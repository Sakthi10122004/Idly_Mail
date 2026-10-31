//! An in-memory resolver for tests. Compiled only for tests and with the
//! `testing` feature, never into the release binary.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use crate::{Answer, Dnssec, Error, Mx, Resolver, Tlsa, normalize_name};

#[derive(Debug, Clone, Default)]
struct Entry {
    mx: Vec<Mx>,
    a: Vec<IpAddr>,
    aaaa: Vec<IpAddr>,
    txt: Vec<Vec<u8>>,
    tlsa: Vec<Tlsa>,
    ptr: Vec<String>,
    /// Forced result for every lookup of this name.
    fail: Option<Error>,
}

/// A static zone. Lookups of unknown names give NXDOMAIN; a known name
/// without records of the asked type gives NODATA. Every query is logged.
#[derive(Debug, Default)]
pub struct StaticResolver {
    entries: HashMap<String, Entry>,
    secure: bool,
    log: Mutex<Vec<String>>,
}

impl StaticResolver {
    /// An empty zone.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark all answers DNSSEC-secure.
    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    fn entry(&mut self, name: &str) -> &mut Entry {
        self.entries.entry(normalize_name(name)).or_default()
    }

    /// Add an MX record. Use exchange "" for a null MX.
    pub fn with_mx(mut self, name: &str, preference: u16, exchange: &str) -> Self {
        self.entry(name).mx.push(Mx {
            preference,
            exchange: normalize_name(exchange),
        });
        self
    }

    /// Add an A or AAAA record, depending on the address family.
    pub fn with_ip(mut self, name: &str, ip: IpAddr) -> Self {
        let e = self.entry(name);
        if ip.is_ipv4() {
            e.a.push(ip)
        } else {
            e.aaaa.push(ip)
        }
        self
    }

    /// Add a TXT record.
    pub fn with_txt(mut self, name: &str, txt: &str) -> Self {
        self.entry(name).txt.push(txt.as_bytes().to_vec());
        self
    }

    /// Add a TLSA record.
    pub fn with_tlsa(mut self, name: &str, tlsa: Tlsa) -> Self {
        self.entry(name).tlsa.push(tlsa);
        self
    }

    /// Add a PTR record for `ip`.
    pub fn with_ptr(mut self, ip: IpAddr, name: &str) -> Self {
        self.entry(&ptr_key(ip)).ptr.push(normalize_name(name));
        self
    }

    /// Make every lookup of `name` fail with `error`.
    pub fn with_failure(mut self, name: &str, error: Error) -> Self {
        self.entry(name).fail = Some(error);
        self
    }

    /// Every query so far, as "TYPE name".
    pub fn queries(&self) -> Vec<String> {
        self.log.lock().map(|l| l.clone()).unwrap_or_default()
    }

    fn lookup<T: Clone>(
        &self,
        rtype: &str,
        name: &str,
        f: impl Fn(&Entry) -> &Vec<T>,
    ) -> Result<Answer<T>, Error> {
        let name = normalize_name(name);
        if let Ok(mut log) = self.log.lock() {
            log.push(format!("{rtype} {name}"));
        }
        let entry = self.entries.get(&name).ok_or(Error::NxDomain)?;
        if let Some(e) = &entry.fail {
            return Err(e.clone());
        }
        let records = f(entry).clone();
        if records.is_empty() {
            return Err(Error::NoRecords);
        }
        Ok(Answer {
            records,
            dnssec: if self.secure {
                Dnssec::Secure
            } else {
                Dnssec::Insecure
            },
        })
    }
}

fn ptr_key(ip: IpAddr) -> String {
    format!("ptr:{ip}")
}

impl Resolver for StaticResolver {
    async fn mx(&self, name: &str) -> Result<Answer<Mx>, Error> {
        self.lookup("MX", name, |e| &e.mx)
    }
    async fn a(&self, name: &str) -> Result<Answer<IpAddr>, Error> {
        self.lookup("A", name, |e| &e.a)
    }
    async fn aaaa(&self, name: &str) -> Result<Answer<IpAddr>, Error> {
        self.lookup("AAAA", name, |e| &e.aaaa)
    }
    async fn txt(&self, name: &str) -> Result<Answer<Vec<u8>>, Error> {
        self.lookup("TXT", name, |e| &e.txt)
    }
    async fn tlsa(&self, name: &str) -> Result<Answer<Tlsa>, Error> {
        self.lookup("TLSA", name, |e| &e.tlsa)
    }
    async fn ptr(&self, ip: IpAddr) -> Result<Answer<String>, Error> {
        self.lookup("PTR", &ptr_key(ip), |e| &e.ptr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_zone_semantics() {
        let r = StaticResolver::new()
            .with_mx("example.org", 10, "mx.example.org.")
            .with_ip("mx.example.org", "192.0.2.1".parse().unwrap())
            .with_mx("nomail.example", 0, "")
            .with_failure("broken.example", Error::Temporary("servfail".into()));
        let mx = r.mx("Example.ORG.").await.unwrap();
        assert_eq!(
            mx.records,
            vec![Mx {
                preference: 10,
                exchange: "mx.example.org".into()
            }]
        );
        assert_eq!(mx.dnssec, Dnssec::Insecure);
        assert_eq!(r.aaaa("mx.example.org").await, Err(Error::NoRecords));
        assert_eq!(r.a("missing.example").await, Err(Error::NxDomain));
        assert!(r.mx("nomail.example").await.unwrap().records[0].is_null());
        assert!(matches!(
            r.txt("broken.example").await,
            Err(Error::Temporary(_))
        ));
        assert_eq!(r.queries().len(), 5);
    }
}
