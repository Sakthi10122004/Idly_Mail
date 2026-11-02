//! DNS resolution for Idly Mail.
//!
//! Hard constraint 2 (CLAUDE.md): we resolve recursively ourselves, starting
//! from the root servers, and validate DNSSEC. No public resolver such as
//! 8.8.8.8 or 1.1.1.1 is ever used. [`Recursive`] is the real implementation;
//! everything else talks to the [`Resolver`] trait.
//!
//! Names passed in are ASCII (A-label) domain names with or without the
//! trailing dot. Names returned (MX exchanges, PTR targets) are lower-case
//! without the trailing dot.

#![forbid(unsafe_code)]

use core::fmt;
use core::future::Future;
use std::net::IpAddr;

mod recursive;
mod roots;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use recursive::Recursive;

/// DNSSEC status of a positive answer (RFC 4035 §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dnssec {
    /// Every record in the answer, including any CNAMEs followed, validated
    /// from the root trust anchor.
    Secure,
    /// The answer is not provably secure: the zone is unsigned, or the
    /// status could not be determined. Never treat this as authenticated.
    Insecure,
}

/// A positive answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer<T> {
    /// The records of the requested type. Never empty.
    pub records: Vec<T>,
    /// Whether the whole answer is DNSSEC-secure.
    pub dnssec: Dnssec,
}

/// An MX record. RFC 5321 §5.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Mx {
    /// Lower values are preferred.
    pub preference: u16,
    /// The exchange host, lower-case, no trailing dot. Empty for the root
    /// name `.`, which is the null MX of RFC 7505 §3.
    pub exchange: String,
}

impl Mx {
    /// RFC 7505 §3: a null MX is a single MX record with preference 0 and
    /// exchange `.`; it means the domain accepts no mail.
    pub fn is_null(&self) -> bool {
        self.preference == 0 && self.exchange.is_empty()
    }
}

/// A TLSA record. RFC 6698 §2.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tlsa {
    /// Certificate usage (RFC 6698 §2.1.1); DANE for SMTP uses 2 and 3.
    pub usage: u8,
    /// Selector (RFC 6698 §2.1.2): 0 full certificate, 1 public key.
    pub selector: u8,
    /// Matching type (RFC 6698 §2.1.3): 0 exact, 1 SHA-256, 2 SHA-512.
    pub matching: u8,
    /// Certificate association data.
    pub data: Vec<u8>,
}

/// Why a lookup produced no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The name does not exist (NXDOMAIN, RFC 1035 §4.1.1 RCODE 3).
    NxDomain,
    /// The name exists but has no records of the requested type (NODATA).
    NoRecords,
    /// DNSSEC validation failed. RFC 4035 §4.3 "Bogus": possibly an attack;
    /// callers must not use the data and should treat it as a failure.
    Bogus,
    /// SERVFAIL, timeout, network error or resolver limit: try again later.
    Temporary(String),
    /// The name passed in is not a valid DNS name.
    InvalidName,
}

impl Error {
    /// NXDOMAIN or NODATA: an authoritative "nothing here", as opposed to a
    /// failure to find out. SPF counts these as void lookups (RFC 7208 §4.6.4).
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NxDomain | Self::NoRecords)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NxDomain => f.write_str("domain does not exist"),
            Self::NoRecords => f.write_str("no records of the requested type"),
            Self::Bogus => f.write_str("DNSSEC validation failed"),
            Self::Temporary(e) => write!(f, "temporary DNS failure: {e}"),
            Self::InvalidName => f.write_str("invalid domain name"),
        }
    }
}

impl std::error::Error for Error {}

/// The lookups Idly Mail needs. Implementations must be cheap to share
/// between tasks.
pub trait Resolver: Send + Sync {
    /// MX records for `name`.
    fn mx(&self, name: &str) -> impl Future<Output = Result<Answer<Mx>, Error>> + Send;
    /// IPv4 addresses (A records) for `name`.
    fn a(&self, name: &str) -> impl Future<Output = Result<Answer<IpAddr>, Error>> + Send;
    /// IPv6 addresses (AAAA records) for `name`.
    fn aaaa(&self, name: &str) -> impl Future<Output = Result<Answer<IpAddr>, Error>> + Send;
    /// TXT records for `name`. Each record's character-strings are
    /// concatenated without separators, as SPF (RFC 7208 §3.3) and DKIM
    /// (RFC 6376 §3.6.2.2) require.
    fn txt(&self, name: &str) -> impl Future<Output = Result<Answer<Vec<u8>>, Error>> + Send;
    /// TLSA records for `name` (e.g. `_25._tcp.mx.example.org`).
    fn tlsa(&self, name: &str) -> impl Future<Output = Result<Answer<Tlsa>, Error>> + Send;
    /// PTR names for `ip`.
    fn ptr(&self, ip: IpAddr) -> impl Future<Output = Result<Answer<String>, Error>> + Send;

    /// A (or, with `v6`, AAAA) records of `name` even when DNSSEC
    /// validation calls them Bogus; such records come back marked
    /// Insecure. Only for a caller that would accept an unsigned answer
    /// for this name anyway: the outbound router, for the hosts of an MX
    /// RRset that was itself not secure (see smtp-client's `route`). Never
    /// for DANE, where Bogus must stay fatal (RFC 7672 §2.2.2).
    ///
    /// The default is the plain lookup; only the real resolver differs.
    fn addresses_despite_bogus(
        &self,
        name: &str,
        v6: bool,
    ) -> impl Future<Output = Result<Answer<IpAddr>, Error>> + Send {
        async move {
            if v6 {
                self.aaaa(name).await
            } else {
                self.a(name).await
            }
        }
    }
}

/// Normalizes a returned name: lower-case, without the trailing dot.
pub(crate) fn normalize_name(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_mx() {
        assert!(
            Mx {
                preference: 0,
                exchange: String::new()
            }
            .is_null()
        );
        assert!(
            !Mx {
                preference: 10,
                exchange: String::new()
            }
            .is_null()
        );
        assert!(
            !Mx {
                preference: 0,
                exchange: "mx.example".into()
            }
            .is_null()
        );
    }

    #[test]
    fn names_normalized() {
        assert_eq!(normalize_name("MX.Example.ORG."), "mx.example.org");
        assert_eq!(normalize_name("."), "");
    }
}
