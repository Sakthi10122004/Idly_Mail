//! TLS certificates from an ACME CA (RFC 8555), and the small web servers
//! that go with them: HTTP-01 challenges on port 80 and MTA-STS policies
//! (RFC 8461 §3.2) on port 443.
//!
//! The certificate key is generated once and kept across renewals, so a
//! DANE `3 1 1` TLSA record stays valid (RFC 7671 §5.1). The certificate
//! is served through [`Certs`], which renewals update in place.
//!
//! All ACME traffic goes through the [`HttpClient`](instant_acme::HttpClient)
//! the caller supplies; `idly` passes one that uses our own resolver and the
//! outbound address guard.

#![forbid(unsafe_code)]

pub mod cert;
pub mod certs;
pub mod manager;
pub mod store;
pub mod web;

pub use certs::Certs;
pub use instant_acme;
pub use manager::{HttpFactory, Manager, Settings};
pub use store::Store;
pub use web::{Challenges, Site};

/// Let's Encrypt's production directory.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Let's Encrypt's staging directory, for testing a setup.
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
