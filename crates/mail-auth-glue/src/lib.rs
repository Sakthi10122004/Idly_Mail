//! SPF, DKIM, DMARC and Authentication-Results for Idly Mail.
//!
//! All DNS goes through the `dns` crate's resolver (our own recursive,
//! DNSSEC-validating one); all crypto through ring.

#![forbid(unsafe_code)]

pub mod auth_results;
pub mod dkim;
pub mod dmarc;
pub mod message;
pub mod mime;
pub mod spf;
pub mod tags;
