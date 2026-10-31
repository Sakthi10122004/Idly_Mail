//! SPF, DKIM, DMARC and Authentication-Results for Idly Mail.
//!
//! All DNS goes through the `dns` crate's resolver (our own recursive,
//! DNSSEC-validating one); all crypto through ring.

#![forbid(unsafe_code)]

pub mod dkim;
pub mod message;
pub mod tags;
