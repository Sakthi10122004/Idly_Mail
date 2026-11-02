//! SMTP AUTH (RFC 4954) uses the shared login code in the `auth` crate.

pub use auth::{Accounts, AuthLimits};
pub(crate) use auth::{Guard, decode, parse_plain};
