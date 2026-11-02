//! Preparing an authenticated submission (RFC 6409) for delivery: sender
//! authorization, Date/Message-ID, line-length fixing, DKIM signing.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use mail_auth_glue::dkim::Signer;
use mail_auth_glue::message::{Message, address_list};
use mail_auth_glue::mime::{self, MimeError};
use smtp_proto::address::domain_to_ascii;
use smtp_proto::date::rfc5322;

use crate::auth::Accounts;

/// DKIM keys by domain (A-label, lower-case). Every key of the From
/// domain signs, so RSA and Ed25519 keys give a dual signature (RFC 8463).
#[derive(Debug, Default)]
pub struct DkimKeys {
    by_domain: HashMap<String, Vec<Signer>>,
}

impl DkimKeys {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a signer for `domain`.
    pub fn add(&mut self, domain: &str, signer: Signer) {
        let key = domain_to_ascii(domain).unwrap_or_else(|_| domain.to_ascii_lowercase());
        self.by_domain.entry(key).or_default().push(signer);
    }

    /// Whether any key exists for `domain`.
    pub fn has(&self, domain: &str) -> bool {
        self.by_domain.contains_key(domain)
    }

    fn sign(&self, domain: &str, message: &[u8], now: u64) -> Vec<String> {
        let Some(signers) = self.by_domain.get(domain) else {
            return Vec::new();
        };
        signers
            .iter()
            .filter_map(|s| match s.sign(message, now) {
                Ok(h) => Some(h),
                Err(e) => {
                    tracing::error!(domain, error = ?e, "DKIM signing failed");
                    None
                }
            })
            .collect()
    }
}

/// Why a submission was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// A From address isn't one the account may use.
    SenderNotOwned,
    /// Lines could not be brought within 998 octets.
    Unencodable(MimeError),
}

/// Checks and prepares a submitted message. Returns the message to deliver.
pub(crate) fn prepare(
    accounts: &dyn Accounts,
    account: &str,
    dkim: Option<&DkimKeys>,
    hostname: &str,
    id: &str,
    message: &[u8],
) -> Result<Vec<u8>, Refusal> {
    let parsed = Message::parse(message).map_err(|_| Refusal::SenderNotOwned)?;
    // The From header must exist (RFC 5322 §3.6: exactly one) and every
    // address in it must belong to the account.
    let mut froms = parsed.headers_named("From");
    let (Some(from), None) = (froms.next(), froms.next()) else {
        return Err(Refusal::SenderNotOwned);
    };
    let addresses = address_list(from.value)
        .filter(|a| !a.is_empty())
        .ok_or(Refusal::SenderNotOwned)?;
    if !addresses.iter().all(|a| accounts.may_send_as(account, a)) {
        return Err(Refusal::SenderNotOwned);
    }
    let author_domain = addresses
        .first()
        .and_then(|a| a.rsplit_once('@'))
        .map(|(_, d)| d.to_owned())
        .unwrap_or_default();

    let now = SystemTime::now();
    let secs = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let mut added = String::new();
    // RFC 6409 §8.2 and §8.3: add Date and Message-ID if missing.
    if parsed.headers_named("Date").next().is_none() {
        added.push_str(&format!("Date: {}\r\n", rfc5322(now)));
    }
    if parsed.headers_named("Message-ID").next().is_none() {
        added.push_str(&format!("Message-ID: <{id}@{hostname}>\r\n"));
    }
    let mut prepared = added.into_bytes();
    prepared.extend_from_slice(message);

    // RFC 6376 §5.3: convert 8-bit bodies to 7 bits BEFORE signing, so a
    // later downgrade for a server without 8BITMIME (RFC 6152 §3) can't
    // break the signature. Mail with 8-bit header fields needs SMTPUTF8,
    // and SMTPUTF8 servers always offer 8BITMIME (RFC 6531 §3.1), so it
    // is never downgraded and is signed as it is.
    let header_end = prepared
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(prepared.len());
    let ascii_headers = prepared.get(..header_end).is_some_and(<[u8]>::is_ascii);
    let seven_bit = if ascii_headers && mime::is_eight_bit(&prepared) {
        match mime::to_seven_bit(&prepared) {
            Ok(m) => Some(m.into_owned()),
            Err(e) => {
                tracing::info!(error = ?e, "8-bit submission can't be converted to 7 bits; signing it as it is");
                None
            }
        }
    } else {
        None
    };
    // CLAUDE.md: re-encode lines over 998 octets BEFORE signing (RFC 6409 §8.4).
    let prepared = match seven_bit {
        Some(m) => m,
        None => mime::fix_long_lines(&prepared)
            .map_err(Refusal::Unencodable)?
            .into_owned(),
    };

    // RFC 6409 §8.5: the MSA may sign; we sign with the From domain's keys.
    let mut out = Vec::with_capacity(prepared.len() + 1024);
    if let Some(keys) = dkim {
        let signatures = keys.sign(&author_domain, &prepared, secs);
        if signatures.is_empty() {
            tracing::warn!(domain = %author_domain, "no DKIM key for this domain; sending unsigned");
        }
        for s in signatures {
            out.extend_from_slice(s.as_bytes());
        }
    }
    out.extend_from_slice(&prepared);
    Ok(out)
}
