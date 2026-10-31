//! DKIM verification (RFC 6376 §6).

use dns::Resolver;
use ring::digest::{SHA256, digest};
use ring::signature::{ED25519, RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY, UnparsedPublicKey};

use super::canon;
use super::key::{KeyRecord, PublicKey};
use super::signature::{Algorithm, Signature, without_b_value};
use super::signed_data;
use crate::message::Message;

/// The most signatures checked per message; each costs a DNS lookup.
const MAX_SIGNATURES: usize = 8;

/// The result of checking one signature, named as in RFC 8601 §2.7.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimResult {
    /// The signature verified.
    Pass,
    /// The signature was checked and did not verify.
    Fail(&'static str),
    /// The signature verified but is not acceptable here: it covers only
    /// part of the body (`l=`). See below.
    Policy(&'static str),
    /// A temporary failure, such as a DNS timeout.
    TempError(&'static str),
    /// The signature or key can never be verified: bad syntax, no key, a
    /// revoked key, an expired signature.
    PermError(&'static str),
}

/// One verified (or failed) signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub result: DkimResult,
    /// `d=`, when the signature could be parsed.
    pub domain: Option<String>,
    /// `s=`, when the signature could be parsed.
    pub selector: Option<String>,
    /// `a=`, when the signature could be parsed.
    pub algorithm: Option<Algorithm>,
    /// The key record had `t=y` (the domain is testing DKIM).
    pub testing: bool,
}

/// Checks every DKIM-Signature on `message` (up to a limit). `now` is the
/// current time in Unix seconds, for `x=`.
pub async fn verify<R: Resolver>(resolver: &R, message: &[u8], now: u64) -> Vec<Verification> {
    let Ok(msg) = Message::parse(message) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for field in msg.headers_named("DKIM-Signature").take(MAX_SIGNATURES) {
        out.push(verify_one(resolver, &msg, field.raw, field.value, now).await);
    }
    out
}

async fn verify_one<R: Resolver>(
    resolver: &R,
    msg: &Message<'_>,
    raw: &[u8],
    value: &[u8],
    now: u64,
) -> Verification {
    let mut v = Verification {
        result: DkimResult::PermError(""),
        domain: None,
        selector: None,
        algorithm: None,
        testing: false,
    };
    let sig = match Signature::parse(value) {
        Ok(s) => s,
        Err(_) => {
            v.result = DkimResult::PermError("malformed signature");
            return v;
        }
    };
    v.domain = Some(sig.domain.clone());
    v.selector = Some(sig.selector.clone());
    v.algorithm = Some(sig.algorithm);
    // RFC 6376 §6.1.1: a signature past its x= time is invalid.
    if sig.expiration.is_some_and(|x| now > x) {
        v.result = DkimResult::PermError("signature expired");
        return v;
    }
    // RFC 6376 §3.6.2.1: the key lives at <selector>._domainkey.<domain>.
    let name = format!("{}._domainkey.{}", sig.selector, sig.domain);
    let key = match resolver.txt(&name).await {
        Ok(answer) => {
            // RFC 6376 §6.1.2: with several records, use one that parses.
            let mut first_err = None;
            let mut found = None;
            for txt in &answer.records {
                match KeyRecord::parse(txt, sig.algorithm.key_type()) {
                    Ok(k) => {
                        found = Some(k);
                        break;
                    }
                    Err(e) => first_err = first_err.or(Some(e)),
                }
            }
            match found {
                Some(k) => k,
                None => {
                    v.result = DkimResult::PermError(if first_err.is_some() {
                        "unusable key record"
                    } else {
                        "no key"
                    });
                    return v;
                }
            }
        }
        // RFC 6376 §6.1.2: no key record is a permanent failure.
        Err(e) if e.is_not_found() => {
            v.result = DkimResult::PermError("no key for signature");
            return v;
        }
        Err(_) => {
            v.result = DkimResult::TempError("key unavailable");
            return v;
        }
    };
    v.testing = key.testing;
    let Some(public) = key.key else {
        v.result = DkimResult::PermError("key revoked");
        return v;
    };
    // RFC 6376 §3.6.1 t=s: i= must not use a subdomain of d=.
    if key.strict
        && let Some(i) = &sig.identity
        && !i
            .rsplit_once('@')
            .is_some_and(|(_, d)| d.eq_ignore_ascii_case(&sig.domain))
    {
        v.result = DkimResult::PermError("key requires i= to equal d=");
        return v;
    }

    // RFC 6376 §3.7 step 1: the body hash.
    let body = canon::body_hash(sig.body_canon, msg.body, sig.length);
    if body.digest.as_ref() != sig.body_hash.as_slice() {
        v.result = DkimResult::Fail("body hash did not verify");
        return v;
    }
    // Step 2: the header hash, and the signature over it.
    let data = signed_data(msg, &sig.headers, sig.header_canon, &without_b_value(raw));
    let ok = match public {
        PublicKey::Rsa(der) => {
            // RFC 8301 §3.2: verifiers must accept 1024 to 4096 bit keys;
            // ring rejects anything under 1024.
            UnparsedPublicKey::new(&RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY, der)
                .verify(&data, &sig.signature)
                .is_ok()
        }
        // RFC 8463 §3: Ed25519 over the SHA-256 hash of the data.
        PublicKey::Ed25519(k) => UnparsedPublicKey::new(&ED25519, k)
            .verify(digest(&SHA256, &data).as_ref(), &sig.signature)
            .is_ok(),
    };
    if !ok {
        v.result = DkimResult::Fail("signature did not verify");
        return v;
    }
    // RFC 6376 §8.2: with l=, content can be appended after signing. We
    // only trust signatures that cover the whole body; a partial one is
    // "policy" (RFC 8601 §2.7.1: valid, but not acceptable to us).
    if sig.length.is_some_and(|l| l < body.canonical_len) {
        v.result = DkimResult::Policy("signature covers only part of the body");
        return v;
    }
    v.result = DkimResult::Pass;
    v
}
