//! DKIM signing (RFC 6376 §5) with ring.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::digest::{SHA256, digest};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};

use super::canon::{self, Canon};
use super::signature::{Algorithm, ascii_domain};
use super::signed_data;
use crate::message::Message;

/// A private signing key.
#[derive(Debug)]
pub enum SigningKey {
    /// RSA, at least 2048 bits (ring refuses smaller keys for signing).
    Rsa(RsaKeyPair),
    /// Ed25519 (RFC 8463).
    Ed25519(Ed25519KeyPair),
}

/// Why signing failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// The key could not be loaded.
    BadKey,
    /// The message has no From field (RFC 6376 §5.4: From MUST be signed).
    NoFrom,
    /// The message's header section is malformed.
    MalformedMessage,
    /// The domain or selector is invalid.
    BadDomain,
    /// The crypto library refused to sign.
    Crypto,
}

impl SigningKey {
    /// Loads a PKCS #8 DER key of either type.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, SignError> {
        if let Ok(k) = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der) {
            return Ok(Self::Ed25519(k));
        }
        RsaKeyPair::from_pkcs8(der)
            .map(Self::Rsa)
            .map_err(|_| SignError::BadKey)
    }

    /// The algorithm this key signs with.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::Rsa(_) => Algorithm::RsaSha256,
            Self::Ed25519(_) => Algorithm::Ed25519Sha256,
        }
    }

    /// Signs the RFC 6376 §3.7 data.
    pub(crate) fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignError> {
        match self {
            Self::Rsa(k) => {
                let mut sig = vec![0u8; k.public().modulus_len()];
                k.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), data, &mut sig)
                    .map_err(|_| SignError::Crypto)?;
                Ok(sig)
            }
            // RFC 8463 §3: Ed25519 (PureEdDSA) over the SHA-256 hash.
            Self::Ed25519(k) => Ok(k.sign(digest(&SHA256, data).as_ref()).as_ref().to_vec()),
        }
    }
}

/// Header fields to sign, after RFC 6376 §5.4.1's recommendations. Each is
/// signed once more than it occurs ("oversigning"), so none can be added
/// after signing without breaking the signature.
pub const DEFAULT_HEADERS: &[&str] = &[
    "From",
    "Reply-To",
    "Subject",
    "Date",
    "To",
    "Cc",
    "Message-ID",
    "In-Reply-To",
    "References",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
    "List-Id",
    "List-Unsubscribe",
    "List-Unsubscribe-Post",
    // RFC 8460 §5.3: TLS reports SHOULD sign these.
    "TLS-Report-Domain",
    "TLS-Report-Submitter",
    "Auto-Submitted",
];

/// Signs messages for one domain and selector.
#[derive(Debug)]
pub struct Signer {
    key: SigningKey,
    domain: String,
    selector: String,
}

impl Signer {
    /// A signer for `d=domain`, `s=selector`.
    pub fn new(key: SigningKey, domain: &str, selector: &str) -> Result<Self, SignError> {
        let domain = ascii_domain(domain).ok_or(SignError::BadDomain)?;
        let selector = ascii_domain(selector).ok_or(SignError::BadDomain)?;
        Ok(Self {
            key,
            domain,
            selector,
        })
    }

    /// Returns a complete `DKIM-Signature:` field, CRLF-terminated, to put
    /// at the top of `message`. Uses relaxed/relaxed canonicalization.
    /// `now` is the signing time in Unix seconds (`t=`).
    pub fn sign(&self, message: &[u8], now: u64) -> Result<String, SignError> {
        let msg = Message::parse(message).map_err(|_| SignError::MalformedMessage)?;
        if msg.headers_named("From").next().is_none() {
            return Err(SignError::NoFrom);
        }
        let mut names = Vec::new();
        for &name in DEFAULT_HEADERS {
            let present = msg.headers_named(name).count();
            if present > 0 {
                names.extend(std::iter::repeat_n(name.to_ascii_lowercase(), present + 1));
            }
        }
        let body_hash = canon::body_hash(Canon::Relaxed, msg.body, None);
        let field = format!(
            "DKIM-Signature: v=1; a={}; c=relaxed/relaxed; d={}; s={};\r\n\tt={}; h={};\r\n\tbh={};\r\n\tb=",
            self.key.algorithm().name(),
            self.domain,
            self.selector,
            now,
            names.join(":"),
            STANDARD.encode(body_hash.digest.as_ref()),
        );
        let data = signed_data(&msg, &names, Canon::Relaxed, field.as_bytes());
        let sig = STANDARD.encode(self.key.sign(&data)?);
        // Fold the signature into lines of at most 72 characters.
        let mut out = field;
        for (i, chunk) in sig.as_bytes().chunks(72).enumerate() {
            if i > 0 {
                out.push_str("\r\n\t ");
            }
            out.push_str(core::str::from_utf8(chunk).unwrap_or_default());
        }
        out.push_str("\r\n");
        Ok(out)
    }
}
