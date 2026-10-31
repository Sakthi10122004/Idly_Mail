//! DKIM key generation.
//!
//! ring cannot generate RSA keys, so RSA generation uses the `rsa` crate.
//! That crate has RUSTSEC-2023-0071 (timing side channel in private-key
//! operations); generating a key offline is not affected, and nothing else
//! in Idly uses it. clippy.toml forbids its signing and decryption APIs.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

/// A newly generated key.
#[derive(Debug)]
pub struct GeneratedKey {
    /// The private key, PKCS #8 DER (load with `SigningKey::from_pkcs8`).
    pub private_pkcs8: Vec<u8>,
    /// The TXT record to publish at `<selector>._domainkey.<domain>`.
    pub dns_record: String,
}

/// Why key generation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeygenError;

/// RSA key size. RFC 8301 §3.2: signers MUST use at least 1024 bits and
/// SHOULD use at least 2048.
pub const RSA_BITS: usize = 2048;

/// Generates a 2048-bit RSA key.
pub fn rsa() -> Result<GeneratedKey, KeygenError> {
    let key = RsaPrivateKey::new(&mut rand_core::OsRng, RSA_BITS).map_err(|_| KeygenError)?;
    let private_pkcs8 = key
        .to_pkcs8_der()
        .map_err(|_| KeygenError)?
        .as_bytes()
        .to_vec();
    // RFC 6376 §3.6.1: p= is the base64 SubjectPublicKeyInfo.
    let spki = key
        .to_public_key()
        .to_public_key_der()
        .map_err(|_| KeygenError)?;
    Ok(GeneratedKey {
        private_pkcs8,
        dns_record: format!("v=DKIM1; k=rsa; p={}", STANDARD.encode(spki.as_bytes())),
    })
}

/// Generates an Ed25519 key (RFC 8463).
pub fn ed25519() -> Result<GeneratedKey, KeygenError> {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| KeygenError)?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| KeygenError)?;
    // RFC 8463 §4: p= is the raw 32-byte public key.
    let public = STANDARD.encode(pair.public_key().as_ref());
    Ok(GeneratedKey {
        private_pkcs8: pkcs8.as_ref().to_vec(),
        dns_record: format!("v=DKIM1; k=ed25519; p={public}"),
    })
}
