//! The certificate every TLS listener presents, swappable at run time: a
//! renewal (or a changed certificate file) takes effect for the next
//! handshake without a restart.

use std::sync::{Arc, RwLock};

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Hands rustls the current certificate.
#[derive(Debug)]
pub struct Certs {
    current: RwLock<Arc<CertifiedKey>>,
}

impl Certs {
    pub fn new(first: Arc<CertifiedKey>) -> Arc<Self> {
        Arc::new(Self {
            current: RwLock::new(first),
        })
    }

    /// Replaces the certificate for new handshakes.
    pub fn set(&self, key: Arc<CertifiedKey>) {
        match self.current.write() {
            Ok(mut c) => *c = key,
            Err(poisoned) => *poisoned.into_inner() = key,
        }
    }

    pub fn current(&self) -> Arc<CertifiedKey> {
        match self.current.read() {
            Ok(c) => c.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl ResolvesServerCert for Certs {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

/// A chain and its key, checked to belong together.
pub fn certified_key(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<CertifiedKey>, String> {
    let provider = rustls::crypto::ring::default_provider();
    CertifiedKey::from_der(chain, key, &provider)
        .map(Arc::new)
        .map_err(|e| format!("certificate and key: {e}"))
}

/// The private key of `key` in the form rustls takes.
pub fn private_key(key: &KeyPair) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()))
}

/// A self-signed stand-in for `hostname`, used until the first ACME
/// certificate arrives. Opportunistic STARTTLS senders accept it (RFC 7435
/// §4); it is never written to disk.
pub fn self_signed(hostname: &str, key: &KeyPair) -> Result<Arc<CertifiedKey>, String> {
    let mut params = CertificateParams::new(vec![hostname.to_owned()])
        .map_err(|e| format!("self-signed certificate for {hostname}: {e}"))?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, hostname);
    let cert = params
        .self_signed(key)
        .map_err(|e| format!("self-signed certificate for {hostname}: {e}"))?;
    certified_key(vec![cert.der().clone()], private_key(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mismatched_key_is_refused() {
        let a = KeyPair::generate().unwrap();
        let b = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["mx.example.org".into()])
            .unwrap()
            .self_signed(&a)
            .unwrap();
        assert!(certified_key(vec![cert.der().clone()], private_key(&a)).is_ok());
        assert!(certified_key(vec![cert.der().clone()], private_key(&b)).is_err());
    }

    #[test]
    fn set_swaps_the_certificate() {
        let key = KeyPair::generate().unwrap();
        let first = self_signed("one.example.org", &key).unwrap();
        let second = self_signed("two.example.org", &key).unwrap();
        let certs = Certs::new(first.clone());
        assert!(Arc::ptr_eq(&certs.current(), &first));
        certs.set(second.clone());
        assert!(Arc::ptr_eq(&certs.current(), &second));
    }
}
