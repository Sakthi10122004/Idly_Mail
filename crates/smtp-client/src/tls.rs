//! TLS for outbound SMTP. The policy for each MX host, strongest first:
//!
//! 1. DANE (RFC 7672) when the host's TLSA records are DNSSEC-secure: TLS
//!    is mandatory and the certificate must match a TLSA record. No
//!    plaintext fallback.
//! 2. MTA-STS `enforce` (RFC 8461): TLS is mandatory and the certificate
//!    must be valid for the MX host name under the system's trusted roots.
//! 3. Opportunistic STARTTLS (RFC 7435): encrypt when offered, without
//!    authenticating the server.

use std::sync::Arc;

use dns::Tlsa;
use ring::digest::{SHA256, SHA512, digest};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

/// The TLS requirement for one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Policy {
    /// Use STARTTLS when offered; don't check the certificate.
    Opportunistic,
    /// DANE TLSA records exist but none is usable: TLS is still mandatory,
    /// without authentication (RFC 7672 §2.2).
    EncryptOnly,
    /// Mandatory TLS, authenticated by these usable TLSA records.
    Dane(Vec<Tlsa>),
    /// Mandatory TLS with a WebPKI certificate for the host (MTA-STS).
    WebPki,
}

impl Policy {
    /// Whether delivery must not happen without TLS.
    pub(crate) fn required(&self) -> bool {
        !matches!(self, Self::Opportunistic)
    }

    /// A short name for logs.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Opportunistic => "opportunistic",
            Self::EncryptOnly => "dane-encrypt-only",
            Self::Dane(_) => "dane",
            Self::WebPki => "mta-sts",
        }
    }
}

/// RFC 7672 §3.1.3: PKIX-TA(0) and PKIX-EE(1) are not usable for SMTP;
/// only DANE-TA(2) and DANE-EE(3), with known selectors and matching types.
pub(crate) fn usable(t: &Tlsa) -> bool {
    matches!(t.usage, 2 | 3) && matches!(t.selector, 0 | 1) && matches!(t.matching, 0..=2)
}

pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The client configuration for `policy`. `roots` are the trusted CAs for
/// MTA-STS (the system's roots in production).
pub(crate) fn client_config(
    policy: &Policy,
    roots: &Arc<RootCertStore>,
) -> Result<Arc<ClientConfig>, rustls::Error> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?;
    let config = match policy {
        Policy::WebPki => builder
            .with_root_certificates(roots.clone())
            .with_no_client_auth(),
        Policy::Dane(tlsa) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DaneVerifier {
                tlsa: tlsa.clone(),
                provider,
            }))
            .with_no_client_auth(),
        Policy::Opportunistic | Policy::EncryptOnly => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate { provider }))
            .with_no_client_auth(),
    };
    Ok(Arc::new(config))
}

/// A DER length header for `len` octets.
fn der_header(tag: u8, len: usize) -> Vec<u8> {
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        let significant = bytes.get(skip..).unwrap_or_default();
        out.push(0x80 | u8::try_from(significant.len()).unwrap_or(0));
        out.extend_from_slice(significant);
    }
    out
}

/// The DER SubjectPublicKeyInfo of a certificate.
fn spki(cert: &CertificateDer<'_>) -> Option<Vec<u8>> {
    let mut store = RootCertStore::empty();
    store.add(cert.clone()).ok()?;
    // The trust anchor holds the SPKI contents without the outer SEQUENCE.
    let inner = store
        .roots
        .first()?
        .subject_public_key_info
        .as_ref()
        .to_vec();
    let mut out = der_header(0x30, inner.len());
    out.extend_from_slice(&inner);
    Some(out)
}

/// Whether `cert` matches the TLSA record (RFC 6698 §2.1.2, §2.1.3).
pub(crate) fn matches(t: &Tlsa, cert: &CertificateDer<'_>) -> bool {
    let data = match t.selector {
        0 => cert.as_ref().to_vec(),
        1 => match spki(cert) {
            Some(s) => s,
            None => return false,
        },
        _ => return false,
    };
    match t.matching {
        0 => data == t.data,
        1 => digest(&SHA256, &data).as_ref() == t.data.as_slice(),
        2 => digest(&SHA512, &data).as_ref() == t.data.as_slice(),
        _ => false,
    }
}

/// Authenticates the server with TLSA records (RFC 7672 §3).
#[derive(Debug)]
struct DaneVerifier {
    tlsa: Vec<Tlsa>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for DaneVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // RFC 7672 §3.1.1: DANE-EE matches the server's own certificate;
        // its names and validity dates are not checked.
        if self
            .tlsa
            .iter()
            .any(|t| t.usage == 3 && matches(t, end_entity))
        {
            return Ok(ServerCertVerified::assertion());
        }
        // RFC 7672 §3.1.2: DANE-TA names a trust anchor that the server
        // includes in its chain; the chain is then checked normally,
        // including the MX host name (§3.2.2) and expiry.
        for ta in intermediates {
            if !self.tlsa.iter().any(|t| t.usage == 2 && matches(t, ta)) {
                continue;
            }
            let mut roots = RootCertStore::empty();
            if roots.add(ta.clone()).is_err() {
                continue;
            }
            let Ok(verifier) =
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
                    .build()
            else {
                continue;
            };
            if verifier
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .is_ok()
            {
                return Ok(ServerCertVerified::assertion());
            }
        }
        Err(rustls::Error::General(
            "certificate matches no DANE TLSA record".into(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Opportunistic TLS (RFC 7435): any certificate is accepted, but the
/// handshake signature must still be valid for it.
#[derive(Debug)]
struct AnyCertificate {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_matches_the_key() {
        let key = rcgen::generate_simple_self_signed(vec!["mx.example.com".into()]).unwrap();
        let cert = key.cert.der().clone();
        assert_eq!(
            spki(&cert).unwrap(),
            rcgen::PublicKeyData::subject_public_key_info(&key.signing_key)
        );
        let sha = digest(
            &SHA256,
            &rcgen::PublicKeyData::subject_public_key_info(&key.signing_key),
        );
        let t = Tlsa {
            usage: 3,
            selector: 1,
            matching: 1,
            data: sha.as_ref().to_vec(),
        };
        assert!(matches(&t, &cert));
        let full = Tlsa {
            usage: 3,
            selector: 0,
            matching: 0,
            data: cert.as_ref().to_vec(),
        };
        assert!(matches(&full, &cert));
        let wrong = Tlsa {
            data: vec![0; 32],
            ..t
        };
        assert!(!matches(&wrong, &cert));
    }

    #[test]
    fn der_lengths() {
        assert_eq!(der_header(0x30, 5), [0x30, 5]);
        assert_eq!(der_header(0x30, 0x80), [0x30, 0x81, 0x80]);
        assert_eq!(der_header(0x30, 0x1234), [0x30, 0x82, 0x12, 0x34]);
    }

    #[test]
    fn usable_tlsa() {
        let t = |usage, selector, matching| Tlsa {
            usage,
            selector,
            matching,
            data: vec![],
        };
        assert!(usable(&t(3, 1, 1)) && usable(&t(2, 0, 2)));
        assert!(!usable(&t(0, 1, 1)) && !usable(&t(1, 1, 1)));
        assert!(!usable(&t(3, 2, 1)) && !usable(&t(3, 1, 3)));
    }
}
