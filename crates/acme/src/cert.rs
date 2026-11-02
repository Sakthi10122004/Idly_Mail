//! Reading certificates: the PEM chain, and from the leaf the validity
//! period, the DNS names and the public key. Certificates come from the
//! ACME server or the operator's files; the parsing itself is done by
//! `x509-cert`, and nothing here panics on bad input (fuzz target
//! `cert_inspect`).

use der::{Decode, Encode};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use x509_cert::Certificate;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;

/// What the renewal logic needs to know about a leaf certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// notBefore and notAfter, in seconds since the Unix epoch
    /// (RFC 5280 §4.1.2.5).
    pub not_before: u64,
    pub not_after: u64,
    /// The dNSName entries of subjectAltName (RFC 5280 §4.2.1.6),
    /// lower-cased.
    pub names: Vec<String>,
    /// The DER SubjectPublicKeyInfo, as hashed for DANE `3 1 1`
    /// (RFC 6698 §2.1.2).
    pub spki: Vec<u8>,
}

impl Info {
    /// Whether the certificate is valid for `name` (exact match; we never
    /// request wildcards).
    pub fn covers(&self, name: &str) -> bool {
        self.names.iter().any(|n| n.eq_ignore_ascii_case(name))
    }

    /// When to renew: once two thirds of the lifetime have passed, so a
    /// 90-day certificate is renewed with 30 days left and a short-lived
    /// one in proportion.
    pub fn renew_at(&self) -> u64 {
        let life = self.not_after.saturating_sub(self.not_before);
        self.not_before.saturating_add(life / 3 * 2)
    }
}

/// Parses a PEM chain (leaf first).
pub fn chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("bad PEM: {e}"))?;
    if certs.is_empty() {
        return Err("no certificate in the PEM data".into());
    }
    Ok(certs)
}

/// Reads the facts we need from a DER certificate.
pub fn inspect(der: &[u8]) -> Result<Info, String> {
    let cert = Certificate::from_der(der).map_err(|e| format!("bad certificate: {e}"))?;
    let tbs = &cert.tbs_certificate;
    let not_before = tbs.validity.not_before.to_unix_duration().as_secs();
    let not_after = tbs.validity.not_after.to_unix_duration().as_secs();
    let mut names = Vec::new();
    if let Ok(Some((_, san))) = tbs.get::<SubjectAltName>() {
        for name in san.0 {
            if let GeneralName::DnsName(n) = name {
                names.push(n.as_str().to_ascii_lowercase());
            }
        }
    }
    let spki = tbs
        .subject_public_key_info
        .to_der()
        .map_err(|e| format!("bad public key: {e}"))?;
    Ok(Info {
        not_before,
        not_after,
        names,
        spki,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair, PublicKeyData};

    #[test]
    fn reads_names_validity_and_key() {
        let key = KeyPair::generate().unwrap();
        let mut params =
            CertificateParams::new(vec!["MX.example.org".into(), "mta-sts.example.org".into()])
                .unwrap();
        params.not_before = rcgen::date_time_ymd(2026, 1, 1);
        params.not_after = rcgen::date_time_ymd(2026, 4, 1);
        let cert = params.self_signed(&key).unwrap();
        let info = inspect(cert.der()).unwrap();
        assert_eq!(info.names, ["mx.example.org", "mta-sts.example.org"]);
        assert!(info.covers("mta-sts.EXAMPLE.org"));
        assert!(!info.covers("example.org"));
        assert_eq!(info.not_before, 1_767_225_600);
        assert_eq!(info.not_after, 1_775_001_600);
        assert_eq!(info.spki, key.subject_public_key_info());
        // 90 days: renew with 30 left.
        assert_eq!(info.renew_at(), 1_767_225_600 + 60 * 86_400);

        let pem = format!("{}\n{}", cert.pem(), cert.pem());
        assert_eq!(chain(pem.as_bytes()).unwrap().len(), 2);
    }

    #[test]
    fn garbage_is_an_error() {
        assert!(inspect(b"").is_err());
        assert!(inspect(&[0x30, 0x82, 0xff]).is_err());
        assert!(chain(b"nothing here").is_err());
    }
}
