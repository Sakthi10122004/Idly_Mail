//! TLS server configuration: rustls with the ring provider only, TLS 1.2
//! and 1.3, certificates from PEM files (ACME arrives in milestone 8).

use std::sync::Arc;

use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Why a TLS configuration could not be built.
#[derive(Debug)]
pub struct TlsError(pub String);

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TlsError {}

/// Builds a server config from a PEM certificate chain and private key.
pub fn server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<ServerConfig>, TlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError(format!("certificate file: {e}")))?;
    if certs.is_empty() {
        return Err(TlsError("certificate file has no certificates".into()));
    }
    let key =
        PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| TlsError(format!("key file: {e}")))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| TlsError(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsError(format!("certificate and key: {e}")))?;
    Ok(Arc::new(config))
}
