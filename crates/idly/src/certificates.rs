//! Where the TLS certificate comes from: `[tls]` files, re-read when they
//! change, or an ACME CA (`[acme]`). Either way every TLS listener asks
//! one [`acme::Certs`] for the certificate, so a new one is used at the
//! next handshake. Also starts the MTA-STS policy server.

use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use acme::cert::Info;
use acme::instant_acme::{BodyWrapper, BytesResponse, HttpClient};
use acme::{Certs, Challenges, Manager, Site};
use http_body_util::{BodyExt, Full};
use hyper::Response;
use hyper::body::Bytes;
use rustls::sign::CertifiedKey;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;

use crate::config::{self, Config};
use crate::metrics::Metrics;

/// How often `[tls]` files are checked for changes.
const FILE_CHECK: Duration = Duration::from_secs(300);
/// The largest ACME response we read (a certificate chain is a few KiB).
const MAX_ACME_RESPONSE: usize = 1024 * 1024;

/// The guarded HTTPS client the ACME CA is reached with.
pub(crate) type Https = smtp_client::Https<dns::Recursive, smtp_client::Direct>;

/// Sets up the certificate source and its background tasks. None when
/// there is neither `[tls]` nor `[acme]`.
pub(crate) async fn start(
    config: &Config,
    metrics: &Arc<Metrics>,
    https: Https,
) -> io::Result<Option<Arc<Certs>>> {
    let names = config.certificate_names();
    let certs = if let Some(files) = &config.tls {
        let (key, info) = load_files(files).map_err(io::Error::other)?;
        warn_uncovered(&info, &names);
        metrics.certificate_expiry.set(gauge(&info));
        let certs = Certs::new(key);
        tokio::spawn(watch_files(
            files.clone(),
            certs.clone(),
            metrics.clone(),
            names,
        ));
        certs
    } else if let Some(a) = &config.acme {
        let store = acme::Store::open(&config.server.data_dir.join("acme"))?;
        let challenges = Challenges::default();
        for (addr, listener) in crate::listen::bind_all(&a.listen)? {
            tracing::info!(%addr, "ACME HTTP-01 listener ready");
            tokio::spawn(serve(
                addr,
                acme::web::serve(listener, Site::Challenges(challenges.clone()), None),
            ));
        }
        let https = Arc::new(https);
        let http: acme::HttpFactory =
            Arc::new(move || Box::new(AcmeHttp(https.clone())) as Box<dyn HttpClient>);
        let settings = acme::Settings {
            directory: a.directory_url().to_owned(),
            contact: a.contact.clone(),
            names,
        };
        tracing::info!(directory = %settings.directory, names = ?settings.names, "TLS certificates from ACME");
        let manager =
            Arc::new(Manager::new(settings, store, challenges, http).map_err(io::Error::other)?);
        let certs = manager.certs();
        tokio::spawn(manager.clone().run());
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(FILE_CHECK);
            loop {
                tick.tick().await;
                metrics
                    .certificate_expiry
                    .set(manager.info().as_ref().map_or(0, gauge));
            }
        });
        certs
    } else {
        return Ok(None);
    };

    if config.mta_sts.enabled {
        serve_mta_sts(config, certs.clone()).await?;
    }
    Ok(Some(certs))
}

/// HTTPS on port 443 for `mta-sts.<domain>` (RFC 8461 §3.2).
async fn serve_mta_sts(config: &Config, certs: Arc<Certs>) -> io::Result<()> {
    let policies = Arc::new(crate::mta_sts::policies(config));
    // RFC 8461 §3.1: senders refetch only when this id changes.
    let id = crate::mta_sts::policy_id(&crate::mta_sts::policy(config));
    tracing::info!(id = %id, "MTA-STS: publish \"v=STSv1; id={id}\" at _mta-sts.<domain> for every domain");
    let mut tls = (*smtp_server::tls::server_config_with(certs).map_err(io::Error::other)?).clone();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    for (addr, listener) in crate::listen::bind_all(&config.mta_sts.listen)? {
        tracing::info!(%addr, mode = config.mta_sts.mode.as_str(), "MTA-STS policy listener ready");
        tokio::spawn(serve(
            addr,
            acme::web::serve(
                listener,
                Site::MtaSts(policies.clone()),
                Some(acceptor.clone()),
            ),
        ));
    }
    Ok(())
}

async fn serve(addr: std::net::SocketAddr, server: impl Future<Output = io::Result<()>>) {
    if let Err(e) = server.await {
        tracing::error!(%addr, error = %e, "web listener failed");
    }
}

/// Reads and checks `[tls]` files.
pub(crate) fn load_files(files: &config::Tls) -> Result<(Arc<CertifiedKey>, Info), String> {
    let read = |p: &Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    let chain = acme::cert::chain(&read(&files.cert_file)?)
        .map_err(|e| format!("{}: {e}", files.cert_file.display()))?;
    let info = chain
        .first()
        .map(|leaf| acme::cert::inspect(leaf))
        .transpose()
        .map_err(|e| format!("{}: {e}", files.cert_file.display()))?
        .ok_or("empty chain")?;
    let key = PrivateKeyDer::from_pem_slice(&read(&files.key_file)?)
        .map_err(|e| format!("{}: {e}", files.key_file.display()))?;
    let ck = acme::certs::certified_key(chain, key)?;
    Ok((ck, info))
}

/// Picks up changed `[tls]` files (e.g. after certbot renewed them). A
/// broken new pair is logged and the old certificate kept.
async fn watch_files(
    files: config::Tls,
    certs: Arc<Certs>,
    metrics: Arc<Metrics>,
    names: Vec<String>,
) {
    let stamp = |f: &config::Tls| {
        let m = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
        (m(&f.cert_file), m(&f.key_file))
    };
    let mut seen = stamp(&files);
    loop {
        tokio::time::sleep(FILE_CHECK).await;
        let now = stamp(&files);
        if now == seen {
            continue;
        }
        seen = now;
        match load_files(&files) {
            Ok((key, info)) => {
                warn_uncovered(&info, &names);
                metrics.certificate_expiry.set(gauge(&info));
                certs.set(key);
                tracing::info!(
                    not_after = info.not_after,
                    "reloaded the TLS certificate files"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "changed TLS files don't load; keeping the old certificate")
            }
        }
    }
}

fn warn_uncovered(info: &Info, names: &[String]) {
    for name in names.iter().filter(|n| !info.covers(n)) {
        tracing::warn!(name = %name, "the TLS certificate does not cover this name");
    }
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if info.not_after <= now {
        tracing::error!(
            not_after = info.not_after,
            "the TLS certificate has expired"
        );
    }
}

fn gauge(info: &Info) -> i64 {
    i64::try_from(info.not_after).unwrap_or(i64::MAX)
}

/// instant-acme's HTTP client trait, on top of our guarded HTTPS client.
struct AcmeHttp(Arc<Https>);

impl HttpClient for AcmeHttp {
    fn request(
        &self,
        req: hyper::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, acme::instant_acme::Error>> + Send>>
    {
        let https = self.0.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let body = body
                .collect()
                .await
                .map(http_body_util::Collected::to_bytes)
                .unwrap_or_default();
            let url = parts.uri.to_string();
            let (status, headers, bytes) = https
                .send(parts.method, &url, parts.headers, body, MAX_ACME_RESPONSE)
                .await
                .map_err(|e| acme::instant_acme::Error::Other(e.into()))?;
            let mut response = Response::new(Full::new(bytes));
            *response.status_mut() = status;
            *response.headers_mut() = headers;
            Ok(BytesResponse::from(response))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_must_match() {
        let dir = tempfile::tempdir().unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let other = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["mx.example.org".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let files = config::Tls {
            cert_file: dir.path().join("cert.pem"),
            key_file: dir.path().join("key.pem"),
        };
        std::fs::write(&files.cert_file, cert.pem()).unwrap();
        std::fs::write(&files.key_file, key.serialize_pem()).unwrap();
        let (_, info) = load_files(&files).unwrap();
        assert!(info.covers("mx.example.org"));
        std::fs::write(&files.key_file, other.serialize_pem()).unwrap();
        assert!(load_files(&files).is_err());
        std::fs::remove_file(&files.cert_file).unwrap();
        assert!(load_files(&files).unwrap_err().contains("cert.pem"));
    }
}
