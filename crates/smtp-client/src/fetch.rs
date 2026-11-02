//! Fetching an MTA-STS policy over HTTPS (RFC 8461 §3.3). The connection
//! goes through the same [`Dialer`] as SMTP, so the SSRF guard applies: a
//! policy host resolving to a private address is never contacted.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dns::Resolver;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper::header::{CONTENT_TYPE, HOST, USER_AGENT};
use hyper_util::rt::TokioIo;
use rustls::RootCertStore;
use rustls_pki_types::ServerName;
use tokio::time::timeout;

use crate::dialer::Dialer;
use crate::mta_sts::{MAX_POLICY_SIZE, Policy, parse_policy};
use crate::route::Families;
use crate::{Sources, tls};

/// RFC 8461 §3.3: "a suggested timeout is one minute".
const FETCH_TIMEOUT: Duration = Duration::from_secs(60);

/// Fetches and parses `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
pub(crate) async fn fetch<R: Resolver, D: Dialer>(
    resolver: &R,
    dialer: &D,
    roots: &Arc<RootCertStore>,
    families: Families,
    sources: Sources,
    domain: &str,
) -> Result<Policy, String> {
    match timeout(
        FETCH_TIMEOUT,
        fetch_inner(resolver, dialer, roots, families, sources, domain),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Err("policy fetch timed out".into()),
    }
}

async fn fetch_inner<R: Resolver, D: Dialer>(
    resolver: &R,
    dialer: &D,
    roots: &Arc<RootCertStore>,
    families: Families,
    sources: Sources,
    domain: &str,
) -> Result<Policy, String> {
    let host = format!("mta-sts.{domain}");
    let mut addrs: Vec<IpAddr> = Vec::new();
    if families.ipv4
        && let Ok(a) = resolver.a(&host).await
    {
        addrs.extend(a.records);
    }
    if families.ipv6
        && let Ok(a) = resolver.aaaa(&host).await
    {
        addrs.extend(a.records);
    }
    if addrs.is_empty() {
        return Err(format!("{host} has no address"));
    }
    let mut last = String::new();
    let mut tcp = None;
    for ip in addrs.into_iter().take(4) {
        match dialer
            .connect(SocketAddr::new(ip, 443), sources.for_ip(ip))
            .await
        {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last = format!("{ip}: {e}"),
        }
    }
    let tcp = tcp.ok_or_else(|| format!("cannot connect to {host}: {last}"))?;

    // RFC 8461 §3.3: the certificate must be valid for the policy host and
    // chain to a trusted root.
    let config = tls::client_config(&tls::Policy::WebPki, roots).map_err(|e| e.to_string())?;
    let name = ServerName::try_from(host.clone()).map_err(|_| format!("{host}: bad name"))?;
    let stream = tokio_rustls::TlsConnector::from(config)
        .connect(name, tcp)
        .await
        .map_err(|e| format!("TLS with {host}: {e}"))?;

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| format!("HTTP with {host}: {e}"))?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = hyper::Request::get("/.well-known/mta-sts.txt")
        .header(HOST, &host)
        .header(USER_AGENT, "Idly Mail")
        .body(Empty::<Bytes>::new())
        .map_err(|e| e.to_string())?;
    let result = async {
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| format!("HTTP with {host}: {e}"))?;
        // RFC 8461 §3.3: only 200 counts; redirects are not followed.
        if response.status() != hyper::StatusCode::OK {
            return Err(format!("{host} answered HTTP {}", response.status()));
        }
        // RFC 8461 §3.2: senders SHOULD check the media type is text/plain.
        let text_plain = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|t| t.trim().eq_ignore_ascii_case("text/plain"));
        if !text_plain {
            return Err(format!("{host} did not serve text/plain"));
        }
        let body = Limited::new(response.into_body(), MAX_POLICY_SIZE)
            .collect()
            .await
            .map_err(|e| format!("policy body from {host}: {e}"))?
            .to_bytes();
        let text =
            std::str::from_utf8(&body).map_err(|_| format!("policy from {host} is not UTF-8"))?;
        parse_policy(text).ok_or_else(|| format!("invalid policy from {host}"))
    }
    .await;
    driver.abort();
    result
}
