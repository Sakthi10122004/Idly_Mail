//! HTTPS for MTA-STS policy fetches (RFC 8461 §3.3) and TLS report
//! uploads (RFC 8460 §5.4), and for the ACME client ([`Https`]). Connections go through the same [`Dialer`] as
//! SMTP, so the SSRF guard applies: a host resolving to a private address
//! is never contacted. Certificates are always checked against the
//! trusted roots.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dns::Resolver;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{CONTENT_TYPE, HOST, HeaderValue, USER_AGENT};
use hyper::{HeaderMap, Method, StatusCode};
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
/// A report upload's response body is read (and discarded) up to this.
const MAX_POST_RESPONSE: usize = 64 * 1024;

/// Where an HTTPS request goes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Net<'a, R, D> {
    pub(crate) resolver: &'a R,
    pub(crate) dialer: &'a D,
    pub(crate) roots: &'a Arc<RootCertStore>,
    pub(crate) families: Families,
    pub(crate) sources: Sources,
}

/// Why an HTTPS request failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Failure {
    /// No address, or no connection.
    Connect(String),
    /// The TLS handshake or certificate check failed.
    Tls(String),
    /// HTTP-level trouble: a protocol error, a bad status, a bad body.
    Http(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) | Self::Tls(e) | Self::Http(e) => f.write_str(e),
        }
    }
}

/// A failed policy fetch: its RFC 8460 §4.3.2.2 result type and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FetchError {
    pub(crate) result_type: &'static str,
    pub(crate) detail: String,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

/// Fetches and parses `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
pub(crate) async fn fetch<R: Resolver, D: Dialer>(
    net: Net<'_, R, D>,
    domain: &str,
) -> Result<Policy, FetchError> {
    let host = format!("mta-sts.{domain}");
    let fail = |result_type, detail| FetchError {
        result_type,
        detail,
    };
    let response = timeout(
        FETCH_TIMEOUT,
        request(
            net,
            &host,
            443,
            Method::GET,
            "/.well-known/mta-sts.txt",
            HeaderMap::new(),
            Bytes::new(),
            MAX_POLICY_SIZE,
        ),
    )
    .await
    .map_err(|_| fail("sts-policy-fetch-error", "policy fetch timed out".into()))?;
    let (status, headers, body) = response.map_err(|e| match e {
        Failure::Tls(d) => fail("sts-webpki-invalid", d),
        Failure::Connect(d) | Failure::Http(d) => fail("sts-policy-fetch-error", d),
    })?;
    // RFC 8461 §3.3: only 200 counts; redirects are not followed.
    if status != StatusCode::OK {
        return Err(fail(
            "sts-policy-fetch-error",
            format!("{host} answered HTTP {status}"),
        ));
    }
    // RFC 8461 §3.2: senders SHOULD check the media type is text/plain.
    let text_plain = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("text/plain"));
    if !text_plain {
        return Err(fail(
            "sts-policy-invalid",
            format!("{host} did not serve text/plain"),
        ));
    }
    let text = std::str::from_utf8(&body).map_err(|_| {
        fail(
            "sts-policy-invalid",
            format!("policy from {host} is not UTF-8"),
        )
    })?;
    parse_policy(text)
        .ok_or_else(|| fail("sts-policy-invalid", format!("invalid policy from {host}")))
}

/// POSTs a TLS report (RFC 8460 §5.4). Any 2xx status is success.
pub(crate) async fn post<R: Resolver, D: Dialer>(
    net: Net<'_, R, D>,
    host: &str,
    path: &str,
    content_type: &'static str,
    body: Vec<u8>,
) -> Result<(), Failure> {
    let r = timeout(
        FETCH_TIMEOUT,
        request(
            net,
            host,
            443,
            Method::POST,
            path,
            content_headers(content_type),
            Bytes::from(body),
            MAX_POST_RESPONSE,
        ),
    )
    .await
    .map_err(|_| Failure::Http("report upload timed out".into()))?;
    let (status, ..) = r?;
    if status.is_success() {
        Ok(())
    } else {
        Err(Failure::Http(format!("{host} answered HTTP {status}")))
    }
}

fn content_headers(content_type: &'static str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    h
}

/// A guarded HTTPS client for other parts of Idly (the ACME client): names
/// are resolved with our resolver, connections go through the dialer (so
/// the address guard applies), and certificates are checked against the
/// trusted roots. Plain HTTP is not offered.
#[derive(Debug, Clone)]
pub struct Https<R, D> {
    resolver: R,
    dialer: D,
    roots: Arc<RootCertStore>,
    families: Families,
    sources: Sources,
}

impl<R: Resolver, D: Dialer> Https<R, D> {
    pub fn new(
        resolver: R,
        dialer: D,
        roots: Arc<RootCertStore>,
        families: Families,
        sources: Sources,
    ) -> Self {
        Self {
            resolver,
            dialer,
            roots,
            families,
            sources,
        }
    }

    /// Sends one request to an `https://` URL; the response body is read
    /// up to `max_body` octets. Redirects are not followed.
    pub async fn send(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Bytes,
        max_body: usize,
    ) -> Result<(StatusCode, HeaderMap, Bytes), String> {
        let uri: hyper::Uri = url.parse().map_err(|e| format!("{url}: {e}"))?;
        if uri.scheme_str() != Some("https") {
            return Err(format!("{url}: only https URLs are allowed"));
        }
        let host = uri
            .host()
            .ok_or_else(|| format!("{url}: no host"))?
            .to_ascii_lowercase();
        let port = uri.port_u16().unwrap_or(443);
        let path = uri.path_and_query().map_or("/", |p| p.as_str());
        let net = Net {
            resolver: &self.resolver,
            dialer: &self.dialer,
            roots: &self.roots,
            families: self.families,
            sources: self.sources,
        };
        timeout(
            FETCH_TIMEOUT,
            request(net, &host, port, method, path, headers, body, max_body),
        )
        .await
        .map_err(|_| format!("{url}: timed out"))?
        .map_err(|e| e.to_string())
    }
}

/// One HTTPS request to `host`:`port`. The response body is read up to
/// `max_body` octets; more is an error.
#[allow(clippy::too_many_arguments)]
async fn request<R: Resolver, D: Dialer>(
    net: Net<'_, R, D>,
    host: &str,
    port: u16,
    method: Method,
    path: &str,
    headers: HeaderMap,
    body: Bytes,
    max_body: usize,
) -> Result<(StatusCode, HeaderMap, Bytes), Failure> {
    let mut addrs: Vec<IpAddr> = Vec::new();
    if net.families.ipv4
        && let Ok(a) = net.resolver.a(host).await
    {
        addrs.extend(a.records);
    }
    if net.families.ipv6
        && let Ok(a) = net.resolver.aaaa(host).await
    {
        addrs.extend(a.records);
    }
    if addrs.is_empty() {
        return Err(Failure::Connect(format!("{host} has no address")));
    }
    let mut last = String::new();
    let mut tcp = None;
    for ip in addrs.into_iter().take(4) {
        match net
            .dialer
            .connect(SocketAddr::new(ip, port), net.sources.for_ip(ip))
            .await
        {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last = format!("{ip}: {e}"),
        }
    }
    let tcp = tcp.ok_or_else(|| Failure::Connect(format!("cannot connect to {host}: {last}")))?;

    // The certificate must be valid for the host and chain to a trusted
    // root (RFC 8461 §3.3; for reports, RFC 8460 §3 allows skipping this,
    // but we never do).
    let (config, _) = tls::client_config(&tls::Policy::WebPki, net.roots)
        .map_err(|e| Failure::Tls(e.to_string()))?;
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| Failure::Connect(format!("{host}: bad name")))?;
    let stream = tokio_rustls::TlsConnector::from(config)
        .connect(name, tcp)
        .await
        .map_err(|e| Failure::Tls(format!("TLS with {host}: {e}")))?;

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| Failure::Http(format!("HTTP with {host}: {e}")))?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    let authority = if port == 443 {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, authority)
        .header(USER_AGENT, "Idly Mail");
    for (name, value) in &headers {
        if name != HOST {
            builder = builder.header(name, value);
        }
    }
    let result = async {
        let request = builder
            .body(Full::new(body))
            .map_err(|e| Failure::Http(e.to_string()))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| Failure::Http(format!("HTTP with {host}: {e}")))?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = Limited::new(response.into_body(), max_body)
            .collect()
            .await
            .map_err(|e| Failure::Http(format!("response body from {host}: {e}")))?
            .to_bytes();
        Ok((status, headers, body))
    }
    .await;
    driver.abort();
    result
}
