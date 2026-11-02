//! The two small web servers: HTTP on port 80 for ACME HTTP-01 challenges
//! (RFC 8555 §8.3), and HTTPS on port 443 for MTA-STS policies
//! (RFC 8461 §3.2). Each serves its one path and 404 for everything else;
//! connections are capped, and slow clients are cut off.

use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONTENT_TYPE, HOST, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

/// Simultaneous connections per listener.
const MAX_CONNECTIONS: usize = 256;
/// Time allowed for the request header, and for a TLS handshake.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// Hard cap on one connection.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";
/// RFC 8461 §3.2: the policy's fixed location.
const POLICY_PATH: &str = "/.well-known/mta-sts.txt";

/// Pending HTTP-01 challenges: token to key authorization.
#[derive(Debug, Clone, Default)]
pub struct Challenges(Arc<Mutex<HashMap<String, String>>>);

impl Challenges {
    pub fn insert(&self, token: &str, key_authorization: &str) {
        self.with(|m| {
            m.insert(token.to_owned(), key_authorization.to_owned());
        });
    }

    pub fn remove(&self, token: &str) {
        self.with(|m| {
            m.remove(token);
        });
    }

    pub fn get(&self, token: &str) -> Option<String> {
        let mut found = None;
        self.with(|m| found = m.get(token).cloned());
        found
    }

    fn with(&self, f: impl FnOnce(&mut HashMap<String, String>)) {
        match self.0.lock() {
            Ok(mut m) => f(&mut m),
            Err(poisoned) => f(&mut poisoned.into_inner()),
        }
    }
}

/// What a listener serves.
#[derive(Debug, Clone)]
pub enum Site {
    /// `/.well-known/acme-challenge/<token>` on port 80.
    Challenges(Challenges),
    /// `/.well-known/mta-sts.txt`, by host name (`mta-sts.<domain>`,
    /// lower-case A-label) to policy text.
    MtaSts(Arc<HashMap<String, String>>),
}

impl Site {
    /// The response to `method` `path` with Host `host`.
    pub fn respond(&self, method: &Method, host: Option<&str>, path: &str) -> Reply {
        if method != Method::GET && method != Method::HEAD {
            return Reply::not_found();
        }
        match self {
            Self::Challenges(challenges) => {
                // RFC 8555 §8.3: the token is base64url, so nothing else
                // can match.
                let Some(token) = path.strip_prefix(CHALLENGE_PREFIX) else {
                    return Reply::not_found();
                };
                if token.is_empty()
                    || !token
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Reply::not_found();
                }
                match challenges.get(token) {
                    Some(answer) => Reply::ok("application/octet-stream", answer),
                    None => Reply::not_found(),
                }
            }
            Self::MtaSts(policies) => {
                if path != POLICY_PATH {
                    return Reply::not_found();
                }
                let host = host.map(normalize_host).unwrap_or_default();
                match policies.get(&host) {
                    // RFC 8461 §3.2: served as text/plain.
                    Some(policy) => Reply::ok("text/plain", policy.clone()),
                    None => Reply::not_found(),
                }
            }
        }
    }
}

/// A response, before it becomes HTTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: StatusCode,
    pub content_type: &'static str,
    pub body: String,
}

impl Reply {
    fn ok(content_type: &'static str, body: String) -> Self {
        Self {
            status: StatusCode::OK,
            content_type,
            body,
        }
    }

    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            content_type: "text/plain",
            body: "not found\n".into(),
        }
    }
}

/// `Host` without the port or a trailing dot, lower-case.
fn normalize_host(host: &str) -> String {
    let name = match host.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    };
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Serves `site` on `listener`, over TLS when `tls` is set.
pub async fn serve(listener: TcpListener, site: Site, tls: Option<TlsAcceptor>) -> io::Result<()> {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, peer) = listener.accept().await?;
        // Over the cap: drop the connection rather than queue it.
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            tracing::debug!(%peer, "web connection limit reached");
            continue;
        };
        let site = site.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let work = async {
                match tls {
                    Some(acceptor) => {
                        let Ok(Ok(stream)) = timeout(HEADER_TIMEOUT, acceptor.accept(stream)).await
                        else {
                            return;
                        };
                        connection(TokioIo::new(stream), site).await;
                    }
                    None => connection(TokioIo::new(stream), site).await,
                }
            };
            let _ = timeout(CONNECTION_TIMEOUT, work).await;
        });
    }
}

async fn connection<I>(io: I, site: Site)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = service_fn(move |req: Request<Incoming>| {
        let site = site.clone();
        async move { Ok::<_, Infallible>(to_response(&site, &req)) }
    });
    let result = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .serve_connection(io, service)
        .await;
    if let Err(e) = result {
        tracing::debug!(error = %e, "web connection error");
    }
}

fn to_response(site: &Site, req: &Request<Incoming>) -> Response<Full<Bytes>> {
    let host = req
        .uri()
        .host()
        .or_else(|| req.headers().get(HOST).and_then(|h| h.to_str().ok()));
    let reply = site.respond(req.method(), host, req.uri().path());
    let body = if req.method() == Method::HEAD {
        Bytes::new()
    } else {
        Bytes::from(reply.body)
    };
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = reply.status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(reply.content_type));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenges_answer_only_known_tokens() {
        let c = Challenges::default();
        c.insert("tok_EN-1", "tok_EN-1.thumb");
        let site = Site::Challenges(c.clone());
        let r = site.respond(&Method::GET, None, "/.well-known/acme-challenge/tok_EN-1");
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body, "tok_EN-1.thumb");
        for path in [
            "/.well-known/acme-challenge/other",
            "/.well-known/acme-challenge/",
            "/.well-known/acme-challenge/../x",
            "/",
            "/.well-known/mta-sts.txt",
        ] {
            assert_eq!(
                site.respond(&Method::GET, None, path).status,
                StatusCode::NOT_FOUND,
                "{path}"
            );
        }
        assert_eq!(
            site.respond(&Method::POST, None, "/.well-known/acme-challenge/tok_EN-1")
                .status,
            StatusCode::NOT_FOUND
        );
        c.remove("tok_EN-1");
        assert_eq!(
            site.respond(&Method::GET, None, "/.well-known/acme-challenge/tok_EN-1")
                .status,
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn policies_are_served_by_host() {
        let mut map = HashMap::new();
        map.insert(
            "mta-sts.example.org".to_owned(),
            "version: STSv1\r\n".to_owned(),
        );
        let site = Site::MtaSts(Arc::new(map));
        for host in [
            "mta-sts.example.org",
            "MTA-STS.Example.org",
            "mta-sts.example.org:443",
            "mta-sts.example.org.",
        ] {
            let r = site.respond(&Method::GET, Some(host), "/.well-known/mta-sts.txt");
            assert_eq!(r.status, StatusCode::OK, "{host}");
            assert_eq!(r.content_type, "text/plain");
            assert_eq!(r.body, "version: STSv1\r\n");
        }
        assert_eq!(
            site.respond(
                &Method::GET,
                Some("mta-sts.other.example"),
                "/.well-known/mta-sts.txt"
            )
            .status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            site.respond(&Method::GET, None, "/.well-known/mta-sts.txt")
                .status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            site.respond(&Method::GET, Some("mta-sts.example.org"), "/")
                .status,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn serves_http() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let c = Challenges::default();
        c.insert("abc", "abc.xyz");
        tokio::spawn(serve(listener, Site::Challenges(c), None));
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(
            b"GET /.well-known/acme-challenge/abc HTTP/1.1\r\nHost: mx.example.org\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        assert!(out.ends_with("abc.xyz"), "{out}");
    }

    #[tokio::test]
    async fn serves_policies_over_tls() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let key = rcgen::KeyPair::generate().unwrap();
        let certs =
            crate::Certs::new(crate::certs::self_signed("mta-sts.example.org", &key).unwrap());
        let leaf = certs.current().cert[0].clone();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(certs);
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut map = HashMap::new();
        map.insert(
            "mta-sts.example.org".to_owned(),
            "version: STSv1\r\n".to_owned(),
        );
        tokio::spawn(serve(
            listener,
            Site::MtaSts(Arc::new(map)),
            Some(TlsAcceptor::from(Arc::new(server))),
        ));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(leaf).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let name = rustls_pki_types::ServerName::try_from("mta-sts.example.org").unwrap();
        let mut s = tokio_rustls::TlsConnector::from(Arc::new(client))
            .connect(name, tcp)
            .await
            .unwrap();
        s.write_all(
            b"GET /.well-known/mta-sts.txt HTTP/1.1\r\nHost: mta-sts.example.org\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out).await;
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        assert!(out.contains("content-type: text/plain"), "{out}");
        assert!(out.ends_with("version: STSv1\r\n"), "{out}");
    }
}
