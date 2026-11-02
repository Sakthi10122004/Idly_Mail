//! Prometheus metrics and the HTTP endpoint that serves them.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use tokio::net::TcpListener;

/// All metrics, shared by every part of the server.
#[derive(Debug)]
pub(crate) struct Metrics {
    registry: Registry,
    /// 1 while test mode restricts outbound delivery.
    pub(crate) test_mode: Gauge,
    /// Connections dropped for a bare CR or LF (SMTP smuggling attempts).
    pub(crate) smuggling_attempts: Counter,
    /// Messages accepted and stored.
    pub(crate) messages_accepted: Counter,
    /// Failed SMTP AUTH attempts.
    pub(crate) auth_failures: Counter,
}

impl Metrics {
    pub(crate) fn new() -> Arc<Self> {
        let mut registry = Registry::with_prefix("idly");
        let test_mode = Gauge::default();
        let smuggling_attempts = Counter::default();
        let messages_accepted = Counter::default();
        let auth_failures = Counter::default();
        registry.register(
            "test_mode",
            "1 while test mode restricts outbound delivery",
            test_mode.clone(),
        );
        registry.register(
            "smuggling_attempts",
            "Connections closed for a bare CR or LF in DATA",
            smuggling_attempts.clone(),
        );
        registry.register(
            "messages_accepted",
            "Messages accepted and stored",
            messages_accepted.clone(),
        );
        registry.register(
            "auth_failures",
            "Failed SMTP AUTH attempts",
            auth_failures.clone(),
        );
        Arc::new(Self {
            registry,
            test_mode,
            smuggling_attempts,
            messages_accepted,
            auth_failures,
        })
    }

    /// The metrics in Prometheus text format.
    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        // Encoding into a String cannot fail.
        let _ = encode(&mut out, &self.registry);
        out
    }
}

/// Feeds SMTP server events into the metrics.
#[derive(Debug, Clone)]
pub(crate) struct MetricsObserver(pub(crate) Arc<Metrics>);

impl smtp_server::Observer for MetricsObserver {
    fn smuggling_attempt(&self, _client_ip: std::net::IpAddr) {
        self.0.smuggling_attempts.inc();
    }
    fn message_accepted(&self) {
        self.0.messages_accepted.inc();
    }
    fn auth_failure(&self, _client_ip: std::net::IpAddr) {
        self.0.auth_failures.inc();
    }
}

/// Serves `GET /metrics` on `addr` until the task is dropped.
pub(crate) async fn serve(addr: SocketAddr, metrics: Arc<Metrics>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    if !addr.ip().is_loopback() {
        tracing::warn!(%addr, "metrics endpoint is not on loopback; anyone who can reach it can read it");
    }
    tracing::info!(%addr, "metrics endpoint listening");
    loop {
        let (stream, _) = listener.accept().await?;
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| respond(req, metrics.clone()));
            if let Err(e) = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!(error = %e, "metrics connection error");
            }
        });
    }
}

async fn respond(
    req: Request<Incoming>,
    metrics: Arc<Metrics>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (status, body) = match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => (StatusCode::OK, metrics.render()),
        _ => (StatusCode::NOT_FOUND, "not found\n".to_owned()),
    };
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_registered_metrics() {
        let m = Metrics::new();
        m.test_mode.set(1);
        m.smuggling_attempts.inc();
        let text = m.render();
        assert!(text.contains("idly_test_mode 1"), "{text}");
        assert!(text.contains("idly_smuggling_attempts_total 1"), "{text}");
    }

    #[tokio::test]
    async fn http_endpoint() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let m = Metrics::new();
        tokio::spawn(serve(addr, m.clone()));
        // Give the listener a moment to bind.
        let mut stream = loop {
            if let Ok(s) = tokio::net::TcpStream::connect(addr).await {
                break s;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        assert!(out.contains("idly_messages_accepted_total"), "{out}");
    }
}
