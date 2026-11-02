//! The whole ACME flow against an in-process fake CA. The fake checks each
//! HTTP-01 challenge by fetching it from our port-80 server over real TCP,
//! reads the CSR, and issues from a test CA.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use acme::instant_acme::{BodyWrapper, BytesResponse, Error, HttpClient};
use acme::{Challenges, Manager, Settings, Site, Store};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use der::{Decode, Encode};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, Response, StatusCode};
use rcgen::{CertificateParams, Issuer, KeyPair, PublicKeyData};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BASE: &str = "https://ca.test";

#[derive(Default)]
struct CaState {
    nonce: u64,
    accounts: u32,
    orders: u32,
    thumbprint: String,
    names: Vec<String>,
    tokens: Vec<String>,
    authz_valid: Vec<bool>,
    order_status: String,
    chain: Option<String>,
    /// Requests seen, as "METHOD path".
    log: Vec<String>,
}

/// A fake ACME CA. Certificates are issued for the key in `key_path`
/// (checked against the CSR) and signed by a test CA.
#[derive(Clone)]
struct FakeCa {
    state: Arc<Mutex<CaState>>,
    /// Our port-80 server, where challenges are checked.
    http01: SocketAddr,
    key_path: std::path::PathBuf,
    ca: Arc<(KeyPair, CertificateParams)>,
    /// Pretend validation fails.
    fail_validation: bool,
}

impl FakeCa {
    fn new(http01: SocketAddr, key_path: std::path::PathBuf) -> Self {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        Self {
            state: Arc::default(),
            http01,
            key_path,
            ca: Arc::new((KeyPair::generate().unwrap(), params)),
            fail_validation: false,
        }
    }

    fn nonce(&self) -> String {
        let mut s = self.state.lock().unwrap();
        s.nonce += 1;
        format!("nonce{}", s.nonce)
    }

    async fn handle(&self, method: Method, uri: String, body: Bytes) -> Response<Full<Bytes>> {
        let path = uri.strip_prefix(BASE).unwrap_or(&uri).to_owned();
        self.state
            .lock()
            .unwrap()
            .log
            .push(format!("{method} {path}"));
        if path == "/dir" {
            return reply(
                StatusCode::OK,
                json!({
                    "newNonce": format!("{BASE}/nonce"),
                    "newAccount": format!("{BASE}/account"),
                    "newOrder": format!("{BASE}/order"),
                }),
                None,
            );
        }
        if path == "/nonce" {
            return reply(StatusCode::OK, Value::Null, None);
        }
        // Every other request is a JWS (RFC 8555 §6.2).
        let jws: Value = serde_json::from_slice(&body).unwrap();
        let protected: Value = b64json(jws["protected"].as_str().unwrap());
        assert_eq!(
            protected["url"].as_str().unwrap(),
            uri,
            "url in the JWS header"
        );
        let payload = jws["payload"].as_str().unwrap();
        let payload: Value = if payload.is_empty() {
            Value::Null
        } else {
            b64json(payload)
        };

        if path == "/account" {
            let jwk = &protected["jwk"];
            // RFC 7638 §3: the required members, sorted, no whitespace.
            let canonical = format!(
                r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
                jwk["crv"].as_str().unwrap(),
                jwk["kty"].as_str().unwrap(),
                jwk["x"].as_str().unwrap(),
                jwk["y"].as_str().unwrap()
            );
            let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());
            let mut s = self.state.lock().unwrap();
            s.thumbprint = URL_SAFE_NO_PAD.encode(digest.as_ref());
            s.accounts += 1;
            assert_eq!(payload["termsOfServiceAgreed"], true);
            return reply(
                StatusCode::CREATED,
                json!({"status": "valid", "contact": payload["contact"]}),
                Some(format!("{BASE}/acct/1")),
            );
        }
        assert_eq!(protected["kid"].as_str(), Some(&*format!("{BASE}/acct/1")));
        if path == "/order" {
            let names: Vec<String> = payload["identifiers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i["value"].as_str().unwrap().to_owned())
                .collect();
            let mut s = self.state.lock().unwrap();
            s.orders += 1;
            s.tokens = (0..names.len())
                .map(|i| format!("tok{}_{i}", s.orders))
                .collect();
            s.authz_valid = vec![false; names.len()];
            s.names = names;
            s.order_status = "pending".into();
            s.chain = None;
            let order = order_json(&s);
            return reply(StatusCode::CREATED, order, Some(format!("{BASE}/order/1")));
        }
        if let Some(i) = path.strip_prefix("/authz/") {
            let i: usize = i.parse().unwrap();
            let s = self.state.lock().unwrap();
            return reply(StatusCode::OK, authz_json(&s, i), None);
        }
        if let Some(i) = path.strip_prefix("/chall/") {
            let i: usize = i.parse().unwrap();
            let (name, token, thumb) = {
                let s = self.state.lock().unwrap();
                (
                    s.names[i].clone(),
                    s.tokens[i].clone(),
                    s.thumbprint.clone(),
                )
            };
            // RFC 8555 §8.3: fetch the key authorization over plain HTTP.
            let body = http_get(
                self.http01,
                &name,
                &format!("/.well-known/acme-challenge/{token}"),
            )
            .await;
            let ok = !self.fail_validation && body == format!("{token}.{thumb}");
            let mut s = self.state.lock().unwrap();
            s.authz_valid[i] = ok;
            if !ok {
                s.order_status = "invalid".into();
            } else if s.authz_valid.iter().all(|v| *v) {
                s.order_status = "ready".into();
            }
            let status = if ok { "valid" } else { "invalid" };
            return reply(
                StatusCode::OK,
                json!({"type": "http-01", "url": format!("{BASE}/chall/{i}"), "token": token, "status": status}),
                None,
            );
        }
        if path == "/order/1" {
            let s = self.state.lock().unwrap();
            return reply(StatusCode::OK, order_json(&s), None);
        }
        if path == "/finalize/1" {
            let csr = URL_SAFE_NO_PAD
                .decode(payload["csr"].as_str().unwrap())
                .unwrap();
            let chain = self.issue(&csr);
            let mut s = self.state.lock().unwrap();
            assert_eq!(s.order_status, "ready");
            s.chain = Some(chain);
            s.order_status = "valid".into();
            return reply(StatusCode::OK, order_json(&s), None);
        }
        if path == "/cert/1" {
            let chain = self.state.lock().unwrap().chain.clone().unwrap();
            let mut r = Response::new(Full::new(Bytes::from(chain)));
            r.headers_mut().insert(
                "content-type",
                "application/pem-certificate-chain".parse().unwrap(),
            );
            r.headers_mut()
                .insert("replay-nonce", self.nonce().parse().unwrap());
            return r;
        }
        panic!("unexpected request {method} {path}");
    }

    /// Checks the CSR (our key, every ordered name) and issues.
    fn issue(&self, csr: &[u8]) -> String {
        let req = x509_cert::request::CertReq::from_der(csr).unwrap();
        let key = KeyPair::from_pem(&std::fs::read_to_string(&self.key_path).unwrap()).unwrap();
        assert_eq!(
            req.info.public_key.to_der().unwrap(),
            key.subject_public_key_info(),
            "the CSR carries the stored key"
        );
        let names = self.state.lock().unwrap().names.clone();
        let leaf = CertificateParams::new(names)
            .unwrap()
            .signed_by(&key, &Issuer::from_params(&self.ca.1, &self.ca.0))
            .unwrap();
        let ca = self.ca.1.self_signed(&self.ca.0).unwrap();
        format!("{}{}", leaf.pem(), ca.pem())
    }
}

impl HttpClient for FakeCa {
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let ca = self.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let body = body.collect().await.unwrap().to_bytes();
            let mut response = ca.handle(parts.method, parts.uri.to_string(), body).await;
            if !response.headers().contains_key("replay-nonce") {
                response
                    .headers_mut()
                    .insert("replay-nonce", ca.nonce().parse().unwrap());
            }
            Ok(BytesResponse::from(response))
        })
    }
}

fn reply(status: StatusCode, body: Value, location: Option<String>) -> Response<Full<Bytes>> {
    let bytes = if body.is_null() {
        Bytes::new()
    } else {
        Bytes::from(serde_json::to_vec(&body).unwrap())
    };
    let mut r = Response::new(Full::new(bytes));
    *r.status_mut() = status;
    r.headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    if let Some(l) = location {
        r.headers_mut().insert("location", l.parse().unwrap());
    }
    r
}

fn order_json(s: &CaState) -> Value {
    let mut order = json!({
        "status": s.order_status,
        "identifiers": s.names.iter().map(|n| json!({"type": "dns", "value": n})).collect::<Vec<_>>(),
        "authorizations": (0..s.names.len()).map(|i| format!("{BASE}/authz/{i}")).collect::<Vec<_>>(),
        "finalize": format!("{BASE}/finalize/1"),
    });
    if s.chain.is_some() {
        order["certificate"] = json!(format!("{BASE}/cert/1"));
    }
    if s.order_status == "invalid" {
        order["error"] = json!({"type": "urn:ietf:params:acme:error:unauthorized", "detail": "challenge failed"});
    }
    order
}

fn authz_json(s: &CaState, i: usize) -> Value {
    let status = if s.authz_valid[i] { "valid" } else { "pending" };
    json!({
        "status": status,
        "identifier": {"type": "dns", "value": s.names[i]},
        "challenges": [
            {"type": "dns-01", "url": format!("{BASE}/dns/{i}"), "token": "unused", "status": "pending"},
            {"type": "http-01", "url": format!("{BASE}/chall/{i}"), "token": s.tokens[i], "status": "pending"},
        ],
    })
}

fn b64json(s: &str) -> Value {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(s).unwrap()).unwrap()
}

async fn http_get(addr: SocketAddr, host: &str, path: &str) -> String {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    if !out.starts_with("HTTP/1.1 200") {
        return String::new();
    }
    out.split_once("\r\n\r\n").unwrap().1.to_owned()
}

struct Setup {
    _dir: tempfile::TempDir,
    store: Store,
    challenges: Challenges,
    ca: FakeCa,
    settings: Settings,
}

async fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("acme")).unwrap();
    let challenges = Challenges::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(acme::web::serve(
        listener,
        Site::Challenges(challenges.clone()),
        None,
    ));
    let ca = FakeCa::new(addr, store.key_path());
    let settings = Settings {
        directory: format!("{BASE}/dir"),
        contact: Some("postmaster@example.org".into()),
        names: vec!["mx.example.org".into(), "mta-sts.example.org".into()],
    };
    Setup {
        _dir: dir,
        store,
        challenges,
        ca,
        settings,
    }
}

fn manager(s: &Setup, ca: FakeCa, settings: Settings) -> Manager {
    let http: acme::HttpFactory = Arc::new(move || Box::new(ca.clone()) as Box<dyn HttpClient>);
    Manager::new(settings, s.store.clone(), s.challenges.clone(), http)
        .unwrap()
        .with_poll_timeout(Duration::from_secs(5))
}

#[tokio::test]
async fn issues_renews_and_keeps_the_key() {
    let s = setup().await;
    let m = manager(&s, s.ca.clone(), s.settings.clone());
    // No certificate yet: a self-signed one is served and renewal is due.
    assert!(m.info().is_none());
    assert!(m.due(0));
    let placeholder = m.certs().current();

    m.renew().await.unwrap();
    let info = m.info().unwrap();
    assert_eq!(info.names, ["mx.example.org", "mta-sts.example.org"]);
    assert!(!m.due(info.not_before));
    assert!(m.due(info.renew_at()));
    assert!(
        !Arc::ptr_eq(&m.certs().current(), &placeholder),
        "the new certificate is served"
    );
    assert!(s.store.cert().unwrap().is_some(), "the chain is stored");
    // Challenge answers are taken down afterwards.
    let tokens = s.ca.state.lock().unwrap().tokens.clone();
    for t in &tokens {
        assert_eq!(s.challenges.get(t), None);
    }

    // A renewal reuses the account and the key.
    let spki = info.spki.clone();
    m.renew().await.unwrap();
    assert_eq!(m.info().unwrap().spki, spki);
    {
        let st = s.ca.state.lock().unwrap();
        assert_eq!(st.accounts, 1, "one account");
        assert_eq!(st.orders, 2);
    }

    // After a restart the stored certificate is used at once.
    let again = manager(&s, s.ca.clone(), s.settings.clone());
    assert_eq!(again.info().unwrap().spki, spki);
    assert!(!again.due(info.not_before));

    // A name added to the configuration makes renewal due.
    let mut more = s.settings.clone();
    more.names.push("mta-sts.example.net".into());
    let grown = manager(&s, s.ca.clone(), more);
    assert!(grown.due(info.not_before));
    grown.renew().await.unwrap();
    assert!(grown.info().unwrap().covers("mta-sts.example.net"));
}

#[tokio::test]
async fn failed_validation_stores_nothing() {
    let s = setup().await;
    let mut ca = s.ca.clone();
    ca.fail_validation = true;
    let m = manager(&s, ca, s.settings.clone());
    let err = m.renew().await.unwrap_err();
    assert!(
        err.contains("challenge failed") || err.contains("Invalid"),
        "{err}"
    );
    assert!(s.store.cert().unwrap().is_none());
    assert!(m.info().is_none());
    let tokens = s.ca.state.lock().unwrap().tokens.clone();
    assert!(!tokens.is_empty());
    for t in &tokens {
        assert_eq!(s.challenges.get(t), None, "challenge answers are removed");
    }
}

#[tokio::test]
async fn a_certificate_for_another_key_is_not_used() {
    let s = setup().await;
    // Someone else's certificate in cert.pem: ignored, a new one is due.
    let other = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["mx.example.org".into()])
        .unwrap()
        .self_signed(&other)
        .unwrap();
    s.store.save_cert(cert.pem().as_bytes()).unwrap();
    let m = manager(&s, s.ca.clone(), s.settings.clone());
    assert!(m.info().is_none());
    assert!(m.due(0));
}
