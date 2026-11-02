//! SMTP listeners for Idly Mail: inbound mail on port 25, and message
//! submission on ports 587 (STARTTLS) and 465 (implicit TLS).
//!
//! Inbound (port 25) accepts mail only for local recipients: everything the
//! [`Directory`] doesn't map to a local account is refused (no open relay).
//! Only an authenticated submission may name remote recipients, and those
//! go to the outbound queue. This crate never connects anywhere itself.
//!
//! Strictness comes from `smtp-proto`: only CRLF ends a line, only
//! `CRLF.CRLF` ends DATA, and a bare CR or LF drops the connection and any
//! partial message (CLAUDE.md, SMTP smuggling).

#![forbid(unsafe_code)]

use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use smtp_proto::{ClientName, ForwardPath, ReversePath};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

mod auth;
mod conn;
mod inbound;
pub mod maildir;
mod session;
mod submission;
pub mod tls;

pub use auth::{Accounts, AuthLimits};
pub use submission::DkimKeys;

/// What a listener is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Port 25: mail for local recipients from anyone; STARTTLS offered when
    /// a certificate is configured; never AUTH.
    Inbound,
    /// Port 587: STARTTLS, then AUTH, then mail to anyone (RFC 6409).
    Submission,
    /// Port 465: TLS from the first byte, then AUTH (RFC 8314 §3.3).
    SubmissionImplicitTls,
}

/// Settings for the SMTP listeners.
#[derive(Debug, Clone)]
pub struct InboundConfig {
    /// Our host name, used in the greeting, EHLO reply and Received header.
    pub hostname: String,
    /// Hard cap on a command line, CRLF included.
    pub command_line_cap: usize,
    /// Hard cap on a DATA line, CRLF included.
    pub data_line_cap: usize,
    /// Maximum message size in octets, announced with SIZE (RFC 1870).
    pub message_size: u64,
    /// Maximum recipients per transaction.
    pub max_recipients: usize,
    /// How long to wait for a command. RFC 5321 §4.5.3.2.7: at least
    /// 5 minutes.
    pub command_timeout: Duration,
    /// How long to wait for more message data before giving up.
    pub data_timeout: Duration,
    /// How long a TLS handshake may take.
    pub tls_handshake_timeout: Duration,
    /// Hard cap on a whole session, so slow clients can't hold
    /// connections forever.
    pub session_timeout: Duration,
    /// Simultaneous connections on port 25; more get 421 and are closed.
    pub max_connections: usize,
    /// Simultaneous submission connections (587 and 465), counted
    /// separately so a flood on port 25 can't lock users out.
    pub max_submission_connections: usize,
    /// Run SPF, DKIM and DMARC on inbound mail (off in `--demo`).
    pub inbound_checks: bool,
    /// Test mode: submission accepts remote recipients only in these domains.
    pub test_mode_allow: Option<Vec<String>>,
    /// Brute-force limits for AUTH.
    pub auth_limits: AuthLimits,
}

impl InboundConfig {
    /// Defaults for `hostname`: 4 KiB commands, 64 KiB data lines, 25 MiB
    /// messages, 100 recipients, 5-minute command and data timeouts,
    /// 30-second TLS handshakes, 30-minute sessions.
    pub fn new(hostname: &str) -> Self {
        Self {
            hostname: hostname.to_owned(),
            command_line_cap: smtp_proto::limits::DEFAULT_COMMAND_LINE_CAP,
            data_line_cap: smtp_proto::limits::DEFAULT_INBOUND_TEXT_LINE_CAP,
            message_size: 25 * 1024 * 1024,
            max_recipients: 100,
            command_timeout: Duration::from_secs(300),
            data_timeout: Duration::from_secs(300),
            tls_handshake_timeout: Duration::from_secs(30),
            session_timeout: Duration::from_secs(30 * 60),
            max_connections: 100,
            max_submission_connections: 50,
            inbound_checks: true,
            test_mode_allow: None,
            auth_limits: AuthLimits::default(),
        }
    }
}

/// Where a recipient goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    /// A local account, identified by its canonical address.
    Local(String),
    /// A local domain, but no such account.
    UnknownUser,
    /// Not one of our domains.
    NotLocal,
}

/// Maps recipients to local accounts.
pub trait Directory: Send + Sync + 'static {
    /// Resolves a RCPT TO forward-path.
    fn resolve(&self, to: &ForwardPath) -> Recipient;
}

/// A recipient of an accepted message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rcpt {
    /// A local account.
    Local(String),
    /// A remote address (authenticated submission only): goes to the queue.
    Remote(String),
}

/// A message accepted from a client, ready for delivery.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// Our identifier for the message, also in the Received header.
    pub id: String,
    /// The client's IP address.
    pub client_ip: IpAddr,
    /// The HELO/EHLO name. An invalid one is a spam-scoring signal
    /// (CLAUDE.md), recorded here and never a reason to reject.
    pub client_name: ClientName,
    /// MAIL FROM.
    pub from: ReversePath,
    /// Recipients, deduplicated, in RCPT order.
    pub recipients: Vec<Rcpt>,
    /// Whether the client used SMTPUTF8.
    pub smtputf8: bool,
    /// Accepted protocol deviations, for the spam scorer.
    pub signals: Signals,
    /// The authenticated account, for submissions.
    pub authenticated: Option<String>,
    /// Deliver local copies to the Junk folder (DMARC quarantine/permerror).
    pub junk: bool,
}

/// Protocol deviations that policy accepts but records for spam scoring
/// (CLAUDE.md, "lenient on harmless syntax"). Sticky for the session, and
/// reset by STARTTLS like all other session state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Signals {
    /// The HELO/EHLO name did not match the RFC 5321 grammar.
    pub invalid_client_name: bool,
    /// A MAIL FROM or RCPT TO path came without angle brackets.
    pub missing_angle_brackets: bool,
}

/// Final storage for accepted messages.
pub trait Sink: Send + Sync + 'static {
    /// Stores `message` for every recipient. Must not return until the
    /// message is safely on disk: the client is told 250 afterwards
    /// (RFC 5321 §6.1). An error of kind `StorageFull` gets 452 4.3.1.
    fn deliver(
        &self,
        envelope: &Envelope,
        message: &[u8],
    ) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Whether there is room for new mail. When false, new mail gets
    /// "452 4.3.1 Insufficient system storage" instead of being accepted.
    fn has_space(&self) -> bool {
        true
    }
}

/// Hooks for metrics.
pub trait Observer: Send + Sync + 'static {
    /// A bare CR or LF in a command or message data: possible smuggling.
    fn smuggling_attempt(&self, _client_ip: IpAddr) {}
    /// A message was accepted and stored.
    fn message_accepted(&self) {}
    /// A failed AUTH attempt.
    fn auth_failure(&self, _client_ip: IpAddr) {}
}

/// A resolver that never answers, for when inbound checks are off
/// (`--demo`). It is never called in that case.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDns;

impl dns::Resolver for NoDns {
    async fn mx(&self, _: &str) -> Result<dns::Answer<dns::Mx>, dns::Error> {
        Err(dns::Error::Temporary("no resolver".into()))
    }
    async fn a(&self, _: &str) -> Result<dns::Answer<IpAddr>, dns::Error> {
        Err(dns::Error::Temporary("no resolver".into()))
    }
    async fn aaaa(&self, _: &str) -> Result<dns::Answer<IpAddr>, dns::Error> {
        Err(dns::Error::Temporary("no resolver".into()))
    }
    async fn txt(&self, _: &str) -> Result<dns::Answer<Vec<u8>>, dns::Error> {
        Err(dns::Error::Temporary("no resolver".into()))
    }
    async fn tlsa(&self, _: &str) -> Result<dns::Answer<dns::Tlsa>, dns::Error> {
        Err(dns::Error::Temporary("no resolver".into()))
    }
    async fn ptr(&self, _: IpAddr) -> Result<dns::Answer<String>, dns::Error> {
        Err(dns::Error::Temporary("no resolver".into()))
    }
}

/// The production sink: local recipients to Maildir, remote recipients to
/// the outbound queue.
#[derive(Debug)]
pub struct Delivery {
    pub maildir: maildir::Maildir,
    pub queue: Arc<queue::Queue>,
}

impl Sink for Delivery {
    async fn deliver(&self, envelope: &Envelope, message: &[u8]) -> std::io::Result<()> {
        let remote: Vec<String> = envelope
            .recipients
            .iter()
            .filter_map(|r| match r {
                Rcpt::Remote(a) => Some(a.clone()),
                Rcpt::Local(_) => None,
            })
            .collect();
        if !remote.is_empty() {
            let sender = match &envelope.from {
                ReversePath::Null => None,
                ReversePath::Mailbox(m) => Some(m.to_string()),
            };
            let queue = self.queue.clone();
            let msg = message.to_vec();
            let result = tokio::task::spawn_blocking(move || {
                queue.enqueue(sender.as_deref(), &remote, &msg)
            })
            .await
            .map_err(std::io::Error::other)?;
            match result {
                Ok(_) => {}
                Err(queue::QueueError::NoSpace) => {
                    return Err(std::io::ErrorKind::StorageFull.into());
                }
                Err(e) => return Err(std::io::Error::other(e.to_string())),
            }
        }
        if envelope
            .recipients
            .iter()
            .any(|r| matches!(r, Rcpt::Local(_)))
        {
            self.maildir.deliver(envelope, message).await?;
        }
        Ok(())
    }

    fn has_space(&self) -> bool {
        self.maildir.has_space() && self.queue.has_space()
    }
}

/// The SMTP server.
pub struct Server<D, K, O, R> {
    config: InboundConfig,
    directory: D,
    sink: K,
    observer: O,
    resolver: R,
    tls: Option<Arc<rustls::ServerConfig>>,
    accounts: Option<Arc<dyn Accounts>>,
    dkim: Option<Arc<DkimKeys>>,
    guard: auth::Guard,
    connections: Semaphore,
    submission_connections: Semaphore,
}

impl<D, K, O, R> std::fmt::Debug for Server<D, K, O, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<D: Directory, K: Sink, O: Observer, R: dns::Resolver + 'static> Server<D, K, O, R> {
    /// A server without TLS, AUTH or DKIM; add them with the `with_*`
    /// methods, then call [`Server::shared`].
    pub fn new(config: InboundConfig, directory: D, sink: K, observer: O, resolver: R) -> Self {
        let connections = Semaphore::new(config.max_connections);
        let submission_connections = Semaphore::new(config.max_submission_connections);
        let guard = auth::Guard::new(config.auth_limits.clone());
        Self {
            config,
            directory,
            sink,
            observer,
            resolver,
            tls: None,
            accounts: None,
            dkim: None,
            guard,
            connections,
            submission_connections,
        }
    }

    /// Enables STARTTLS and implicit TLS with this certificate.
    pub fn with_tls(mut self, tls: Arc<rustls::ServerConfig>) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Enables AUTH (submission only) against these accounts.
    pub fn with_accounts(mut self, accounts: Arc<dyn Accounts>) -> Self {
        self.accounts = Some(accounts);
        self
    }

    /// DKIM keys for signing submitted mail.
    pub fn with_dkim(mut self, keys: Arc<DkimKeys>) -> Self {
        self.dkim = Some(keys);
        self
    }

    /// Wraps the server for sharing between listeners.
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Accepts connections on `listener` in `mode` until it fails.
    pub async fn run(self: Arc<Self>, listener: TcpListener, mode: Mode) -> std::io::Result<()> {
        loop {
            let (stream, peer) = listener.accept().await?;
            let server = self.clone();
            tokio::spawn(async move { server.handle(stream, peer.ip(), mode).await });
        }
    }

    /// Runs one session over any byte stream (also used by tests and the
    /// fuzzer, over in-memory streams).
    pub async fn handle<S>(self: &Arc<Self>, stream: S, client_ip: IpAddr, mode: Mode)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let pool = match mode {
            Mode::Inbound => &self.connections,
            Mode::Submission | Mode::SubmissionImplicitTls => &self.submission_connections,
        };
        let permit = pool.try_acquire();
        session::run(self, stream, client_ip, mode, permit.is_ok()).await;
    }
}
