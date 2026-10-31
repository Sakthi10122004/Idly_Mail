//! Inbound SMTP for Idly Mail.
//!
//! This crate accepts mail for local recipients and hands it to a [`Sink`].
//! It has no way to send mail anywhere: it does not depend on the outbound
//! client, and it rejects every recipient that the [`Directory`] does not
//! map to a local account (no open relay).
//!
//! Strictness comes from `smtp-proto`: only CRLF ends a line, only
//! `CRLF.CRLF` ends DATA, and a bare CR or LF in message data drops the
//! connection and the partial message (CLAUDE.md, SMTP smuggling).

#![forbid(unsafe_code)]

use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use smtp_proto::{ClientName, ForwardPath, ReversePath};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

mod date;
pub mod maildir;
mod session;

/// Settings for an inbound listener.
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
    /// How long to wait for the client. RFC 5321 §4.5.3.2.7: at least
    /// 5 minutes while awaiting a command.
    pub idle_timeout: Duration,
    /// Simultaneous connections; more get 421 and are closed.
    pub max_connections: usize,
}

/// Where a recipient goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    /// A local account, identified by its canonical address.
    Local(String),
    /// A local domain, but no such account.
    UnknownUser,
    /// Not one of our domains. We never relay, so this is rejected.
    NotLocal,
}

/// Maps recipients to local accounts.
pub trait Directory: Send + Sync + 'static {
    /// Resolves a RCPT TO forward-path.
    fn resolve(&self, to: &ForwardPath) -> Recipient;
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
    /// Local accounts, deduplicated, in RCPT order.
    pub recipients: Vec<String>,
    /// Whether the client used SMTPUTF8.
    pub smtputf8: bool,
}

/// Final storage for accepted messages.
pub trait Sink: Send + Sync + 'static {
    /// Stores `message` for every recipient. Must not return until the
    /// message is safely on disk: the client is told 250 afterwards
    /// (RFC 5321 §6.1).
    fn deliver(
        &self,
        envelope: &Envelope,
        message: &[u8],
    ) -> impl Future<Output = std::io::Result<()>> + Send;
}

/// Hooks for metrics.
pub trait Observer: Send + Sync + 'static {
    /// A bare CR or LF in message data: possible SMTP smuggling.
    fn smuggling_attempt(&self, _client_ip: IpAddr) {}
    /// A message was accepted and stored.
    fn message_accepted(&self) {}
}

/// An inbound SMTP server.
#[derive(Debug)]
pub struct Server<D, K, O> {
    config: InboundConfig,
    directory: D,
    sink: K,
    observer: O,
    connections: Semaphore,
}

impl<D: Directory, K: Sink, O: Observer> Server<D, K, O> {
    /// Creates a server.
    pub fn new(config: InboundConfig, directory: D, sink: K, observer: O) -> Arc<Self> {
        let connections = Semaphore::new(config.max_connections);
        Arc::new(Self {
            config,
            directory,
            sink,
            observer,
            connections,
        })
    }

    /// Accepts connections on `listener` until it fails.
    pub async fn run(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (stream, peer) = listener.accept().await?;
            let server = self.clone();
            tokio::spawn(async move {
                let permit = server.connections.try_acquire();
                session::run(&server, stream, peer.ip(), permit.is_ok()).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_variants_are_distinct() {
        assert_ne!(Recipient::UnknownUser, Recipient::NotLocal);
    }
}
