//! One SMTP client conversation (RFC 5321 §3, §4): greeting, EHLO,
//! STARTTLS, then one transaction for all recipients, with one outcome per
//! recipient. Reply codes and framing are strict; reply text and unknown
//! EHLO keywords are read leniently (CLAUDE.md).

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use mail_auth_glue::mime;
use queue::Outcome;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use smtp_proto::ehlo::{Capability, EhloResponse};
use smtp_proto::params::{BodyType, MailParam};
use smtp_proto::{ClientName, Command, ForwardPath, Host, Mailbox, Reply, ReversePath};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;

/// RFC 5321 §4.5.3.2 timeouts.
const GREETING_TIMEOUT: Duration = Duration::from_secs(300); // §4.5.3.2.1
const MAIL_TIMEOUT: Duration = Duration::from_secs(300); // §4.5.3.2.2
const RCPT_TIMEOUT: Duration = Duration::from_secs(300); // §4.5.3.2.3
const DATA_INIT_TIMEOUT: Duration = Duration::from_secs(120); // §4.5.3.2.4
const DATA_BLOCK_TIMEOUT: Duration = Duration::from_secs(180); // §4.5.3.2.5
const DATA_END_TIMEOUT: Duration = Duration::from_secs(600); // §4.5.3.2.6
/// EHLO, STARTTLS and QUIT have no RFC timeout; use the command one.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
const TLS_TIMEOUT: Duration = Duration::from_secs(60);
/// Reply lines longer than the RFC's 512 octets are read leniently up to this.
const MAX_REPLY_LINE: usize = 4096;
/// A whole (multi-line) reply may not exceed this.
const MAX_REPLY: usize = 64 * 1024;

/// How to treat STARTTLS on this connection.
#[derive(Debug, Clone)]
pub enum Tls {
    /// Never use STARTTLS (the retry after a failed opportunistic handshake).
    Never,
    /// Use STARTTLS when offered; continue in plaintext otherwise.
    Opportunistic(Arc<ClientConfig>),
    /// STARTTLS is mandatory; without it, give up on this host.
    Required(Arc<ClientConfig>),
}

/// What is being sent.
#[derive(Debug, Clone, Copy)]
pub struct Transaction<'a> {
    /// MAIL FROM; `None` for the null reverse-path.
    pub sender: Option<&'a str>,
    pub recipients: &'a [String],
    /// The message, CRLF line endings.
    pub message: &'a [u8],
}

/// How a conversation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// The transaction ran: one outcome per recipient.
    Done(Vec<Outcome>),
    /// This host failed before the transaction; try the next one.
    HostFailed(String),
    /// An opportunistic TLS handshake failed; the caller may retry this
    /// host without STARTTLS.
    TlsFailed(String),
}

enum Stream<S> {
    Plain(S),
    Tls(Box<TlsStream<S>>),
    Gone,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
            Self::Gone => Poll::Ready(Ok(())),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Stream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_write(cx, buf),
            Self::Gone => Poll::Ready(Err(std::io::ErrorKind::NotConnected.into())),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
            Self::Gone => Poll::Ready(Ok(())),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
            Self::Gone => Poll::Ready(Ok(())),
        }
    }
}

/// Why the conversation stopped early.
#[derive(Debug)]
enum Stop {
    Io(String),
    TlsHandshake(String),
}

struct Conversation<S> {
    stream: Stream<S>,
    buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conversation<S> {
    async fn send(&mut self, bytes: &[u8], limit: Duration) -> Result<(), Stop> {
        let write = async {
            self.stream.write_all(bytes).await?;
            self.stream.flush().await
        };
        match timeout(limit, write).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(Stop::Io(format!("write failed: {e}"))),
            Err(_) => Err(Stop::Io("timed out sending".into())),
        }
    }

    async fn reply(&mut self, limit: Duration) -> Result<Reply, Stop> {
        let read = async {
            loop {
                match Reply::parse(&self.buf, MAX_REPLY_LINE) {
                    Ok(Some((reply, used))) => {
                        self.buf.drain(..used.min(self.buf.len()));
                        return Ok(reply);
                    }
                    Ok(None) if self.buf.len() > MAX_REPLY => {
                        return Err(Stop::Io("reply too long".into()));
                    }
                    Ok(None) => {}
                    Err(e) => return Err(Stop::Io(format!("malformed reply: {e}"))),
                }
                let mut chunk = [0u8; 4096];
                match self.stream.read(&mut chunk).await {
                    Ok(0) => return Err(Stop::Io("connection closed".into())),
                    Ok(n) => self
                        .buf
                        .extend_from_slice(chunk.get(..n).unwrap_or_default()),
                    Err(e) => return Err(Stop::Io(format!("read failed: {e}"))),
                }
            }
        };
        match timeout(limit, read).await {
            Ok(r) => r,
            Err(_) => Err(Stop::Io("timed out waiting for a reply".into())),
        }
    }

    async fn command(&mut self, cmd: &Command, limit: Duration) -> Result<Reply, Stop> {
        self.send(&cmd.to_bytes(), limit).await?;
        self.reply(limit).await
    }

    /// EHLO, falling back to HELO if EHLO isn't recognized (RFC 5321 §3.2).
    async fn hello(&mut self, hostname: &str) -> Result<Result<EhloResponse, String>, Stop> {
        let name = || ClientName::Valid(Host::Domain(hostname.to_owned()));
        let r = self
            .command(&Command::Ehlo { name: name() }, COMMAND_TIMEOUT)
            .await?;
        if r.code == 250 {
            return Ok(EhloResponse::from_reply(&r).map_err(|e| format!("bad EHLO reply: {e}")));
        }
        if !matches!(r.code, 500 | 502) {
            return Ok(Err(describe(&r)));
        }
        let r = self
            .command(&Command::Helo { name: name() }, COMMAND_TIMEOUT)
            .await?;
        if r.code != 250 {
            return Ok(Err(describe(&r)));
        }
        Ok(Ok(EhloResponse {
            domain: String::new(),
            greeting: None,
            capabilities: Vec::new(),
        }))
    }

    async fn starttls(&mut self, config: Arc<ClientConfig>, host: &str) -> Result<(), Stop> {
        let Stream::Plain(plain) = std::mem::replace(&mut self.stream, Stream::Gone) else {
            return Err(Stop::TlsHandshake("already encrypted".into()));
        };
        // RFC 3207 §4.2: nothing from before the handshake may be used.
        self.buf.clear();
        let name = ServerName::try_from(host.to_owned())
            .map_err(|_| Stop::TlsHandshake(format!("{host} is not a valid TLS server name")))?;
        let connector = tokio_rustls::TlsConnector::from(config);
        match timeout(TLS_TIMEOUT, connector.connect(name, plain)).await {
            Ok(Ok(tls)) => {
                self.stream = Stream::Tls(Box::new(tls));
                Ok(())
            }
            Ok(Err(e)) => Err(Stop::TlsHandshake(format!("TLS handshake failed: {e}"))),
            Err(_) => Err(Stop::TlsHandshake("TLS handshake timed out".into())),
        }
    }
}

/// A reply as one line of text, for logs and bounces.
fn describe(r: &Reply) -> String {
    let mut text = r.code.to_string();
    if let Some(e) = r.enhanced {
        text.push(' ');
        text.push_str(&e.to_string());
    }
    for l in &r.lines {
        text.push(' ');
        text.push_str(l);
    }
    // Keep bounces and logs readable.
    text.chars().filter(|c| !c.is_control()).take(500).collect()
}

/// The outcome a reply gives a recipient.
fn outcome(r: &Reply, default_status: &str) -> Outcome {
    if r.is_positive() {
        return Outcome::Delivered;
    }
    let diagnostic = describe(r);
    if r.code / 100 == 4 {
        return Outcome::Temporary(diagnostic);
    }
    let status = r
        .enhanced
        .filter(|e| e.class == 5)
        .map_or_else(|| default_status.to_owned(), |e| e.to_string());
    Outcome::Permanent { status, diagnostic }
}

fn all(n: usize, o: &Outcome) -> Vec<Outcome> {
    vec![o.clone(); n]
}

fn permanent(status: &str, diagnostic: impl Into<String>) -> Outcome {
    Outcome::Permanent {
        status: status.to_owned(),
        diagnostic: diagnostic.into(),
    }
}

/// Whether the transaction needs SMTPUTF8 (RFC 6531 §3.4): non-ASCII in
/// the envelope addresses or in the header section.
pub fn needs_smtputf8(tx: &Transaction<'_>) -> bool {
    let header_end = tx
        .message
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(tx.message.len());
    !tx.sender.unwrap_or_default().is_ascii()
        || tx.recipients.iter().any(|r| !r.is_ascii())
        || !tx.message.get(..header_end).unwrap_or_default().is_ascii()
}

/// Runs one conversation over `stream` as `hostname` with the server
/// `host` (the MX host name, also the TLS server name).
pub async fn run<S>(stream: S, host: &str, hostname: &str, tls: Tls, tx: &Transaction<'_>) -> End
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut c = Conversation {
        stream: Stream::Plain(stream),
        buf: Vec::new(),
    };
    let required = matches!(tls, Tls::Required(_));
    let end = match converse(&mut c, host, hostname, tls, tx).await {
        Ok(end) => end,
        Err(Stop::TlsHandshake(e)) if !required => End::TlsFailed(e),
        Err(Stop::TlsHandshake(e) | Stop::Io(e)) => End::HostFailed(e),
    };
    // RFC 5321 §4.1.1.10: end politely, but don't wait long.
    if !matches!(c.stream, Stream::Gone) {
        let quit = async {
            let _ = c.command(&Command::Quit, Duration::from_secs(10)).await;
            let _ = c.stream.shutdown().await;
        };
        let _ = timeout(Duration::from_secs(15), quit).await;
    }
    end
}

async fn converse<S>(
    c: &mut Conversation<S>,
    host: &str,
    hostname: &str,
    tls: Tls,
    tx: &Transaction<'_>,
) -> Result<End, Stop>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let n = tx.recipients.len();
    // RFC 5321 §3.1: 220 greeting; anything else means try another host.
    let greeting = c.reply(GREETING_TIMEOUT).await?;
    if greeting.code != 220 {
        return Ok(End::HostFailed(format!(
            "greeting: {}",
            describe(&greeting)
        )));
    }
    let mut ehlo = match c.hello(hostname).await? {
        Ok(e) => e,
        Err(e) => return Ok(End::HostFailed(format!("EHLO: {e}"))),
    };

    // STARTTLS (RFC 3207).
    let config = match &tls {
        Tls::Never => None,
        Tls::Opportunistic(cfg) | Tls::Required(cfg) => Some(cfg.clone()),
    };
    if let Some(config) = config {
        if ehlo.has(&Capability::StartTls) {
            let r = c.command(&Command::StartTls, COMMAND_TIMEOUT).await?;
            if r.code == 220 {
                c.starttls(config, host).await?;
                // RFC 3207 §4.2: EHLO again; earlier capabilities are void.
                ehlo = match c.hello(hostname).await? {
                    Ok(e) => e,
                    Err(e) => return Ok(End::HostFailed(format!("EHLO after STARTTLS: {e}"))),
                };
            } else if matches!(tls, Tls::Required(_)) {
                return Ok(End::HostFailed(format!(
                    "STARTTLS refused: {}",
                    describe(&r)
                )));
            }
        } else if matches!(tls, Tls::Required(_)) {
            return Ok(End::HostFailed(
                "TLS is required but STARTTLS is not offered".into(),
            ));
        }
    }

    // RFC 6531 §3.4: SMTPUTF8 mail can't go to a server without it.
    let utf8 = needs_smtputf8(tx);
    if utf8 && !ehlo.has(&Capability::SmtpUtf8) {
        let o = permanent(
            "5.6.7",
            "the message needs SMTPUTF8 (RFC 6531) and the receiving server does not support it",
        );
        return Ok(End::Done(all(n, &o)));
    }
    // RFC 6152 §3: 8-bit data only to servers announcing 8BITMIME;
    // otherwise convert it to 7 bits.
    let eight_bit = mime::is_eight_bit(tx.message);
    let eight_bit_mime = ehlo.has(&Capability::EightBitMime);
    let message: std::borrow::Cow<'_, [u8]> = if eight_bit && !eight_bit_mime && !utf8 {
        match mime::to_seven_bit(tx.message) {
            Ok(m) => m,
            Err(_) => {
                let o = permanent(
                    "5.6.3",
                    "the message has 8-bit data that can't be converted for a server without 8BITMIME",
                );
                return Ok(End::Done(all(n, &o)));
            }
        }
    } else {
        std::borrow::Cow::Borrowed(tx.message)
    };
    // RFC 1870 §6: respect the server's fixed maximum size.
    let size = u64::try_from(message.len()).unwrap_or(u64::MAX);
    if let Some(Some(max)) = ehlo.size()
        && max > 0
        && size > max
    {
        let o = permanent(
            "5.3.4",
            format!("message of {size} octets exceeds the receiving server's limit of {max}"),
        );
        return Ok(End::Done(all(n, &o)));
    }

    // MAIL FROM (RFC 5321 §4.1.1.2).
    let from = match tx.sender {
        None => ReversePath::Null,
        Some(s) => match Mailbox::parse(s) {
            Ok(m) => ReversePath::Mailbox(m),
            Err(_) => {
                let o = permanent("5.1.7", format!("invalid sender address {s:?}"));
                return Ok(End::Done(all(n, &o)));
            }
        },
    };
    let mut params = Vec::new();
    if ehlo.size().is_some() {
        params.push(MailParam::Size(size));
    }
    if eight_bit && eight_bit_mime {
        params.push(MailParam::Body(BodyType::EightBitMime));
    }
    if utf8 {
        params.push(MailParam::SmtpUtf8);
    }
    let r = c
        .command(&Command::Mail { from, params }, MAIL_TIMEOUT)
        .await?;
    if !r.is_positive() {
        return Ok(End::Done(all(n, &outcome(&r, "5.1.7"))));
    }

    // RCPT TO for each recipient (RFC 5321 §4.1.1.3); failures are per
    // recipient.
    let mut outcomes: Vec<Option<Outcome>> = vec![None; n];
    let mut accepted = Vec::new();
    for (i, rcpt) in tx.recipients.iter().enumerate() {
        let Ok(mailbox) = Mailbox::parse(rcpt) else {
            if let Some(o) = outcomes.get_mut(i) {
                *o = Some(permanent(
                    "5.1.3",
                    format!("invalid recipient address {rcpt:?}"),
                ));
            }
            continue;
        };
        let cmd = Command::Rcpt {
            to: ForwardPath::Mailbox(mailbox),
            params: Vec::new(),
        };
        let r = c.command(&cmd, RCPT_TIMEOUT).await?;
        if r.is_positive() {
            accepted.push(i);
        } else if let Some(o) = outcomes.get_mut(i) {
            *o = Some(outcome(&r, "5.1.1"));
        }
    }
    let finish = |outcomes: Vec<Option<Outcome>>, rest: &Outcome| {
        outcomes
            .into_iter()
            .map(|o| o.unwrap_or_else(|| rest.clone()))
            .collect::<Vec<_>>()
    };
    if accepted.is_empty() {
        let _ = c.command(&Command::Rset, COMMAND_TIMEOUT).await;
        let none = Outcome::Temporary("no recipient was accepted".into());
        return Ok(End::Done(finish(outcomes, &none)));
    }

    // DATA (RFC 5321 §4.1.1.4).
    let r = c.command(&Command::Data, DATA_INIT_TIMEOUT).await?;
    if r.code != 354 {
        let o = if r.is_positive() {
            Outcome::Temporary(format!("unexpected reply to DATA: {}", describe(&r)))
        } else {
            outcome(&r, "5.0.0")
        };
        return Ok(End::Done(finish(outcomes, &o)));
    }
    let mut body = Vec::with_capacity(message.len() + message.len() / 64 + 8);
    if smtp_proto::data::encode(&message, &mut body).is_err() {
        // Spooled mail always has CRLF line endings; this is a bug.
        return Err(Stop::Io("message has bare CR or LF; not sent".into()));
    }
    for chunk in body.chunks(64 * 1024) {
        c.send(chunk, DATA_BLOCK_TIMEOUT).await?;
    }
    let r = c.reply(DATA_END_TIMEOUT).await?;
    let o = outcome(&r, "5.0.0");
    Ok(End::Done(finish(outcomes, &o)))
}
