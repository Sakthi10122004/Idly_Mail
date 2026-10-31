//! One SMTP connection: greeting, commands, DATA, replies.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use smtp_proto::data::{DataDecoder, Progress};
use smtp_proto::ehlo::{Capability, EhloResponse};
use smtp_proto::line::split_line;
use smtp_proto::{
    BodyType, ClientName, Command, EnhancedCode, Error, ForwardPath, Host, MailParam, Reply,
    ReversePath,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::{Directory, Envelope, Observer, Recipient, Server, Sink, date};

/// Too many bad commands in one session: the client is not speaking SMTP.
const MAX_ERRORS: u32 = 20;

/// Read buffer growth step.
const READ_CHUNK: usize = 8 * 1024;

/// What the command loop does next.
enum Next {
    Continue,
    Close,
}

struct Transaction {
    from: ReversePath,
    smtputf8: bool,
    recipients: Vec<String>,
}

struct Session<'a, D, K, O, S> {
    server: &'a Server<D, K, O>,
    stream: S,
    client_ip: IpAddr,
    buf: Vec<u8>,
    out: Vec<u8>,
    client_name: Option<ClientName>,
    esmtp: bool,
    tx: Option<Transaction>,
    errors: u32,
}

/// Runs a session to completion. `admitted` is false when the connection
/// limit is reached: the client gets 421 and is closed.
pub(crate) async fn run<D, K, O, S>(
    server: &Server<D, K, O>,
    stream: S,
    client_ip: IpAddr,
    admitted: bool,
) where
    D: Directory,
    K: Sink,
    O: Observer,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut session = Session {
        server,
        stream,
        client_ip,
        buf: Vec::new(),
        out: Vec::new(),
        client_name: None,
        esmtp: false,
        tx: None,
        errors: 0,
    };
    tracing::debug!(%client_ip, "connection opened");
    if !admitted {
        // RFC 5321 §3.8: 421 when the service must close the channel.
        session.reply(421, (4, 7, 0), "Too many connections, try again later");
        let _ = session.flush().await;
        return;
    }
    if let Err(e) = session.serve().await {
        tracing::debug!(%client_ip, error = %e, "connection ended with error");
    }
    tracing::debug!(%client_ip, "connection closed");
}

impl<D, K, O, S> Session<'_, D, K, O, S>
where
    D: Directory,
    K: Sink,
    O: Observer,
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn cfg(&self) -> &crate::InboundConfig {
        &self.server.config
    }

    fn reply(&mut self, code: u16, (c, s, d): (u8, u16, u16), text: &str) {
        Reply::new(code, Some(EnhancedCode::new(c, s, d)), text).write_to(&mut self.out);
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        if !self.out.is_empty() {
            self.stream.write_all(&self.out).await?;
            self.stream.flush().await?;
            self.out.clear();
        }
        Ok(())
    }

    /// Reads more input into `buf`. Returns false on EOF or timeout.
    async fn fill(&mut self) -> std::io::Result<bool> {
        let start = self.buf.len();
        self.buf.resize(start + READ_CHUNK, 0);
        let idle = self.cfg().idle_timeout;
        let read = timeout(
            idle,
            self.stream
                .read(self.buf.get_mut(start..).unwrap_or_default()),
        )
        .await;
        let n = match read {
            Ok(r) => r?,
            Err(_) => {
                self.buf.truncate(start);
                // RFC 5321 §4.5.3.2.7: we waited at least 5 minutes.
                self.reply(421, (4, 4, 2), "Idle timeout, closing connection");
                self.flush().await?;
                return Ok(false);
            }
        };
        self.buf.truncate(start + n);
        Ok(n > 0)
    }

    async fn serve(&mut self) -> std::io::Result<()> {
        // RFC 5321 §4.2: the greeting is a 220 reply.
        let greeting = format!("{} ESMTP Idly Mail ready", self.cfg().hostname);
        Reply::new(220, None, greeting).write_to(&mut self.out);
        self.flush().await?;
        loop {
            // Handle every complete line already buffered (pipelining,
            // RFC 2920 §3.1), then flush the replies together.
            loop {
                let cap = self.cfg().command_line_cap;
                let line = match split_line(&self.buf, cap) {
                    Ok(Some((line, consumed))) => {
                        let line = line.to_vec();
                        self.buf.drain(..consumed);
                        line
                    }
                    Ok(None) => break,
                    Err(e) => {
                        // A bare CR/LF or an over-long line: the stream
                        // can't be resynchronized, so reply and close.
                        tracing::warn!(client_ip = %self.client_ip, reason = "bad-command-line", error = %e, "closing connection");
                        self.reply_error(&e);
                        return self.flush().await;
                    }
                };
                match self.command(&line).await? {
                    Next::Continue => {}
                    Next::Close => return self.flush().await,
                }
            }
            self.flush().await?;
            if !self.fill().await? {
                return Ok(());
            }
        }
    }

    fn reply_error(&mut self, e: &Error) {
        let (code, enh) = e.reply_code().unwrap_or((500, EnhancedCode::new(5, 5, 2)));
        Reply::new(code, Some(enh), e.to_string()).write_to(&mut self.out);
    }

    async fn command(&mut self, line: &[u8]) -> std::io::Result<Next> {
        let cmd = match Command::parse(line) {
            Ok(c) => c,
            Err(e) => {
                self.reply_error(&e);
                return Ok(self.count_error());
            }
        };
        match cmd {
            Command::Ehlo { name } => {
                self.greet(name, true);
            }
            Command::Helo { name } => {
                self.greet(name, false);
            }
            Command::Mail { from, params } => self.mail(from, &params),
            Command::Rcpt { to, .. } => self.rcpt(&to),
            Command::Data => return self.data().await,
            Command::Rset => {
                // RFC 5321 §4.1.1.5: RSET aborts the current transaction.
                self.tx = None;
                self.reply(250, (2, 0, 0), "OK");
            }
            Command::Noop(_) => self.reply(250, (2, 0, 0), "OK"),
            Command::Help(_) => self.reply(214, (2, 0, 0), "See RFC 5321"),
            Command::Vrfy(_) => {
                // RFC 5321 §3.5.3: 252 when we won't verify but will accept.
                self.reply(252, (2, 5, 0), "Cannot VRFY user, but will accept message");
            }
            Command::Quit => {
                // RFC 5321 §4.1.1.10: QUIT gets 221 and the channel closes.
                self.reply(221, (2, 0, 0), "Bye");
                return Ok(Next::Close);
            }
            Command::Expn(_) | Command::StartTls | Command::Auth { .. } | Command::Bdat { .. } => {
                // Not offered on this listener: no TLS, no AUTH and no
                // CHUNKING yet (milestone 6). RFC 5321 §4.2.4: 502 for a
                // recognized but unimplemented command.
                self.reply(502, (5, 5, 1), "Command not implemented");
                return Ok(self.count_error());
            }
        }
        Ok(Next::Continue)
    }

    fn count_error(&mut self) -> Next {
        self.errors = self.errors.saturating_add(1);
        if self.errors >= MAX_ERRORS {
            self.reply(421, (4, 7, 0), "Too many errors, closing connection");
            return Next::Close;
        }
        Next::Continue
    }

    fn greet(&mut self, name: ClientName, esmtp: bool) {
        if !name.is_valid() {
            // CLAUDE.md: never reject on the name; record it for scoring.
            tracing::info!(client_ip = %self.client_ip, client_name = %name, signal = "invalid-client-name", "accepted invalid HELO/EHLO name");
        }
        self.client_name = Some(name);
        self.esmtp = esmtp;
        // RFC 5321 §4.1.4: EHLO/HELO also reset any transaction.
        self.tx = None;
        let hostname = self.cfg().hostname.clone();
        if esmtp {
            let ehlo = EhloResponse {
                domain: hostname,
                greeting: Some(format!("greets [{}]", self.client_ip)),
                capabilities: vec![
                    Capability::Pipelining,
                    Capability::Size(Some(self.cfg().message_size)),
                    Capability::EightBitMime,
                    Capability::SmtpUtf8,
                    Capability::EnhancedStatusCodes,
                ],
            };
            ehlo.to_reply().write_to(&mut self.out);
        } else {
            Reply::new(250, None, hostname).write_to(&mut self.out);
        }
    }

    fn mail(&mut self, from: ReversePath, params: &[MailParam]) {
        if self.client_name.is_none() {
            // RFC 5321 §4.1.4: a transaction starts only after EHLO/HELO.
            return self.reply(503, (5, 5, 1), "Send EHLO first");
        }
        if self.tx.is_some() {
            // RFC 5321 §4.1.4: MAIL must not be sent inside a transaction.
            return self.reply(503, (5, 5, 1), "Nested MAIL command");
        }
        let mut smtputf8 = false;
        for p in params {
            match p {
                // RFC 1870 §6.1: a declared size over our limit gets 552.
                MailParam::Size(n) if *n > self.cfg().message_size => {
                    return self.reply(
                        552,
                        (5, 3, 4),
                        "Message size exceeds fixed maximum message size",
                    );
                }
                MailParam::Size(_)
                | MailParam::Body(BodyType::SevenBit | BodyType::EightBitMime) => {}
                MailParam::SmtpUtf8 if self.esmtp => smtputf8 = true,
                // RFC 5321 §4.1.1.11: 555 for parameters we don't support
                // (including BINARYMIME without CHUNKING, and anything after
                // HELO, which offers no extensions).
                _ => return self.reply(555, (5, 5, 4), "Parameter not supported"),
            }
        }
        if let ReversePath::Mailbox(m) = &from
            && !m.is_ascii()
            && !smtputf8
        {
            // RFC 6531 §3.5: 550 and X.6.7 for a non-ASCII sender without SMTPUTF8.
            return self.reply(550, (5, 6, 7), "Non-ASCII address requires SMTPUTF8");
        }
        self.tx = Some(Transaction {
            from,
            smtputf8,
            recipients: Vec::new(),
        });
        self.reply(250, (2, 1, 0), "Sender OK");
    }

    fn rcpt(&mut self, to: &ForwardPath) {
        let max = self.cfg().max_recipients;
        let Some(tx) = &self.tx else {
            // RFC 5321 §3.3: RCPT without MAIL gets 503.
            return self.reply(503, (5, 5, 1), "Send MAIL first");
        };
        if let ForwardPath::Mailbox(m) = to
            && !m.is_ascii()
            && !tx.smtputf8
        {
            // RFC 6531 §3.5: 553 and X.6.7 for a non-ASCII recipient.
            return self.reply(553, (5, 6, 7), "Non-ASCII address requires SMTPUTF8");
        }
        if tx.recipients.len() >= max {
            // RFC 5321 §4.5.3.1.10: 452 for too many recipients.
            return self.reply(452, (4, 5, 3), "Too many recipients");
        }
        let account = match self.server.directory.resolve(to) {
            Recipient::Local(account) => account,
            // RFC 3463 §3.2: X.1.1 bad destination mailbox address.
            Recipient::UnknownUser => return self.reply(550, (5, 1, 1), "No such user here"),
            Recipient::NotLocal => {
                // We never relay (CLAUDE.md hard constraint 1).
                // RFC 3463 §3.8: X.7.1 delivery not authorized.
                tracing::info!(client_ip = %self.client_ip, recipient = %to, "relay attempt refused");
                return self.reply(550, (5, 7, 1), "Relaying denied");
            }
        };
        if let Some(tx) = &mut self.tx
            && !tx.recipients.contains(&account)
        {
            tx.recipients.push(account);
        }
        self.reply(250, (2, 1, 5), "Recipient OK");
    }

    async fn data(&mut self) -> std::io::Result<Next> {
        let has_recipients = self.tx.as_ref().is_some_and(|t| !t.recipients.is_empty());
        if !has_recipients {
            // RFC 5321 §3.3: 503 or 554 when there is no valid recipient.
            self.reply(554, (5, 5, 1), "No valid recipients");
            return Ok(Next::Continue);
        }
        // RFC 5321 §4.1.1.4: 354, then the client sends the message.
        self.reply(354, (2, 0, 0), "End data with <CR><LF>.<CR><LF>");
        self.flush().await?;

        let limit = self.cfg().message_size;
        let mut decoder = DataDecoder::new(Some(self.cfg().data_line_cap));
        let mut message = Vec::new();
        let mut too_big = false;
        loop {
            let input = std::mem::take(&mut self.buf);
            let result = decoder.decode(&input, &mut message);
            if usize::try_from(limit).is_ok_and(|l| message.len() > l) {
                // Keep reading to the end of data, but stop storing.
                too_big = true;
                message.clear();
            }
            match result {
                Ok(Progress::Done { consumed }) => {
                    // Anything after the end of data is the next command.
                    self.buf = input.get(consumed..).unwrap_or_default().to_vec();
                    break;
                }
                Ok(Progress::NeedMore) => {
                    if !self.fill().await? {
                        // EOF or timeout mid-message: nothing is stored.
                        return Ok(Next::Close);
                    }
                }
                Err(e @ (Error::BareCr | Error::BareLf)) => {
                    // CLAUDE.md policy: reply 5xx 5.5.2, close, discard the
                    // partial message (never stored), log for reputation.
                    tracing::warn!(
                        client_ip = %self.client_ip,
                        reason = "smuggling-attempt",
                        error = %e,
                        "bare CR or LF in message data; message discarded, closing connection"
                    );
                    self.server.observer.smuggling_attempt(self.client_ip);
                    self.reply(
                        500,
                        (5, 5, 2),
                        "Bare CR or LF in message data; closing connection",
                    );
                    self.tx = None;
                    return Ok(Next::Close);
                }
                Err(e) => {
                    // Line too long: also no safe way to continue.
                    tracing::warn!(client_ip = %self.client_ip, reason = "bad-data-line", error = %e, "closing connection");
                    self.reply_error(&e);
                    self.tx = None;
                    return Ok(Next::Close);
                }
            }
        }

        let Some(tx) = self.tx.take() else {
            return Ok(Next::Continue);
        };
        if too_big {
            // RFC 1870 §6.1: 552 when the message exceeds the limit.
            self.reply(
                552,
                (5, 3, 4),
                "Message size exceeds fixed maximum message size",
            );
            return Ok(Next::Continue);
        }
        let envelope = Envelope {
            id: new_id(),
            client_ip: self.client_ip,
            client_name: self
                .client_name
                .clone()
                .unwrap_or(ClientName::Invalid(String::new())),
            from: tx.from,
            recipients: tx.recipients,
            smtputf8: tx.smtputf8,
        };
        let mut stored = received_header(&envelope, &self.cfg().hostname, self.esmtp).into_bytes();
        stored.extend_from_slice(&message);
        match self.server.sink.deliver(&envelope, &stored).await {
            Ok(()) => {
                self.server.observer.message_accepted();
                tracing::info!(
                    id = %envelope.id,
                    client_ip = %self.client_ip,
                    from = %envelope.from,
                    recipients = envelope.recipients.len(),
                    size = stored.len(),
                    "message accepted"
                );
                self.reply(250, (2, 0, 0), &format!("OK, queued as {}", envelope.id));
            }
            Err(e) => {
                tracing::error!(id = %envelope.id, error = %e, "local delivery failed");
                // RFC 3463 §3.4: X.3.0 mail system problem; the client retries.
                self.reply(451, (4, 3, 0), "Local delivery failed, try again later");
            }
        }
        Ok(Next::Continue)
    }
}

fn new_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "{:x}{:05x}{:04x}",
        now.as_secs(),
        now.subsec_micros(),
        n & 0xffff
    )
}

/// RFC 5321 §4.4 trace header, with the protocol name from RFC 3848 and
/// RFC 6531 §4.3. The client's claimed name is only shown when valid.
fn received_header(env: &Envelope, hostname: &str, esmtp: bool) -> String {
    let from = match &env.client_name {
        ClientName::Valid(Host::Domain(d)) => d.clone(),
        ClientName::Valid(h) => h.to_string(),
        ClientName::Invalid(_) => "unknown".to_owned(),
    };
    let with = match (esmtp, env.smtputf8) {
        (_, true) => "UTF8SMTP",
        (true, false) => "ESMTP",
        (false, false) => "SMTP",
    };
    let date = date::rfc5322(SystemTime::now());
    format!(
        "Received: from {from} ([{ip}])\r\n\tby {hostname} (Idly Mail) with {with} id {id};\r\n\t{date}\r\n",
        ip = env.client_ip,
        id = env.id,
    )
}
