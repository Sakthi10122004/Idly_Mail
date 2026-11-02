//! One SMTP connection: greeting, commands, STARTTLS, AUTH, DATA, replies.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use smtp_proto::address::domain_to_ascii;
use smtp_proto::data::{DataDecoder, Progress};
use smtp_proto::date;
use smtp_proto::ehlo::{Capability, EhloResponse};
use smtp_proto::limits::AUTH_COMMAND_LINE;
use smtp_proto::line::split_line;
use smtp_proto::{
    BodyType, ClientName, Command, EnhancedCode, Error, ForwardPath, Host, InitialResponse,
    MailParam, Mailbox, Reply, ReversePath,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::conn::Conn;
use crate::inbound::{self, Decision};
use crate::submission::{self, Refusal};
use crate::{Directory, Envelope, Mode, Observer, Rcpt, Recipient, Server, Signals, Sink, auth};

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
    recipients: Vec<Rcpt>,
}

/// How a SASL exchange line ended, other than with a response.
enum SaslEnd {
    /// "*": the client cancelled (RFC 4954 §4: 501).
    Cancelled,
    /// The connection closed, timed out, or sent a bad line.
    Closed,
}

struct Session<'a, D, K, O, R, S> {
    server: &'a Server<D, K, O, R>,
    conn: Conn<S>,
    mode: Mode,
    client_ip: IpAddr,
    buf: Vec<u8>,
    out: Vec<u8>,
    client_name: Option<ClientName>,
    esmtp: bool,
    tx: Option<Transaction>,
    errors: u32,
    signals: Signals,
    /// The authenticated account.
    auth: Option<String>,
    auth_failures: u32,
}

/// Runs a session to completion. `admitted` is false when the connection
/// limit is reached: the client gets 421 and is closed.
pub(crate) async fn run<D, K, O, R, S>(
    server: &Arc<Server<D, K, O, R>>,
    stream: S,
    client_ip: IpAddr,
    mode: Mode,
    admitted: bool,
) where
    D: Directory,
    K: Sink,
    O: Observer,
    R: dns::Resolver,
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut session = Session {
        server,
        conn: Conn::Plain(stream),
        mode,
        client_ip,
        buf: Vec::new(),
        out: Vec::new(),
        client_name: None,
        esmtp: false,
        tx: None,
        errors: 0,
        signals: Signals::default(),
        auth: None,
        auth_failures: 0,
    };
    tracing::debug!(%client_ip, ?mode, "connection opened");
    if !admitted {
        // RFC 5321 §3.8: 421 when the service must close the channel.
        session.reply(421, (4, 7, 0), "Too many connections, try again later");
        let _ = timeout(Duration::from_secs(5), session.flush()).await;
        return;
    }
    // A hard cap on the whole session, so slow clients can't hold a
    // connection forever.
    match timeout(server.config.session_timeout, session.serve()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::debug!(%client_ip, error = %e, "connection ended with error"),
        Err(_) => {
            tracing::info!(%client_ip, "session time limit reached; closing");
            session.out.clear();
            session.reply(
                421,
                (4, 4, 2),
                "Session time limit reached, closing connection",
            );
            let _ = timeout(Duration::from_secs(5), session.flush()).await;
        }
    }
    let _ = timeout(Duration::from_secs(5), session.conn.shutdown()).await;
    tracing::debug!(%client_ip, "connection closed");
}

fn starts_with_ignore_case(b: &[u8], prefix: &[u8]) -> bool {
    b.get(..prefix.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
}

/// `local@domain` with the domain in A-label form, for ownership checks.
fn normalized(m: &Mailbox) -> String {
    match &m.host {
        Host::Domain(d) => format!(
            "{}@{}",
            m.local_part,
            domain_to_ascii(d).unwrap_or_else(|_| d.to_ascii_lowercase())
        ),
        other => format!("{}@{other}", m.local_part),
    }
}

impl<D, K, O, R, S> Session<'_, D, K, O, R, S>
where
    D: Directory,
    K: Sink,
    O: Observer,
    R: dns::Resolver,
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn cfg(&self) -> &crate::InboundConfig {
        &self.server.config
    }

    fn is_submission(&self) -> bool {
        matches!(self.mode, Mode::Submission | Mode::SubmissionImplicitTls)
    }

    fn reply(&mut self, code: u16, (c, s, d): (u8, u16, u16), text: &str) {
        Reply::new(code, Some(EnhancedCode::new(c, s, d)), text).write_to(&mut self.out);
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        if !self.out.is_empty() {
            self.conn.write_all(&self.out).await?;
            self.conn.flush().await?;
            self.out.clear();
        }
        Ok(())
    }

    /// Reads more input into `buf`, waiting at most `wait`. Returns false on
    /// EOF or timeout.
    async fn fill(&mut self, wait: Duration) -> std::io::Result<bool> {
        let start = self.buf.len();
        self.buf.resize(start + READ_CHUNK, 0);
        let read = timeout(
            wait,
            self.conn
                .read(self.buf.get_mut(start..).unwrap_or_default()),
        )
        .await;
        let n = match read {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                self.buf.truncate(start);
                return Err(e);
            }
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

    /// The next complete line, if one is buffered. Command lines are capped
    /// at `command_line_cap`, except AUTH lines and SASL responses, which
    /// may be up to 12288 octets (RFC 4954 §4).
    fn next_line(&mut self, sasl: bool) -> Result<Option<Vec<u8>>, Error> {
        let cap = self.cfg().command_line_cap;
        let max = cap.max(AUTH_COMMAND_LINE);
        let long_ok = |b: &[u8]| sasl || starts_with_ignore_case(b, b"AUTH ");
        match split_line(&self.buf, max)? {
            Some((line, consumed)) => {
                if consumed > cap && !long_ok(line) {
                    return Err(Error::LineTooLong { limit: cap });
                }
                let line = line.to_vec();
                self.buf.drain(..consumed);
                Ok(Some(line))
            }
            None if self.buf.len() + 2 > cap && !long_ok(&self.buf) => {
                Err(Error::LineTooLong { limit: cap })
            }
            None => Ok(None),
        }
    }

    /// Replies to a framing error; the stream can't be resynchronized.
    fn line_error(&mut self, e: &Error) {
        if matches!(e, Error::BareCr | Error::BareLf) {
            // CLAUDE.md policy: counted like bare CR/LF in DATA.
            tracing::warn!(client_ip = %self.client_ip, reason = "smuggling-attempt", error = %e, "bare CR or LF in command line, closing connection");
            self.server.observer.smuggling_attempt(self.client_ip);
        } else {
            tracing::warn!(client_ip = %self.client_ip, reason = "bad-command-line", error = %e, "closing connection");
        }
        self.reply_error(e);
    }

    async fn serve(&mut self) -> std::io::Result<()> {
        // RFC 8314 §3.3: on port 465 TLS starts before the greeting.
        if self.mode == Mode::SubmissionImplicitTls && !self.start_tls().await? {
            return Ok(());
        }
        // RFC 5321 §4.2: the greeting is a 220 reply.
        let greeting = format!("{} ESMTP Idly Mail ready", self.cfg().hostname);
        Reply::new(220, None, greeting).write_to(&mut self.out);
        self.flush().await?;
        loop {
            // Handle every complete line already buffered (pipelining,
            // RFC 2920 §3.1), then flush the replies together.
            loop {
                let line = match self.next_line(false) {
                    Ok(Some(line)) => line,
                    Ok(None) => break,
                    Err(e) => {
                        self.line_error(&e);
                        return self.flush().await;
                    }
                };
                match self.command(&line).await? {
                    Next::Continue => {}
                    Next::Close => return self.flush().await,
                }
            }
            self.flush().await?;
            if !self.fill(self.cfg().command_timeout).await? {
                return Ok(());
            }
        }
    }

    fn reply_error(&mut self, e: &Error) {
        let (code, enh) = e.reply_code().unwrap_or((500, EnhancedCode::new(5, 5, 2)));
        Reply::new(code, Some(enh), e.to_string()).write_to(&mut self.out);
    }

    async fn command(&mut self, line: &[u8]) -> std::io::Result<Next> {
        let cmd = match Command::parse_with_signals(line) {
            Ok((c, signals)) => {
                if signals.missing_angle_brackets {
                    // CLAUDE.md: accepted, never rejected; recorded for scoring.
                    tracing::info!(client_ip = %self.client_ip, signal = "missing-angle-brackets", "accepted path without angle brackets");
                    self.signals.missing_angle_brackets = true;
                }
                c
            }
            Err(e) => {
                self.reply_error(&e);
                return Ok(self.count_error());
            }
        };
        match cmd {
            Command::Ehlo { name } => self.greet(name, true),
            Command::Helo { name } => self.greet(name, false),
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
            Command::StartTls => return self.starttls().await,
            Command::Auth {
                mechanism,
                initial_response,
            } => return self.auth(&mechanism, initial_response).await,
            Command::Expn(_) | Command::Bdat { .. } => {
                // RFC 5321 §4.2.4: 502 for a recognized but unimplemented command.
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
            self.signals.invalid_client_name = true;
            // CLAUDE.md: never reject on the name; record it for scoring.
            tracing::info!(client_ip = %self.client_ip, client_name = %name, signal = "invalid-client-name", "accepted invalid HELO/EHLO name");
        }
        self.client_name = Some(name);
        self.esmtp = esmtp;
        // RFC 5321 §4.1.4: EHLO/HELO also reset any transaction.
        self.tx = None;
        let hostname = self.cfg().hostname.clone();
        if !esmtp {
            Reply::new(250, None, hostname).write_to(&mut self.out);
            return;
        }
        let mut capabilities = vec![
            Capability::Pipelining,
            Capability::Size(Some(self.cfg().message_size)),
            Capability::EightBitMime,
            Capability::SmtpUtf8,
            Capability::EnhancedStatusCodes,
        ];
        // RFC 3207 §4.2: never offer STARTTLS once TLS is active.
        if self.server.tls.is_some() && !self.conn.is_tls() {
            capabilities.push(Capability::StartTls);
        }
        // AUTH only on submission ports, only under TLS, only once.
        if self.is_submission()
            && self.conn.is_tls()
            && self.auth.is_none()
            && self.server.accounts.is_some()
        {
            // RFC 4954 §3: the AUTH keyword lists the SASL mechanisms.
            capabilities.push(Capability::Auth(vec!["PLAIN".into(), "LOGIN".into()]));
        }
        let ehlo = EhloResponse {
            domain: hostname,
            greeting: Some(format!("greets [{}]", self.client_ip)),
            capabilities,
        };
        ehlo.to_reply().write_to(&mut self.out);
    }

    /// RFC 3207 §4.2: after the handshake, discard everything learned from
    /// the client: name, transaction, authentication, signals.
    fn reset_after_tls(&mut self) {
        self.client_name = None;
        self.esmtp = false;
        self.tx = None;
        self.auth = None;
        self.signals = Signals::default();
        self.buf.clear();
    }

    /// Runs the TLS handshake on the current plaintext connection.
    async fn start_tls(&mut self) -> std::io::Result<bool> {
        let Some(tls) = self.server.tls.clone() else {
            return Ok(false);
        };
        let Conn::Plain(stream) = std::mem::replace(&mut self.conn, Conn::Closed) else {
            return Ok(false);
        };
        match timeout(
            self.cfg().tls_handshake_timeout,
            TlsAcceptor::from(tls).accept(stream),
        )
        .await
        {
            Ok(Ok(s)) => {
                let (_, info) = s.get_ref();
                tracing::debug!(client_ip = %self.client_ip, version = ?info.protocol_version(), cipher = ?info.negotiated_cipher_suite().map(|c| c.suite()), "TLS established");
                self.conn = Conn::Tls(Box::new(s));
                self.reset_after_tls();
                Ok(true)
            }
            Ok(Err(e)) => {
                tracing::info!(client_ip = %self.client_ip, error = %e, "TLS handshake failed");
                Ok(false)
            }
            Err(_) => {
                tracing::info!(client_ip = %self.client_ip, "TLS handshake timed out");
                Ok(false)
            }
        }
    }

    async fn starttls(&mut self) -> std::io::Result<Next> {
        if self.server.tls.is_none() || self.mode == Mode::SubmissionImplicitTls {
            self.reply(502, (5, 5, 1), "Command not implemented");
            return Ok(self.count_error());
        }
        if self.conn.is_tls() {
            self.reply(503, (5, 5, 1), "TLS already active");
            return Ok(Next::Continue);
        }
        // STARTTLS command injection (the CVE-2011-0411 class): anything the
        // client sent after the STARTTLS line arrived in plaintext and must
        // never be executed inside the TLS session. Refuse and close.
        if !self.buf.is_empty() {
            tracing::warn!(client_ip = %self.client_ip, reason = "starttls-injection", bytes = self.buf.len(), "plaintext pipelined after STARTTLS; closing connection");
            self.buf.clear();
            self.reply(
                554,
                (5, 5, 1),
                "Pipelined commands after STARTTLS are not allowed",
            );
            return Ok(Next::Close);
        }
        // RFC 3207 §4: 220 Ready to start TLS.
        self.reply(220, (2, 0, 0), "Ready to start TLS");
        self.flush().await?;
        Ok(if self.start_tls().await? {
            Next::Continue
        } else {
            Next::Close
        })
    }

    /// Writes a 334 challenge (RFC 4954 §4) and reads the client's response.
    async fn sasl_exchange(&mut self, challenge: &str) -> std::io::Result<Result<String, SaslEnd>> {
        // Written by hand so an empty challenge still gets "334 ".
        self.out
            .extend_from_slice(format!("334 {challenge}\r\n").as_bytes());
        self.flush().await?;
        loop {
            match self.next_line(true) {
                Ok(Some(line)) => {
                    let line = String::from_utf8(line).unwrap_or_default();
                    return Ok(if line == "*" {
                        Err(SaslEnd::Cancelled)
                    } else {
                        Ok(line)
                    });
                }
                Ok(None) => {
                    if !self.fill(self.cfg().command_timeout).await? {
                        return Ok(Err(SaslEnd::Closed));
                    }
                }
                Err(e) => {
                    self.line_error(&e);
                    return Ok(Err(SaslEnd::Closed));
                }
            }
        }
    }

    async fn auth(
        &mut self,
        mechanism: &str,
        initial: Option<InitialResponse>,
    ) -> std::io::Result<Next> {
        // Never on port 25.
        let accounts = match (&self.server.accounts, self.is_submission()) {
            (Some(a), true) => a.clone(),
            _ => {
                self.reply(502, (5, 5, 1), "Command not implemented");
                return Ok(self.count_error());
            }
        };
        // RFC 4954 §6: 538 when the mechanism needs an encrypted channel.
        if !self.conn.is_tls() {
            self.reply(
                538,
                (5, 7, 11),
                "Encryption required for requested authentication mechanism",
            );
            return Ok(Next::Continue);
        }
        // RFC 4954 §4: no second AUTH, and none during a transaction.
        if self.auth.is_some() || self.tx.is_some() {
            self.reply(503, (5, 5, 1), "Bad sequence of commands");
            return Ok(Next::Continue);
        }
        if self.server.guard.ip_locked(self.client_ip) {
            tracing::warn!(client_ip = %self.client_ip, "AUTH refused: too many failures from this address");
            self.reply(421, (4, 7, 0), "Too many failed logins, try again later");
            return Ok(Next::Close);
        }
        let initial = initial.map(|r| match r {
            InitialResponse::Empty => "=".to_owned(),
            InitialResponse::Base64(b) => b,
        });
        // Each step yields the decoded response, or ends the exchange.
        macro_rules! step {
            ($challenge:expr, $given:expr) => {{
                let line = match $given {
                    Some(l) => l,
                    None => match self.sasl_exchange($challenge).await? {
                        Ok(l) => l,
                        Err(SaslEnd::Cancelled) => {
                            // RFC 4954 §4: a cancelled exchange gets 501.
                            self.reply(501, (5, 0, 0), "Authentication cancelled");
                            return Ok(Next::Continue);
                        }
                        Err(SaslEnd::Closed) => return Ok(Next::Close),
                    },
                };
                match auth::decode(&line) {
                    Ok(v) => v,
                    Err(_) => {
                        // RFC 4954 §4: undecodable base64 gets 501.
                        self.reply(501, (5, 5, 2), "Invalid base64 data");
                        return Ok(Next::Continue);
                    }
                }
            }};
        }
        let credentials = match mechanism {
            // RFC 4616 §2.
            "PLAIN" => {
                let msg = step!("", initial);
                auth::parse_plain(&msg)
            }
            // LOGIN: base64 prompts for "Username:" and "Password:".
            "LOGIN" => {
                let user = step!("VXNlcm5hbWU6", initial);
                let pass = step!("UGFzc3dvcmQ6", None::<String>);
                match (String::from_utf8(user), String::from_utf8(pass)) {
                    (Ok(u), Ok(p)) if !u.is_empty() => Some((u, p)),
                    _ => None,
                }
            }
            _ => {
                // RFC 4954 §4: 504 for an unsupported mechanism.
                self.reply(504, (5, 5, 4), "Unrecognized authentication type");
                return Ok(Next::Continue);
            }
        };
        let username = credentials
            .as_ref()
            .map(|(u, _)| u.clone())
            .unwrap_or_default();
        let accounts_for_log = accounts.clone();
        let account = match credentials {
            Some((user, pass)) => {
                // Argon2 is CPU-heavy: at most a few checks at once, each on
                // a blocking thread. The password is never logged.
                let Ok(_permit) = self.server.guard.verifications.acquire().await else {
                    return Ok(Next::Close);
                };
                tokio::task::spawn_blocking(move || accounts.verify(&user, &pass))
                    .await
                    .ok()
                    .flatten()
            }
            None => None,
        };
        match account {
            Some(account) => {
                self.server.guard.success(&username);
                tracing::info!(client_ip = %self.client_ip, account = %account, "authenticated");
                self.auth = Some(account);
                // RFC 4954 §6.
                self.reply(235, (2, 7, 0), "Authentication successful");
                Ok(Next::Continue)
            }
            None => {
                let delay = self.server.guard.failure(self.client_ip, &username);
                self.server.observer.auth_failure(self.client_ip);
                // Only existing account names are logged: a user who types the
                // password into the user-name field must not leak it to logs.
                let logged = accounts_for_log
                    .account_name(&username)
                    .unwrap_or_else(|| "unknown-user".to_owned());
                tracing::warn!(client_ip = %self.client_ip, username = %logged, "authentication failed");
                // The same reply, whether or not the account exists.
                tokio::time::sleep(delay).await;
                self.auth_failures = self.auth_failures.saturating_add(1);
                if self.auth_failures >= self.server.guard.limits.max_attempts_per_session {
                    self.reply(421, (4, 7, 0), "Too many failed logins, closing connection");
                    return Ok(Next::Close);
                }
                // RFC 4954 §6.
                self.reply(535, (5, 7, 8), "Authentication credentials invalid");
                Ok(Next::Continue)
            }
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
        if self.is_submission() {
            // RFC 3207 §4: 530 until STARTTLS; RFC 4954 §6: 530 until AUTH.
            if !self.conn.is_tls() {
                return self.reply(530, (5, 7, 0), "Must issue a STARTTLS command first");
            }
            if self.auth.is_none() {
                return self.reply(530, (5, 7, 0), "Authentication required");
            }
        }
        if !self.server.sink.has_space() {
            return self.no_space();
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
                // RFC 4954 §5: accepted from authenticated clients, and ignored.
                MailParam::Auth(_) if self.auth.is_some() => {}
                // RFC 5321 §4.1.1.11: 555 for parameters we don't support.
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
        // A logged-in user may only use their own addresses.
        if let (Some(account), Some(accounts)) = (&self.auth, &self.server.accounts) {
            let owned = match &from {
                ReversePath::Mailbox(m) => accounts.may_send_as(account, &normalized(m)),
                ReversePath::Null => false,
            };
            if !owned {
                tracing::warn!(client_ip = %self.client_ip, account = %account, from = %from, "MAIL FROM not owned by the authenticated account");
                return self.reply(553, (5, 7, 1), "sender not owned by user");
            }
        }
        self.tx = Some(Transaction {
            from,
            smtputf8,
            recipients: Vec::new(),
        });
        self.reply(250, (2, 1, 0), "Sender OK");
    }

    /// RFC 5321 §4.2.2: 452 for insufficient system storage; RFC 3463
    /// §3.4 X.3.1 mail system full. Temporary, so the client retries.
    fn no_space(&mut self) {
        tracing::warn!(client_ip = %self.client_ip, "refusing mail: free disk space below the floor");
        self.reply(452, (4, 3, 1), "Insufficient system storage");
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
        let rcpt = match self.server.directory.resolve(to) {
            Recipient::Local(account) => Rcpt::Local(account),
            // RFC 3463 §3.2: X.1.1 bad destination mailbox address.
            Recipient::UnknownUser => return self.reply(550, (5, 1, 1), "No such user here"),
            Recipient::NotLocal if self.auth.is_some() => {
                // Authenticated submission: remote mail goes to the queue,
                // which delivers only via DNS MX (no relays).
                let ForwardPath::Mailbox(m) = to else {
                    return self.reply(550, (5, 1, 1), "No such user here");
                };
                let Host::Domain(d) = &m.host else {
                    // RFC 3463 §3.2: X.1.2 bad destination system address.
                    return self.reply(550, (5, 1, 2), "Address literals are not accepted");
                };
                let domain = domain_to_ascii(d).unwrap_or_else(|_| d.to_ascii_lowercase());
                if let Some(allow) = &self.cfg().test_mode_allow
                    && !allow.iter().any(|a| a.eq_ignore_ascii_case(&domain))
                {
                    return self.reply(
                        550,
                        (5, 7, 1),
                        "Test mode: delivery to this domain is not allowed",
                    );
                }
                Rcpt::Remote(m.to_string())
            }
            Recipient::NotLocal => {
                // We never relay (CLAUDE.md hard constraint 1).
                // RFC 3463 §3.8: X.7.1 delivery not authorized.
                tracing::info!(client_ip = %self.client_ip, recipient = %to, "relay attempt refused");
                return self.reply(550, (5, 7, 1), "Relaying denied");
            }
        };
        if let Some(tx) = &mut self.tx
            && !tx.recipients.contains(&rcpt)
        {
            tx.recipients.push(rcpt);
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
                    if !self.fill(self.cfg().data_timeout).await? {
                        // EOF or timeout mid-message: nothing is stored.
                        return Ok(Next::Close);
                    }
                }
                Err(e @ (Error::BareCr | Error::BareLf)) => {
                    // CLAUDE.md policy: reply 5xx 5.5.2, close, discard the
                    // partial message (never stored), log for reputation.
                    tracing::warn!(client_ip = %self.client_ip, reason = "smuggling-attempt", error = %e, "bare CR or LF in message data; message discarded, closing connection");
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
        let mut envelope = Envelope {
            id: new_id(),
            client_ip: self.client_ip,
            client_name: self
                .client_name
                .clone()
                .unwrap_or(ClientName::Invalid(String::new())),
            from: tx.from,
            recipients: tx.recipients,
            smtputf8: tx.smtputf8,
            signals: self.signals,
            authenticated: self.auth.clone(),
            junk: false,
        };
        if !self.server.sink.has_space() {
            self.no_space();
            return Ok(Next::Continue);
        }
        let hostname = self.cfg().hostname.clone();
        let message = match (&self.auth, &self.server.accounts) {
            // Authenticated submission: no inbound DMARC rejection (CLAUDE.md).
            (Some(account), Some(accounts)) => {
                match submission::prepare(
                    accounts.as_ref(),
                    account,
                    self.server.dkim.as_deref(),
                    &hostname,
                    &envelope.id,
                    &message,
                ) {
                    Ok(m) => m,
                    Err(Refusal::SenderNotOwned) => {
                        tracing::warn!(client_ip = %self.client_ip, account = %account, "From header not owned by the authenticated account");
                        self.reply(553, (5, 7, 1), "sender not owned by user");
                        return Ok(Next::Continue);
                    }
                    Err(Refusal::Unencodable(e)) => {
                        tracing::info!(client_ip = %self.client_ip, error = ?e, "submitted message has lines that can't be re-encoded");
                        // RFC 3463 §3.7: X.6.0 other or undefined media error.
                        self.reply(
                            554,
                            (5, 6, 0),
                            "Message lines are too long and could not be re-encoded",
                        );
                        return Ok(Next::Continue);
                    }
                }
            }
            _ if self.mode == Mode::Inbound && self.cfg().inbound_checks => {
                let (checked, decision) = inbound::check(
                    &self.server.resolver,
                    &hostname,
                    self.client_ip,
                    &envelope.client_name,
                    &envelope.from,
                    &message,
                )
                .await;
                match decision {
                    Decision::Reject => {
                        // CLAUDE.md policy 3: DMARC p=reject gives 550 5.7.1.
                        self.reply(
                            550,
                            (5, 7, 1),
                            "Message rejected by the sender domain's DMARC policy",
                        );
                        return Ok(Next::Continue);
                    }
                    Decision::Deliver { junk } => envelope.junk = junk,
                }
                checked
            }
            _ => message,
        };
        let mut stored =
            received_header(&envelope, &hostname, self.esmtp, self.conn.is_tls()).into_bytes();
        stored.extend_from_slice(&message);
        match self.server.sink.deliver(&envelope, &stored).await {
            Ok(()) => {
                self.server.observer.message_accepted();
                tracing::info!(id = %envelope.id, client_ip = %self.client_ip, from = %envelope.from, recipients = envelope.recipients.len(), junk = envelope.junk, size = stored.len(), "message accepted");
                self.reply(250, (2, 0, 0), &format!("OK, queued as {}", envelope.id));
            }
            Err(e) if e.kind() == std::io::ErrorKind::StorageFull => self.no_space(),
            Err(e) => {
                tracing::error!(id = %envelope.id, error = %e, "delivery failed");
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

/// RFC 5321 §4.4 trace header. The protocol name follows RFC 3848 (ESMTP,
/// ESMTPS, ESMTPA, ESMTPSA) and RFC 6531 §4.3 (UTF8SMTP...). The client's
/// claimed name is only shown when valid; the account name is never shown.
fn received_header(env: &Envelope, hostname: &str, esmtp: bool, tls: bool) -> String {
    let from = match &env.client_name {
        ClientName::Valid(Host::Domain(d)) => d.clone(),
        ClientName::Valid(h) => h.to_string(),
        ClientName::Invalid(_) => "unknown".to_owned(),
    };
    let base = match (esmtp, env.smtputf8) {
        (_, true) => "UTF8SMTP",
        (true, false) => "ESMTP",
        (false, false) => "SMTP",
    };
    let with = if base == "SMTP" {
        base.to_owned()
    } else {
        format!(
            "{base}{}{}",
            if tls { "S" } else { "" },
            if env.authenticated.is_some() { "A" } else { "" }
        )
    };
    let date = date::rfc5322(SystemTime::now());
    format!(
        "Received: from {from} ([{ip}])\r\n\tby {hostname} (Idly Mail) with {with} id {id};\r\n\t{date}\r\n",
        ip = env.client_ip,
        id = env.id,
    )
}
