//! `idly` — the Idly Mail server binary.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};

mod accounts;
mod certificates;
mod checks;
mod config;
mod directory;
mod dkim;
mod metrics;
mod mta_sts;
mod outbound;
mod records;
mod tlsrpt;

use config::{Config, LogFormat};

/// Idly Mail: send, receive, store and serve email. Delivers directly to the
/// recipient's MX; never through a relay.
#[derive(Debug, Parser)]
#[command(name = "idly", version, about)]
struct Cli {
    /// Path to the configuration file.
    #[arg(long, global = true, default_value = "/etc/idly/idly.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the mail server.
    Serve {
        /// Deliver only to `test_mode.allow_domains`, never anywhere else.
        #[arg(long)]
        test_mode: bool,
        /// Local demo: receive-only, 127.0.0.1 only, mail goes to Maildir.
        #[arg(long, conflicts_with = "test_mode")]
        demo: bool,
    },
    /// Validate the configuration file and exit.
    CheckConfig,
    /// Account helpers.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// DKIM key management.
    Dkim {
        #[command(subcommand)]
        command: DkimCommand,
    },
    /// Print the DNS records the domains need; with --check, look them up.
    Dns {
        /// Only this domain (default: every [[domain]]).
        #[arg(long)]
        domain: Option<String>,
        /// Look each record up with Idly's own resolver and compare; also
        /// check reverse DNS and outbound port 25.
        #[arg(long)]
        check: bool,
    },
    /// Inspect and manage the outbound queue.
    Queue {
        #[command(subcommand)]
        command: QueueCommand,
    },
}

#[derive(Debug, Subcommand)]
enum QueueCommand {
    /// List every queued or held recipient.
    List,
    /// Retry a message now instead of waiting for its next attempt.
    Retry {
        /// The message id from `idly queue list`.
        id: String,
    },
    /// Remove a message without delivering it or sending a bounce.
    Drop {
        /// The message id from `idly queue list`.
        id: String,
    },
}

#[derive(Debug, Subcommand)]
enum UserCommand {
    /// Read a password from standard input and print its Argon2id hash for
    /// `password_hash` in `[[account]]`.
    HashPassword,
}

#[derive(Debug, Subcommand)]
enum DkimCommand {
    /// Generate signing keys for a domain and print the DNS records.
    Generate {
        /// One of the configured `[[domain]]` names.
        #[arg(long)]
        domain: String,
        /// The selector (with `both`, `-rsa` and `-ed25519` are appended).
        #[arg(long)]
        selector: String,
        #[arg(long, value_enum, default_value = "both")]
        algorithm: dkim::Algorithm,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::CheckConfig => {
            let config = match Config::load(&cli.config) {
                Ok(c) => c,
                Err(e) => return fail(&e),
            };
            match dkim::load(&config) {
                Ok(loaded) => {
                    for d in &loaded.unsigned {
                        eprintln!(
                            "warning: {d} has no DKIM key; allow_unsigned is set, so its mail will be sent unsigned"
                        );
                    }
                    println!("{}: OK", cli.config.display());
                    ExitCode::SUCCESS
                }
                Err(e) => fail(&e),
            }
        }
        Command::User {
            command: UserCommand::HashPassword,
        } => hash_password(),
        Command::Dkim {
            command:
                DkimCommand::Generate {
                    domain,
                    selector,
                    algorithm,
                },
        } => {
            let config = match Config::load(&cli.config) {
                Ok(c) => c,
                Err(e) => return fail(&e),
            };
            if !config.is_local_domain(&domain) {
                return fail(&format!("{domain} is not one of the [[domain]] entries"));
            }
            match dkim::generate(&config.server.data_dir, &domain, &selector, algorithm) {
                Ok(keys) => {
                    println!("Publish these TXT records, then restart idly:");
                    for (sel, record) in keys {
                        println!("\n{sel}._domainkey.{domain}.  TXT  \"{record}\"");
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => fail(&e),
            }
        }
        Command::Dns { domain, check } => {
            let config = match Config::load(&cli.config) {
                Ok(c) => c,
                Err(e) => return fail(&e),
            };
            let domains: Vec<String> = match domain {
                Some(d) if !config.is_local_domain(&d) => {
                    return fail(&format!("{d} is not one of the [[domain]] entries"));
                }
                Some(d) => vec![d],
                None => config.domains.iter().map(|d| d.name.clone()).collect(),
            };
            let domains: Vec<String> = domains
                .iter()
                .map(|d| {
                    smtp_proto::address::domain_to_ascii(d).unwrap_or_else(|_| d.to_lowercase())
                })
                .collect();
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => return fail(&e),
            };
            runtime.block_on(dns_command(&config, &domains, check))
        }
        Command::Queue { command } => {
            let config = match Config::load(&cli.config) {
                Ok(c) => c,
                Err(e) => return fail(&e),
            };
            queue_command(&config, command)
        }
        Command::Serve { test_mode, demo } => {
            let mut config = match Config::load(&cli.config) {
                Ok(c) => c,
                Err(e) => return fail(&e),
            };
            if test_mode {
                config.test_mode.enabled = true;
                // Re-validate: test mode needs an allow-list.
                if let Err(p) = config.validate() {
                    return fail(&config::LoadError::Invalid(cli.config, p));
                }
            }
            if demo && let Err(p) = config.validate_demo() {
                return fail(&config::LoadError::Invalid(cli.config, p));
            }
            init_logging(&config);
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => return fail(&e),
            };
            match runtime.block_on(serve(config, demo)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e),
            }
        }
    }
}

/// `idly user hash-password`: the password comes from standard input
/// (e.g. `read -rs P; printf %s "$P" | idly user hash-password`), never
/// from the command line, where other users could see it.
fn hash_password() -> ExitCode {
    let mut password = String::new();
    if let Err(e) = std::io::Read::read_to_string(&mut std::io::stdin(), &mut password) {
        return fail(&e);
    }
    let password = password.strip_suffix('\n').unwrap_or(&password);
    let password = password.strip_suffix('\r').unwrap_or(password);
    if password.is_empty() {
        return fail(&"empty password");
    }
    match accounts::hash_password(password.as_bytes()) {
        Ok(hash) => {
            println!("{hash}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

/// `idly dns`: prints the records; with `check`, what DNS has now. Exits
/// with 1 if a check found a problem.
async fn dns_command(config: &Config, domains: &[String], check: bool) -> ExitCode {
    let (tlsa, tlsa_note) = records::tlsa(config);
    let inputs = records::Inputs {
        ips: checks::public_ips(config),
        tlsa,
        tlsa_note,
        dkim: records::dkim_records(&config.server.data_dir, domains),
    };
    let sections = records::plan(config, domains, &inputs);
    if !check {
        print!("{}", records::render(&sections, None, &[]));
        println!("; Publish these, then run `idly dns --check` to verify them.");
        return ExitCode::SUCCESS;
    }
    let resolver = match dns::Recursive::new() {
        Ok(r) => r,
        Err(e) => return fail(&e),
    };
    let mut statuses = Vec::new();
    let mut problems = 0;
    for section in &sections {
        let mut found = Vec::new();
        for record in &section.records {
            let status = records::check(&resolver, record).await;
            if status != records::Status::Ok {
                problems += 1;
            }
            found.push(status);
        }
        statuses.push(found);
    }
    let mut zones = Vec::new();
    for d in domains {
        zones.push((d.clone(), records::dnssec(&resolver, d).await));
    }
    print!("{}", records::render(&sections, Some(&statuses), &zones));

    println!("; outside checks");
    if inputs.ips.is_empty() {
        problems += 1;
        println!("[PROBLEM] no public IP address found; set server.public_ips");
    }
    for p in checks::reverse_dns(&resolver, &config.server.hostname, &inputs.ips).await {
        problems += 1;
        println!("[PROBLEM] {p}");
    }
    if config.checks.port25_probe {
        let (_, sources) = outbound::families_and_sources(config);
        match checks::probe_port25(
            &resolver,
            &smtp_client::Direct,
            sources,
            &config.checks.probe_domains,
            checks::PROBE_TIMEOUT,
        )
        .await
        {
            checks::Port25::Open(via) => println!("[OK] outbound port 25 is open ({via})"),
            checks::Port25::Blocked => {
                problems += 1;
                println!(
                    "[PROBLEM] outbound port 25 seems blocked: every probe timed out. Ask your provider to open it."
                );
            }
            checks::Port25::Unknown(why) => {
                problems += 1;
                println!("[UNKNOWN] outbound port 25: {why}");
            }
        }
    }
    if problems == 0 {
        println!("\nEverything checks out.");
        ExitCode::SUCCESS
    } else {
        println!("\n{problems} item(s) need attention.");
        ExitCode::from(1)
    }
}

/// `idly queue ...`. While `idly serve` runs it owns the queue, so the
/// command attaches to it instead (no crash recovery).
fn queue_command(config: &Config, command: QueueCommand) -> ExitCode {
    let dir = config.server.data_dir.join("queue");
    if !dir.join("queue.db").exists() {
        println!("The queue is empty (no queue in {} yet).", dir.display());
        return ExitCode::SUCCESS;
    }
    let qc = queue::QueueConfig::new(&config.server.hostname);
    let clock = Arc::new(queue::SystemClock);
    let space = Arc::new(queue::space::Statvfs);
    let queue = match queue::Queue::open(&dir, qc.clone(), clock.clone(), space.clone()) {
        Err(queue::QueueError::Busy) => queue::Queue::attach(&dir, qc, clock, space),
        other => other,
    };
    let queue = match queue {
        Ok(q) => q,
        Err(e) => return fail(&e),
    };
    match command {
        QueueCommand::List => {
            if config.test_mode.enabled {
                println!(
                    "TEST MODE is on: mail is delivered only to {}; everything else is held.\n",
                    config.test_mode.allow_domains.join(", ")
                );
            }
            let entries = match queue.list() {
                Ok(e) => e,
                Err(e) => return fail(&e),
            };
            for e in &entries {
                let next = std::time::UNIX_EPOCH + Duration::from_secs(e.next_attempt);
                println!(
                    "{}  {:<6}  attempts={}  next={}  <{}> -> {}",
                    e.message_id,
                    e.status,
                    e.attempts,
                    smtp_proto::date::rfc5322(next),
                    e.sender.as_deref().unwrap_or(""),
                    e.recipient
                );
                if let Some(err) = &e.last_error {
                    println!("    last error: {err}");
                }
            }
            println!("{} recipient(s) in the queue", entries.len());
            ExitCode::SUCCESS
        }
        QueueCommand::Retry { id } => match queue.retry_now(&id) {
            Ok(0) => fail(&format!("{id}: no queued recipients to retry")),
            Ok(n) => {
                println!("{id}: {n} recipient(s) due now");
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e),
        },
        QueueCommand::Drop { id } => match queue.drop_message(&id) {
            Ok(true) => {
                println!("{id}: dropped");
                ExitCode::SUCCESS
            }
            Ok(false) => fail(&format!("{id}: no such message")),
            Err(e) => fail(&e),
        },
    }
}

fn fail(e: &dyn std::fmt::Display) -> ExitCode {
    eprintln!("idly: {e}");
    ExitCode::from(2)
}

fn init_logging(config: &Config) {
    // Validated in Config::validate, so this cannot fail.
    let filter = tracing_subscriber::EnvFilter::try_new(&config.log.level).unwrap_or_default();
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()));
    match config.log.format {
        LogFormat::Json => builder.json().init(),
        LogFormat::Text => builder.init(),
    }
}

async fn serve(config: Config, demo: bool) -> std::io::Result<()> {
    let metrics = metrics::Metrics::new();
    if config.test_mode.enabled {
        metrics.test_mode.set(1);
        tracing::warn!(
            allow_domains = ?config.test_mode.allow_domains,
            "TEST MODE: outbound delivery is restricted to the allow-listed domains"
        );
    }
    tracing::info!(hostname = %config.server.hostname, version = env!("CARGO_PKG_VERSION"), "idly starting");
    if let Some(addr) = config.listen.metrics {
        let metrics = metrics.clone();
        tokio::spawn(async move {
            if let Err(e) = metrics::serve(addr, metrics).await {
                tracing::error!(%addr, error = %e, "metrics endpoint failed");
            }
        });
    }
    if demo {
        start_demo(&config, metrics).await?;
    } else {
        start(&config, metrics).await?;
    }
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}

/// Listener settings shared by the demo and production.
fn listener_config(config: &Config, inbound_checks: bool) -> smtp_server::InboundConfig {
    let l = &config.limits;
    let mut c = smtp_server::InboundConfig::new(&config.server.hostname);
    c.command_line_cap = l.command_line;
    c.data_line_cap = l.inbound_line;
    c.message_size = l.message_size;
    c.max_recipients = l.max_recipients;
    c.command_timeout = Duration::from_secs(l.command_timeout);
    c.data_timeout = Duration::from_secs(l.data_timeout);
    c.tls_handshake_timeout = Duration::from_secs(l.tls_handshake_timeout);
    c.session_timeout = Duration::from_secs(l.session_timeout);
    c.max_connections = l.max_connections;
    c.max_submission_connections = l.max_submission_connections;
    c.inbound_checks = inbound_checks;
    c
}

/// Binds every address and serves it in `mode`.
async fn listen<D, K, O, R>(
    server: &Arc<smtp_server::Server<D, K, O, R>>,
    addrs: &[SocketAddr],
    mode: smtp_server::Mode,
) -> std::io::Result<()>
where
    D: smtp_server::Directory,
    K: smtp_server::Sink,
    O: smtp_server::Observer,
    R: dns::Resolver + 'static,
{
    for &addr in addrs {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| std::io::Error::new(e.kind(), format!("cannot listen on {addr}: {e}")))?;
        tracing::info!(%addr, ?mode, "SMTP listener ready");
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(e) = server.run(listener, mode).await {
                tracing::error!(%addr, error = %e, "listener failed");
            }
        });
    }
    Ok(())
}

/// Receive-only demo (milestone 3.5). Only the inbound server and the
/// Maildir sink are built here: there is no submission listener and no
/// outbound delivery code in this path. `validate_demo` has already
/// checked that every address is 127.0.0.1.
async fn start_demo(config: &Config, metrics: Arc<metrics::Metrics>) -> std::io::Result<()> {
    use smtp_server::maildir::Maildir;
    use smtp_server::{Mode, NoDns, Server};

    let maildir_root = config.server.data_dir.join("maildir");
    tracing::warn!(
        maildir = %maildir_root.display(),
        "DEMO MODE: receive-only and 127.0.0.1 only; no TLS, no AUTH, no SPF/DKIM/DMARC checks, no outbound delivery"
    );
    let server = Server::new(
        listener_config(config, false),
        directory::ConfigDirectory::new(config),
        Maildir::new(maildir_root, &config.server.hostname).with_min_free_space(
            config.limits.min_free_space,
            Arc::new(queue::space::Statvfs),
        ),
        metrics::MetricsObserver(metrics),
        NoDns,
    )
    .shared();
    listen(&server, &config.listen.smtp, Mode::Inbound).await
}

/// The production server: inbound on 25 with SPF/DKIM/DMARC, submission on
/// 587 and 465 with AUTH, local mail to Maildir, remote mail to the queue.
async fn start(config: &Config, metrics: Arc<metrics::Metrics>) -> std::io::Result<()> {
    use smtp_proto::address::domain_to_ascii;
    use smtp_server::maildir::Maildir;
    use smtp_server::{Delivery, Mode, Server};

    let other =
        |what: &str, e: &dyn std::fmt::Display| std::io::Error::other(format!("{what}: {e}"));
    let data = &config.server.data_dir;
    let hostname = &config.server.hostname;
    let resolver = dns::Recursive::new().map_err(|e| other("DNS resolver", &e))?;
    // MTA-STS and ACME need the system's trusted CAs (webpki-roots is banned).
    let roots = Arc::new(smtp_client::system_roots().map_err(|e| other("TLS roots", &e))?);
    let (families, sources) = outbound::families_and_sources(config);
    // The certificate: [tls] files or ACME. ACME traffic uses our resolver
    // and the outbound address guard, like everything else.
    let https = smtp_client::Https::new(
        resolver.clone(),
        smtp_client::Direct,
        roots.clone(),
        families,
        sources,
    );
    let certs = certificates::start(config, &metrics, https).await?;
    let tls = match &certs {
        Some(certs) => Some(
            smtp_server::tls::server_config_with(certs.clone()).map_err(|e| other("TLS", &e))?,
        ),
        None => None,
    };
    // Reverse DNS, outbound port 25 and certificate expiry: warnings only.
    tokio::spawn(checks::run(
        config.clone(),
        resolver.clone(),
        sources,
        metrics.clone(),
        certs,
    ));
    outbound::check(config, &resolver)
        .await
        .map_err(|e| other("server.outbound_ips", &e))?;
    let accounts = accounts::ConfigAccounts::new(config).map_err(|e| other("accounts", &e))?;
    let dkim = dkim::load(config).map_err(|e| other("DKIM", &e))?;
    for d in &dkim.unsigned {
        tracing::warn!(domain = %d, "no DKIM key and allow_unsigned is set: this domain's mail is sent unsigned and will fail DMARC at most receivers");
    }
    let dkim = Arc::new(dkim.keys);
    // dkim::load made sure this domain has a key.
    let report_domain = config.tls_reporting.report_domain();

    let test_mode_allow = config.test_mode.enabled.then(|| {
        config
            .test_mode
            .allow_domains
            .iter()
            .filter_map(|d| domain_to_ascii(d).ok())
            .collect::<Vec<_>>()
    });
    let probe: Arc<dyn queue::space::SpaceProbe> = Arc::new(queue::space::Statvfs);
    let mut queue_config = queue::QueueConfig::new(hostname);
    queue_config.min_free_space = config.limits.min_free_space;
    queue_config.test_mode_allow = test_mode_allow.clone();
    let queue = Arc::new(
        queue::Queue::open(
            &data.join("queue"),
            queue_config,
            Arc::new(queue::SystemClock),
            probe.clone(),
        )
        .map_err(|e| other("queue", &e))?,
    );

    // Outbound: direct to each domain's MX, never through a relay.
    let mut client_config = smtp_client::ClientConfig::new(hostname, roots);
    client_config.families = families;
    client_config.sources = sources;
    client_config.test_mode_allow = test_mode_allow.clone();
    client_config.tls_reporting = report_domain.is_some();
    // MTA-STS policies and TLS report data survive restarts.
    let state = Arc::new(
        smtp_client::State::open(&data.join("outbound.db"))
            .map_err(|e| other("outbound.db", &e))?,
    );
    let client = |config| {
        smtp_client::Client::new(
            config,
            resolver.clone(),
            smtp_client::Direct,
            Arc::new(queue::SystemClock),
        )
        .with_state(state.clone())
    };
    let runner = queue::Runner::new(queue.clone(), client(client_config.clone()), hostname);
    tokio::spawn(runner.run(Duration::from_secs(30)));
    if let (Some(domain), Some(from)) = (report_domain, &config.tls_reporting.from) {
        let reporter = smtp_client::tlsrpt::Reporter {
            organization: config
                .tls_reporting
                .organization
                .clone()
                .unwrap_or_else(|| hostname.clone()),
            contact: from.clone(),
            hostname: hostname.clone(),
        };
        let reports = client(client_config);
        let mail = tlsrpt::mailer(queue.clone(), dkim.clone(), domain);
        tracing::info!(from = %from, "TLS reporting (RFC 8460) is on");
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(tlsrpt::INTERVAL);
            loop {
                tick.tick().await;
                reports.send_tls_reports(&reporter, &mail).await;
            }
        });
    }

    let mut listen_config = listener_config(config, true);
    listen_config.test_mode_allow = test_mode_allow;
    let sink = Delivery {
        maildir: Maildir::new(data.join("maildir"), hostname)
            .with_min_free_space(config.limits.min_free_space, probe),
        queue,
    };
    let mut server = Server::new(
        listen_config,
        directory::ConfigDirectory::new(config),
        sink,
        metrics::MetricsObserver(metrics.clone()),
        resolver,
    )
    .with_accounts(Arc::new(accounts))
    .with_dkim(dkim);
    if let Some(tls) = &tls {
        server = server.with_tls(tls.clone());
    }
    let server = server.shared();

    listen(&server, &config.listen.smtp, Mode::Inbound).await?;
    if tls.is_some() {
        listen(&server, &config.listen.submission, Mode::Submission).await?;
        listen(
            &server,
            &config.listen.submissions,
            Mode::SubmissionImplicitTls,
        )
        .await?;
    } else {
        // AUTH is never offered without TLS, so submission would be useless.
        tracing::warn!(
            "no [tls] or [acme] certificate: port 25 runs without STARTTLS and the submission ports are not started"
        );
    }
    Ok(())
}
