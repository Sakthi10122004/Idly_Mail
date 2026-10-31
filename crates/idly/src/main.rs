//! `idly` — the Idly Mail server binary.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod config;
mod directory;
mod metrics;

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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::CheckConfig => match Config::load(&cli.config) {
            Ok(_) => {
                println!("{}: OK", cli.config.display());
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e),
        },
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
        // The production listeners (TLS, AUTH, checks) arrive in milestone 6.
        tracing::warn!("no SMTP listeners yet outside --demo: this build only serves metrics");
    }
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}

/// Receive-only demo (milestone 3.5). Only the inbound server and the
/// Maildir sink are built here: there is no submission listener and no
/// outbound delivery code in this path. `validate_demo` has already
/// checked that every address is 127.0.0.1.
async fn start_demo(
    config: &Config,
    metrics: std::sync::Arc<metrics::Metrics>,
) -> std::io::Result<()> {
    use smtp_server::maildir::Maildir;
    use smtp_server::{InboundConfig, Server};

    let maildir_root = config.server.data_dir.join("maildir");
    tracing::warn!(
        maildir = %maildir_root.display(),
        "DEMO MODE: receive-only and 127.0.0.1 only; no TLS, no AUTH, no SPF/DKIM/DMARC checks, no outbound delivery"
    );
    let inbound = InboundConfig {
        hostname: config.server.hostname.clone(),
        command_line_cap: config.limits.command_line,
        data_line_cap: config.limits.inbound_line,
        message_size: config.limits.message_size,
        max_recipients: config.limits.max_recipients,
        idle_timeout: std::time::Duration::from_secs(300),
        max_connections: 100,
    };
    let server = Server::new(
        inbound,
        directory::ConfigDirectory::new(config),
        Maildir::new(maildir_root, &config.server.hostname),
        metrics::MetricsObserver(metrics),
    );
    for &addr in &config.listen.smtp {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| std::io::Error::new(e.kind(), format!("cannot listen on {addr}: {e}")))?;
        tracing::info!(%addr, "demo SMTP listener ready");
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(e) = server.run(listener).await {
                tracing::error!(%addr, error = %e, "listener failed");
            }
        });
    }
    Ok(())
}
