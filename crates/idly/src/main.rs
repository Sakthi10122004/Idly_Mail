//! `idly` — the Idly Mail server binary.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod config;
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
        Command::Serve { test_mode } => {
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
            init_logging(&config);
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => return fail(&e),
            };
            match runtime.block_on(serve(config)) {
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
        .with_writer(std::io::stderr);
    match config.log.format {
        LogFormat::Json => builder.json().init(),
        LogFormat::Text => builder.init(),
    }
}

async fn serve(config: Config) -> std::io::Result<()> {
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
    // The SMTP listeners arrive in milestone 6 (milestone 3.5 adds --demo).
    tracing::warn!("no SMTP listeners yet: this build only serves metrics");
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
