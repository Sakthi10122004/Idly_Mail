//! `idly` — the Idly Mail server binary.
//!
//! Phase 0 only provides the CLI skeleton. Configuration, logging and the
//! SMTP listeners arrive in Phase 1.

#![forbid(unsafe_code)]

use clap::Parser;

/// Idly Mail: send, receive, store and serve email. Delivers directly to the
/// recipient's MX; never through a relay.
#[derive(Debug, Parser)]
#[command(name = "idly", version, about)]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
}
