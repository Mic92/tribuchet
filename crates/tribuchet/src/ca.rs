//! `tribuchet ca`: minimal certificate authority for hub/worker mTLS.

use std::path::PathBuf;

use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum CaAction {
    /// Create a new CA key and root certificate.
    Init {
        #[arg(long, default_value = "/etc/tribuchet/ca")]
        dir: PathBuf,
    },
    /// Issue a certificate for a worker or the hub.
    Issue {
        /// Common name, e.g. worker hostname.
        name: String,
        #[arg(long, default_value = "/etc/tribuchet/ca")]
        dir: PathBuf,
    },
}

pub fn run(action: CaAction) -> Result<()> {
    match action {
        CaAction::Init { .. } => anyhow::bail!("not yet implemented: ca init"),
        CaAction::Issue { .. } => anyhow::bail!("not yet implemented: ca issue"),
    }
}
