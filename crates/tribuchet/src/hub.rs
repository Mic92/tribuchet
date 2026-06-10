//! `tribuchet hub`: scheduler and NAR relay, colocated with nix-daemon.
//!
//! - accepts build submissions from `attach` over a unix socket
//! - dedupes in-flight builds by scratch-output set
//! - queues per system type; blocks submitters until a worker is free
//! - serves the WorkerHub gRPC service (mTLS); workers dial in
//! - reads input store paths directly from the local /nix/store

use std::path::Path;

use anyhow::Result;

pub fn run(_socket: &Path, listen: &str, _config_dir: &Path) -> Result<()> {
    tracing::info!(listen, "hub starting");
    anyhow::bail!("not yet implemented: hub");
}
