//! `tribuchet worker`: dials the hub, caches input paths, executes builds
//! in a local sandbox, signs and returns output NARs.

pub mod sandbox;

use std::path::Path;

use anyhow::Result;

pub fn run(hub: &str, _state_dir: &Path) -> Result<()> {
    tracing::info!(hub, "worker starting");
    anyhow::bail!("not yet implemented: worker");
}
