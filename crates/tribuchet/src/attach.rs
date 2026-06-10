//! `tribuchet attach`: shim executed by Nix (external-builders).
//!
//! Parses build.json, submits the build to the local hub over a unix
//! socket, streams logs to stderr, verifies output signatures and unpacks
//! the returned NARs at the scratch output paths, then exits with the
//! builder's exit code.

use std::path::Path;

use anyhow::Result;

use crate::build_json::BuildJson;

pub fn run(build_json: &Path, _socket: &Path) -> Result<()> {
    let build = BuildJson::load(build_json)?;
    tracing::info!(
        system = build.system,
        outputs = build.outputs.len(),
        inputs = build.input_paths.len(),
        fixed_output = build.is_fixed_output(),
        "submitting build to hub"
    );
    anyhow::bail!("not yet implemented: hub submission");
}
