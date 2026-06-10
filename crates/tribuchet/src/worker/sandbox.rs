//! Build sandbox.
//!
//! Linux: user/mount/pid/ipc/uts (and, unless fixed-output, net)
//! namespaces; input paths bind-mounted read-only at their store paths,
//! scratch outputs writable, tmpfs /build, minimal /dev and /proc,
//! pivot_root, drop to build uid. Reference:
//! `nix/src/libstore/unix/build/derivation-builder.cc`.
//!
//! macOS: sandbox_init_with_parameters with a deny-default profile
//! modeled on `nix/src/libstore/darwin/build/sandbox-defaults.sb`;
//! fixed-output builds get the network allowance.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Result;

pub struct SandboxSpec {
    pub builder: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    /// Read-only inputs, mounted at their store paths.
    pub input_paths: Vec<PathBuf>,
    /// Writable scratch output paths.
    pub output_paths: Vec<PathBuf>,
    /// Host directory mounted as /build (tmpDirInSandbox).
    pub build_dir: PathBuf,
    pub network: bool,
}

pub fn execute(_spec: &SandboxSpec) -> Result<i32> {
    anyhow::bail!("not yet implemented: sandbox");
}
