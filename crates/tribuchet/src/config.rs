//! TOML configuration for the long-running services (hub, worker).
//!
//! The services take a single `--config` path instead of command-line
//! flags so that a worker reload (which execs a new worker generation
//! through the reaper) picks up settings changes without a restart.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

pub fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing config file {}", path.display()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct HubConfig {
    /// Unix socket `tribuchet attach` connects to.
    #[serde(default = "default_hub_socket")]
    pub socket: PathBuf,
    /// gRPC listen address for workers.
    #[serde(default = "default_hub_listen")]
    pub listen: String,
    /// Directory with the CA material and the hub TLS key pair.
    #[serde(default = "default_hub_config_dir")]
    pub config_dir: PathBuf,
}

fn default_hub_socket() -> PathBuf {
    "/run/tribuchet/hub.sock".into()
}
fn default_hub_listen() -> String {
    "0.0.0.0:7437".into()
}
fn default_hub_config_dir() -> PathBuf {
    "/etc/tribuchet".into()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct WorkerConfig {
    /// Hub gRPC address, e.g. https://hub.example.org:7437
    pub hub: String,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    /// Systems this worker builds for (default: host system).
    #[serde(default)]
    pub systems: Vec<String>,
    #[serde(default = "default_ca_cert")]
    pub ca_cert: PathBuf,
    #[serde(default = "default_cert")]
    pub cert: PathBuf,
    #[serde(default = "default_key")]
    pub key: PathBuf,
    /// Kill builds running longer than this many seconds.
    #[serde(default = "default_build_timeout")]
    pub build_timeout_secs: u64,
    /// Kill builds producing no log output for this many seconds
    /// (Nix's max-silent-time); 0 disables.
    #[serde(default)]
    pub max_silent_time_secs: u64,
    /// Kill builds whose log exceeds this many bytes (Nix's
    /// max-log-size); 0 disables.
    #[serde(default)]
    pub max_log_size: u64,
    /// Static shell bound at /bin/sh inside the sandbox (Linux),
    /// e.g. a busybox sh; without it #!/bin/sh shebangs fail.
    #[serde(default)]
    pub sandbox_bin_sh: Option<PathBuf>,
    /// memory.max for each build's cgroup (Linux; needs a delegated
    /// cgroup, e.g. systemd Delegate=yes). Unlimited when unset.
    #[serde(default)]
    pub build_memory_max_bytes: Option<u64>,
    /// Concurrent build slots.
    #[serde(default = "default_max_jobs")]
    pub max_jobs: u32,
    /// First uid of the per-slot 65536-uid ranges for builds that
    /// require the uid-range feature (Nix's auto-allocate-uids
    /// start-id; needs a root worker).
    #[serde(default = "default_uid_base")]
    pub auto_allocate_uids_base: u32,
    /// Emulated systems: system -> path of a static emulator binary
    /// (Linux, kernel 6.7+).
    #[serde(default)]
    pub emulate: BTreeMap<String, PathBuf>,
    /// pasta binary; fixed-output builds then get a private network
    /// namespace with user-mode NAT (Linux). Defaults to the path
    /// baked in at build time, if any; "none" disables it.
    #[serde(default)]
    pub pasta: Option<PathBuf>,
}

fn default_state_dir() -> PathBuf {
    "/var/lib/tribuchet".into()
}
fn default_ca_cert() -> PathBuf {
    "/var/lib/tribuchet/tls/ca.crt".into()
}
fn default_cert() -> PathBuf {
    "/var/lib/tribuchet/tls/worker.crt".into()
}
fn default_key() -> PathBuf {
    "/var/lib/tribuchet/tls/worker.key".into()
}
fn default_build_timeout() -> u64 {
    24 * 3600
}
fn default_max_jobs() -> u32 {
    1
}
fn default_uid_base() -> u32 {
    872_415_232
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_defaults_and_emulate_map() {
        let cfg: WorkerConfig = toml::from_str(
            r#"
            hub = "https://hub:7437"
            max-jobs = 2

            [emulate]
            aarch64-linux = "/nix/store/x-qemu/bin/qemu-aarch64"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.hub, "https://hub:7437");
        assert_eq!(cfg.max_jobs, 2);
        assert_eq!(cfg.build_timeout_secs, 24 * 3600);
        assert_eq!(cfg.state_dir, PathBuf::from("/var/lib/tribuchet"));
        assert_eq!(
            cfg.emulate.get("aarch64-linux"),
            Some(&PathBuf::from("/nix/store/x-qemu/bin/qemu-aarch64"))
        );
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = toml::from_str::<HubConfig>("max-jobs = 2").unwrap_err();
        assert!(err.to_string().contains("max-jobs"), "{err}");
    }
}
