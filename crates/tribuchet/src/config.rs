//! TOML configuration for the long-running services (hub, worker).
//!
//! The services take a single `--config` path instead of command-line
//! flags so that a worker reload (which execs a new worker generation
//! through the reaper) picks up settings changes without a restart.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// How the worker listener authenticates peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Auth {
    /// Mutual TLS against the `tribuchet ca` root (default).
    #[default]
    Mtls,
    /// No TLS; identity comes from tailscaled's LocalAPI `whois`.
    /// Transport security is the WireGuard tunnel.
    Tailscale,
}

pub fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing config file {}", path.display()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct HubConfig {
    /// Worker authentication mode.
    #[serde(default)]
    pub auth: Auth,
    /// Unix socket `tribuchet attach` connects to.
    #[serde(default = "default_hub_socket")]
    pub socket: PathBuf,
    /// gRPC listen address for workers.
    #[serde(default = "default_hub_listen")]
    pub listen: String,
    /// Directory with the CA material and the hub TLS key pair.
    #[serde(default = "default_hub_config_dir")]
    pub config_dir: PathBuf,
    /// Seconds a build waits for a platform we expect a worker to
    /// (re)serve before declining (lets a patched Nix fall back to a
    /// local build). Covers the startup re-registration window and a
    /// worker's reconnect window; a never-seen platform declines at
    /// once.
    #[serde(default = "default_worker_grace_secs")]
    pub worker_grace_secs: u64,
    /// Optional address (e.g. 127.0.0.1:7438) for the Prometheus
    /// metrics endpoint; disabled when unset.
    #[serde(default)]
    pub metrics_listen: Option<String>,
    /// tailscaled LocalAPI socket (auth = tailscale).
    #[serde(default = "default_tailscale_socket")]
    pub tailscale_socket: PathBuf,
    /// When set, only nodes carrying one of these ACL tags may
    /// register as a worker (auth = tailscale).
    #[serde(default)]
    pub tailscale_allowed_tags: Vec<String>,
    /// When set, the hub rewrites a nix.conf fragment (the
    /// external-builders and max-jobs settings) whenever the
    /// connected-worker set changes, so a local nix-daemon offloads to
    /// whatever systems are available right now.
    #[serde(default)]
    pub nix_config: Option<NixConfig>,
}

/// A hub-maintained nix.conf fragment. A local nix.conf `include`s the
/// path; a systemd path unit watching it restarts nix-daemon to apply
/// changes (in-flight build children survive the restart).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NixConfig {
    /// File the fragment is written to.
    pub path: PathBuf,
    /// external-builders `program`: the attach shim nix runs.
    pub attach_program: PathBuf,
    /// Percent to scale summed worker capacity by for the emitted
    /// max-jobs (200 = 2x). Oversubscription keeps every worker's queue
    /// fed regardless of the system mix nix admits into its single
    /// global slot pool, and hides the per-build dispatch round trip.
    #[serde(default = "default_oversubscribe_percent")]
    pub oversubscribe_percent: u32,
    /// Hard ceiling on the emitted max-jobs. Bounds the local-build
    /// burst if every worker vanishes and offloaded builds fall back
    /// to local execution.
    #[serde(default = "default_max_jobs_cap")]
    pub max_jobs_cap: u32,
}

fn default_oversubscribe_percent() -> u32 {
    200
}
fn default_max_jobs_cap() -> u32 {
    256
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
fn default_worker_grace_secs() -> u64 {
    30
}
fn default_tailscale_socket() -> PathBuf {
    "/var/run/tailscale/tailscaled.sock".into()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct WorkerConfig {
    /// Hub gRPC address, e.g. https://hub.example.org:7437 (mTLS) or
    /// http://hub:7437 (tailscale).
    pub hub: String,
    /// Hub authentication mode; must match the hub.
    #[serde(default)]
    pub auth: Auth,
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
    /// Advertise the `recursive-nix` system feature so the hub routes
    /// derivations using it here. Requires the patched Nix on the
    /// client side (see `nix/patches/`).
    #[serde(default)]
    pub recursive_nix: bool,
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
    std::thread::available_parallelism()
        .ok()
        .and_then(|n| u32::try_from(n.get()).ok())
        .unwrap_or(1)
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
