//! `tribuchet worker`: dials the hub over mTLS, imports input paths
//! into the local /nix/store via the Nix daemon, executes builds in a
//! local sandbox, signs and returns output NARs.
//!
//! Inputs the local store already has (per the daemon) are reused;
//! missing ones are imported from hub NAR streams with AddToStoreNar,
//! so they are registered in the Nix database and protected from GC
//! by per-build temp roots. The worker user must be trusted by the
//! local nix-daemon (inputs are imported without signature checks).
//!
//! Runs up to `--max-jobs` builds concurrently over one hub session.

pub mod agent;
#[cfg(target_os = "linux")]
pub(crate) mod agent_spawn;
mod agents;
pub mod binfmt;
mod build;
mod caps;
mod logtail;
mod pins;
mod resume;
pub mod sandbox;
mod session;
#[cfg(target_os = "linux")]
pub(crate) mod userns;
#[cfg(target_os = "linux")]
pub use userns::{USERNS_HOLD_ARG, hold_stage as userns_hold_stage};

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use harmonia_store_remote::DaemonClient;
use harmonia_utils_signature::SecretKey;
use tokio::sync::{Semaphore, mpsc};

use caps::host_system;
use logtail::spawn_log_tail;
use resume::{ResumableBuild, adopt_builds, spawn_resumable_reaper, sweep_orphaned_agent_builds};

use crate::config::WorkerConfig;
use crate::errors::{Result, err_ctx, err_msg};
use crate::fsutil::io_ctx;
use crate::netpolicy::NetPolicy;
use crate::proto::{BuildAssignment, RequestJob, WorkerMessage, worker_message};
use crate::{fsutil, rt, sd};

/// Connection to the local nix-daemon; one per active build so its
/// temp roots live exactly as long as the build.
type DaemonConn = DaemonClient<tokio::net::unix::OwnedReadHalf, tokio::net::unix::OwnedWriteHalf>;

/// Per-process context threaded through builds.
struct WorkerCtx {
    state_dir: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    sandbox_bin_sh: Option<PathBuf>,
    /// Files a build must never read even where DAC would allow it
    /// (macOS Seatbelt deny rules; Linux relies on the mount namespace).
    secret_paths: Vec<PathBuf>,
    /// One permit per concurrent build; the session loop turns free
    /// permits into RequestJob credits.
    slots: Arc<Semaphore>,
    /// dedupe_key -> build past staging; survives session loss so a
    /// replacement hub can resume instead of rebuilding.
    resumable: Mutex<HashMap<String, ResumableBuild>>,
    /// system -> static emulator binary, from the emulate setting.
    emulators: HashMap<String, PathBuf>,
    /// Fixed-output builds get a private netns with the presto-pasta
    /// user-mode NAT (Linux workers with /dev/net/tun).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fod_isolation: bool,
    /// Flow policy for that network, from the fod-network setting.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fod_network: NetPolicy,
    max_silent_time: Duration,
    max_log_size: u64,
    /// memory.max for each build's cgroup.
    build_memory_max_bytes: Option<u64>,
    /// Builder gets the host nix-daemon socket bind-mounted in; the
    /// worker advertises the `recursive-nix` feature.
    pub(super) recursive_nix: bool,
    /// The per-uid build agents, one leased per build.
    agents: agents::AgentPool,
    /// Dedupe keys of builds the hub cancelled; the supervising loops
    /// abort them. Keyed like the registry, since a resumed build's
    /// build_id changes while it runs.
    cancelled: Mutex<HashSet<String>>,
    /// Input paths a build is currently importing. Other builds defer
    /// to that import instead of requesting the same NAR again.
    staging_inflight: Mutex<HashSet<String>>,
}

impl WorkerCtx {
    /// Reason to abort a running build, evaluated each supervision
    /// tick. Reads the log file (size for max-log-size, mtime for
    /// max-silent-time): counters fed by a session-bound tailer freeze
    /// when the hub session drops and would kill a healthy build.
    /// `timed_out` carries the caller's deadline check (wall clock vs
    /// the persisted unix deadline of an adopted build).
    fn abort_reason(
        &self,
        dedupe_key: &str,
        log_path: &Path,
        timed_out: Option<String>,
    ) -> Option<String> {
        let log = fs::metadata(log_path).ok();
        let silent = log
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .unwrap_or_default();
        let log_size = log.map_or(0, |m| m.len());
        if self.cancelled.lock().unwrap().remove(dedupe_key) {
            return Some("build cancelled".into());
        }
        if let Some(reason) = timed_out {
            return Some(reason);
        }
        if self.max_log_size > 0 && log_size > self.max_log_size {
            return Some(format!(
                "build log exceeded the limit of {} bytes",
                self.max_log_size
            ));
        }
        if !self.max_silent_time.is_zero() && silent > self.max_silent_time {
            return Some(format!(
                "build produced no output for {}s",
                self.max_silent_time.as_secs()
            ));
        }
        None
    }

    fn resumable_keys(&self) -> Vec<String> {
        self.resumable.lock().unwrap().keys().cloned().collect()
    }

    /// Re-point an already-held build (same dedupe key) at the
    /// assignment's new build_id and session; true if one existed.
    /// A tailer streams the log to the new session from the persisted
    /// offset and keeps following it.
    fn adopt_assignment(
        self: &Arc<Self>,
        a: &BuildAssignment,
        out_tx: &mpsc::Sender<WorkerMessage>,
    ) -> bool {
        let mut map = self.resumable.lock().unwrap();
        match map.get_mut(&a.dedupe_key) {
            Some(e) => {
                e.build_id.clone_from(&a.build_id);
                e.out_tx = Some(out_tx.clone());
                if let Some(t) = e.log_tail.take() {
                    // An earlier resume's tailer feeds a dead session.
                    // Only flag it (no join): it may be waiting on the
                    // registry lock held right here.
                    t.done.store(true, Ordering::Relaxed);
                }
                e.log_tail = Some(spawn_log_tail(
                    self.clone(),
                    a.dedupe_key.clone(),
                    a.build_id.clone(),
                    e.dir.clone(),
                    out_tx.clone(),
                ));
                true
            }
            None => false,
        }
    }
}

/// Load or create the worker's NAR signing key, stored in Nix's
/// "name:base64" secret key format (nix-store --generate-binary-cache-key)
/// so operators can inspect it with standard tooling.
/// 1-minute load average for the heartbeat; informational only, the
/// hub does not schedule on it.
fn loadavg1() -> f64 {
    let mut avg = [0.0f64; 1];
    // SAFETY: getloadavg writes at most nelem doubles to the buffer.
    if unsafe { libc::getloadavg(avg.as_mut_ptr(), 1) } == 1 {
        avg[0]
    } else {
        0.0
    }
}

fn hostname() -> String {
    let uname = rustix::system::uname();
    let nodename = uname.nodename().to_string_lossy();
    if nodename.is_empty() {
        "worker".into()
    } else {
        nodename.into_owned()
    }
}

fn load_signing_key(state_dir: &Path) -> Result<SecretKey> {
    let path = state_dir.join("signing.key");
    if path.exists() {
        fs::read_to_string(&path)
            .map_err(io_ctx("reading", &path))?
            .trim()
            .parse::<SecretKey>()
            .map_err(|e| {
                err_msg(format!(
                    "{}: {e}; expected Nix secret key format (name:base64); \
                     delete the file to generate a fresh key",
                    path.display()
                ))
            })
    } else {
        let key = SecretKey::generate(format!("{}-1", hostname()))
            .map_err(|e| err_msg(format!("generating signing key: {e}")))?;
        fsutil::write_secret(&path, format!("{key}\n").as_bytes())?;
        Ok(key)
    }
}

/// Remove a build dir. Only worker-owned staging and packing files
/// live here; the build's own files sit in agent scratch.
pub(super) fn remove_build_dir(dir: &Path) {
    if let Err(e) = fs::remove_dir_all(dir) {
        tracing::warn!("cleaning up {}: {e}", dir.display());
    }
}

/// Remove leftovers from interrupted runs: abandoned build dirs.
fn sweep_state_dir(state_dir: &Path) {
    if let Ok(entries) = fs::read_dir(state_dir.join("builds")) {
        for entry in entries.flatten() {
            // Dirs with persisted resume/finished state belong to
            // builds another worker generation left for adoption.
            let dir = entry.path();
            if dir.join("resume.json").exists() || dir.join("finished.json").exists() {
                continue;
            }
            tracing::info!("removing stale build dir {}", dir.display());
            fsutil::remove_path_all(&dir);
        }
    }
    // Input caching moved into the real /nix/store (daemon import);
    // clear the legacy cache directory left by older versions.
    let legacy = state_dir.join("store");
    if legacy.symlink_metadata().is_ok() {
        tracing::info!("removing legacy input cache {}", legacy.display());
        fsutil::remove_path_all(&legacy);
    }
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn msg(m: worker_message::Msg) -> WorkerMessage {
    WorkerMessage { msg: Some(m) }
}

fn request_job() -> WorkerMessage {
    msg(worker_message::Msg::RequestJob(RequestJob {}))
}

pub fn run(opts: WorkerConfig) -> Result<()> {
    let rt = rt::runtime("trib-worker").map_err(err_ctx("creating the tokio runtime"))?;
    rt.block_on(run_async(opts))
}

async fn run_async(opts: WorkerConfig) -> Result<()> {
    let builds_dir = opts.state_dir.join("builds");
    fs::create_dir_all(&builds_dir).map_err(io_ctx("creating", &builds_dir))?;
    // Traverse-only so leased build uids reach their own tree but
    // other local users get no listing.
    fs::set_permissions(&builds_dir, fs::Permissions::from_mode(0o711))
        .map_err(io_ctx("setting permissions on", &builds_dir))?;
    sweep_state_dir(&opts.state_dir);
    // Arc: SecretKey is not Clone (zeroized on drop); build threads share it.
    let signing_key = Arc::new(load_signing_key(&opts.state_dir)?);
    let mut opts = opts;
    if opts.systems.is_empty() {
        opts.systems.push(host_system());
    }
    // "none" disables the baked-in /bin/sh; else fall back to it so
    // builds using system(3)/#!/bin/sh work without extra config.
    opts.sandbox_bin_sh = match opts.sandbox_bin_sh.take() {
        Some(p) if p.as_os_str() == "none" => None,
        Some(p) => Some(p),
        None => option_env!("TRIBUCHET_BIN_SH").map(PathBuf::from),
    };
    if opts.spawn_agents > 0 {
        if !cfg!(target_os = "linux") {
            return Err(err_msg("spawn-agents requires Linux"));
        }
        if !opts.agent_sockets.is_empty() {
            return Err(err_msg(
                "agent-sockets and spawn-agents are mutually exclusive",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            opts.agent_sockets =
                agent_spawn::spawn(&opts.state_dir, opts.spawn_agents, opts.agent_uid_base)?;
        }
    }
    // Every build runs on one agent, so the agent list bounds
    // concurrency.
    if opts.agent_sockets.is_empty() {
        return Err(err_msg("agent-sockets must list at least one build agent"));
    }
    opts.max_jobs = opts
        .max_jobs
        .min(u32::try_from(opts.agent_sockets.len()).unwrap_or(u32::MAX));
    if cfg!(target_os = "macos") && opts.build_memory_max_bytes.is_some() {
        tracing::warn!("build-memory-max is not enforced on macOS");
    }
    let fod_isolation = cfg!(target_os = "linux") && Path::new("/dev/net/tun").exists();
    // main logs the config before the baked-in bin_sh default applies;
    // log the effective values.
    tracing::info!(fod_isolation, bin_sh = ?opts.sandbox_bin_sh, "resolved sandbox defaults");
    let mut emulators = HashMap::new();
    for (system, path) in &opts.emulate {
        if !cfg!(target_os = "linux") {
            return Err(err_msg("emulate requires Linux (binfmt_misc)"));
        }
        if binfmt::register_line(system).is_none() {
            return Err(err_msg(format!("emulate {system}: no binfmt magic known")));
        }
        if !path.is_file() {
            return Err(err_msg(format!(
                "emulate {system}: {} not found",
                path.display()
            )));
        }
        if !opts.systems.contains(system) {
            opts.systems.push(system.clone());
        }
        emulators.insert(system.clone(), path.clone());
    }
    let opts = opts;
    let ctx = Arc::new(WorkerCtx {
        state_dir: opts.state_dir.clone(),
        sandbox_bin_sh: opts.sandbox_bin_sh.clone(),
        secret_paths: vec![opts.key.clone(), opts.state_dir.join("signing.key")],
        slots: Arc::new(Semaphore::new(opts.max_jobs.max(1) as usize)),
        cancelled: Mutex::new(HashSet::new()),
        staging_inflight: Mutex::new(HashSet::new()),
        resumable: Mutex::new(HashMap::new()),
        emulators,
        fod_isolation,
        fod_network: opts.fod_network.clone(),
        max_silent_time: Duration::from_secs(opts.max_silent_time_secs),
        max_log_size: opts.max_log_size,
        build_memory_max_bytes: opts.build_memory_max_bytes,
        recursive_nix: opts.recursive_nix,
        agents: agents::AgentPool::new(opts.agent_sockets.clone()),
    });

    // Ready once local setup is done, not once the hub answers: the
    // worker is designed to outlive hub outages, so a restart must not
    // hang in "activating" waiting for a hub that may be down.
    sd::notify_ready();
    sd::spawn_watchdog();
    spawn_resumable_reaper(ctx.clone());
    spawn_handover();
    adopt_builds(&ctx, &signing_key).await;
    sweep_orphaned_agent_builds(&ctx);

    // Reconnect with backoff: a hub restart must not drain the fleet.
    let mut backoff = Duration::from_secs(1);
    loop {
        let started = Instant::now();
        match session::session(&opts, &signing_key, &ctx).await {
            Ok(()) => unreachable!("session only returns on error"),
            Err(e) => tracing::warn!("hub session ended: {e:#}"),
        }
        if started.elapsed() > Duration::from_mins(1) {
            backoff = Duration::from_secs(1);
        }
        tracing::info!("reconnecting to hub in {}s", backoff.as_secs());
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_mins(1));
    }
}

/// SIGTERM (unit stop or restart): exit immediately. All resumable
/// state is already on disk and builds run in their own process
/// groups/cgroups (KillMode=process), so a replacement worker
/// re-adopts them.
fn spawn_handover() {
    tokio::spawn(async {
        sd::stop_requested().await;
        tracing::info!("handover requested; exiting");
        process::exit(0);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_removes_stale_builds_and_legacy_cache() -> Result<()> {
        let state = tempfile::tempdir()?;
        fs::create_dir_all(state.path().join("builds/deadbeef"))?;
        // legacy input cache from pre-daemon-import versions: must go
        fs::create_dir_all(state.path().join("store/zzz-good"))?;
        sweep_state_dir(state.path());
        assert!(!state.path().join("builds/deadbeef").exists());
        assert!(!state.path().join("store").exists());
        Ok(())
    }
}
