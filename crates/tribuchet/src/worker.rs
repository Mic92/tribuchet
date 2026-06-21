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

pub mod binfmt;
mod build;
mod caps;
mod cgroup;
mod logtail;
pub mod reaper;
mod resume;
pub mod sandbox;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use harmonia_store_remote::DaemonClient;
use harmonia_utils_signature::SecretKey;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

use build::{validate_assignment, ActiveBuild};
use caps::{host_system, system_caps};
use logtail::spawn_log_tail;
use resume::{
    ack_delivery, adopt_builds, execute_to_finished, record_finished, spawn_resumable_reaper,
    try_deliver, ResumableBuild,
};

use crate::config::WorkerConfig;
use crate::proto::{
    hub_message, worker_hub_client::WorkerHubClient, worker_message, BuildAssignment, BuildResult,
    Heartbeat, MissingPaths, Register, RequestJob, Resumed, WorkerMessage,
};

/// Connection to the local nix-daemon; one per active build so its
/// temp roots live exactly as long as the build.
type DaemonConn = DaemonClient<tokio::net::unix::OwnedReadHalf, tokio::net::unix::OwnedWriteHalf>;

/// Per-process context threaded through builds.
struct WorkerCtx {
    state_dir: PathBuf,
    /// Handle to the reaper (the pre-fork parent half), which spawns
    /// and reaps builder processes so they are not our children.
    spawner: reaper::Spawner,
    /// Where the reaper records exit codes, one file per pid.
    status_dir: PathBuf,
    sandbox_bin_sh: Option<PathBuf>,
    cgroup_base: Option<PathBuf>,
    build_memory_max: Option<u64>,
    /// Files a build must never read even where DAC would allow it
    /// (macOS Seatbelt deny rules; Linux relies on the mount namespace).
    secret_paths: Vec<PathBuf>,
    /// Builds currently executing, reported in heartbeats.
    running: atomic::AtomicU32,
    /// dedupe_key -> build past staging; survives session loss so a
    /// replacement hub can resume instead of rebuilding.
    resumable: Mutex<HashMap<String, ResumableBuild>>,
    /// system -> static emulator binary, from the emulate setting.
    emulators: HashMap<String, PathBuf>,
    /// pasta binary for fixed-output network isolation.
    pasta: Option<PathBuf>,
    max_silent_time: Duration,
    max_log_size: u64,
    /// Builder gets the host nix-daemon socket bind-mounted in; the
    /// worker advertises the `recursive-nix` feature.
    pub(super) recursive_nix: bool,
    /// Slot i maps the uid block [uid_base + i*65536, 65536); disjoint
    /// blocks keep concurrent uid-range builds apart.
    uid_base: u32,
    uid_slots: Mutex<Vec<bool>>,
    /// Dedupe keys of builds the hub cancelled; the supervising loops
    /// abort them. Keyed like the registry, since a resumed build's
    /// build_id changes while it runs.
    cancelled: Mutex<HashSet<String>>,
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
                    t.done.store(true, atomic::Ordering::Relaxed);
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
    nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "worker".into())
}

fn load_signing_key(state_dir: &Path) -> Result<SecretKey> {
    let path = state_dir.join("signing.key");
    if path.exists() {
        fs::read_to_string(&path)?
            .trim()
            .parse::<SecretKey>()
            .map_err(|e| {
                anyhow::anyhow!(
                    "{}: {e}; expected Nix secret key format (name:base64); \
                     delete the file to generate a fresh key",
                    path.display()
                )
            })
    } else {
        let key = SecretKey::generate(format!("{}-1", hostname()))
            .map_err(|e| anyhow::anyhow!("generating signing key: {e}"))?;
        crate::fsutil::write_secret(&path, format!("{key}\n").as_bytes())?;
        Ok(key)
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
            crate::fsutil::remove_path_all(&dir);
        }
    }
    // Input caching moved into the real /nix/store (daemon import);
    // clear the legacy cache directory left by older versions.
    let legacy = state_dir.join("store");
    if legacy.symlink_metadata().is_ok() {
        tracing::info!("removing legacy input cache {}", legacy.display());
        crate::fsutil::remove_path_all(&legacy);
    }
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn msg(m: worker_message::Msg) -> WorkerMessage {
    WorkerMessage { msg: Some(m) }
}

fn request_job() -> WorkerMessage {
    msg(worker_message::Msg::RequestJob(RequestJob {}))
}

pub fn run(opts: WorkerConfig) -> Result<()> {
    // ensure() either becomes the reaper (never returns) or, in the
    // worker generation it exec'd, hands back the spawner. It runs
    // before tokio because the reaper must stay single-threaded.
    let spawner = reaper::ensure(&opts.state_dir.join("exited"))?;
    let cgroup_base = std::env::var(reaper::CGROUP_ENV).ok().map(PathBuf::from);
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(opts, spawner, cgroup_base))
}

async fn run_async(
    opts: WorkerConfig,
    spawner: reaper::Spawner,
    cgroup_base: Option<PathBuf>,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let builds_dir = opts.state_dir.join("builds");
    fs::create_dir_all(&builds_dir)?;
    // Traverse-only so leased build uids reach their own tree but
    // other local users get no listing; see BuildOwner.
    fs::set_permissions(&builds_dir, fs::Permissions::from_mode(0o711))?;
    sweep_state_dir(&opts.state_dir);
    // Arc: SecretKey is not Clone (zeroized on drop); build threads share it.
    let signing_key = Arc::new(load_signing_key(&opts.state_dir)?);
    let mut opts = opts;
    if opts.systems.is_empty() {
        opts.systems.push(host_system());
    }
    // "none" disables pasta even when a default path was baked in at
    // build time.
    opts.pasta = match opts.pasta.take() {
        Some(p) if p.as_os_str() == "none" => None,
        Some(p) => Some(p),
        None => option_env!("TRIBUCHET_PASTA").map(PathBuf::from),
    };
    let mut emulators = HashMap::new();
    for (system, path) in &opts.emulate {
        if !cfg!(target_os = "linux") {
            anyhow::bail!("emulate requires Linux (binfmt_misc)");
        }
        if binfmt::register_line(system).is_none() {
            anyhow::bail!("emulate {system}: no binfmt magic known");
        }
        if !path.is_file() {
            anyhow::bail!("emulate {system}: {} not found", path.display());
        }
        if !opts.systems.contains(system) {
            opts.systems.push(system.clone());
        }
        emulators.insert(system.clone(), path.clone());
    }
    if let Some(p) = &opts.pasta {
        if !cfg!(target_os = "linux") {
            anyhow::bail!("pasta requires Linux (network namespaces)");
        }
        if !p.is_file() {
            anyhow::bail!("pasta: {} not found", p.display());
        }
    }
    let opts = opts;
    let ctx = Arc::new(WorkerCtx {
        state_dir: opts.state_dir.clone(),
        spawner,
        status_dir: opts.state_dir.join("exited"),
        sandbox_bin_sh: opts.sandbox_bin_sh.clone(),
        cgroup_base,
        build_memory_max: opts.build_memory_max_bytes,
        secret_paths: vec![opts.key.clone(), opts.state_dir.join("signing.key")],
        running: atomic::AtomicU32::new(0),
        cancelled: Mutex::new(HashSet::new()),
        resumable: Mutex::new(HashMap::new()),
        emulators,
        pasta: opts.pasta.clone(),
        max_silent_time: Duration::from_secs(opts.max_silent_time_secs),
        max_log_size: opts.max_log_size,
        recursive_nix: opts.recursive_nix,
        uid_base: opts.auto_allocate_uids_base,
        uid_slots: Mutex::new(vec![false; opts.max_jobs.max(1) as usize]),
    });

    // Ready once local setup is done, not once the hub answers: the
    // worker is designed to outlive hub outages, so a restart must not
    // hang in "activating" waiting for a hub that may be down.
    crate::sd::notify_ready();
    crate::sd::spawn_watchdog();
    spawn_resumable_reaper(ctx.clone());
    spawn_handover();
    adopt_builds(&ctx, &signing_key).await;

    // Reconnect with backoff: a hub restart must not drain the fleet.
    let mut backoff = Duration::from_secs(1);
    loop {
        let started = std::time::Instant::now();
        match session(&opts, &signing_key, &ctx).await {
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

/// SIGUSR1 (reload: a new generation is about to be exec'd) or
/// SIGTERM (unit stop): exit immediately either way. All resumable
/// state is already on disk; on reload the replacement worker
/// re-adopts the running builds, on stop the unit teardown ends them
/// and the hub requeues their jobs.
fn spawn_handover() {
    tokio::spawn(async {
        let Ok(mut usr1) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
        else {
            return;
        };
        tokio::select! {
            _ = usr1.recv() => {}
            () = crate::sd::stop_requested() => {}
        }
        tracing::info!("handover requested; exiting");
        std::process::exit(0);
    });
}

async fn session(
    opts: &WorkerConfig,
    signing_key: &Arc<SecretKey>,
    ctx: &Arc<WorkerCtx>,
) -> Result<()> {
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(
            fs::read(&opts.ca_cert).context("reading CA cert")?,
        ))
        .identity(Identity::from_pem(
            fs::read(&opts.cert).context("reading worker cert")?,
            fs::read(&opts.key).context("reading worker key")?,
        ));
    let channel = Endpoint::from_shared(opts.hub.clone())?
        .tls_config(tls)?
        // Detect a silently dead hub connection instead of waiting on a
        // half-open TCP session forever.
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(20))
        .keep_alive_while_idle(true)
        .connect()
        .await
        .context("connecting to hub")?;
    let mut client = WorkerHubClient::new(channel)
        .max_decoding_message_size(crate::proto::MAX_MSG_SIZE)
        .max_encoding_message_size(crate::proto::MAX_MSG_SIZE);

    let (out_tx, out_rx) = mpsc::channel::<WorkerMessage>(64);
    // Register must be the first message the hub reads; it fits in the
    // channel buffer, so queue it before the stream is consumed.
    out_tx
        .send(msg(worker_message::Msg::Register(Register {
            worker_name: hostname(),
            caps: system_caps(opts, ctx),
            signing_public_key: signing_key.to_public_key().to_string(),
            resumable_keys: ctx.resumable_keys(),
        })))
        .await?;

    let heartbeat_tx = out_tx.clone();
    let heartbeat_ctx = ctx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            if heartbeat_tx
                .send(msg(worker_message::Msg::Heartbeat(Heartbeat {
                    running_jobs: heartbeat_ctx.running.load(atomic::Ordering::Relaxed),
                    load1: loadavg1(),
                })))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let mut inbound = client
        .session(ReceiverStream::new(out_rx))
        .await?
        .into_inner();
    tracing::info!(hub = opts.hub, systems = ?opts.systems, "connected to hub");

    // One outstanding RequestJob per *free* slot; occupied slots
    // (adopted or running across a reconnect) are re-dispatched
    // credit-free and must not be funded again. Sent only now that
    // session() drains the channel: priming past its capacity first
    // would deadlock the handshake.
    let occupied = u64::from(ctx.running.load(atomic::Ordering::Relaxed));
    for _ in 0..u64::from(opts.max_jobs.max(1)).saturating_sub(occupied) {
        out_tx.send(request_job()).await?;
    }

    let mut active: HashMap<String, ActiveBuild> = HashMap::new();
    let result = session_loop(
        &mut inbound,
        &mut active,
        &out_tx,
        signing_key,
        ctx,
        Duration::from_secs(opts.build_timeout_secs),
    )
    .await;
    // Builds still staging when the session dies must not keep their
    // unpackers writing; executing builds finish on their own threads.
    for (_, build) in active.drain() {
        build.abort().await;
    }
    result
}

async fn session_loop(
    inbound: &mut tonic::Streaming<crate::proto::HubMessage>,
    active: &mut HashMap<String, ActiveBuild>,
    out_tx: &mpsc::Sender<WorkerMessage>,
    signing_key: &Arc<SecretKey>,
    ctx: &Arc<WorkerCtx>,
    build_timeout: Duration,
) -> Result<()> {
    while let Some(m) = inbound.message().await? {
        let Some(m) = m.msg else { continue };
        match m {
            hub_message::Msg::Assignment(a) => {
                // A key we already hold means a hub (likely freshly
                // restarted) re-dispatched a build we are running or
                // have finished: adopt the new build_id and deliver
                // the result when there is one, instead of building
                // again.
                if ctx.adopt_assignment(&a, out_tx) {
                    tracing::info!(id = a.build_id, key = a.dedupe_key, "build resumed");
                    out_tx
                        .send(msg(worker_message::Msg::Resumed(Resumed {
                            build_id: a.build_id.clone(),
                        })))
                        .await?;
                    let ctx = ctx.clone();
                    tokio::task::spawn_blocking(move || try_deliver(&ctx, &a.dedupe_key));
                    continue;
                }
                tracing::info!(id = a.build_id, "build assigned");
                // build ids are never reused; a duplicate is a confused hub
                if let Some(old) = active.remove(&a.build_id) {
                    tracing::warn!(id = old.assignment.build_id, "discarding duplicate build");
                    old.abort().await;
                }
                let build_id = a.build_id.clone();
                match validate_assignment(&a).and_then(|()| ActiveBuild::new(a, ctx.clone())) {
                    Ok(b) => {
                        active.insert(build_id, b);
                    }
                    Err(e) => fail_build(out_tx, &build_id, &e).await?,
                }
            }
            hub_message::Msg::PathOffer(offer) => {
                let Some(build) = active.get_mut(&offer.build_id) else {
                    continue;
                };
                match build.negotiate(&offer.store_paths).await {
                    Ok(missing) => {
                        out_tx
                            .send(msg(worker_message::Msg::MissingPaths(MissingPaths {
                                build_id: offer.build_id,
                                store_paths: missing,
                            })))
                            .await?;
                    }
                    Err(e) => abort_active(active, &offer.build_id, out_tx, &e).await?,
                }
            }
            hub_message::Msg::Nar(n) => {
                let id = n.build_id.clone();
                if let Some(build) = active.get_mut(&id) {
                    // A bad transfer fails this build, not the session.
                    if let Err(e) = build.feed_nar(n).await {
                        abort_active(active, &id, out_tx, &e).await?;
                    }
                }
            }
            hub_message::Msg::TmpDir(t) => {
                let id = t.build_id.clone();
                if let Some(build) = active.get_mut(&id) {
                    match build.feed_tmp_dir(t).await {
                        Err(e) => abort_active(active, &id, out_tx, &e).await?,
                        Ok(false) => {}
                        Ok(true) => {
                            let build = active.remove(&id).unwrap();
                            launch_build(ctx, build, out_tx, signing_key, build_timeout);
                        }
                    }
                }
            }
            hub_message::Msg::PathInfo(pi) => {
                let id = pi.build_id.clone();
                if let Some(build) = active.get_mut(&id) {
                    if let Err(e) = build.feed_path_info(&pi) {
                        abort_active(active, &id, out_tx, &e).await?;
                    }
                }
            }
            hub_message::Msg::Cancel(c) => {
                tracing::info!(id = c.build_id, "hub cancelled the build");
                // Still staging: tear it down right here. Already
                // executing: flag its dedupe key for the supervising
                // loop. The key is the stable identity; the build_id
                // the hub knows may predate a concurrent resume.
                if let Some(build) = active.remove(&c.build_id) {
                    build.abort().await;
                    fail_build(out_tx, &c.build_id, &anyhow::anyhow!("build cancelled")).await?;
                } else {
                    // Only flag builds that are still running: a key
                    // flagged for an already-finished build would
                    // never be consumed and would kill the next build
                    // sharing that dedupe key. The flag is set while
                    // holding the registry lock so a build finishing
                    // concurrently (record_finished) cannot slip
                    // between the check and the insert.
                    let map = ctx.resumable.lock().unwrap();
                    if map.get(&c.dedupe_key).is_some_and(|e| e.finished.is_none()) {
                        ctx.cancelled.lock().unwrap().insert(c.dedupe_key);
                    }
                }
            }
            hub_message::Msg::ResultAck(a) => {
                ack_delivery(ctx, &a.dedupe_key, &a.build_id);
            }
        }
    }
    bail!("hub closed the session");
}

/// Register a fully-staged build as resumable and run it on a blocking
/// thread; the result is delivered via the resumable registry, so the
/// build outlives this session.
fn launch_build(
    ctx: &Arc<WorkerCtx>,
    build: ActiveBuild,
    out_tx: &mpsc::Sender<WorkerMessage>,
    signing_key: &Arc<SecretKey>,
    build_timeout: Duration,
) {
    let ctx = ctx.clone();
    let out_tx = out_tx.clone();
    let signing_key = signing_key.clone();
    let key = build.assignment.dedupe_key.clone();
    ctx.resumable.lock().unwrap().insert(
        key.clone(),
        ResumableBuild {
            build_id: build.assignment.build_id.clone(),
            out_tx: Some(out_tx.clone()),
            finished: None,
            delivering: false,
            dir: build.dir.clone(),
            // execute() streams the log live itself
            log_tail: None,
        },
    );
    ctx.running.fetch_add(1, atomic::Ordering::Relaxed);
    tokio::task::spawn_blocking(move || {
        let fin = execute_to_finished(&build, &out_tx, &signing_key, build_timeout);
        build.teardown();
        drop(build);
        ctx.running.fetch_sub(1, atomic::Ordering::Relaxed);
        record_finished(&ctx, &key, fin);
        let _ = out_tx.blocking_send(request_job());
    });
}

/// Tear down a still-staging build and report the error to the hub.
async fn abort_active(
    active: &mut HashMap<String, ActiveBuild>,
    id: &str,
    out_tx: &mpsc::Sender<WorkerMessage>,
    e: &anyhow::Error,
) -> Result<()> {
    if let Some(build) = active.remove(id) {
        build.abort().await;
    }
    fail_build(out_tx, id, e).await
}

/// Report a per-build failure to the hub without tearing the session down.
async fn fail_build(
    out_tx: &mpsc::Sender<WorkerMessage>,
    build_id: &str,
    err: &anyhow::Error,
) -> Result<()> {
    tracing::error!(id = build_id, "build setup failed: {err:#}");
    out_tx
        .send(msg(worker_message::Msg::Result(BuildResult {
            build_id: build_id.into(),
            exit_code: 1,
            outputs: vec![],
            extras: vec![],
            error: format!("{err:#}"),
        })))
        .await
        .map_err(|_| anyhow::anyhow!("hub connection lost"))?;
    out_tx
        .send(request_job())
        .await
        .map_err(|_| anyhow::anyhow!("hub connection lost"))
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
