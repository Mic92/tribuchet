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
mod cgroup;
pub mod reaper;
pub mod sandbox;

use std::collections::{BTreeSet, HashMap};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use harmonia_store_path::{StoreDir, StorePath};
use harmonia_store_path_info::{NarHash, UnkeyedValidPathInfo, ValidPathInfo};
use harmonia_store_remote::{DaemonClient, DaemonStore};
use harmonia_utils_signature::SecretKey;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

use crate::chunkio::{ChannelReader, CHUNK_SIZE};
use crate::nar;
use crate::proto::{
    hub_message, nar_transfer, worker_hub_client::WorkerHubClient, worker_message, BuildAssignment,
    BuildResult, Heartbeat, LogChunk, MissingPaths, NarTransfer, OutputSignature, PathInfoMsg,
    Register, RequestJob, Resumed, WorkerMessage,
};

/// Connection to the local nix-daemon; one per active build so its
/// temp roots live exactly as long as the build.
type DaemonConn = DaemonClient<tokio::net::unix::OwnedReadHalf, tokio::net::unix::OwnedWriteHalf>;

pub struct WorkerOpts {
    pub hub: String,
    pub state_dir: PathBuf,
    pub systems: Vec<String>,
    pub ca_cert: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
    /// Hard limit per build; a hung builder would otherwise occupy the
    /// worker forever.
    pub build_timeout: std::time::Duration,
    /// Kill builds producing no log output for this long (Nix's
    /// max-silent-time). Zero disables the check.
    pub max_silent_time: std::time::Duration,
    /// Kill builds whose log exceeds this many bytes (Nix's
    /// max-log-size). Zero disables the check.
    pub max_log_size: u64,
    /// Optional static shell bound at /bin/sh inside the Linux sandbox
    /// (like Nix's busybox sandbox path); #!/bin/sh shebangs and libc
    /// system() fail without it.
    pub sandbox_bin_sh: Option<PathBuf>,

    /// Optional memory.max for the per-build cgroup (Linux, requires a
    /// delegated cgroup; see worker/cgroup.rs).
    pub build_memory_max: Option<u64>,
    /// Concurrent build slots advertised to the hub.
    pub max_jobs: u32,
    /// First uid of the per-slot 65536-uid ranges for uid-range builds
    /// (Nix's auto-allocate-uids scheme; needs a root worker).
    pub auto_allocate_uids_base: u32,
    /// "system=/path/to/static-emulator" pairs; each system is
    /// advertised to the hub and its builds run under a per-sandbox
    /// binfmt_misc registration (Linux, kernel 6.7+).
    pub emulate: Vec<String>,
    /// pasta binary for fixed-output network isolation (Linux).
    pub pasta: Option<PathBuf>,
}

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
    running: std::sync::atomic::AtomicU32,
    /// dedupe_key -> build past staging; survives session loss so a
    /// replacement hub can resume instead of rebuilding.
    resumable: std::sync::Mutex<HashMap<String, ResumableBuild>>,
    /// system -> static emulator binary, from --emulate.
    emulators: HashMap<String, PathBuf>,
    /// pasta binary for fixed-output network isolation.
    pasta: Option<PathBuf>,
    max_silent_time: std::time::Duration,
    max_log_size: u64,
    /// Slot i maps the uid block [uid_base + i*65536, 65536); disjoint
    /// blocks keep concurrent uid-range builds apart.
    uid_base: u32,
    uid_slots: std::sync::Mutex<Vec<bool>>,
    /// macOS: tmpDirInSandbox=/build is one global symlink (no mount
    /// namespace); builds sharing it run one at a time.
    shared_link_lock: std::sync::Mutex<()>,
}

impl WorkerCtx {
    fn alloc_uid_slot(self: &std::sync::Arc<Self>) -> Option<UidSlot> {
        let mut slots = self.uid_slots.lock().unwrap();
        let idx = slots.iter().position(|used| !used)?;
        slots[idx] = true;
        Some(UidSlot {
            ctx: self.clone(),
            base: self.uid_base + (idx as u32) * 65536,
            idx,
        })
    }

    fn resumable_keys(&self) -> Vec<String> {
        self.resumable.lock().unwrap().keys().cloned().collect()
    }

    /// Re-point an already-held build (same dedupe key) at the
    /// assignment's new build_id and session; true if one existed.
    /// A tailer streams the log to the new session from the persisted
    /// offset and keeps following it.
    fn adopt_assignment(
        self: &std::sync::Arc<Self>,
        a: &BuildAssignment,
        out_tx: &mpsc::Sender<WorkerMessage>,
    ) -> bool {
        let mut map = self.resumable.lock().unwrap();
        match map.get_mut(&a.dedupe_key) {
            Some(e) => {
                e.build_id = a.build_id.clone();
                e.out_tx = Some(out_tx.clone());
                if let Some(t) = e.log_tail.take() {
                    // An earlier resume's tailer feeds a dead session.
                    // Only flag it (no join): it may be waiting on the
                    // registry lock held right here.
                    t.done.store(true, std::sync::atomic::Ordering::Relaxed);
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

/// A log-replay thread; `stop()` makes it drain to EOF, then waits
/// for it.
struct LogTail {
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: std::thread::JoinHandle<()>,
}

impl LogTail {
    fn stop(self) {
        self.done.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = self.handle.join();
    }
}

/// How far of `dir`'s build.log has already been streamed to a hub.
/// Persisted next to the log so resumed sessions and later worker
/// generations continue where the previous tailer stopped instead of
/// repeating the log from the start.
fn read_log_offset(dir: &std::path::Path) -> u64 {
    std::fs::read_to_string(dir.join("log.offset"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn write_log_offset(dir: &std::path::Path, offset: u64) {
    let _ = std::fs::write(dir.join("log.offset"), offset.to_string());
}

/// Stream `dir`'s build.log to `out_tx` as LogChunks for `build_id`,
/// starting at the persisted offset and advancing it after every
/// chunk handed to the session. Polls past EOF until `done()` says
/// nothing more can arrive (one final read has then already drained
/// what was flushed); a failed send ends it, the offset stays put.
fn tail_log(
    dir: &std::path::Path,
    build_id: &str,
    out_tx: &mpsc::Sender<WorkerMessage>,
    done: impl Fn() -> bool,
    mut on_chunk: impl FnMut(usize),
) {
    use std::io::Seek;
    let Ok(mut file) = std::fs::File::open(dir.join("build.log")) else {
        return;
    };
    let mut sent = read_log_offset(dir);
    if file.seek(std::io::SeekFrom::Start(sent)).is_err() {
        return;
    }
    let mut buf = [0u8; 8192];
    loop {
        match file.read(&mut buf) {
            Ok(0) => {
                if done() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(_) => break,
            Ok(n) => {
                on_chunk(n);
                if out_tx
                    .blocking_send(msg(worker_message::Msg::Log(LogChunk {
                        build_id: build_id.into(),
                        data: buf[..n].to_vec(),
                    })))
                    .is_err()
                {
                    break;
                }
                sent += n as u64;
                write_log_offset(dir, sent);
            }
        }
    }
}

/// Tail a resumed build's log on a thread until the registry entry
/// has finished (or vanished) or `stop()` is called.
fn spawn_log_tail(
    ctx: std::sync::Arc<WorkerCtx>,
    key: String,
    build_id: String,
    dir: PathBuf,
    out_tx: mpsc::Sender<WorkerMessage>,
) -> LogTail {
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let thread_done = done.clone();
    let handle = std::thread::spawn(move || {
        use std::sync::atomic::Ordering;
        let done = || {
            thread_done.load(Ordering::Relaxed) || {
                let map = ctx.resumable.lock().unwrap();
                map.get(&key).is_none_or(|e| e.finished.is_some())
            }
        };
        tail_log(&dir, &build_id, &out_tx, done, |_| {});
    });
    LogTail { done, handle }
}

/// A leased 65536-uid range; returned to the pool on drop.
struct UidSlot {
    ctx: std::sync::Arc<WorkerCtx>,
    base: u32,
    idx: usize,
}

impl Drop for UidSlot {
    fn drop(&mut self) {
        self.ctx.uid_slots.lock().unwrap()[self.idx] = false;
    }
}

/// Host credentials backing one build's sandbox.
///
/// Root workers lease a uid slot for two cases: uid-range builds (the
/// builder is namespace root over a 65536-uid block) and pasta FOD
/// builds (pasta is rootless-only, so the build drops to a single
/// unprivileged uid). A leased uid runs the whole sandbox setup itself
/// after the drop, which is why sandbox::prepare hands it the per-build
/// tree (chown + 0700) and the worker state dirs are traverse-only
/// (0711). Everything else runs as the worker's own uid.
enum BuildOwner {
    Worker,
    UidRange(UidSlot),
    Fod(UidSlot),
}

impl BuildOwner {
    fn for_build(ctx: &std::sync::Arc<WorkerCtx>, a: &BuildAssignment) -> Result<Self> {
        let is_root = nix::unistd::geteuid().is_root();
        if requires_uid_range(&a.env) {
            if !is_root {
                bail!("build requires the uid-range feature, but the worker does not run as root");
            }
            if !cfg!(target_os = "linux") {
                bail!("the uid-range feature is only supported on Linux workers");
            }
            let slot = ctx.alloc_uid_slot().context("no free uid range slot")?;
            return Ok(Self::UidRange(slot));
        }
        if a.fixed_output && ctx.pasta.is_some() && cfg!(target_os = "linux") && is_root {
            let slot = ctx.alloc_uid_slot().context("no free uid slot")?;
            return Ok(Self::Fod(slot));
        }
        Ok(Self::Worker)
    }

    fn uid_range(&self) -> Option<u32> {
        match self {
            Self::UidRange(slot) => Some(slot.base),
            _ => None,
        }
    }

    fn fod_uid(&self) -> Option<u32> {
        match self {
            Self::Fod(slot) => Some(slot.base),
            _ => None,
        }
    }

    /// Slot index for resume state: a re-adopting worker must mark it
    /// used again so new builds get disjoint uid ranges.
    fn slot_idx(&self) -> Option<usize> {
        match self {
            Self::UidRange(slot) | Self::Fod(slot) => Some(slot.idx),
            Self::Worker => None,
        }
    }
}

/// Nix's `uid-range` system feature: a full 65536-uid range with the
/// builder as in-namespace root (containers, systemd-nspawn).
fn requires_uid_range(env: &HashMap<String, String>) -> bool {
    crate::build_json::required_system_features(env)
        .iter()
        .any(|f| f == "uid-range")
}

/// System features this worker can honor, advertised to the hub for
/// scheduling. Mirrors Nix's defaults. Emulated systems get only the
/// baseline: kvm is an x86 device to an emulated guest, and uid-range
/// under emulation is untested.
fn local_features(native: bool, uid_base: u32) -> Vec<String> {
    let mut features = vec![
        "nixos-test".to_owned(),
        "benchmark".to_owned(),
        "big-parallel".to_owned(),
    ];
    if cfg!(target_os = "linux") && native {
        if std::path::Path::new("/dev/kvm").exists() {
            features.push("kvm".to_owned());
        }
        if can_map_uid_range(uid_base) {
            features.push("uid-range".to_owned());
        }
    }
    features
}

/// Per-system capability list for Register; native systems get the
/// probed feature set, emulated ones only the baseline.
fn system_caps(opts: &WorkerOpts, ctx: &WorkerCtx) -> Vec<crate::proto::SystemCaps> {
    let native = local_features(true, opts.auto_allocate_uids_base);
    let emulated = local_features(false, opts.auto_allocate_uids_base);
    opts.systems
        .iter()
        .map(|s| crate::proto::SystemCaps {
            system: s.clone(),
            features: if ctx.emulators.contains_key(s) {
                emulated.clone()
            } else {
                native.clone()
            },
        })
        .collect()
}

/// Probe whether a 65536-uid mapping actually works (root alone is not
/// enough: user namespaces may be disabled). The child unshares and the
/// parent writes the map: after CLONE_NEWUSER the child has no caps in
/// the parent namespace, so it could not map a range itself. Forks
/// because unshare(CLONE_NEWUSER) fails with EINVAL in a multithreaded
/// process; the child runs only async-signal-safe syscalls.
#[cfg(target_os = "linux")]
fn can_map_uid_range(base: u32) -> bool {
    use nix::unistd::ForkResult;
    let Ok((sync_r, sync_w)) = nix::unistd::pipe() else {
        return false;
    };
    let Ok((hold_r, hold_w)) = nix::unistd::pipe() else {
        return false;
    };
    match unsafe { nix::unistd::fork() } {
        Ok(ForkResult::Child) => {
            if nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUSER).is_err() {
                unsafe { libc::_exit(1) }
            }
            let _ = nix::unistd::write(&sync_w, b"u");
            drop(sync_w);
            // block until the parent has tried the map write
            drop(hold_w);
            let _ = nix::unistd::read(&hold_r, &mut [0u8; 1]);
            unsafe { libc::_exit(0) }
        }
        Ok(ForkResult::Parent { child }) => {
            drop(sync_w);
            let unshared = nix::unistd::read(&sync_r, &mut [0u8; 1]) == Ok(1);
            let mapped = unshared
                && std::fs::write(format!("/proc/{child}/uid_map"), format!("0 {base} 65536"))
                    .is_ok();
            drop(hold_w);
            let _ = nix::sys::wait::waitpid(child, None);
            mapped
        }
        Err(_) => false,
    }
}

#[cfg(not(target_os = "linux"))]
fn can_map_uid_range(_base: u32) -> bool {
    false
}

/// Cap on a single NAR transfer in either direction; a `truncate -s 1P
/// $out` build would otherwise tie up the worker and fill its disk.
const MAX_NAR_BYTES: u64 = 64 * 1024 * 1024 * 1024;

pub fn host_system() -> String {
    let arch = std::env::consts::ARCH;
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        os => os,
    };
    format!("{arch}-{os}")
}

/// Write a secret file atomically with mode 0600: created via a temp
/// file so it is never world-readable (fs::write + chmod would race)
/// and a torn write cannot leave a short key behind.
pub(crate) fn write_secret(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Load or create the worker's NAR signing key, stored in Nix's
/// "name:base64" secret key format (nix-store --generate-binary-cache-key)
/// so operators can inspect it with standard tooling.
fn hostname() -> String {
    nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "worker".into())
}

fn load_signing_key(state_dir: &Path) -> Result<SecretKey> {
    let path = state_dir.join("signing.key");
    if path.exists() {
        std::fs::read_to_string(&path)?
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
        write_secret(&path, format!("{key}\n").as_bytes())?;
        Ok(key)
    }
}

/// Remove leftovers from interrupted runs: abandoned build dirs.
fn sweep_state_dir(state_dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(state_dir.join("builds")) {
        for entry in entries.flatten() {
            // Dirs with persisted resume/finished state belong to
            // builds another worker generation left for adoption.
            let dir = entry.path();
            if dir.join("resume.json").exists() || dir.join("finished.json").exists() {
                continue;
            }
            tracing::info!("removing stale build dir {}", dir.display());
            remove_path_all(&dir);
        }
    }
    // Input caching moved into the real /nix/store (daemon import);
    // clear the legacy cache directory left by older versions.
    let legacy = state_dir.join("store");
    if legacy.symlink_metadata().is_ok() {
        tracing::info!("removing legacy input cache {}", legacy.display());
        remove_path_all(&legacy);
    }
}

/// Remove whatever is at `path` without following a symlink at `path`.
fn remove_path_all(path: &Path) {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => {
            let _ = std::fs::remove_dir_all(path);
        }
        Ok(_) => {
            let _ = std::fs::remove_file(path);
        }
        Err(_) => {}
    }
}

fn msg(m: worker_message::Msg) -> WorkerMessage {
    WorkerMessage { msg: Some(m) }
}

fn request_job() -> WorkerMessage {
    msg(worker_message::Msg::RequestJob(RequestJob {}))
}

pub fn run(opts: WorkerOpts) -> Result<()> {
    // ensure() either becomes the reaper (never returns) or, in the
    // worker generation it exec'd, hands back the spawner. It runs
    // before tokio because the reaper must stay single-threaded.
    let spawner = reaper::ensure(opts.state_dir.join("exited"))?;
    let cgroup_base = std::env::var(reaper::CGROUP_ENV).ok().map(PathBuf::from);
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(opts, spawner, cgroup_base))
}

async fn run_async(
    opts: WorkerOpts,
    spawner: reaper::Spawner,
    cgroup_base: Option<PathBuf>,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let builds_dir = opts.state_dir.join("builds");
    std::fs::create_dir_all(&builds_dir)?;
    // Traverse-only so leased build uids reach their own tree but
    // other local users get no listing; see BuildOwner.
    std::fs::set_permissions(&builds_dir, std::fs::Permissions::from_mode(0o711))?;
    sweep_state_dir(&opts.state_dir);
    // Arc: SecretKey is not Clone (zeroized on drop); build threads share it.
    let signing_key = std::sync::Arc::new(load_signing_key(&opts.state_dir)?);
    let mut opts = opts;
    let mut emulators = HashMap::new();
    for pair in &opts.emulate {
        if !cfg!(target_os = "linux") {
            anyhow::bail!("--emulate requires Linux (binfmt_misc)");
        }
        let (system, path) = pair
            .split_once('=')
            .with_context(|| format!("--emulate {pair}: expected system=/path"))?;
        if binfmt::register_line(system).is_none() {
            anyhow::bail!("--emulate {system}: no binfmt magic known");
        }
        let path = PathBuf::from(path);
        if !path.is_file() {
            anyhow::bail!("--emulate {system}: {} not found", path.display());
        }
        if !opts.systems.contains(&system.to_string()) {
            opts.systems.push(system.to_string());
        }
        emulators.insert(system.to_string(), path);
    }
    if let Some(p) = &opts.pasta {
        if !cfg!(target_os = "linux") {
            anyhow::bail!("--pasta requires Linux (network namespaces)");
        }
        if !p.is_file() {
            anyhow::bail!("--pasta: {} not found", p.display());
        }
    }
    let opts = opts;
    let ctx = std::sync::Arc::new(WorkerCtx {
        state_dir: opts.state_dir.clone(),
        spawner,
        status_dir: opts.state_dir.join("exited"),
        sandbox_bin_sh: opts.sandbox_bin_sh.clone(),
        cgroup_base,
        build_memory_max: opts.build_memory_max,
        secret_paths: vec![opts.key.clone(), opts.state_dir.join("signing.key")],
        running: std::sync::atomic::AtomicU32::new(0),
        resumable: std::sync::Mutex::new(HashMap::new()),
        emulators,
        pasta: opts.pasta.clone(),
        max_silent_time: opts.max_silent_time,
        max_log_size: opts.max_log_size,
        uid_base: opts.auto_allocate_uids_base,
        uid_slots: std::sync::Mutex::new(vec![false; opts.max_jobs.max(1) as usize]),
        shared_link_lock: std::sync::Mutex::new(()),
    });

    // Ready once local setup is done, not once the hub answers: the
    // worker is designed to outlive hub outages, so a restart must not
    // hang in "activating" waiting for a hub that may be down.
    crate::sd::notify_ready();
    crate::sd::spawn_watchdog();
    spawn_resumable_reaper(ctx.clone());
    spawn_handover();
    adopt_builds(&ctx, &signing_key);

    // Reconnect with backoff: a hub restart must not drain the fleet.
    let mut backoff = std::time::Duration::from_secs(1);
    loop {
        let started = std::time::Instant::now();
        match session(&opts, &signing_key, &ctx).await {
            Ok(()) => unreachable!("session only returns on error"),
            Err(e) => tracing::warn!("hub session ended: {e:#}"),
        }
        if started.elapsed() > std::time::Duration::from_secs(60) {
            backoff = std::time::Duration::from_secs(1);
        }
        tracing::info!("reconnecting to hub in {}s", backoff.as_secs());
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(60));
    }
}

/// Pick up builds a previous worker generation left behind: still
/// running (same reaper, so their pids and exit statuses are valid)
/// or finished but undelivered. Anything stale is swept.
fn adopt_builds(ctx: &std::sync::Arc<WorkerCtx>, signing_key: &std::sync::Arc<SecretKey>) {
    let reaper_id = std::env::var(reaper::ID_ENV).unwrap_or_default();
    let Ok(entries) = std::fs::read_dir(ctx.state_dir.join("builds")) else {
        return;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if let Ok(s) = std::fs::read_to_string(dir.join("finished.json")) {
            let Ok(f) = serde_json::from_str::<FinishedState>(&s) else {
                remove_path_all(&dir);
                continue;
            };
            tracing::info!(id = f.build_id, "adopted finished build awaiting delivery");
            ctx.resumable.lock().unwrap().insert(
                f.dedupe_key.clone(),
                ResumableBuild {
                    build_id: f.build_id,
                    out_tx: None,
                    finished: Some(FinishedBuild {
                        exit_code: f.exit_code,
                        error: f.error,
                        outputs: f.outputs,
                        dir: dir.clone(),
                        finished_at: std::time::Instant::now(),
                    }),
                    delivering: false,
                    dir,
                    log_tail: None,
                },
            );
            continue;
        }
        let Ok(s) = std::fs::read_to_string(dir.join("resume.json")) else {
            continue; // already swept by sweep_state_dir
        };
        let st = match serde_json::from_str::<ResumeState>(&s) {
            Ok(st) if st.reaper_id == reaper_id => st,
            // Different reaper: the pid is meaningless and the build
            // died with the old unit; the client will resubmit.
            _ => {
                remove_path_all(&dir);
                continue;
            }
        };
        set_uid_slot(ctx, st.uid_slot, true);
        tracing::info!(id = st.build_id, pid = st.pid, "adopted running build");
        ctx.resumable.lock().unwrap().insert(
            st.dedupe_key.clone(),
            ResumableBuild {
                build_id: st.build_id.clone(),
                out_tx: None,
                finished: None,
                delivering: false,
                dir: dir.clone(),
                log_tail: None,
            },
        );
        ctx.running
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let task_ctx = ctx.clone();
        let signing_key = signing_key.clone();
        tokio::task::spawn_blocking(move || {
            let ctx = task_ctx;
            let key = st.dedupe_key.clone();
            let fin = supervise_adopted(&ctx, st, dir, &signing_key);
            ctx.running
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            record_finished(&ctx, &key, fin);
        });
    }
}

/// Wait out a re-adopted build and pack its outputs, mirroring the
/// tail end of execute(). Logs are streamed by the tailer that
/// adopt_assignment starts once a session re-dispatches the build.
fn supervise_adopted(
    ctx: &std::sync::Arc<WorkerCtx>,
    st: ResumeState,
    dir: PathBuf,
    signing_key: &SecretKey,
) -> FinishedBuild {
    let pgrp = nix::unistd::Pid::from_raw(st.pid);
    let mut timed_out = false;
    let code = loop {
        if let Some(code) = reaper::take_status(&ctx.status_dir, st.pid) {
            break code;
        }
        if !timed_out && unix_now() >= st.deadline_unix {
            timed_out = true;
            let _ = nix::sys::signal::killpg(pgrp, nix::sys::signal::Signal::SIGKILL);
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    let _ = nix::sys::signal::killpg(pgrp, nix::sys::signal::Signal::SIGKILL);
    // Tear down cgroup and sandbox like teardown() would.
    if let Some(base) = ctx.cgroup_base.as_deref() {
        cgroup::kill_and_remove(base, &st.build_id);
    }
    let synth = BuildAssignment {
        build_id: st.build_id.clone(),
        outputs: st.outputs.clone(),
        ..Default::default()
    };
    sandbox::cleanup(&synth, &dir);
    set_uid_slot(ctx, st.uid_slot, false);
    let (exit_code, error, outputs) = if timed_out {
        (1, "build timed out".into(), vec![])
    } else if code != 0 {
        (
            code,
            sandbox::setup_error_detail(&st.spec).unwrap_or_default(),
            vec![],
        )
    } else {
        // Fresh deadline: the build's own one bounded execution; this
        // one only stops packing a pathological (e.g. sparse-file)
        // output from running away.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
        match pack_outputs(&dir, &st.spec, deadline, signing_key) {
            Ok(outputs) => (0, String::new(), outputs),
            Err(e) => (1, format!("{e:#}"), vec![]),
        }
    };
    FinishedBuild {
        exit_code,
        error,
        outputs,
        dir,
        finished_at: std::time::Instant::now(),
    }
}

/// Forget finished builds nobody resumed. Without a client
/// resubmitting (it gave up or died), the result has no taker; the
/// entry would otherwise pin the build dir forever.
fn spawn_resumable_reaper(ctx: std::sync::Arc<WorkerCtx>) {
    const TTL: std::time::Duration = std::time::Duration::from_secs(300);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let mut expired = Vec::new();
            {
                let mut map = ctx.resumable.lock().unwrap();
                map.retain(|key, e| match &e.finished {
                    Some(fin) if !e.delivering && fin.finished_at.elapsed() > TTL => {
                        expired.push((key.clone(), fin.dir.clone()));
                        false
                    }
                    _ => true,
                });
            }
            for (key, dir) in expired {
                let _ = std::fs::remove_dir_all(&dir);
                tracing::warn!(
                    key,
                    "dropping undelivered build result (no resume within TTL)"
                );
            }
        }
    });
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
            _ = crate::sd::stop_requested() => {}
        }
        tracing::info!("handover requested; exiting");
        std::process::exit(0);
    });
}

async fn session(
    opts: &WorkerOpts,
    signing_key: &std::sync::Arc<SecretKey>,
    ctx: &std::sync::Arc<WorkerCtx>,
) -> Result<()> {
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(
            std::fs::read(&opts.ca_cert).context("reading CA cert")?,
        ))
        .identity(Identity::from_pem(
            std::fs::read(&opts.cert).context("reading worker cert")?,
            std::fs::read(&opts.key).context("reading worker key")?,
        ));
    let channel = Endpoint::from_shared(opts.hub.clone())?
        .tls_config(tls)?
        // Detect a silently dead hub connection instead of waiting on a
        // half-open TCP session forever.
        .http2_keep_alive_interval(std::time::Duration::from_secs(30))
        .keep_alive_timeout(std::time::Duration::from_secs(20))
        .keep_alive_while_idle(true)
        .connect()
        .await
        .context("connecting to hub")?;
    let mut client = WorkerHubClient::new(channel)
        .max_decoding_message_size(crate::hub::MAX_MSG_SIZE)
        .max_encoding_message_size(crate::hub::MAX_MSG_SIZE);

    let (out_tx, out_rx) = mpsc::channel::<WorkerMessage>(64);
    out_tx
        .send(msg(worker_message::Msg::Register(Register {
            worker_name: hostname(),
            caps: system_caps(opts, ctx),
            signing_public_key: signing_key.to_public_key().to_string(),
            resumable_keys: ctx.resumable_keys(),
        })))
        .await?;
    // One outstanding RequestJob per build slot; every finished build
    // sends the next one, keeping the sum constant.
    for _ in 0..opts.max_jobs.max(1) {
        out_tx.send(request_job()).await?;
    }

    let heartbeat_tx = out_tx.clone();
    let heartbeat_ctx = ctx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            if heartbeat_tx
                .send(msg(worker_message::Msg::Heartbeat(Heartbeat {
                    running_jobs: heartbeat_ctx
                        .running
                        .load(std::sync::atomic::Ordering::Relaxed),
                    load1: 0.0,
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

    let mut active: HashMap<String, ActiveBuild> = HashMap::new();
    let result = session_loop(
        &mut inbound,
        &mut active,
        &out_tx,
        signing_key,
        ctx,
        opts.build_timeout,
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
    signing_key: &std::sync::Arc<SecretKey>,
    ctx: &std::sync::Arc<WorkerCtx>,
    build_timeout: std::time::Duration,
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
                    Err(e) => {
                        let build = active.remove(&offer.build_id).unwrap();
                        let id = build.assignment.build_id.clone();
                        build.abort().await;
                        fail_build(out_tx, &id, &e).await?;
                    }
                }
            }
            hub_message::Msg::Nar(n) => {
                let id = n.build_id.clone();
                if let Some(build) = active.get_mut(&id) {
                    // A bad transfer fails this build, not the session.
                    if let Err(e) = build.feed_nar(n).await {
                        let build = active.remove(&id).unwrap();
                        build.abort().await;
                        fail_build(out_tx, &id, &e).await?;
                    }
                }
            }
            hub_message::Msg::TmpDir(t) => {
                let id = t.build_id.clone();
                if let Some(build) = active.get_mut(&id) {
                    match build.feed_tmp_dir(t).await {
                        Err(e) => {
                            let build = active.remove(&id).unwrap();
                            build.abort().await;
                            fail_build(out_tx, &id, &e).await?;
                        }
                        Ok(false) => {}
                        Ok(true) => {
                            let build = active.remove(&id).unwrap();
                            let out_tx = out_tx.clone();
                            let signing_key = signing_key.clone();
                            let ctx = ctx.clone();
                            let key = build.assignment.dedupe_key.clone();
                            // From here the build outlives the session:
                            // it is resumable until its result reaches
                            // some hub.
                            ctx.resumable.lock().unwrap().insert(
                                key.clone(),
                                ResumableBuild {
                                    build_id: id.clone(),
                                    out_tx: Some(out_tx.clone()),
                                    finished: None,
                                    delivering: false,
                                    dir: build.dir.clone(),
                                    // execute() streams the log live itself
                                    log_tail: None,
                                },
                            );
                            ctx.running
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            tokio::task::spawn_blocking(move || {
                                let fin = execute_to_finished(
                                    &build,
                                    &out_tx,
                                    &signing_key,
                                    build_timeout,
                                );
                                build.teardown();
                                drop(build);
                                ctx.running
                                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                                record_finished(&ctx, &key, fin);
                                let _ = out_tx.blocking_send(request_job());
                            });
                        }
                    }
                }
            }
            hub_message::Msg::PathInfo(pi) => {
                let id = pi.build_id.clone();
                if let Some(build) = active.get_mut(&id) {
                    if let Err(e) = build.feed_path_info(pi) {
                        let build = active.remove(&id).unwrap();
                        build.abort().await;
                        fail_build(out_tx, &id, &e).await?;
                    }
                }
            }
            hub_message::Msg::Cancel(_) => {
                tracing::warn!("build cancellation not implemented yet");
            }
            hub_message::Msg::ResultAck(a) => {
                ack_delivery(ctx, &a.build_id);
            }
        }
    }
    bail!("hub closed the session");
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
            error: format!("{err:#}"),
        })))
        .await
        .map_err(|_| anyhow::anyhow!("hub connection lost"))?;
    out_tx
        .send(request_job())
        .await
        .map_err(|_| anyhow::anyhow!("hub connection lost"))
}

/// The worker must not trust the hub for filesystem-relevant strings:
/// build ids become path components, output paths are packed (and on
/// macOS deleted) on the host.
fn validate_assignment(a: &BuildAssignment) -> Result<()> {
    if a.build_id.len() != 32 || !a.build_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid build id {:?}", a.build_id);
    }
    if !a.builder.starts_with('/') {
        bail!("builder must be an absolute path");
    }
    let tmp = Path::new(&a.tmp_dir_in_sandbox);
    if !tmp.is_absolute()
        || tmp.components().any(|c| {
            !matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        bail!("invalid tmpDirInSandbox {:?}", a.tmp_dir_in_sandbox);
    }
    for p in a.outputs.values() {
        if !crate::hub::valid_store_path(crate::hub::STORE_DIR, p) {
            bail!("invalid output path {p:?}");
        }
    }
    Ok(())
}

type Unpacker = (mpsc::Sender<Vec<u8>>, tokio::task::JoinHandle<Result<()>>);

/// In-flight daemon import of one input NAR. Owns the build's daemon
/// connection while streaming (AddToStoreNar holds the protocol);
/// the connection comes back when the transfer finishes.
struct Importer {
    store_path: String,
    tx: mpsc::Sender<bytes::Bytes>,
    task: tokio::task::JoinHandle<(DaemonConn, Result<()>)>,
}

struct ActiveBuild {
    assignment: BuildAssignment,
    dir: PathBuf, // state_dir/builds/<id>
    ctx: std::sync::Arc<WorkerCtx>,
    /// Input store paths available in /nix/store (bind-mount sources).
    inputs: Vec<String>,
    /// Paths reported missing, waiting for PathInfo + NAR. The value
    /// holds the parsed metadata once it arrived.
    pending: HashMap<String, Option<ValidPathInfo>>,
    /// Daemon connection; carries this build's temp roots, so it must
    /// outlive the build. None while an Importer borrows it.
    daemon: Option<DaemonConn>,
    importer: Option<Importer>,
    tmp_unpacker: Option<Unpacker>,
}

fn store_base(store_path: &str) -> &str {
    store_path.rsplit('/').next().unwrap_or(store_path)
}

/// Wire metadata -> daemon ValidPathInfo.
fn parse_path_info(msg: &PathInfoMsg) -> Result<ValidPathInfo> {
    let store_dir = StoreDir::default();
    Ok(ValidPathInfo {
        path: store_dir.parse(&msg.store_path)?,
        info: UnkeyedValidPathInfo {
            deriver: (!msg.deriver.is_empty())
                .then(|| store_dir.parse(&msg.deriver))
                .transpose()?,
            nar_hash: NarHash::from_slice(&msg.nar_sha256)?,
            references: msg
                .references
                .iter()
                .map(|r| store_dir.parse(r))
                .collect::<Result<BTreeSet<StorePath>, _>>()?,
            registration_time: None,
            nar_size: msg.nar_size,
            ultimate: false,
            signatures: msg
                .signatures
                .iter()
                .map(|s| s.parse())
                .collect::<Result<BTreeSet<_>, _>>()?,
            ca: (!msg.ca.is_empty()).then(|| msg.ca.parse()).transpose()?,
            store_dir,
        },
    })
}

/// Drive one AddToStoreNar: hub chunks -> zstd decode -> daemon. The
/// daemon verifies the NAR against info.nar_hash and registers the
/// path, so no separate integrity check is needed here.
async fn import_nar(
    conn: &mut DaemonConn,
    info: &ValidPathInfo,
    rx: mpsc::Receiver<bytes::Bytes>,
) -> Result<()> {
    use futures_util::StreamExt as _;
    use tokio::io::AsyncReadExt as _;
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(Ok::<_, std::io::Error>);
    let reader = tokio_util::io::StreamReader::new(stream);
    let dec =
        async_compression::tokio::bufread::ZstdDecoder::new(tokio::io::BufReader::new(reader));
    // take(nar_size): the daemon reads a self-delimiting NAR, but a
    // malicious hub must not stream unbounded decompressed bytes.
    let limited = tokio::io::BufReader::new(dec.take(info.info.nar_size));
    conn.add_to_store_nar(info, limited, false, true)
        .await
        .map_err(|e| anyhow::anyhow!("importing {} via the daemon: {e}", info.path))?;
    Ok(())
}

impl ActiveBuild {
    fn new(assignment: BuildAssignment, ctx: std::sync::Arc<WorkerCtx>) -> Result<Self> {
        let dir = ctx.state_dir.join("builds").join(&assignment.build_id);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        std::fs::create_dir_all(dir.join("top"))?;
        Ok(Self {
            assignment,
            dir,
            ctx,
            inputs: Vec::new(),
            pending: HashMap::new(),
            daemon: None,
            importer: None,
            tmp_unpacker: None,
        })
    }

    async fn negotiate(&mut self, offered: &[String]) -> Result<Vec<String>> {
        let store_dir = StoreDir::default();
        let mut daemon = DaemonClient::builder()
            .connect_daemon()
            .await
            .context("connecting to the local nix-daemon")?;
        let mut missing = Vec::new();
        for p in offered {
            // Only real store paths may become bind-mount sources; a
            // compromised hub must not get the worker's own files
            // (signing key, TLS key) mounted into a sandbox.
            let sp: StorePath = store_dir
                .parse(p)
                .with_context(|| format!("offered path {p:?} is not a store path"))?;
            // Temp root before the validity check: the daemon must not
            // GC the path between check and build start. Temp roots die
            // with this connection, which the build keeps open.
            daemon
                .add_temp_root(&sp)
                .await
                .with_context(|| format!("adding temp root for {p}"))?;
            if daemon
                .is_valid_path(&sp)
                .await
                .with_context(|| format!("querying validity of {p}"))?
            {
                self.inputs.push(p.clone());
            } else {
                self.pending.insert(p.clone(), None);
                missing.push(p.clone());
            }
        }
        self.daemon = Some(daemon);
        Ok(missing)
    }

    fn feed_path_info(&mut self, pi: PathInfoMsg) -> Result<()> {
        let Some(slot) = self.pending.get_mut(&pi.store_path) else {
            bail!("hub sent path info for unrequested path {}", pi.store_path);
        };
        if pi.nar_size > MAX_NAR_BYTES {
            bail!(
                "input {} exceeds the {MAX_NAR_BYTES} byte NAR limit",
                pi.store_path
            );
        }
        *slot =
            Some(parse_path_info(&pi).with_context(|| format!("path info for {}", pi.store_path))?);
        Ok(())
    }

    async fn feed_nar(&mut self, n: NarTransfer) -> Result<()> {
        if self
            .importer
            .as_ref()
            .is_none_or(|i| i.store_path != n.store_path)
        {
            // Start a new import; the hub streams one path at a time.
            if self.importer.is_some() {
                bail!("hub interleaved NAR transfers for different paths");
            }
            let info = match self.pending.remove(&n.store_path) {
                Some(Some(info)) => info,
                Some(None) => bail!("hub sent NAR before path info for {}", n.store_path),
                None => bail!("hub sent NAR for unrequested path {}", n.store_path),
            };
            let mut conn = self
                .daemon
                .take()
                .context("daemon connection missing (no negotiation?)")?;
            let (tx, rx) = mpsc::channel::<bytes::Bytes>(8);
            let task = tokio::spawn(async move {
                let res = import_nar(&mut conn, &info, rx).await;
                (conn, res)
            });
            self.importer = Some(Importer {
                store_path: n.store_path.clone(),
                tx,
                task,
            });
        }
        let importer = self.importer.as_ref().unwrap();
        let send_failed = match n.payload {
            Some(nar_transfer::Payload::ZstdNarChunk(chunk)) => {
                importer.tx.send(chunk.into()).await.is_err()
            }
            None => false,
        };
        if send_failed || n.eof {
            // Reap the import task: on eof for its result, on a failed
            // send for the error that killed it.
            let Importer { task, tx, .. } = self.importer.take().unwrap();
            drop(tx);
            let (conn, res) = task.await?;
            self.daemon = Some(conn);
            res?;
            if send_failed {
                bail!("input import ended early for {}", n.store_path);
            }
            self.inputs.push(n.store_path);
        }
        Ok(())
    }

    /// Returns true when the tmp dir transfer completed, which is the
    /// signal to start the build.
    async fn feed_tmp_dir(&mut self, t: crate::proto::TmpDirArchive) -> Result<bool> {
        let (tx, _) = self.tmp_unpacker.get_or_insert_with(|| {
            let dest = self.dir.join("top");
            let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
            let task = tokio::task::spawn_blocking(move || -> Result<()> {
                let dec = zstd::stream::read::Decoder::new(ChannelReader::new(rx))?;
                unpack_tmp_dir_archive(dec, &dest).context("unpacking tmp dir archive")
            });
            (tx, task)
        });
        if !t.zstd_tar_chunk.is_empty() {
            tx.send(t.zstd_tar_chunk)
                .await
                .map_err(|_| anyhow::anyhow!("tmp dir unpacker died"))?;
        }
        if t.eof {
            let (tx, task) = self.tmp_unpacker.take().unwrap();
            drop(tx);
            task.await??;
            if !self.pending.is_empty() || self.importer.is_some() {
                bail!("tmp dir transfer finished before all input paths arrived");
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Runs on a blocking thread: sandboxed build, live log streaming,
    /// output packing and signing. Sends only logs; the result and
    /// output NARs go through deliver(), which can run again on a
    /// later session if this one dies first.
    fn execute(
        &self,
        out_tx: &mpsc::Sender<WorkerMessage>,
        signing_key: &SecretKey,
        timeout: std::time::Duration,
    ) -> Result<FinishedBuild> {
        let a = &self.assignment;
        // Serialize macOS builds sharing the global /build symlink;
        // Linux mounts it inside a private namespace, no lock needed.
        let _link_guard = if cfg!(target_os = "macos") && a.tmp_dir_in_sandbox == "/build" {
            Some(
                self.ctx
                    .shared_link_lock
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()),
            )
        } else {
            None
        };
        // The slot lease keeps concurrent uids disjoint; returned on
        // drop when the build finishes.
        let owner = BuildOwner::for_build(&self.ctx, a)?;
        let mut spec = sandbox::prepare(
            a,
            &self.dir,
            &self.inputs,
            &sandbox::PrepareOpts {
                bin_sh: self.ctx.sandbox_bin_sh.as_deref(),
                secrets: &self.ctx.secret_paths,
                uid_range: owner.uid_range(),
                emulator: self.ctx.emulators.get(&a.system).map(PathBuf::as_path),
                pasta: self.ctx.pasta.as_deref(),
                fod_uid: owner.fod_uid(),
            },
        )?;
        spec.cgroup = self
            .ctx
            .cgroup_base
            .as_deref()
            .and_then(|base| cgroup::create(base, &a.build_id, self.ctx.build_memory_max));
        if let (Some(base), Some(cg)) = (owner.uid_range(), &spec.cgroup) {
            // the build manages its own delegated cgroup (Nix's
            // `cgroups` setting); needed by nspawn inside the sandbox
            cgroup::chown_to_builder(cg, base);
        }
        let deadline = std::time::Instant::now() + timeout;
        // Logs go through a file in the build dir, not pipes: capture
        // is decoupled from this process's lifetime, so a later worker
        // generation can resume tailing where we stopped.
        let log_path = self.dir.join("build.log");
        let log_file = std::fs::File::create(&log_path)?;
        let (mut req, child_stdin, spec_w) = sandbox::spawn_request(&spec)?;
        let pid = self.ctx.spawner.spawn(&mut req, &log_file, child_stdin)?;
        if let Some(w) = spec_w {
            sandbox::send_spec_to(&spec, w)?;
        }
        // From here the build can be re-adopted by a replacement
        // worker generation under the same reaper.
        let resume = ResumeState {
            reaper_id: std::env::var(reaper::ID_ENV).unwrap_or_default(),
            dedupe_key: a.dedupe_key.clone(),
            build_id: a.build_id.clone(),
            pid,
            spec: spec.clone(),
            outputs: a.outputs.clone(),
            deadline_unix: unix_now() + timeout.as_secs(),
            uid_slot: owner.slot_idx(),
        };
        std::fs::write(self.dir.join("resume.json"), serde_json::to_vec(&resume)?)?;

        let log_bytes = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        // ms since `started`, updated on every log chunk
        let last_log_ms = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let started = std::time::Instant::now();
        let log_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let tailer = {
            let tx = out_tx.clone();
            let build_id = a.build_id.clone();
            let log_bytes = log_bytes.clone();
            let last_log_ms = last_log_ms.clone();
            let log_done = log_done.clone();
            let dir = self.dir.clone();
            std::thread::spawn(move || {
                use std::sync::atomic::Ordering;
                tail_log(
                    &dir,
                    &build_id,
                    &tx,
                    || log_done.load(Ordering::Relaxed),
                    |n| {
                        log_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        last_log_ms.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
                    },
                );
            })
        };
        let pgrp = nix::unistd::Pid::from_raw(pid);
        let max_silent_ms = self.ctx.max_silent_time.as_millis() as u64;
        let max_log = self.ctx.max_log_size;
        use std::sync::atomic::Ordering;
        let mut abort: Option<String> = None;
        let status = loop {
            if let Some(code) = reaper::take_status(&self.ctx.status_dir, pid) {
                break code;
            }
            // saturating: a log thread may store a newer timestamp
            // between the elapsed() read and the load
            let silent_ms = (started.elapsed().as_millis() as u64)
                .saturating_sub(last_log_ms.load(Ordering::Relaxed));
            if std::time::Instant::now() >= deadline {
                abort = Some(format!("build timed out after {}s", timeout.as_secs()));
            } else if max_log > 0 && log_bytes.load(Ordering::Relaxed) > max_log {
                abort = Some(format!("build log exceeded the limit of {max_log} bytes"));
            } else if max_silent_ms > 0 && silent_ms > max_silent_ms {
                abort = Some(format!(
                    "build produced no output for {}s",
                    self.ctx.max_silent_time.as_secs()
                ));
            }
            if abort.is_some() {
                let _ = nix::sys::signal::killpg(pgrp, nix::sys::signal::Signal::SIGKILL);
                // The reaper collects the kill within its sweep interval.
                break loop {
                    if let Some(code) = reaper::take_status(&self.ctx.status_dir, pid) {
                        break code;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                };
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        };
        // The builder is PID 1 of its PID namespace, so its death took
        // every descendant with it; the killpg also covers the brief
        // pre-exec window and macOS, where there is no PID namespace.
        let _ = nix::sys::signal::killpg(pgrp, nix::sys::signal::Signal::SIGKILL);
        log_done.store(true, Ordering::Relaxed);
        let _ = tailer.join();
        if let Some(reason) = abort {
            bail!("{reason}");
        }
        // The reaper already folded signal deaths into 128 + signo
        // (matching shell conventions), so an OOM SIGKILL (137) is
        // distinguishable from a SIGSEGV (139).
        let exit_code = status;
        tracing::info!(id = a.build_id, exit_code, "builder finished");

        if exit_code != 0 {
            // present on Linux when the sandbox setup stage failed
            let error = sandbox::setup_error_detail(&spec).unwrap_or_default();
            if !error.is_empty() {
                tracing::warn!(id = a.build_id, error, "sandbox setup failed");
            }
            return Ok(FinishedBuild {
                exit_code,
                error,
                outputs: Vec::new(),
                dir: self.dir.clone(),
                finished_at: std::time::Instant::now(),
            });
        }

        let packed = pack_outputs(&self.dir, &spec, deadline, signing_key)?;
        Ok(FinishedBuild {
            exit_code: 0,
            error: String::new(),
            outputs: packed,
            dir: self.dir.clone(),
            finished_at: std::time::Instant::now(),
        })
    }

    /// Tear down sandbox and cgroup, keeping the build dir: it holds
    /// the packed output NARs until they are delivered to a hub.
    fn teardown(&self) {
        if let Some(base) = self.ctx.cgroup_base.as_deref() {
            // cgroup.kill reaches setsid'd survivors that escaped killpg.
            cgroup::kill_and_remove(base, &self.assignment.build_id);
        }
        sandbox::cleanup(&self.assignment, &self.dir);
    }

    /// Tear down a build abandoned before execution: stop the import
    /// and unpacker tasks and remove everything staged on disk. The
    /// daemon connection (and with it the temp roots) drops here; a
    /// half-imported path is the daemon's to clean up.
    async fn abort(mut self) {
        if let Some(Importer { tx, task, .. }) = self.importer.take() {
            drop(tx);
            task.abort();
            let _ = task.await;
        }
        if let Some((tx, task)) = self.tmp_unpacker.take() {
            drop(tx);
            task.abort();
            let _ = task.await;
        }
        if let Err(e) = std::fs::remove_dir_all(&self.dir) {
            tracing::warn!("cleaning up {}: {e}", self.dir.display());
        }
    }
}

/// A build past staging: running, or finished with its result not yet
/// delivered to any hub. Keyed by the assignment's dedupe_key, which
/// survives hub restarts (build ids do not).
struct ResumableBuild {
    /// From the latest assignment; result messages carry this id.
    build_id: String,
    /// Sender of the session that issued that assignment. Kept here,
    /// not captured by the build thread: the session alive when the
    /// build *finishes* may not be the one that assigned it. None for
    /// a freshly re-adopted build no session has assigned yet.
    out_tx: Option<mpsc::Sender<WorkerMessage>>,
    finished: Option<FinishedBuild>,
    /// A delivery is in flight; a concurrent re-assignment must not
    /// start a second one.
    delivering: bool,
    /// Build dir holding build.log, for log replay on resume.
    dir: PathBuf,
    /// Replays the log to the resumed session; joined before the
    /// result is delivered so logs arrive first.
    log_tail: Option<LogTail>,
}

#[derive(Clone)]
struct FinishedBuild {
    exit_code: i32,
    error: String,
    outputs: Vec<PackedOutput>,
    /// Build dir holding the packed NARs; removed after delivery.
    dir: PathBuf,
    finished_at: std::time::Instant,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PackedOutput {
    scratch: String,
    nar_file: PathBuf,
    nar_sha256: Vec<u8>,
    signature: String,
}

/// On-disk state for re-adopting a running build after a worker
/// handover. Only valid within one reaper generation: a different
/// reaper never spawned these pids, so their statuses cannot come.
#[derive(serde::Serialize, serde::Deserialize)]
struct ResumeState {
    reaper_id: String,
    dedupe_key: String,
    /// Original assignment id: names the cgroup and the log file.
    build_id: String,
    pid: i32,
    spec: sandbox::SandboxSpec,
    /// Assignment outputs (name -> scratch path), for cleanup.
    outputs: HashMap<String, String>,
    deadline_unix: u64,
    uid_slot: Option<usize>,
}

/// On-disk form of a finished-but-undelivered result; the packed NARs
/// sit next to it in the build dir.
#[derive(serde::Serialize, serde::Deserialize)]
struct FinishedState {
    dedupe_key: String,
    build_id: String,
    exit_code: i32,
    error: String,
    outputs: Vec<PackedOutput>,
}

/// Pack, hash and sign every output before announcing the result,
/// because signatures travel in BuildResult ahead of the NAR data.
fn pack_outputs(
    dir: &Path,
    spec: &sandbox::SandboxSpec,
    deadline: std::time::Instant,
    signing_key: &SecretKey,
) -> Result<Vec<PackedOutput>> {
    let mut packed = Vec::new();
    for scratch in &spec.outputs {
        let host_path = sandbox::output_host_path(spec, scratch);
        // lstat: a symlink output whose target only resolves inside
        // the sandbox is still a valid output.
        if host_path.symlink_metadata().is_err() {
            bail!("builder did not produce output {scratch}");
        }
        let nar_file = dir.join(format!("{}.nar.zst", store_base(scratch)));
        let mut hasher = Sha256::new();
        {
            let f = std::fs::File::create(&nar_file)?;
            let mut enc = zstd::stream::write::Encoder::new(f, 3)?;
            let mut tee = TeeWriter(&mut enc, &mut hasher);
            // The build deadline also bounds packing: a builder can
            // exit instantly leaving a multi-TB sparse output.
            let mut limited = LimitedWriter {
                inner: &mut tee,
                remaining: MAX_NAR_BYTES,
                deadline,
            };
            nar::pack(&host_path, &mut limited)
                .with_context(|| format!("packing output {scratch}"))?;
            enc.finish()?.flush()?;
        }
        let hash = hasher.finalize();
        let sig = signing_key.sign(format!("{}:{}", scratch, hex::encode(hash)).as_bytes());
        packed.push(PackedOutput {
            scratch: scratch.clone(),
            nar_file,
            nar_sha256: hash.to_vec(),
            signature: sig.to_string(),
        });
    }
    Ok(packed)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Record a build's result in the registry (persisted for redelivery
/// across worker generations) and start delivering it. Shared by the
/// normal execute path and re-adopted builds.
fn record_finished(ctx: &std::sync::Arc<WorkerCtx>, key: &str, fin: FinishedBuild) {
    {
        let mut map = ctx.resumable.lock().unwrap();
        if let Some(e) = map.get_mut(key) {
            // build_id may have changed via a resume assignment meanwhile
            persist_finished(key, &e.build_id, &fin);
            e.finished = Some(fin);
        }
    }
    try_deliver(ctx, key);
}

/// Mark or release a leased uid slot by index (re-adopted builds,
/// where no BuildOwner exists to do it on drop).
fn set_uid_slot(ctx: &WorkerCtx, idx: Option<usize>, used: bool) {
    if let Some(idx) = idx {
        if let Some(s) = ctx.uid_slots.lock().unwrap().get_mut(idx) {
            *s = used;
        }
    }
}

/// Persist a finished result so a replacement worker can redeliver
/// it; supersedes the running-build resume state.
fn persist_finished(key: &str, build_id: &str, fin: &FinishedBuild) {
    let state = FinishedState {
        dedupe_key: key.to_string(),
        build_id: build_id.to_string(),
        exit_code: fin.exit_code,
        error: fin.error.clone(),
        outputs: fin.outputs.clone(),
    };
    if let Ok(json) = serde_json::to_vec(&state) {
        let _ = std::fs::write(fin.dir.join("finished.json"), json);
    }
    let _ = std::fs::remove_file(fin.dir.join("resume.json"));
}

/// Run a build to a FinishedBuild, whatever happens: errors and even
/// panics become a failed result. Nothing else reports it -- the
/// JoinHandle is dropped, so a leaked panic would leave the registry
/// entry unfinished and the client waiting forever.
fn execute_to_finished(
    build: &ActiveBuild,
    out_tx: &mpsc::Sender<WorkerMessage>,
    signing_key: &SecretKey,
    timeout: std::time::Duration,
) -> FinishedBuild {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        build.execute(out_tx, signing_key, timeout)
    }))
    .unwrap_or_else(|_| Err(anyhow::anyhow!("build execution panicked")))
    .unwrap_or_else(|e| {
        tracing::error!("build execution failed: {e:#}");
        FinishedBuild {
            exit_code: 1,
            error: format!("{e:#}"),
            outputs: vec![],
            dir: build.dir.clone(),
            finished_at: std::time::Instant::now(),
        }
    })
}

/// Send a finished build's result and output NARs. Blocking; runs on
/// a blocking thread.
fn deliver(
    fin: &FinishedBuild,
    build_id: &str,
    out_tx: &mpsc::Sender<WorkerMessage>,
) -> Result<()> {
    out_tx.blocking_send(msg(worker_message::Msg::Result(BuildResult {
        build_id: build_id.into(),
        exit_code: fin.exit_code,
        outputs: fin
            .outputs
            .iter()
            .map(|o| OutputSignature {
                store_path: o.scratch.clone(),
                nar_sha256: o.nar_sha256.clone(),
                signature: o.signature.clone(),
            })
            .collect(),
        error: fin.error.clone(),
    })))?;
    for o in &fin.outputs {
        let mut f = std::fs::File::open(&o.nar_file)?;
        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out_tx.blocking_send(msg(worker_message::Msg::Nar(NarTransfer {
                build_id: build_id.into(),
                store_path: o.scratch.clone(),
                payload: Some(nar_transfer::Payload::ZstdNarChunk(buf[..n].to_vec())),
                eof: false,
            })))?;
        }
        out_tx.blocking_send(msg(worker_message::Msg::Nar(NarTransfer {
            build_id: build_id.into(),
            store_path: o.scratch.clone(),
            payload: None,
            eof: true,
        })))?;
    }
    Ok(())
}

/// Drop a build whose result the hub confirmed: only now is it safe
/// to forget it, a result merely handed to a dying session would
/// otherwise be lost and cost a rebuild.
fn ack_delivery(ctx: &std::sync::Arc<WorkerCtx>, build_id: &str) {
    let removed = {
        let mut map = ctx.resumable.lock().unwrap();
        let key = map
            .iter()
            .find(|(_, e)| e.build_id == build_id && e.finished.is_some())
            .map(|(k, _)| k.clone());
        key.and_then(|k| map.remove(&k))
    };
    if let Some(e) = removed {
        if let Err(err) = std::fs::remove_dir_all(&e.dir) {
            tracing::warn!("cleaning up {}: {err}", e.dir.display());
        }
        tracing::info!(id = build_id, "build result acknowledged");
    }
}

/// Deliver `key`'s finished result if there is one and no other
/// delivery is running, over the session that issued its latest
/// assignment. The build is kept until the hub acknowledges the
/// result; a failed or unacknowledged delivery is retried on the next
/// assignment of the same key.
fn try_deliver(ctx: &std::sync::Arc<WorkerCtx>, key: &str) {
    let (build_id, out_tx, fin, log_tail) = {
        let mut map = ctx.resumable.lock().unwrap();
        let Some(e) = map.get_mut(key) else { return };
        if e.delivering {
            return;
        }
        let (Some(fin), Some(out_tx)) = (e.finished.clone(), e.out_tx.clone()) else {
            return;
        };
        e.delivering = true;
        (e.build_id.clone(), out_tx, fin, e.log_tail.take())
    };
    // Flush any log replay first so the result arrives after the log.
    if let Some(t) = log_tail {
        t.stop();
    }
    let result = deliver(&fin, &build_id, &out_tx);
    let mut map = ctx.resumable.lock().unwrap();
    // The ack may already have removed the entry; nothing to update then.
    if let Some(entry) = map.get_mut(key) {
        entry.delivering = false;
    }
    match result {
        Ok(()) => {
            tracing::info!(id = build_id, "build result sent, awaiting ack");
        }
        Err(e) => {
            tracing::warn!(
                id = build_id,
                "result delivery failed, keeping for resume: {e:#}"
            );
        }
    }
}

/// Unpack the client-supplied tmp-dir tar, refusing anything but plain
/// files, directories, and symlinks, and applying only the 0777 mode
/// bits: a root worker must not materialize client-chosen setuid bits.
fn unpack_tmp_dir_archive(reader: impl Read, dest: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut tar = tar::Archive::new(reader);
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = dest.join(entry.path()?);
        let kind = entry.header().entry_type();
        match kind {
            tar::EntryType::Regular | tar::EntryType::Directory | tar::EntryType::Symlink => {}
            other => bail!("unsupported tar entry type {other:?} in tmp dir archive"),
        }
        let mode = entry.header().mode()? & 0o777;
        entry.set_preserve_permissions(false);
        if !entry.unpack_in(dest)? {
            bail!("tar entry escapes the tmp dir");
        }
        if kind != tar::EntryType::Symlink {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

/// Enforces a byte budget and a wall-clock deadline on a Write chain.
struct LimitedWriter<W> {
    inner: W,
    remaining: u64,
    deadline: std::time::Instant,
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if std::time::Instant::now() >= self.deadline {
            return Err(std::io::Error::other("build timed out"));
        }
        if buf.len() as u64 > self.remaining {
            return Err(std::io::Error::other(format!(
                "NAR exceeds the {MAX_NAR_BYTES} byte limit"
            )));
        }
        let n = self.inner.write(buf)?;
        self.remaining -= n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct TeeWriter<'a, A: Write, B: Write>(&'a mut A, &'a mut B);

impl<A: Write, B: Write> Write for TeeWriter<'_, A, B> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write_all(buf)?;
        self.1.write_all(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_assignment() -> BuildAssignment {
        BuildAssignment {
            build_id: "0123456789abcdef0123456789abcdef".into(),
            dedupe_key: "test-key".into(),
            system: "x86_64-linux".into(),
            builder: "/nix/store/00000000000000000000000000000000-bash/bin/bash".into(),
            args: vec![],
            env: Default::default(),
            outputs: [(
                "out".to_string(),
                "/nix/store/00000000000000000000000000000000-out".to_string(),
            )]
            .into(),
            tmp_dir_in_sandbox: "/build".into(),
            store_dir: "/nix/store".into(),
            fixed_output: false,
        }
    }

    #[test]
    fn assignment_validation() {
        assert!(validate_assignment(&base_assignment()).is_ok());

        // build_id becomes a path component under state_dir/builds
        for id in ["../../../../etc", "/etc", "0123", ""] {
            let mut a = base_assignment();
            a.build_id = id.into();
            assert!(validate_assignment(&a).is_err(), "{id:?}");
        }

        let mut a = base_assignment();
        a.tmp_dir_in_sandbox = "../escape".into();
        assert!(validate_assignment(&a).is_err());

        // output paths are packed (and on macOS deleted) on the host
        let mut a = base_assignment();
        a.outputs.insert("doc".into(), "/etc/shadow".into());
        assert!(validate_assignment(&a).is_err());

        let mut a = base_assignment();
        a.builder = "-p".into();
        assert!(validate_assignment(&a).is_err());
    }

    #[test]
    fn uid_range_detection() {
        let mut env = HashMap::new();
        assert!(!requires_uid_range(&env));
        env.insert(
            "requiredSystemFeatures".into(),
            "big-parallel uid-range".into(),
        );
        assert!(requires_uid_range(&env));

        let mut env = HashMap::new();
        env.insert(
            "__json".into(),
            r#"{"requiredSystemFeatures":["uid-range"]}"#.into(),
        );
        assert!(requires_uid_range(&env));
        let mut env = HashMap::new();
        env.insert("__json".into(), r#"{"outputHash":"x"}"#.into());
        assert!(!requires_uid_range(&env));
    }

    #[test]
    fn sweep_removes_stale_builds_and_legacy_cache() -> Result<()> {
        let state = tempfile::tempdir()?;
        std::fs::create_dir_all(state.path().join("builds/deadbeef"))?;
        // legacy input cache from pre-daemon-import versions: must go
        std::fs::create_dir_all(state.path().join("store/zzz-good"))?;
        sweep_state_dir(state.path());
        assert!(!state.path().join("builds/deadbeef").exists());
        assert!(!state.path().join("store").exists());
        Ok(())
    }

    #[test]
    fn tmp_dir_archive_strips_setuid_and_rejects_hardlinks() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        // setuid bit in the archive must not materialize on disk
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path("evil")?;
        header.set_size(2);
        header.set_mode(0o4755);
        header.set_cksum();
        builder.append(&header, &b"hi"[..])?;
        let data = builder.into_inner()?;
        let dest = tempfile::tempdir()?;
        unpack_tmp_dir_archive(data.as_slice(), dest.path())?;
        let mode = std::fs::metadata(dest.path().join("evil"))?
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o755, "mode {mode:o}");

        // hard links could alias files outside the build dir
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path("link")?;
        header.set_entry_type(tar::EntryType::Link);
        header.set_link_name("/etc/passwd")?;
        header.set_size(0);
        header.set_cksum();
        builder.append(&header, &b""[..])?;
        let data = builder.into_inner()?;
        let dest = tempfile::tempdir()?;
        assert!(unpack_tmp_dir_archive(data.as_slice(), dest.path()).is_err());
        Ok(())
    }
}
