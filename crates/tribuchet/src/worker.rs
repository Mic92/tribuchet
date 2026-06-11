//! `tribuchet worker`: dials the hub over mTLS, caches input paths,
//! executes builds in a local sandbox, signs and returns output NARs.
//!
//! Input sources, in order of preference:
//! 1. the host's own /nix/store (read-only seed; no transfer needed)
//! 2. the worker cache (`state_dir/store`), filled from hub NAR streams
//!
//! Runs up to `--max-jobs` builds concurrently over one hub session.

pub mod binfmt;
mod cgroup;
pub mod sandbox;

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

use crate::chunkio::{ChannelReader, CHUNK_SIZE};
use crate::nar;
use crate::proto::{
    hub_message, nar_transfer, worker_hub_client::WorkerHubClient, worker_message, BuildAssignment,
    BuildResult, Heartbeat, LogChunk, MissingPaths, NarTransfer, OutputSignature, Register,
    WorkerMessage,
};

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
    /// Optional static shell bound at /bin/sh inside the Linux sandbox
    /// (like Nix's busybox sandbox path); #!/bin/sh shebangs and libc
    /// system() fail without it.
    pub sandbox_bin_sh: Option<PathBuf>,
    /// Total byte budget for the input NAR cache (`state_dir/store`);
    /// least-recently-used entries are evicted past it.
    pub cache_max_bytes: u64,
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
    sandbox_bin_sh: Option<PathBuf>,
    cache_max_bytes: u64,
    cgroup_base: Option<PathBuf>,
    build_memory_max: Option<u64>,
    /// Files a build must never read even where DAC would allow it
    /// (macOS Seatbelt deny rules; Linux relies on the mount namespace).
    secret_paths: Vec<PathBuf>,
    /// Serializes cache installs; two builds finishing the same input
    /// concurrently must not rename over each other.
    cache_lock: std::sync::Mutex<()>,
    /// Cache entries referenced by running builds (refcounted by store
    /// basename); eviction skips them.
    pinned: std::sync::Mutex<HashMap<String, u32>>,
    /// Builds currently executing, reported in heartbeats.
    running: std::sync::atomic::AtomicU32,
    /// system -> static emulator binary, from --emulate.
    emulators: HashMap<String, PathBuf>,
    /// pasta binary for fixed-output network isolation.
    pasta: Option<PathBuf>,
    /// Slot i maps the uid block [uid_base + i*65536, 65536); disjoint
    /// blocks keep concurrent uid-range builds apart.
    uid_base: u32,
    uid_slots: std::sync::Mutex<Vec<bool>>,
    /// macOS: tmpDirInSandbox=/build is one global symlink (no mount
    /// namespace); builds sharing it run one at a time.
    shared_link_lock: std::sync::Mutex<()>,
}

impl WorkerCtx {
    fn pin(&self, base: &str) {
        *self
            .pinned
            .lock()
            .unwrap()
            .entry(base.to_string())
            .or_insert(0) += 1;
    }

    fn unpin(&self, base: &str) {
        let mut pinned = self.pinned.lock().unwrap();
        if let Some(n) = pinned.get_mut(base) {
            *n -= 1;
            if *n == 0 {
                pinned.remove(base);
            }
        }
    }

    fn pinned_bases(&self) -> HashSet<String> {
        self.pinned.lock().unwrap().keys().cloned().collect()
    }

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

/// Nix's `uid-range` system feature: a full 65536-uid range with the
/// builder as in-namespace root (containers, systemd-nspawn).
fn requires_uid_range(env: &HashMap<String, String>) -> bool {
    crate::build_json::required_system_features(env)
        .iter()
        .any(|f| f == "uid-range")
}

/// System features this worker can honor, advertised to the hub for
/// scheduling. Mirrors Nix's defaults; `kvm` needs the device node and
/// `uid-range` needs root for the 65536-uid mapping.
fn local_features() -> Vec<String> {
    let mut features = vec![
        "nixos-test".to_owned(),
        "benchmark".to_owned(),
        "big-parallel".to_owned(),
    ];
    if cfg!(target_os = "linux") {
        if std::path::Path::new("/dev/kvm").exists() {
            features.push("kvm".to_owned());
        }
        if nix::unistd::geteuid().is_root() {
            features.push("uid-range".to_owned());
        }
    }
    features
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

fn load_signing_key(state_dir: &Path) -> Result<SigningKey> {
    let path = state_dir.join("signing.key");
    if path.exists() {
        let bytes: [u8; 32] = std::fs::read(&path)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing.key must be 32 bytes"))?;
        Ok(SigningKey::from_bytes(&bytes))
    } else {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        write_secret(&path, &key.to_bytes())?;
        Ok(key)
    }
}

/// Remove leftovers from interrupted runs: abandoned build dirs, stale
/// staging entries, and cache entries without a completion marker (a
/// crash mid-install may have left them truncated).
fn sweep_state_dir(state_dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(state_dir.join("builds")) {
        for entry in entries.flatten() {
            tracing::info!("removing stale build dir {}", entry.path().display());
            remove_path_all(&entry.path());
        }
    }
    if let Ok(entries) = std::fs::read_dir(state_dir.join("store")) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let stale = if name.starts_with(".tmp-") {
                true
            } else if let Some(base) = name.strip_prefix(MARKER_PREFIX) {
                // marker without its entry
                state_dir
                    .join("store")
                    .join(base)
                    .symlink_metadata()
                    .is_err()
            } else {
                // entry without its marker
                cache_marker(state_dir, &name).symlink_metadata().is_err()
            };
            if stale {
                tracing::info!("removing stale cache item {}", entry.path().display());
                remove_path_all(&entry.path());
            }
        }
    }
}

/// Completion marker of a cache entry: written (after syncing the
/// filesystem) only once the entry is fully installed, so a crash can
/// never leave a truncated tree that passes for a valid input. Content
/// is the entry's byte size; mtime doubles as the LRU clock.
const MARKER_PREFIX: &str = ".ok-";

fn cache_marker(state_dir: &Path, base: &str) -> PathBuf {
    state_dir
        .join("store")
        .join(format!("{MARKER_PREFIX}{base}"))
}

fn tree_size(path: &Path) -> u64 {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if !meta.is_dir() {
        return meta.len();
    }
    let mut total = meta.len();
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            total += tree_size(&entry.path());
        }
    }
    total
}

/// Install a fully-unpacked transfer into the cache: sync, rename,
/// marker, then evict least-recently-used entries past the byte budget
/// (skipping entries the current build uses).
fn cache_install(
    state_dir: &Path,
    partial: &Path,
    base: &str,
    max_bytes: u64,
    in_use: &HashSet<String>,
) -> Result<PathBuf> {
    use std::os::fd::AsRawFd;
    let store = state_dir.join("store");
    let cached = store.join(base);
    // A concurrent build already installed this entry (and may be using
    // it); keep theirs, drop ours.
    if cache_marker(state_dir, base).symlink_metadata().is_ok() && cached.symlink_metadata().is_ok()
    {
        remove_path_all(partial);
        return Ok(cached);
    }
    remove_path_all(&cached); // stale/truncated leftover
    let size = tree_size(partial);
    // One syncfs instead of per-file fsync: the marker below must not
    // hit disk before the data it vouches for.
    let dirfd = std::fs::File::open(&store)?;
    unsafe { libc::syncfs(dirfd.as_raw_fd()) };
    std::fs::rename(partial, &cached)?;
    let marker = cache_marker(state_dir, base);
    let mut f = std::fs::File::create(&marker)?;
    f.write_all(size.to_string().as_bytes())?;
    f.sync_all()?;

    // LRU eviction by marker mtime.
    let mut entries: Vec<(std::time::SystemTime, String, u64)> = Vec::new();
    let mut total: u64 = 0;
    if let Ok(dir) = std::fs::read_dir(&store) {
        for entry in dir.flatten() {
            let name = entry.file_name();
            let Some(entry_base) = name
                .to_string_lossy()
                .strip_prefix(MARKER_PREFIX)
                .map(String::from)
            else {
                continue;
            };
            let Ok(meta) = entry.metadata() else { continue };
            let size: u64 = std::fs::read_to_string(entry.path())
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            total += size;
            entries.push((
                meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH),
                entry_base,
                size,
            ));
        }
    }
    entries.sort();
    for (_, entry_base, size) in entries {
        if total <= max_bytes {
            break;
        }
        if entry_base == base || in_use.contains(&entry_base) {
            continue;
        }
        tracing::info!("evicting cache entry {entry_base} ({size} bytes)");
        remove_path_all(&cache_marker(state_dir, &entry_base));
        remove_path_all(&store.join(&entry_base));
        total = total.saturating_sub(size);
    }
    Ok(cached)
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

pub fn run(opts: WorkerOpts) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(opts))
}

async fn run_async(opts: WorkerOpts) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for sub in ["store", "builds"] {
        let dir = opts.state_dir.join(sub);
        std::fs::create_dir_all(&dir)?;
        // Traverse-only: dropped-uid FOD builds must reach their own
        // build tree and cached inputs, but other local users get no
        // listing; per-build dirs are chowned and locked down further.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o711))?;
    }
    sweep_state_dir(&opts.state_dir);
    let signing_key = load_signing_key(&opts.state_dir)?;
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
        sandbox_bin_sh: opts.sandbox_bin_sh.clone(),
        cache_max_bytes: opts.cache_max_bytes,
        cgroup_base: if cfg!(target_os = "linux") {
            cgroup::init()
        } else {
            None
        },
        build_memory_max: opts.build_memory_max,
        secret_paths: vec![opts.key.clone(), opts.state_dir.join("signing.key")],
        cache_lock: std::sync::Mutex::new(()),
        pinned: std::sync::Mutex::new(HashMap::new()),
        running: std::sync::atomic::AtomicU32::new(0),
        emulators,
        pasta: opts.pasta.clone(),
        uid_base: opts.auto_allocate_uids_base,
        uid_slots: std::sync::Mutex::new(vec![false; opts.max_jobs.max(1) as usize]),
        shared_link_lock: std::sync::Mutex::new(()),
    });

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

async fn session(
    opts: &WorkerOpts,
    signing_key: &SigningKey,
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
            worker_name: nix::unistd::gethostname()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "worker".into()),
            systems: opts.systems.clone(),
            features: local_features(),
            max_jobs: opts.max_jobs.max(1),
            signing_public_key: signing_key.verifying_key().to_bytes().to_vec(),
        })))
        .await?;

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
    signing_key: &SigningKey,
    ctx: &std::sync::Arc<WorkerCtx>,
    build_timeout: std::time::Duration,
) -> Result<()> {
    while let Some(m) = inbound.message().await? {
        let Some(m) = m.msg else { continue };
        match m {
            hub_message::Msg::Assignment(a) => {
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
                match build.negotiate(&offer.store_paths) {
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
                            ctx.running
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            tokio::task::spawn_blocking(move || {
                                if let Err(e) = build.execute(&out_tx, &signing_key, build_timeout)
                                {
                                    tracing::error!("build execution failed: {e:#}");
                                    let _ = out_tx.blocking_send(msg(worker_message::Msg::Result(
                                        BuildResult {
                                            build_id: build.assignment.build_id.clone(),
                                            exit_code: 1,
                                            outputs: vec![],
                                            error: format!("{e:#}"),
                                        },
                                    )));
                                }
                                build.cleanup();
                                ctx.running
                                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                            });
                        }
                    }
                }
            }
            hub_message::Msg::Cancel(_) => {
                tracing::warn!("build cancellation not implemented yet");
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

struct ActiveBuild {
    assignment: BuildAssignment,
    dir: PathBuf, // state_dir/builds/<id>
    ctx: std::sync::Arc<WorkerCtx>,
    /// Input store path -> host filesystem source.
    sources: HashMap<String, PathBuf>,
    pending: HashSet<String>,
    nar_unpackers: HashMap<String, Unpacker>,
    tmp_unpacker: Option<Unpacker>,
    /// Cache bases this build pinned against eviction; released on Drop
    /// (covers execute, abort, and every error path).
    pinned: HashSet<String>,
}

impl Drop for ActiveBuild {
    fn drop(&mut self) {
        for base in &self.pinned {
            self.ctx.unpin(base);
        }
    }
}

fn store_base(store_path: &str) -> &str {
    store_path.rsplit('/').next().unwrap_or(store_path)
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
            sources: HashMap::new(),
            pending: HashSet::new(),
            nar_unpackers: HashMap::new(),
            tmp_unpacker: None,
            pinned: HashSet::new(),
        })
    }

    /// Pin a cache entry for this build's lifetime so eviction (from
    /// any concurrent build's install) cannot pull it out from under us.
    fn pin(&mut self, base: &str) {
        if self.pinned.insert(base.to_string()) {
            self.ctx.pin(base);
        }
    }

    fn negotiate(&mut self, offered: &[String]) -> Result<Vec<String>> {
        // cloned: self.pin() below needs &mut self
        let state_dir = self.ctx.state_dir.clone();
        let mut missing = Vec::new();
        for p in offered {
            // Only real store paths may become bind-mount sources; a
            // compromised hub must not get the worker's own files
            // (signing key, TLS key) mounted into a sandbox.
            if !crate::hub::valid_store_path(crate::hub::STORE_DIR, p) {
                bail!("offered path {p:?} is not a store path");
            }
            let host = PathBuf::from(p);
            let cached = state_dir.join("store").join(store_base(p));
            let marker = cache_marker(&state_dir, store_base(p));
            // symlink_metadata: store paths that are dangling symlinks
            // are legitimate and must count as present.
            if host.symlink_metadata().is_ok() {
                self.sources.insert(p.clone(), host);
            } else if cached.symlink_metadata().is_ok() && marker.symlink_metadata().is_ok() {
                // bump the LRU clock
                if let Ok(f) = std::fs::File::options().write(true).open(&marker) {
                    let _ = f.set_modified(std::time::SystemTime::now());
                }
                self.pin(store_base(p));
                self.sources.insert(p.clone(), cached);
            } else {
                self.pending.insert(p.clone());
                missing.push(p.clone());
            }
        }
        Ok(missing)
    }

    async fn feed_nar(&mut self, n: NarTransfer) -> Result<()> {
        // cloned: self.pin() below needs &mut self
        let state_dir = self.ctx.state_dir.clone();
        if !self.pending.contains(&n.store_path) && !self.nar_unpackers.contains_key(&n.store_path)
        {
            bail!("hub sent NAR for unrequested path {}", n.store_path);
        }
        // Staging name starts with ".": disjoint from finished cache
        // entries, because valid store names never start with a dot.
        // The build id keeps concurrent transfers of the same input
        // from writing into one staging tree.
        let partial = state_dir.join("store").join(format!(
            ".tmp-{}-{}",
            self.assignment.build_id,
            store_base(&n.store_path)
        ));
        let (tx, _) = self
            .nar_unpackers
            .entry(n.store_path.clone())
            .or_insert_with(|| {
                let dest = partial.clone();
                let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
                let task = tokio::task::spawn_blocking(move || -> Result<()> {
                    // stale leftover from a crashed transfer; lstat so a
                    // dangling symlink is removed rather than skipped
                    remove_path_all(&dest);
                    let dec = zstd::stream::read::Decoder::new(ChannelReader::new(rx))?;
                    let mut dec = LimitedReader {
                        inner: dec,
                        remaining: MAX_NAR_BYTES,
                    };
                    nar::unpack(&mut dec, &dest)
                        .with_context(|| format!("unpacking {}", dest.display()))
                });
                (tx, task)
            });
        if let Some(nar_transfer::Payload::ZstdNarChunk(chunk)) = n.payload {
            tx.send(chunk)
                .await
                .map_err(|_| anyhow::anyhow!("input unpacker died"))?;
        }
        if n.eof {
            let (tx, task) = self.nar_unpackers.remove(&n.store_path).unwrap();
            drop(tx);
            task.await??;
            let base = store_base(&n.store_path).to_string();
            // pin before install: no window where the entry is evictable
            self.pin(&base);
            let cached = {
                let _guard = self.ctx.cache_lock.lock().unwrap();
                cache_install(
                    &state_dir,
                    &partial,
                    &base,
                    self.ctx.cache_max_bytes,
                    &self.ctx.pinned_bases(),
                )?
            };
            self.pending.remove(&n.store_path);
            self.sources.insert(n.store_path, cached);
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
            if !self.pending.is_empty() {
                bail!("tmp dir transfer finished before all input paths arrived");
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Runs on a blocking thread: sandboxed build, live log streaming,
    /// output packing/signing/upload.
    fn execute(
        &self,
        out_tx: &mpsc::Sender<WorkerMessage>,
        signing_key: &SigningKey,
        timeout: std::time::Duration,
    ) -> Result<()> {
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
        // The slot lease keeps concurrent uid ranges disjoint; returned
        // on drop when the build finishes.
        let uid_slot = if requires_uid_range(&a.env) {
            if !nix::unistd::geteuid().is_root() {
                bail!("build requires the uid-range feature, but the worker does not run as root");
            }
            if !cfg!(target_os = "linux") {
                bail!("the uid-range feature is only supported on Linux workers");
            }
            Some(
                self.ctx
                    .alloc_uid_slot()
                    .context("no free uid range slot")?,
            )
        } else {
            None
        };
        // Root workers back fixed-output builds with an unprivileged
        // slot uid (pasta is rootless-only; see SandboxSpec::fod_uid).
        let fod_slot = if a.fixed_output
            && self.ctx.pasta.is_some()
            && uid_slot.is_none()
            && cfg!(target_os = "linux")
            && nix::unistd::geteuid().is_root()
        {
            Some(self.ctx.alloc_uid_slot().context("no free uid slot")?)
        } else {
            None
        };
        let mut spec = sandbox::prepare(
            a,
            &self.dir,
            &self.sources,
            &sandbox::PrepareOpts {
                bin_sh: self.ctx.sandbox_bin_sh.as_deref(),
                secrets: &self.ctx.secret_paths,
                uid_range: uid_slot.as_ref().map(|s| s.base),
                emulator: self.ctx.emulators.get(&a.system).map(PathBuf::as_path),
                pasta: self.ctx.pasta.as_deref(),
                fod_uid: fod_slot.as_ref().map(|s| s.base),
            },
        )?;
        spec.cgroup = self
            .ctx
            .cgroup_base
            .as_deref()
            .and_then(|base| cgroup::create(base, &a.build_id, self.ctx.build_memory_max));
        if let (Some(slot), Some(cg)) = (&uid_slot, &spec.cgroup) {
            // the build manages its own delegated cgroup (Nix's
            // `cgroups` setting); needed by nspawn inside the sandbox
            cgroup::chown_to_builder(cg, slot.base);
        }
        let deadline = std::time::Instant::now() + timeout;
        let mut child = sandbox::spawn(&spec)?;

        let mut log_threads = Vec::new();
        for pipe in [
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let tx = out_tx.clone();
            let build_id = a.build_id.clone();
            log_threads.push(std::thread::spawn(move || {
                let mut pipe = pipe;
                let mut buf = [0u8; 8192];
                loop {
                    match pipe.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx
                                .blocking_send(msg(worker_message::Msg::Log(LogChunk {
                                    build_id: build_id.clone(),
                                    data: buf[..n].to_vec(),
                                })))
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
            }));
        }
        let pgrp = nix::unistd::Pid::from_raw(child.id() as i32);
        let mut timed_out = false;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                timed_out = true;
                let _ = nix::sys::signal::killpg(pgrp, nix::sys::signal::Signal::SIGKILL);
                break child.wait()?;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        };
        // The builder is PID 1 of its PID namespace, so its death took
        // every descendant with it; the killpg also covers the brief
        // pre-exec window and macOS, where there is no PID namespace.
        let _ = nix::sys::signal::killpg(pgrp, nix::sys::signal::Signal::SIGKILL);
        for t in log_threads {
            let _ = t.join();
        }
        if timed_out {
            bail!("build timed out after {}s", timeout.as_secs());
        }
        // Signal deaths become 128 + signo (matching shell conventions),
        // so an OOM SIGKILL (137) is distinguishable from a SIGSEGV (139).
        let exit_code = status.code().unwrap_or_else(|| {
            use std::os::unix::process::ExitStatusExt;
            128 + status.signal().unwrap_or(0)
        });
        tracing::info!(id = a.build_id, exit_code, "builder finished");

        if exit_code != 0 {
            out_tx.blocking_send(msg(worker_message::Msg::Result(BuildResult {
                build_id: a.build_id.clone(),
                exit_code,
                outputs: vec![],
                error: String::new(),
            })))?;
            return Ok(());
        }

        // Pack, hash and sign every output before announcing the result,
        // because signatures travel in BuildResult ahead of the NAR data.
        let mut packed = Vec::new();
        for scratch in a.outputs.values() {
            let host_path = sandbox::output_host_path(&spec, scratch);
            // lstat: a symlink output whose target only resolves inside
            // the sandbox is still a valid output.
            if host_path.symlink_metadata().is_err() {
                bail!("builder did not produce output {scratch}");
            }
            let nar_file = self.dir.join(format!("{}.nar.zst", store_base(scratch)));
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
            packed.push((
                scratch.clone(),
                nar_file,
                hash.to_vec(),
                sig.to_bytes().to_vec(),
            ));
        }

        out_tx.blocking_send(msg(worker_message::Msg::Result(BuildResult {
            build_id: a.build_id.clone(),
            exit_code: 0,
            outputs: packed
                .iter()
                .map(|(path, _, hash, sig)| OutputSignature {
                    store_path: path.clone(),
                    nar_sha256: hash.clone(),
                    signature: sig.clone(),
                })
                .collect(),
            error: String::new(),
        })))?;

        for (path, nar_file, _, _) in &packed {
            let mut f = std::fs::File::open(nar_file)?;
            let mut buf = vec![0u8; CHUNK_SIZE];
            loop {
                if std::time::Instant::now() >= deadline {
                    bail!("build timed out during output upload");
                }
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                out_tx.blocking_send(msg(worker_message::Msg::Nar(NarTransfer {
                    build_id: a.build_id.clone(),
                    store_path: path.clone(),
                    payload: Some(nar_transfer::Payload::ZstdNarChunk(buf[..n].to_vec())),
                    eof: false,
                })))?;
            }
            out_tx.blocking_send(msg(worker_message::Msg::Nar(NarTransfer {
                build_id: a.build_id.clone(),
                store_path: path.clone(),
                payload: None,
                eof: true,
            })))?;
        }
        Ok(())
    }

    fn cleanup(&self) {
        if let Some(base) = self.ctx.cgroup_base.as_deref() {
            // cgroup.kill reaches setsid'd survivors that escaped killpg.
            cgroup::kill_and_remove(base, &self.assignment.build_id);
        }
        sandbox::cleanup(&self.assignment, &self.dir);
        if let Err(e) = std::fs::remove_dir_all(&self.dir) {
            tracing::warn!("cleaning up {}: {e}", self.dir.display());
        }
    }

    /// Tear down a build abandoned before execution: stop the unpacker
    /// tasks (so none keeps writing into shared staging paths) and
    /// remove everything staged on disk.
    async fn abort(mut self) {
        for (_, (tx, task)) in self.nar_unpackers.drain() {
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

/// Enforces a byte budget on a Read chain (input NAR transfers).
struct LimitedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::other(format!(
                "input NAR exceeds the {MAX_NAR_BYTES} byte limit"
            )));
        }
        let max = buf.len().min(self.remaining as usize);
        let n = self.inner.read(&mut buf[..max])?;
        self.remaining -= n as u64;
        Ok(n)
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
            system: "x86_64-linux".into(),
            builder: "/nix/store/abc-bash/bin/bash".into(),
            args: vec![],
            env: Default::default(),
            outputs: [("out".to_string(), "/nix/store/abc-out".to_string())].into(),
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
    fn cache_install_marks_and_evicts() -> Result<()> {
        let state = tempfile::tempdir()?;
        std::fs::create_dir_all(state.path().join("store"))?;
        let mk = |name: &str, bytes: usize| -> Result<PathBuf> {
            let p = state.path().join("store").join(format!(".tmp-{name}"));
            std::fs::create_dir(&p)?;
            std::fs::write(p.join("data"), vec![0u8; bytes])?;
            Ok(p)
        };
        let empty = HashSet::new();

        // install two entries under a generous budget: both survive
        let p = mk("aaa-one", 1000)?;
        cache_install(state.path(), &p, "aaa-one", 1 << 20, &empty)?;
        std::thread::sleep(std::time::Duration::from_millis(20)); // distinct mtimes
        let p = mk("bbb-two", 1000)?;
        cache_install(state.path(), &p, "bbb-two", 1 << 20, &empty)?;
        assert!(cache_marker(state.path(), "aaa-one").exists());
        assert!(cache_marker(state.path(), "bbb-two").exists());

        // a third install under a tight budget evicts the oldest entry;
        // entry sizes are fs-dependent, so derive the budget from a marker
        let entry_size: u64 = std::fs::read_to_string(cache_marker(state.path(), "aaa-one"))?
            .parse()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let p = mk("ccc-three", 1000)?;
        cache_install(state.path(), &p, "ccc-three", entry_size * 5 / 2, &empty)?;
        assert!(
            !state.path().join("store/aaa-one").exists(),
            "oldest evicted"
        );
        assert!(!cache_marker(state.path(), "aaa-one").exists());
        // the just-installed entry is never evicted
        assert!(state.path().join("store/ccc-three").exists());

        // in-use entries are skipped by eviction
        let in_use: HashSet<String> = ["bbb-two".to_string()].into();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let p = mk("ddd-four", 1000)?;
        cache_install(state.path(), &p, "ddd-four", 1, &in_use)?;
        assert!(state.path().join("store/bbb-two").exists(), "in-use kept");
        Ok(())
    }

    #[test]
    fn sweep_removes_unmarked_cache_entries() -> Result<()> {
        let state = tempfile::tempdir()?;
        std::fs::create_dir_all(state.path().join("store"))?;
        std::fs::create_dir_all(state.path().join("builds"))?;
        // entry without marker: possibly truncated, must go
        std::fs::create_dir(state.path().join("store/xxx-unmarked"))?;
        // orphan marker without entry: must go
        std::fs::write(state.path().join("store/.ok-yyy-gone"), "1")?;
        // complete pair: stays
        std::fs::create_dir(state.path().join("store/zzz-good"))?;
        std::fs::write(state.path().join("store/.ok-zzz-good"), "1")?;
        sweep_state_dir(state.path());
        assert!(!state.path().join("store/xxx-unmarked").exists());
        assert!(!state.path().join("store/.ok-yyy-gone").exists());
        assert!(state.path().join("store/zzz-good").exists());
        assert!(state.path().join("store/.ok-zzz-good").exists());
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
