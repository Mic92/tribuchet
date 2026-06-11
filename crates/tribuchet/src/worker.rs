//! `tribuchet worker`: dials the hub over mTLS, caches input paths,
//! executes builds in a local sandbox, signs and returns output NARs.
//!
//! Input sources, in order of preference:
//! 1. the host's own /nix/store (read-only seed; no transfer needed)
//! 2. the worker cache (`state_dir/store`), filled from hub NAR streams
//!
//! One build at a time (max_jobs = 1) for the MVP.

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

/// Remove leftovers from interrupted runs: abandoned build dirs and
/// stale staging entries in the input cache.
fn sweep_state_dir(state_dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(state_dir.join("builds")) {
        for entry in entries.flatten() {
            tracing::info!("removing stale build dir {}", entry.path().display());
            remove_path_all(&entry.path());
        }
    }
    if let Ok(entries) = std::fs::read_dir(state_dir.join("store")) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(".tmp-") {
                tracing::info!("removing stale partial transfer {}", entry.path().display());
                remove_path_all(&entry.path());
            }
        }
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

pub fn run(opts: WorkerOpts) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(opts))
}

async fn run_async(opts: WorkerOpts) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for sub in ["store", "builds"] {
        let dir = opts.state_dir.join(sub);
        std::fs::create_dir_all(&dir)?;
        // Shipped tmp dirs and staged NARs are not for other local users.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    sweep_state_dir(&opts.state_dir);
    let signing_key = load_signing_key(&opts.state_dir)?;

    // Reconnect with backoff: a hub restart must not drain the fleet.
    let mut backoff = std::time::Duration::from_secs(1);
    loop {
        let started = std::time::Instant::now();
        match session(&opts, &signing_key).await {
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

async fn session(opts: &WorkerOpts, signing_key: &SigningKey) -> Result<()> {
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
            features: vec![],
            max_jobs: 1,
            signing_public_key: signing_key.verifying_key().to_bytes().to_vec(),
        })))
        .await?;

    let heartbeat_tx = out_tx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            if heartbeat_tx
                .send(msg(worker_message::Msg::Heartbeat(Heartbeat {
                    running_jobs: 0,
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

    let mut active: Option<ActiveBuild> = None;
    while let Some(m) = inbound.message().await? {
        let Some(m) = m.msg else { continue };
        match m {
            hub_message::Msg::Assignment(a) => {
                tracing::info!(id = a.build_id, "build assigned");
                // The hub never re-dispatches an abandoned build; tear
                // down anything still staged for the previous one.
                if let Some(old) = active.take() {
                    tracing::warn!(id = old.assignment.build_id, "discarding abandoned build");
                    old.abort().await;
                }
                let build_id = a.build_id.clone();
                match validate_assignment(&a).and_then(|()| {
                    ActiveBuild::new(a, &opts.state_dir, opts.sandbox_bin_sh.clone())
                }) {
                    Ok(b) => active = Some(b),
                    Err(e) => fail_build(&out_tx, &build_id, &e).await?,
                }
            }
            hub_message::Msg::PathOffer(offer) => {
                let Some(build) = active.as_mut() else {
                    continue;
                };
                match build.negotiate(&offer.store_paths, &opts.state_dir) {
                    Ok(missing) => {
                        out_tx
                            .send(msg(worker_message::Msg::MissingPaths(MissingPaths {
                                build_id: offer.build_id,
                                store_paths: missing,
                            })))
                            .await?;
                    }
                    Err(e) => {
                        let build = active.take().unwrap();
                        let id = build.assignment.build_id.clone();
                        build.abort().await;
                        fail_build(&out_tx, &id, &e).await?;
                    }
                }
            }
            hub_message::Msg::Nar(n) => {
                if let Some(build) = active.as_mut() {
                    // A bad transfer fails this build, not the session.
                    if let Err(e) = build.feed_nar(n, &opts.state_dir).await {
                        let build = active.take().unwrap();
                        let id = build.assignment.build_id.clone();
                        build.abort().await;
                        fail_build(&out_tx, &id, &e).await?;
                    }
                }
            }
            hub_message::Msg::TmpDir(t) => {
                if let Some(build) = active.as_mut() {
                    match build.feed_tmp_dir(t).await {
                        Err(e) => {
                            let build = active.take().unwrap();
                            let id = build.assignment.build_id.clone();
                            build.abort().await;
                            fail_build(&out_tx, &id, &e).await?;
                        }
                        Ok(false) => {}
                        Ok(true) => {
                            let build = active.take().unwrap();
                            let out_tx = out_tx.clone();
                            let signing_key = signing_key.clone();
                            let timeout = opts.build_timeout;
                            tokio::task::spawn_blocking(move || {
                                if let Err(e) = build.execute(&out_tx, &signing_key, timeout) {
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
    sandbox_bin_sh: Option<PathBuf>,
    /// Input store path -> host filesystem source.
    sources: HashMap<String, PathBuf>,
    pending: HashSet<String>,
    nar_unpackers: HashMap<String, Unpacker>,
    tmp_unpacker: Option<Unpacker>,
}

fn store_base(store_path: &str) -> &str {
    store_path.rsplit('/').next().unwrap_or(store_path)
}

impl ActiveBuild {
    fn new(
        assignment: BuildAssignment,
        state_dir: &Path,
        sandbox_bin_sh: Option<PathBuf>,
    ) -> Result<Self> {
        let dir = state_dir.join("builds").join(&assignment.build_id);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        std::fs::create_dir_all(dir.join("top"))?;
        Ok(Self {
            assignment,
            dir,
            sandbox_bin_sh,
            sources: HashMap::new(),
            pending: HashSet::new(),
            nar_unpackers: HashMap::new(),
            tmp_unpacker: None,
        })
    }

    fn negotiate(&mut self, offered: &[String], state_dir: &Path) -> Result<Vec<String>> {
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
            // symlink_metadata: store paths that are dangling symlinks
            // are legitimate and must count as present.
            if host.symlink_metadata().is_ok() {
                self.sources.insert(p.clone(), host);
            } else if cached.symlink_metadata().is_ok() {
                self.sources.insert(p.clone(), cached);
            } else {
                self.pending.insert(p.clone());
                missing.push(p.clone());
            }
        }
        Ok(missing)
    }

    async fn feed_nar(&mut self, n: NarTransfer, state_dir: &Path) -> Result<()> {
        if !self.pending.contains(&n.store_path) && !self.nar_unpackers.contains_key(&n.store_path)
        {
            bail!("hub sent NAR for unrequested path {}", n.store_path);
        }
        // Staging name starts with ".": disjoint from finished cache
        // entries, because valid store names never start with a dot.
        let partial = state_dir
            .join("store")
            .join(format!(".tmp-{}", store_base(&n.store_path)));
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
            let cached = state_dir.join("store").join(store_base(&n.store_path));
            remove_path_all(&cached); // stale/truncated leftover
            std::fs::rename(&partial, &cached)?;
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
        let spec = sandbox::prepare(a, &self.dir, &self.sources, self.sandbox_bin_sh.as_deref())?;
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
