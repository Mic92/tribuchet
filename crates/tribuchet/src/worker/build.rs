//! One build on this worker: input staging, sandbox execution, output packing.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use anyhow::{bail, Context, Result};
use harmonia_store_path::{StoreDir, StorePath};
use harmonia_store_path_info::ValidPathInfo;
use harmonia_store_remote::{DaemonClient, DaemonStore};
use harmonia_utils_signature::SecretKey;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use super::caps::requires_uid_range;
use super::logtail::tail_log;
use super::resume::{FinishedBuild, PackedOutput, ResumeState};
use super::{cgroup, reaper, sandbox, unix_now, DaemonConn, WorkerCtx};
use crate::chunkio::ChannelReader;
use crate::nar;
use crate::proto::{nar_transfer, BuildAssignment, NarTransfer, PathInfoMsg, WorkerMessage};
use crate::store::{parse_path_info, valid_store_path, STORE_DIR};

impl WorkerCtx {
    fn alloc_uid_slot(self: &std::sync::Arc<Self>) -> Option<UidSlot> {
        let mut slots = self.uid_slots.lock().unwrap();
        let idx = slots.iter().position(|used| !used)?;
        slots[idx] = true;
        Some(UidSlot {
            ctx: self.clone(),
            base: self.uid_base + u32::try_from(idx).expect("slot index fits u32") * 65536,
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

    pub(super) fn uid_range(&self) -> Option<u32> {
        match self {
            Self::UidRange(slot) => Some(slot.base),
            _ => None,
        }
    }

    pub(super) fn fod_uid(&self) -> Option<u32> {
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

/// Cap on a single NAR transfer in either direction; a `truncate -s 1P
/// $out` build would otherwise tie up the worker and fill its disk.
const MAX_NAR_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// The worker must not trust the hub for filesystem-relevant strings:
/// build ids become path components, output paths are packed (and on
/// macOS deleted) on the host.
pub(super) fn validate_assignment(a: &BuildAssignment) -> Result<()> {
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
        if !valid_store_path(STORE_DIR, p) {
            bail!("invalid output path {p:?}");
        }
        // Scratch outputs handed out by Nix never exist yet. An output
        // naming an existing store path would give the build write
        // access to it (macOS builds write outputs in place) and have
        // the post-build cleanup delete it.
        if std::fs::symlink_metadata(p).is_ok() {
            bail!("output path {p} already exists on this worker");
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

pub(super) struct ActiveBuild {
    pub(super) assignment: BuildAssignment,
    pub(super) dir: PathBuf, // state_dir/builds/<id>
    pub(super) ctx: std::sync::Arc<WorkerCtx>,
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
    pub(super) fn new(assignment: BuildAssignment, ctx: std::sync::Arc<WorkerCtx>) -> Result<Self> {
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

    pub(super) async fn negotiate(&mut self, offered: &[String]) -> Result<Vec<String>> {
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

    pub(super) fn feed_path_info(&mut self, pi: &PathInfoMsg) -> Result<()> {
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
            Some(parse_path_info(pi).with_context(|| format!("path info for {}", pi.store_path))?);
        Ok(())
    }

    pub(super) async fn feed_nar(&mut self, n: NarTransfer) -> Result<()> {
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
    pub(super) async fn feed_tmp_dir(&mut self, t: crate::proto::TmpDirArchive) -> Result<bool> {
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

    fn build_spec(&self, owner: &BuildOwner) -> Result<sandbox::SandboxSpec> {
        let a = &self.assignment;
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
                recursive_nix: self.ctx.recursive_nix,
                nix_daemon_socket: None,
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
        Ok(spec)
    }

    /// Runs on a blocking thread: sandboxed build, live log streaming,
    /// output packing and signing. Sends only logs; the result and
    /// output NARs go through deliver(), which can run again on a
    /// later session if this one dies first.
    pub(super) fn execute(
        &self,
        out_tx: &mpsc::Sender<WorkerMessage>,
        signing_key: &SecretKey,
        timeout: std::time::Duration,
    ) -> Result<FinishedBuild> {
        let a = &self.assignment;
        // The slot lease keeps concurrent uids disjoint; returned on
        // drop when the build finishes.
        let owner = BuildOwner::for_build(&self.ctx, a)?;
        let spec = self.build_spec(&owner)?;
        let deadline = std::time::Instant::now() + timeout;
        // Logs go through a file in the build dir, not pipes: capture
        // is decoupled from this process's lifetime, so a later worker
        // generation can resume tailing where we stopped.
        let log_path = self.dir.join("build.log");
        let log_file = std::fs::File::create(&log_path)?;
        let (mut req, child_stdin, spec_w) = sandbox::spawn_request(&spec)?;
        let pid = self
            .ctx
            .spawner
            .spawn(&mut req, &log_file, child_stdin.as_ref())?;
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
            status_token: req.token.clone(),
            spec: spec.clone(),
            outputs: a.outputs.clone(),
            deadline_unix: unix_now() + timeout.as_secs(),
            uid_slot: owner.slot_idx(),
        };
        std::fs::write(self.dir.join("resume.json"), serde_json::to_vec(&resume)?)?;

        let log_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let tailer = {
            let tx = out_tx.clone();
            let build_id = a.build_id.clone();
            let log_done = log_done.clone();
            let dir = self.dir.clone();
            std::thread::spawn(move || {
                tail_log(&dir, &build_id, &tx, || log_done.load(Ordering::Relaxed));
            })
        };
        let pgrp = nix::unistd::Pid::from_raw(pid);
        let mut abort: Option<String> = None;
        let status = loop {
            if let Some(code) = reaper::take_status(&self.ctx.status_dir, &req.token) {
                break code;
            }
            let timed_out = (std::time::Instant::now() >= deadline)
                .then(|| format!("build timed out after {}s", timeout.as_secs()));
            abort = self.ctx.abort_reason(&a.dedupe_key, &log_path, timed_out);
            if abort.is_some() {
                let _ = nix::sys::signal::killpg(pgrp, nix::sys::signal::Signal::SIGKILL);
                // The reaper collects the kill within its sweep interval.
                break loop {
                    if let Some(code) = reaper::take_status(&self.ctx.status_dir, &req.token) {
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

        let extra_candidates = if spec.recursive_nix {
            // The builder may have added paths via the daemon socket
            // bind-mount; without widening the candidate set the
            // ref-scan would miss them.
            tokio::runtime::Handle::current()
                .block_on(query_all_valid_paths())
                .unwrap_or_else(|e| {
                    tracing::warn!(id = a.build_id, "queryAllValidPaths failed: {e:#}");
                    std::collections::BTreeSet::new()
                })
        } else {
            std::collections::BTreeSet::new()
        };
        let packed = pack_outputs(&self.dir, &spec, &extra_candidates, deadline, signing_key)?;
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
    pub(super) fn teardown(&self) {
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
    pub(super) async fn abort(mut self) {
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

/// Snapshot of every valid store path on the worker, used to widen
/// the ref-scan candidate set when recursive-nix is on.
async fn query_all_valid_paths(
) -> Result<std::collections::BTreeSet<harmonia_store_path::StorePath>> {
    let mut daemon = DaemonClient::builder()
        .connect_daemon()
        .await
        .context("connecting to the local nix-daemon")?;
    let set = daemon
        .query_all_valid_paths()
        .await
        .context("queryAllValidPaths")?;
    Ok(set.into_iter().collect())
}

/// Pack, hash and sign every output before announcing the result,
/// because signatures travel in BuildResult ahead of the NAR data.
pub(super) fn pack_outputs(
    dir: &Path,
    spec: &sandbox::SandboxSpec,
    extra_candidates: &std::collections::BTreeSet<harmonia_store_path::StorePath>,
    deadline: std::time::Instant,
    signing_key: &SecretKey,
) -> Result<Vec<PackedOutput>> {
    let mut candidates = scan_candidates(&spec.store_inputs, &spec.outputs);
    candidates.extend(extra_candidates.iter().cloned());
    let mut packed = Vec::new();
    for scratch in &spec.outputs {
        let host_path = sandbox::output_host_path(spec, scratch);
        // lstat: a symlink output whose target only resolves inside
        // the sandbox is still a valid output.
        if host_path.symlink_metadata().is_err() {
            bail!("builder did not produce output {scratch}");
        }
        let nar_file = dir.join(format!("{}.nar.zst", store_base(scratch)));
        let self_path = harmonia_store_path::StorePath::from_base_path(store_base(scratch)).ok();
        let res = pack_one_nar(
            &host_path,
            &nar_file,
            &candidates,
            self_path.as_ref(),
            deadline,
        )
        .with_context(|| format!("packing output {scratch}"))?;
        let sig =
            signing_key.sign(format!("{scratch}:{}", hex::encode(&res.nar_sha256)).as_bytes());
        packed.push(PackedOutput {
            scratch: scratch.clone(),
            nar_file,
            nar_sha256: res.nar_sha256,
            signature: sig.to_string(),
            references: res.references,
        });
    }
    Ok(packed)
}

struct NarPackResult {
    nar_sha256: Vec<u8>,
    references: Vec<String>,
}

/// Pack `host_path` as a zstd-compressed NAR into `nar_path`, hashing
/// and reference-scanning the plaintext NAR in the same pass.
fn pack_one_nar(
    host_path: &Path,
    nar_path: &Path,
    candidates: &std::collections::BTreeSet<harmonia_store_path::StorePath>,
    self_path: Option<&harmonia_store_path::StorePath>,
    deadline: std::time::Instant,
) -> Result<NarPackResult> {
    let mut hasher = Sha256::new();
    let mut sink = harmonia_store_ref_scan::RefScanSink::new(candidates, self_path);
    {
        let f = std::fs::File::create(nar_path)?;
        let mut enc = zstd::stream::write::Encoder::new(f, 3)?;
        let mut tee = TeeScanner {
            zstd: &mut enc,
            hasher: &mut hasher,
            scan: &mut sink,
        };
        // Deadline bounds packing too: a builder can exit instantly
        // leaving a multi-TB sparse output.
        let mut limited = LimitedWriter {
            inner: &mut tee,
            remaining: MAX_NAR_BYTES,
            deadline,
        };
        nar::pack(host_path, &mut limited)?;
        enc.finish()?.flush()?;
    }
    let store_dir = harmonia_store_path::StoreDir::default();
    let references = sink
        .found_paths()
        .into_iter()
        .filter(|p| self_path != Some(p))
        .map(|p| {
            p.to_absolute_path(&store_dir)
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    Ok(NarPackResult {
        nar_sha256: hasher.finalize().to_vec(),
        references,
    })
}

fn scan_candidates(
    inputs: &[String],
    outputs: &[String],
) -> std::collections::BTreeSet<harmonia_store_path::StorePath> {
    inputs
        .iter()
        .chain(outputs.iter())
        .filter_map(|p| harmonia_store_path::StorePath::from_base_path(store_base(p)).ok())
        .collect()
}

/// Unpack the client-supplied tmp-dir tar, refusing anything but plain
/// files, directories, and symlinks, and applying only the 0777 mode
/// bits: a root worker must not materialize client-chosen setuid bits.
///
/// Every path is created relative to the destination directory's fd via
/// openat with O_NOFOLLOW, so no entry name -- absolute, dot-dotted, or
/// aimed at a symlink planted by an earlier entry -- can place or chmod
/// anything outside the destination.
fn unpack_tmp_dir_archive(reader: impl Read, dest: &Path) -> Result<()> {
    use nix::fcntl::OFlag;
    use std::os::fd::{AsFd, OwnedFd};
    use std::path::Component;

    fn open_dir_at(at: &impl AsFd, name: &std::ffi::OsStr) -> Result<OwnedFd> {
        Ok(nix::fcntl::openat(
            at.as_fd(),
            name,
            OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_RDONLY | OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )?)
    }

    fn mkdir_at(at: &impl AsFd, name: &std::ffi::OsStr, mode: nix::sys::stat::Mode) -> Result<()> {
        match nix::sys::stat::mkdirat(at.as_fd(), name, mode) {
            Ok(()) | Err(nix::errno::Errno::EEXIST) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    let dest = std::fs::File::open(dest).context("opening tmp dir destination")?;
    let mut tar = tar::Archive::new(reader);
    for entry in tar.entries()? {
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        match kind {
            tar::EntryType::Regular | tar::EntryType::Directory | tar::EntryType::Symlink => {}
            other => bail!("unsupported tar entry type {other:?} in tmp dir archive"),
        }
        // Mirror unpack_in's name handling: drop root/cur-dir
        // components (absolute names land under dest), refuse `..`.
        let path = entry.path()?.into_owned();
        let mut comps = Vec::new();
        for c in path.components() {
            match c {
                Component::Normal(p) => comps.push(p.to_owned()),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
                Component::ParentDir => {
                    bail!("tar entry escapes the tmp dir: {}", path.display())
                }
            }
        }
        let Some(leaf) = comps.pop() else { continue };
        // Descend to the parent, creating intermediate directories.
        let mut parent: OwnedFd = dest.as_fd().try_clone_to_owned()?;
        for c in &comps {
            mkdir_at(&parent, c.as_os_str(), nix::sys::stat::Mode::S_IRWXU)?;
            parent = open_dir_at(&parent, c)?;
        }
        let mode = nix::sys::stat::Mode::from_bits_truncate(entry.header().mode()? & 0o777);
        match kind {
            tar::EntryType::Directory => {
                mkdir_at(&parent, leaf.as_os_str(), mode)?;
                let dir = open_dir_at(&parent, &leaf)?;
                nix::sys::stat::fchmod(dir.as_fd(), mode)?;
            }
            tar::EntryType::Symlink => {
                let target = entry
                    .link_name()?
                    .ok_or_else(|| anyhow::anyhow!("symlink entry without target"))?
                    .into_owned();
                nix::unistd::symlinkat(target.as_os_str(), parent.as_fd(), leaf.as_os_str())?;
            }
            _ => {
                let file: std::fs::File = nix::fcntl::openat(
                    parent.as_fd(),
                    leaf.as_os_str(),
                    OFlag::O_WRONLY
                        | OFlag::O_CREAT
                        | OFlag::O_TRUNC
                        | OFlag::O_NOFOLLOW
                        | OFlag::O_CLOEXEC,
                    mode,
                )?
                .into();
                std::io::copy(&mut entry, &mut &file)?;
                // the umask at create time may have masked bits off
                nix::sys::stat::fchmod(file.as_fd(), mode)?;
            }
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

/// One-pass tee of plaintext NAR bytes into zstd, sha256, and the
/// reference scanner.
struct TeeScanner<'a, W: Write> {
    zstd: &'a mut W,
    hasher: &'a mut Sha256,
    scan: &'a mut harmonia_store_ref_scan::RefScanSink,
}

impl<W: Write> Write for TeeScanner<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.zstd.write_all(buf)?;
        self.hasher.update(buf);
        self.scan.feed(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.zstd.flush()
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
            env: HashMap::default(),
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

        // an existing, registered store path must not be claimable as
        // an output (in-place tampering, deletion by cleanup)
        if let Some(existing) = std::fs::read_dir("/nix/store")
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path().to_string_lossy().into_owned())
            .find(|p| valid_store_path(STORE_DIR, p))
        {
            let mut a = base_assignment();
            a.outputs.insert("doc".into(), existing);
            assert!(validate_assignment(&a).is_err());
        }

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

    /// A symlink planted by an earlier entry must not redirect later
    /// entries outside the destination: descent uses O_NOFOLLOW.
    #[test]
    fn tmp_dir_archive_does_not_follow_planted_symlinks() -> Result<()> {
        let outside = tempfile::tempdir()?;
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path("exit")?;
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name(outside.path())?;
        header.set_size(0);
        header.set_cksum();
        builder.append(&header, &b""[..])?;
        let mut header = tar::Header::new_gnu();
        header.set_path("exit/pwn")?;
        header.set_size(1);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, &b"x"[..])?;
        let data = builder.into_inner()?;
        let dest = tempfile::tempdir()?;
        assert!(unpack_tmp_dir_archive(data.as_slice(), dest.path()).is_err());
        assert!(!outside.path().join("pwn").exists());
        Ok(())
    }

    /// pack_one_nar finds references in the same pass as the NAR
    /// hash; self-paths are dropped.
    #[test]
    fn pack_one_nar_finds_references_and_excludes_self() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let host = dir.path().join("out");
        std::fs::create_dir(&host)?;
        let input = "/nix/store/00000000000000000000000000000001-input";
        let self_path = "/nix/store/00000000000000000000000000000002-self";
        let unrelated = "/nix/store/00000000000000000000000000000003-unrelated";
        std::fs::write(host.join("data"), format!("refs: {input} {self_path}\n"))?;
        let candidates = scan_candidates(&[input.into(), unrelated.into()], &[self_path.into()]);
        let self_sp = harmonia_store_path::StorePath::from_base_path(store_base(self_path)).ok();
        let res = pack_one_nar(
            &host,
            &dir.path().join("out.nar.zst"),
            &candidates,
            self_sp.as_ref(),
            std::time::Instant::now() + std::time::Duration::from_secs(30),
        )?;
        assert_eq!(res.references, vec![input.to_string()]);
        assert_eq!(res.nar_sha256.len(), 32);
        Ok(())
    }

    /// An absolute entry name unpacks under dest (unpack_in skips the
    /// root component); the chmod must follow it there instead of
    /// touching the literal host path.
    #[test]
    fn tmp_dir_archive_chmod_stays_inside_dest() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let outside = tempfile::tempdir()?;
        let victim = outside.path().join("victim");
        std::fs::write(&victim, "x")?;
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644))?;
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        // set_path refuses absolute names, so write the name bytes the
        // way a hostile archive would carry them
        let name = victim.to_str().unwrap().as_bytes();
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        header.set_size(1);
        header.set_mode(0o600);
        header.set_cksum();
        builder.append(&header, &b"y"[..])?;
        let data = builder.into_inner()?;
        let dest = tempfile::tempdir()?;
        unpack_tmp_dir_archive(data.as_slice(), dest.path())?;
        let mode = std::fs::metadata(&victim)?.permissions().mode();
        assert_eq!(mode & 0o777, 0o644, "outside file was chmodded: {mode:o}");
        let unpacked = dest
            .path()
            .join(victim.strip_prefix("/").unwrap_or(&victim));
        assert_eq!(
            std::fs::metadata(&unpacked)?.permissions().mode() & 0o777,
            0o600
        );
        Ok(())
    }
}
