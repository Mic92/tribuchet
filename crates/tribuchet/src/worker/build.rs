//! One build on this worker: input staging, sandbox execution, output packing.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{self, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use harmonia_store_path::{StoreDir, StorePath, StorePathSet};
use harmonia_store_path_info::{UnkeyedValidPathInfo, ValidPathInfo};
use harmonia_store_remote::{DaemonClient, DaemonStore};
use harmonia_utils_signature::SecretKey;
#[cfg(target_os = "linux")]
use nix::sys::signal;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use super::caps::requires_uid_range;
use super::logtail::tail_log;
use super::resume::{FinishedBuild, PackedExtra, PackedOutput, ResumeState};
use super::{DaemonConn, WorkerCtx, sandbox, unix_now};
use crate::chunkio::ChannelReader;
use crate::nar;
use crate::proto::{BuildAssignment, NarTransfer, PathInfoMsg, WorkerMessage, nar_transfer};
use crate::store::{STORE_DIR, parse_path_info, topo_order, valid_store_path};
use crate::tmptar::unpack_tmp_dir_archive;

/// Credentials backing one build's sandbox.
///
/// Linux workers lease every build's sandbox from tribuchet-sandboxd:
/// a mapped user namespace (65536 uids for uid-range builds, one
/// otherwise) plus a delegated cgroup, so no build runs as the
/// worker's own uid. The sandbox setup stage joins the pre-mapped
/// namespace and no host file is chowned. macOS builds go through the
/// per-uid agents instead (see `execute` below).
#[cfg(target_os = "linux")]
struct BuildOwner {
    _lease: super::sandboxd::SandboxLease,
}

/// Pre-spawn half of a lease: the user namespace exists (so its path
/// can go into the spec) but sandboxd has not been contacted yet.
#[cfg(target_os = "linux")]
struct OwnerPrep {
    ns: super::sandboxd::SandboxPrep,
    uid_count: u32,
}

#[cfg(target_os = "linux")]
impl BuildOwner {
    fn prepare(a: &BuildAssignment) -> Result<OwnerPrep> {
        Ok(OwnerPrep {
            ns: super::sandboxd::SandboxPrep::new()?,
            uid_count: if requires_uid_range(&a.env) { 65536 } else { 1 },
        })
    }

    /// Lease the sandbox now that the setup stage exists, so sandboxd
    /// can place it in the build cgroup. Fills in `spec.cgroup`.
    fn lease(
        ctx: &WorkerCtx,
        build_id: &str,
        prep: OwnerPrep,
        stage: i32,
        spec: &mut sandbox::SandboxSpec,
    ) -> Result<Self> {
        let socket = ctx
            .sandboxd
            .as_deref()
            .context("tribuchet-sandboxd socket unavailable")?;
        let OwnerPrep { ns, uid_count } = prep;
        let tmp_dir = spec.build_dir.parent().unwrap_or(&spec.build_dir);
        let lease = ns.allocate(
            socket,
            build_id,
            uid_count,
            nix::unistd::Pid::from_raw(stage),
            tmp_dir,
        )?;
        tracing::info!(
            build_id,
            pool_base = lease.pool_base,
            uid_count,
            "leased sandbox"
        );
        // memory.max is group-writable for the worker.
        if let Some(bytes) = ctx.build_memory_max
            && let Err(e) = fs::write(lease.cgroup().join("memory.max"), bytes.to_string())
        {
            tracing::warn!("setting memory.max on the leased cgroup: {e}");
        }
        spec.cgroup = Some(lease.cgroup().to_path_buf());
        Ok(Self { _lease: lease })
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
        || tmp
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        bail!("invalid tmpDirInSandbox {:?}", a.tmp_dir_in_sandbox);
    }
    for p in a.outputs.values() {
        if !valid_store_path(STORE_DIR, p) {
            bail!("invalid output path {p:?}");
        }
        // macOS builds write into /nix/store and cleanup deletes the
        // output, so a pre-existing path would be tampered with and
        // removed; reject it. Linux builds run in a private root with
        // a no-op cleanup, so the real path is untouched -- and
        // rejecting it would break re-dispatch of a path already valid
        // here (e.g. a fixed-output derivation built before).
        if cfg!(target_os = "macos") && fs::symlink_metadata(p).is_ok() {
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
    pub(super) ctx: Arc<WorkerCtx>,
    /// Job slot; drops back to `WorkerCtx::slots` with the build.
    pub(super) permit: Option<tokio::sync::OwnedSemaphorePermit>,
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
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(Ok::<_, io::Error>);
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
    pub(super) fn new(assignment: BuildAssignment, ctx: Arc<WorkerCtx>) -> Result<Self> {
        let dir = ctx.state_dir.join("builds").join(&assignment.build_id);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        fs::create_dir_all(dir.join("top"))?;
        Ok(Self {
            assignment,
            dir,
            ctx,
            permit: None,
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
        let mut parsed = Vec::with_capacity(offered.len());
        let mut set = StorePathSet::new();
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
            set.insert(sp.clone());
            parsed.push((p, sp));
        }
        // One bulk validity query instead of a round trip per path.
        let valid = daemon
            .query_valid_paths(&set, false)
            .await
            .context("querying valid paths")?;
        let mut missing = Vec::new();
        for (p, sp) in parsed {
            if valid.contains(&sp) {
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
        if !t.zstd_tar_chunk.is_empty() && tx.send(t.zstd_tar_chunk).await.is_err() {
            // The unpacker only stops early on error; report that error.
            let (_, task) = self.tmp_unpacker.take().unwrap();
            let err = task
                .await?
                .err()
                .unwrap_or_else(|| anyhow::anyhow!("tmp dir unpacker exited early"));
            return Err(err);
        }
        if t.eof {
            let (tx, task) = self.tmp_unpacker.take().unwrap();
            drop(tx);
            task.await??;
            if self.importer.is_some() {
                bail!("tmp dir transfer finished during an input NAR transfer");
            }
            self.finish_staging().await?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Inputs the hub skipped (streamed for an earlier build in this
    /// session) never got a NAR here; verify they are valid in the
    /// local store before treating them as bind-mount sources.
    async fn finish_staging(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let store_dir = StoreDir::default();
        let mut set = StorePathSet::new();
        let mut skipped = Vec::new();
        for (p, info) in std::mem::take(&mut self.pending) {
            if info.is_some() {
                bail!("hub sent path info but no NAR for {p}");
            }
            set.insert(store_dir.parse(&p)?);
            skipped.push(p);
        }
        let daemon = self
            .daemon
            .as_mut()
            .context("daemon connection missing (no negotiation?)")?;
        let valid = daemon
            .query_valid_paths(&set, false)
            .await
            .context("re-checking inputs staged for earlier builds")?;
        for p in skipped {
            if !valid.contains(&store_dir.parse(&p)?) {
                bail!(
                    "input {p} was staged for an earlier build but is not valid in the local store"
                );
            }
            self.inputs.push(p);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn build_spec(&self, prep: &OwnerPrep) -> Result<sandbox::SandboxSpec> {
        let a = &self.assignment;
        let (leased_userns, leased_uid_count) = (Some(prep.ns.ns_path()), Some(prep.uid_count));
        let spec = sandbox::prepare(
            a,
            &self.dir,
            &self.inputs,
            &sandbox::PrepareOpts {
                bin_sh: self.ctx.sandbox_bin_sh.as_deref(),
                secrets: &self.ctx.secret_paths,
                leased_userns,
                leased_uid_count,
                emulator: self.ctx.emulators.get(&a.system).map(PathBuf::as_path),
                net_isolation: self.ctx.fod_isolation,
                net_policy: self.ctx.fod_network.clone(),
                recursive_nix: self.ctx.recursive_nix,
                nix_daemon_socket: None,
            },
        )?;
        tracing::info!(
            id = a.build_id,
            fixed_output = a.fixed_output,
            network = spec.network,
            net_isolation = spec.net_isolation,
            "sandbox network decision"
        );
        Ok(spec)
    }

    /// Runs on a blocking thread: sandboxed build, live log streaming,
    /// output packing and signing. Sends only logs; the result and
    /// output NARs go through deliver(), which can run again on a
    /// later session if this one dies first.
    #[cfg(target_os = "linux")]
    pub(super) fn execute(
        &self,
        out_tx: &mpsc::Sender<WorkerMessage>,
        signing_key: &SecretKey,
        timeout: Duration,
    ) -> Result<FinishedBuild> {
        let a = &self.assignment;
        // Spawn first, lease after: sandboxd needs the stage's pidfd to
        // move it into the build cgroup. The stage blocks on stdin
        // until the spec is sent below, so nothing runs before leasing.
        let prep = BuildOwner::prepare(a)?;
        let mut spec = self.build_spec(&prep)?;
        // Logs go through a file in the build dir, not pipes: capture
        // is decoupled from this process's lifetime, so a restarted
        // worker can resume tailing where we stopped.
        let log_file = fs::File::create(self.dir.join("build.log"))?;
        let (child, spec_w) = sandbox::spawn(&spec, &log_file)?;
        let pid = child.id().cast_signed();
        let _owner = BuildOwner::lease(&self.ctx, &a.build_id, prep, pid, &mut spec)?;
        if let Some(w) = spec_w {
            sandbox::send_spec_to(&spec, w)?;
        }
        // From here the build can be re-adopted by a restarted worker.
        // The exit status lands in the exit-status file, not only in
        // this process's wait().
        let resume = ResumeState {
            dedupe_key: a.dedupe_key.clone(),
            build_id: a.build_id.clone(),
            pid,
            spec,
            deadline_unix: unix_now() + timeout.as_secs(),
            agent_socket: None,
        };
        fs::write(self.dir.join("resume.json"), serde_json::to_vec(&resume)?)?;

        let log_done = Arc::new(atomic::AtomicBool::new(false));
        let tailer = {
            let tx = out_tx.clone();
            let build_id = a.build_id.clone();
            let log_done = log_done.clone();
            let dir = self.dir.clone();
            std::thread::spawn(move || {
                tail_log(&dir, &build_id, &tx, || log_done.load(Ordering::Relaxed));
            })
        };
        let fin = supervise(
            &self.ctx,
            &resume,
            self.dir.clone(),
            signing_key,
            Some(child),
        );
        log_done.store(true, Ordering::Relaxed);
        let _ = tailer.join();
        Ok(fin)
    }

    /// macOS: lease a per-uid agent and run the build there. The agent
    /// unpacks the tmp dir into its own scratch dir, applies the
    /// seatbelt profile and owns the builder process. The worker tails
    /// the log fd, polls its abort conditions, and packs the outputs
    /// (written at their real store paths) once the agent made them
    /// readable.
    #[cfg(target_os = "macos")]
    pub(super) fn execute(
        &self,
        out_tx: &mpsc::Sender<WorkerMessage>,
        signing_key: &SecretKey,
        timeout: Duration,
    ) -> Result<FinishedBuild> {
        if requires_uid_range(&self.assignment.env) {
            bail!("the uid-range feature is only supported on Linux workers");
        }
        let socket = self
            .ctx
            .agents
            .acquire()
            .context("no free build agent (max-jobs exceeds the agent count?)")?;
        let result = self.execute_on_agent(&socket, out_tx, signing_key, timeout);
        self.ctx.agents.release(socket);
        result
    }

    #[cfg(target_os = "macos")]
    fn execute_on_agent(
        &self,
        socket: &Path,
        out_tx: &mpsc::Sender<WorkerMessage>,
        signing_key: &SecretKey,
        timeout: Duration,
    ) -> Result<FinishedBuild> {
        let a = &self.assignment;
        let outputs: Vec<String> = a.outputs.values().cloned().collect();
        let profile =
            super::agents::seatbelt_profile(&outputs, &self.ctx.secret_paths, a.fixed_output)?;
        // Re-tar the staged tmp dir: the agent unpacks it into its own
        // scratch dir, since the worker's copy is not agent-writable.
        fs::write(
            self.dir.join("top.tar.zst"),
            crate::tmptar::tar_zstd_dir(&self.dir.join("top"))?,
        )?;
        let req = sandbox_proto::darwin::StartRequest {
            build_id: a.build_id.clone(),
            builder: a.builder.clone(),
            args: a.args.clone(),
            env: a.env.clone(),
            tmp_dir_in_sandbox: a.tmp_dir_in_sandbox.clone(),
            profile,
            outputs: outputs.clone(),
        };
        let build = super::agents::AgentBuild::start(
            socket,
            &req,
            &fs::File::open(self.dir.join("top.tar.zst"))?,
        )?;
        tracing::info!(
            id = a.build_id,
            pid = build.pid,
            agent = %socket.display(),
            scratch = %build.scratch_dir.display(),
            "builder started on agent"
        );

        // Mirror the agent-side log into dir/build.log so the shared
        // tailing, replay and resume paths work exactly as on Linux.
        let mirror = LogMirror::start(&build.log, self.dir.join("build.log"))?;
        let log_done = Arc::new(atomic::AtomicBool::new(false));
        let tailer = {
            let tx = out_tx.clone();
            let build_id = a.build_id.clone();
            let log_done = log_done.clone();
            let dir = self.dir.clone();
            std::thread::spawn(move || {
                tail_log(&dir, &build_id, &tx, || log_done.load(Ordering::Relaxed));
            })
        };
        // From here a restarted worker can re-adopt the build from
        // its agent.
        let resume = ResumeState {
            dedupe_key: a.dedupe_key.clone(),
            build_id: a.build_id.clone(),
            pid: build.pid,
            spec: sandbox::SandboxSpec {
                outputs,
                store_inputs: self.inputs.clone(),
                recursive_nix: self.ctx.recursive_nix,
                ..sandbox::SandboxSpec::default()
            },
            deadline_unix: unix_now() + timeout.as_secs(),
            agent_socket: Some(socket.to_path_buf()),
        };
        fs::write(self.dir.join("resume.json"), serde_json::to_vec(&resume)?)?;
        let fin = supervise_agent(
            &self.ctx,
            &resume,
            self.dir.clone(),
            socket,
            build,
            signing_key,
        );
        // The mirror is drained before the tailer's final read so no
        // trailing log lines are lost.
        mirror.stop();
        log_done.store(true, Ordering::Relaxed);
        let _ = tailer.join();
        Ok(fin)
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
        if let Err(e) = fs::remove_dir_all(&self.dir) {
            tracing::warn!("cleaning up {}: {e}", self.dir.display());
        }
    }
}

/// True while the build's processes are still around: cgroup still
/// populated (Linux lease) or, without a cgroup, the shim/builder pid
/// still exists. The pid check alone would be fooled by pid reuse for
/// adopted builds, so the cgroup wins when there is one.
#[cfg(target_os = "linux")]
fn build_alive(st: &ResumeState) -> bool {
    if let Some(cg) = &st.spec.cgroup {
        return match fs::read_to_string(cg.join("cgroup.events")) {
            Ok(events) => !events.contains("populated 0"),
            Err(_) => false, // cgroup gone: lease over, build dead
        };
    }
    // EPERM means the process exists (leased uid). Only ESRCH is gone.
    signal::kill(nix::unistd::Pid::from_raw(st.pid), None) != Err(nix::errno::Errno::ESRCH)
}

/// Wait out a running build (fresh or re-adopted), pack its outputs,
/// and tear the sandbox down. Driven off the persisted `ResumeState`
/// so both entry points share one wait/kill/pack path. `child` is the
/// spawned shim for a fresh build, reaped here. An adopted build has
/// no child, its exit code comes from the persisted exit-status file.
#[cfg(target_os = "linux")]
pub(super) fn supervise(
    ctx: &WorkerCtx,
    st: &ResumeState,
    dir: PathBuf,
    signing_key: &SecretKey,
    mut child: Option<std::process::Child>,
) -> FinishedBuild {
    // POSIX-shell style exit code of a reaped child.
    fn exit_code(status: std::process::ExitStatus) -> i32 {
        use std::os::unix::process::ExitStatusExt;
        status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
    }
    let pgrp = nix::unistd::Pid::from_raw(st.pid);
    let log_path = dir.join("build.log");
    let mut aborted: Option<String> = None;
    // Exit code of the reaped child. The exit-status file wins when it
    // exists (setup failures exit before the shim can write it).
    let mut child_code: Option<i32> = None;
    // Build gone but no exit status anywhere: bounded grace, then
    // treat as failed.
    let mut gone_since: Option<Instant> = None;
    let code = loop {
        if child_code.is_none()
            && let Some(c) = child.as_mut()
            && let Ok(Some(status)) = c.try_wait()
        {
            child_code = Some(exit_code(status));
        }
        if let Some(code) = sandbox::exit_status(&st.spec).or(child_code) {
            break code;
        }
        if build_alive(st) {
            gone_since = None;
        } else {
            let since = gone_since.get_or_insert_with(Instant::now);
            if since.elapsed() > Duration::from_secs(5) {
                aborted.get_or_insert_with(|| "build exit status was lost".into());
                break 1;
            }
        }
        if aborted.is_none() {
            let timed_out = (unix_now() >= st.deadline_unix).then(|| "build timed out".to_string());
            if let Some(r) = ctx.abort_reason(&st.dedupe_key, &log_path, timed_out) {
                aborted = Some(r);
                kill_build(pgrp, st.spec.cgroup.as_deref());
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    // Reap the shim if we spawned it and have not reaped it yet.
    if child_code.is_none()
        && let Some(mut c) = child
    {
        let _ = c.wait();
    }
    // Builder is PID 1 of its PID namespace, so its death took every
    // descendant with it; also covers macOS (no pidns) and the pre-exec
    // window.
    kill_build(pgrp, st.spec.cgroup.as_deref());
    tracing::info!(id = st.build_id, exit_code = code, aborted = ?aborted, "builder finished");
    let (exit_code, error, outputs, extras) = if let Some(reason) = aborted {
        (1, reason, vec![], vec![])
    } else if code != 0 {
        (
            code,
            sandbox::setup_error_detail(&st.spec).unwrap_or_default(),
            vec![],
            vec![],
        )
    } else {
        // At least a few minutes to pack even if the build ate its budget.
        let remaining = Duration::from_secs(st.deadline_unix.saturating_sub(unix_now()));
        let deadline = Instant::now() + remaining.max(Duration::from_mins(10));
        match tokio::runtime::Handle::current().block_on(pack_outputs_and_extras(
            &dir,
            &st.spec,
            deadline,
            signing_key,
            &st.build_id,
        )) {
            Ok((o, e)) => (0, String::new(), o, e),
            Err(e) => (1, format!("{e:#}"), vec![], vec![]),
        }
    };
    sandbox::cleanup(&st.spec.outputs, &dir);
    FinishedBuild {
        exit_code,
        error,
        outputs,
        extras,
        dir,
        finished_at: Instant::now(),
    }
}

/// Kill a build's processes. killpg alone misses a builder that
/// setsid()'d out of the group; the shim is outside the pidns, so its
/// death does not tear it down. cgroup.kill (group-writable via
/// sandboxd) reaches everything.
#[cfg(target_os = "linux")]
fn kill_build(pgrp: nix::unistd::Pid, cgroup: Option<&Path>) {
    let _ = signal::killpg(pgrp, signal::Signal::SIGKILL);
    if let Some(cg) = cgroup {
        let _ = fs::write(cg.join("cgroup.kill"), "1");
    }
}

/// Wait out a build running on an agent (fresh or re-adopted), pack
/// its outputs, and have the agent clean up. The macOS counterpart of
/// `supervise`, driven off the same persisted `ResumeState`.
#[cfg(target_os = "macos")]
pub(super) fn supervise_agent(
    ctx: &WorkerCtx,
    st: &ResumeState,
    dir: PathBuf,
    socket: &Path,
    build: super::agents::AgentBuild,
    signing_key: &SecretKey,
) -> FinishedBuild {
    let log_path = dir.join("build.log");
    // The exit notice arrives on the lease connection. Wait for it on
    // its own thread so the abort conditions keep being polled.
    let waiter = std::thread::spawn(move || build.wait_exit());
    let mut aborted: Option<String> = None;
    while !waiter.is_finished() {
        if aborted.is_none() {
            let timed_out = (unix_now() >= st.deadline_unix).then(|| "build timed out".to_string());
            if let Some(r) = ctx.abort_reason(&st.dedupe_key, &log_path, timed_out) {
                aborted = Some(r);
                if let Err(e) = super::agents::kill(socket, &st.build_id) {
                    tracing::warn!(id = st.build_id, "killing the build via its agent: {e:#}");
                }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let code = match waiter.join() {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => {
            aborted.get_or_insert(format!("agent connection lost: {e:#}"));
            1
        }
        Err(_) => {
            aborted.get_or_insert("agent wait thread panicked".into());
            1
        }
    };
    tracing::info!(id = st.build_id, exit_code = code, aborted = ?aborted, "builder finished");
    let (exit_code, error, outputs, extras) = if let Some(reason) = aborted {
        (1, reason, vec![], vec![])
    } else if code != 0 {
        (code, String::new(), vec![], vec![])
    } else {
        // The outputs are agent-owned files at their real store
        // paths; Finish makes them readable for packing.
        let remaining = Duration::from_secs(st.deadline_unix.saturating_sub(unix_now()));
        let deadline = Instant::now() + remaining.max(Duration::from_mins(10));
        let packed = super::agents::finish(socket, &st.build_id)
            .context("finishing the build on its agent")
            .and_then(|()| {
                tokio::runtime::Handle::current().block_on(pack_outputs_and_extras(
                    &dir,
                    &st.spec,
                    deadline,
                    signing_key,
                    &st.build_id,
                ))
            });
        match packed {
            Ok((o, e)) => (0, String::new(), o, e),
            Err(e) => (1, format!("{e:#}"), vec![], vec![]),
        }
    };
    // The agent removes its scratch dir and the scratch outputs
    // (packing above already read them) and forgets the build.
    if let Err(e) = super::agents::cleanup(socket, &st.build_id) {
        tracing::warn!(id = st.build_id, "agent cleanup failed: {e:#}");
    }
    FinishedBuild {
        exit_code,
        error,
        outputs,
        extras,
        dir,
        finished_at: Instant::now(),
    }
}

/// Background thread appending everything the agent writes to its log
/// fd into the build dir's build.log, so the path-based tailing,
/// replay and resume machinery works as on Linux.
#[cfg(target_os = "macos")]
pub(super) struct LogMirror {
    done: Arc<atomic::AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

#[cfg(target_os = "macos")]
impl LogMirror {
    /// Start mirroring `log` into `dest_path`, appending where a
    /// previous worker generation's mirror left off.
    pub(super) fn start(log: &fs::File, dest_path: PathBuf) -> Result<Self> {
        let mut src = log.try_clone()?;
        let done = Arc::new(atomic::AtomicBool::new(false));
        let thread = {
            let done = done.clone();
            std::thread::spawn(move || {
                use std::io::{Read as _, Seek as _};
                let Ok(mut dest) = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&dest_path)
                else {
                    return;
                };
                let already = dest.metadata().map(|m| m.len()).unwrap_or(0);
                if src.seek(io::SeekFrom::Start(already)).is_err() {
                    return;
                }
                let mut buf = [0u8; 8192];
                loop {
                    match src.read(&mut buf) {
                        Ok(0) => {
                            if done.load(Ordering::Relaxed) {
                                return;
                            }
                            std::thread::sleep(Duration::from_millis(200));
                        }
                        Ok(n) => {
                            if dest.write_all(&buf[..n]).is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            })
        };
        Ok(Self { done, thread })
    }

    /// Drain what is still buffered agent-side, then stop.
    pub(super) fn stop(self) {
        self.done.store(true, Ordering::Relaxed);
        let _ = self.thread.join();
    }
}

/// Pack the outputs, then (under recursive-nix) the closure-delta
/// extras.
async fn pack_outputs_and_extras(
    dir: &Path,
    spec: &sandbox::SandboxSpec,
    deadline: Instant,
    signing_key: &SecretKey,
    build_id: &str,
) -> Result<(Vec<PackedOutput>, Vec<PackedExtra>)> {
    let extra_candidates = if spec.recursive_nix {
        query_all_valid_paths().await.unwrap_or_else(|e| {
            tracing::warn!(id = build_id, "queryAllValidPaths failed: {e:#}");
            BTreeSet::new()
        })
    } else {
        BTreeSet::new()
    };
    let packed = pack_outputs(dir, spec, &extra_candidates, deadline, signing_key).await?;
    let extras = if spec.recursive_nix {
        pack_extras(
            dir,
            &packed,
            &spec.store_inputs,
            &spec.outputs,
            deadline,
            signing_key,
        )
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(id = build_id, "packing extras failed: {e:#}");
            Vec::new()
        })
    } else {
        Vec::new()
    };
    Ok((packed, extras))
}

/// Snapshot of every valid store path on the worker, used to widen
/// the ref-scan candidate set when recursive-nix is on.
async fn query_all_valid_paths() -> Result<BTreeSet<harmonia_store_path::StorePath>> {
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
async fn pack_outputs(
    dir: &Path,
    spec: &sandbox::SandboxSpec,
    extra_candidates: &BTreeSet<harmonia_store_path::StorePath>,
    deadline: Instant,
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
        .await
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

/// Pack the closure-delta extras: paths an output references that
/// are neither inputs nor sibling outputs.
async fn pack_extras(
    dir: &Path,
    outputs: &[PackedOutput],
    store_inputs: &[String],
    spec_outputs: &[String],
    deadline: Instant,
    signing_key: &SecretKey,
) -> Result<Vec<PackedExtra>> {
    let known: BTreeSet<&str> = store_inputs
        .iter()
        .map(String::as_str)
        .chain(spec_outputs.iter().map(String::as_str))
        .collect();
    let mut queue: Vec<String> = outputs
        .iter()
        .flat_map(|o| o.references.iter())
        .filter(|r| !known.contains(r.as_str()))
        .cloned()
        .collect();
    if queue.is_empty() {
        return Ok(Vec::new());
    }
    let store_dir = StoreDir::default();
    let mut daemon = DaemonClient::builder()
        .connect_daemon()
        .await
        .context("connecting to the local nix-daemon")?;
    // Transitive closure: the hub daemon rejects an import whose
    // references are not already valid.
    let mut infos: HashMap<String, UnkeyedValidPathInfo> = HashMap::new();
    while let Some(path) = queue.pop() {
        if infos.contains_key(&path) {
            continue;
        }
        let sp = StorePath::from_base_path(store_base(&path))
            .with_context(|| format!("parsing extra path {path}"))?;
        // Hold a temp root so the daemon does not GC the path while
        // we read it.
        daemon
            .add_temp_root(&sp)
            .await
            .with_context(|| format!("temp-rooting {path}"))?;
        let info = daemon
            .query_path_info(&sp)
            .await
            .with_context(|| format!("queryPathInfo {path}"))?
            .ok_or_else(|| anyhow::anyhow!("extra {path} vanished from store"))?;
        for r in &info.references {
            let r = r
                .to_absolute_path(&store_dir)
                .to_string_lossy()
                .into_owned();
            if !known.contains(r.as_str()) {
                queue.push(r);
            }
        }
        infos.insert(path, info);
    }
    // Referenced-before-referrer, matching hub-side sequential import.
    let ordered = topo_order(infos.keys().cloned(), |p| {
        infos[p]
            .references
            .iter()
            .map(|r| {
                r.to_absolute_path(&store_dir)
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|r| infos.contains_key(r))
            .collect()
    });
    let mut out = Vec::with_capacity(infos.len());
    for path in ordered {
        let info = infos.remove(&path).unwrap();
        let sp = StorePath::from_base_path(store_base(&path))?;
        let mut candidates: BTreeSet<StorePath> = info.references.iter().cloned().collect();
        candidates.insert(sp.clone());
        let nar_file = dir.join(format!("extra-{}.nar.zst", store_base(&path)));
        let res = pack_one_nar(
            Path::new(&path),
            &nar_file,
            &candidates,
            Some(&sp),
            deadline,
        )
        .await
        .with_context(|| format!("packing extra {path}"))?;
        // Daemon NAR layout is deterministic, so its recorded
        // nar_size matches the bytes we just hashed.
        let nar_size = info.nar_size;
        let sig = signing_key.sign(format!("{path}:{}", hex::encode(&res.nar_sha256)).as_bytes());
        out.push(PackedExtra {
            path,
            nar_file,
            nar_sha256: res.nar_sha256,
            nar_size,
            signature: sig.to_string(),
            references: info
                .references
                .iter()
                .map(|p| {
                    p.to_absolute_path(&store_dir)
                        .to_string_lossy()
                        .into_owned()
                })
                .collect(),
            sigs: info.signatures.iter().map(ToString::to_string).collect(),
            deriver: info
                .deriver
                .as_ref()
                .map(|p| {
                    p.to_absolute_path(&store_dir)
                        .to_string_lossy()
                        .into_owned()
                })
                .unwrap_or_default(),
            ca: info
                .ca
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
        });
    }
    Ok(out)
}

struct NarPackResult {
    nar_sha256: Vec<u8>,
    references: Vec<String>,
}

/// Pack `host_path` as a zstd-compressed NAR into `nar_path`, hashing
/// and reference-scanning the plaintext NAR in the same pass.
async fn pack_one_nar(
    host_path: &Path,
    nar_path: &Path,
    candidates: &BTreeSet<harmonia_store_path::StorePath>,
    self_path: Option<&harmonia_store_path::StorePath>,
    deadline: Instant,
) -> Result<NarPackResult> {
    let mut hasher = Sha256::new();
    let mut sink = harmonia_store_ref_scan::RefScanSink::new(candidates, self_path);
    {
        let f = fs::File::create(nar_path)?;
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
        nar::pack(host_path, &mut limited).await?;
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
) -> BTreeSet<harmonia_store_path::StorePath> {
    inputs
        .iter()
        .chain(outputs.iter())
        .filter_map(|p| harmonia_store_path::StorePath::from_base_path(store_base(p)).ok())
        .collect()
}

/// Enforces a byte budget and a wall-clock deadline on a Write chain.
struct LimitedWriter<W> {
    inner: W,
    remaining: u64,
    deadline: Instant,
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::other("build timed out"));
        }
        if buf.len() as u64 > self.remaining {
            return Err(io::Error::other(format!(
                "NAR exceeds the {MAX_NAR_BYTES} byte limit"
            )));
        }
        let n = self.inner.write(buf)?;
        self.remaining -= n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
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
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.zstd.write_all(buf)?;
        self.hasher.update(buf);
        self.scan.feed(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
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

        // An existing store path as an output: rejected on macOS
        // (in-place tampering, deletion by cleanup), accepted on Linux
        // (isolated build root, no-op cleanup).
        if let Some(existing) = fs::read_dir("/nix/store")
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path().to_string_lossy().into_owned())
            .find(|p| valid_store_path(STORE_DIR, p))
        {
            let mut a = base_assignment();
            a.outputs.insert("doc".into(), existing);
            if cfg!(target_os = "macos") {
                assert!(validate_assignment(&a).is_err());
            } else {
                assert!(validate_assignment(&a).is_ok());
            }
        }

        let mut a = base_assignment();
        a.builder = "-p".into();
        assert!(validate_assignment(&a).is_err());
    }

    /// pack_one_nar finds references in the same pass as the NAR
    /// hash; self-paths are dropped.
    #[tokio::test]
    async fn pack_one_nar_finds_references_and_excludes_self() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let host = dir.path().join("out");
        fs::create_dir(&host)?;
        let input = "/nix/store/00000000000000000000000000000001-input";
        let self_path = "/nix/store/00000000000000000000000000000002-self";
        let unrelated = "/nix/store/00000000000000000000000000000003-unrelated";
        fs::write(host.join("data"), format!("refs: {input} {self_path}\n"))?;
        let candidates = scan_candidates(&[input.into(), unrelated.into()], &[self_path.into()]);
        let self_sp = harmonia_store_path::StorePath::from_base_path(store_base(self_path)).ok();
        let res = pack_one_nar(
            &host,
            &dir.path().join("out.nar.zst"),
            &candidates,
            self_sp.as_ref(),
            Instant::now() + Duration::from_secs(30),
        )
        .await?;
        assert_eq!(res.references, vec![input.to_string()]);
        assert_eq!(res.nar_sha256.len(), 32);
        Ok(())
    }
}
