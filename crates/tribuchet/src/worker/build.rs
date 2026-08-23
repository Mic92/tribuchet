//! One build on this worker: input staging, sandbox execution, output packing.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::mem;
use std::path::PathBuf;
use std::sync::Arc;

use harmonia_store_path::{StoreDir, StorePath, StorePathSet};
use harmonia_store_path_info::ValidPathInfo;
use harmonia_store_remote::{DaemonClient, DaemonStore};
use tokio::sync::{mpsc, watch};

use chunks::ChunkStaging;
use import_pool::{ImportHandle, ImportJob, ImportPool, ImportState};

use super::pins;
use super::{DaemonConn, WorkerCtx, unix_now};
use crate::chunkio::ChannelReader;
use crate::errors::chain;
use crate::errors::{Result, err_ctx, err_msg};
use crate::fsutil::io_ctx;
use crate::proto::{
    BuildAssignment, MAX_NAR_BYTES, MAX_RESEND_ROUNDS, NarTransfer, PathInfoMsg, TmpDirArchive,
    nar_transfer,
};
use crate::store::parse_path_info;
use crate::tmpdir::unpack_tmp_dir;

/// Where staging of one build stands after a hub message.
pub(super) enum StagingStatus {
    InProgress,
    /// Everything staged; start the build.
    Ready,
    /// Deferred paths never became valid; ask the hub for them.
    NeedResend(Vec<String>),
}

type Unpacker = (mpsc::Sender<Vec<u8>>, tokio::task::JoinHandle<Result<()>>);

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
    /// Missing paths another build is importing; not requested from
    /// the hub, re-checked when staging completes.
    deferred: Vec<String>,
    /// Paths this build claimed in `WorkerCtx::staging_inflight`.
    registered: HashSet<String>,
    /// True once the tmp dir stream finished unpacking.
    tmp_dir_done: bool,
    resend_rounds: u32,
    /// A NeedResend answer is on the wire. A StagingComplete crossing
    /// it belongs to the superseded round and is ignored.
    awaiting_resend: bool,
    /// Daemon connection; carries this build's temp roots, so it must
    /// outlive the build.
    daemon: Option<DaemonConn>,
    imports: HashMap<String, ImportHandle>,
    pool: Option<ImportPool>,
    /// Chunk-staging state, created by the first recipe.
    chunks: Option<ChunkStaging>,
    tmp_unpacker: Option<Unpacker>,
}

fn store_base(store_path: &str) -> &str {
    store_path.rsplit('/').next().unwrap_or(store_path)
}

async fn add_temp_root(daemon: &mut DaemonConn, path: &str, sp: &StorePath) -> Result<()> {
    daemon
        .add_temp_root(sp)
        .await
        .map_err(err_ctx(format!("adding temp root for {path}")))
}

impl ActiveBuild {
    pub(super) fn new(assignment: BuildAssignment, ctx: Arc<WorkerCtx>) -> Result<Self> {
        let dir = ctx.state_dir.join("builds").join(&assignment.build_id);
        if dir.exists() {
            fs::remove_dir_all(&dir).map_err(io_ctx("removing", &dir))?;
        }
        fs::create_dir_all(dir.join("top/build"))
            .map_err(io_ctx("creating", &dir.join("top/build")))?;
        Ok(Self {
            assignment,
            dir,
            ctx,
            permit: None,
            inputs: Vec::new(),
            pending: HashMap::new(),
            deferred: Vec::new(),
            registered: HashSet::new(),
            tmp_dir_done: false,
            resend_rounds: 0,
            awaiting_resend: false,
            daemon: None,
            imports: HashMap::new(),
            pool: None,
            chunks: None,
            tmp_unpacker: None,
        })
    }

    pub(super) async fn negotiate(&mut self, offered: &[String]) -> Result<Vec<String>> {
        let store_dir = StoreDir::default();
        let mut daemon = DaemonClient::builder()
            .connect_daemon()
            .await
            .map_err(err_ctx("connecting to the local nix-daemon"))?;
        let mut parsed = Vec::with_capacity(offered.len());
        let mut set = StorePathSet::new();
        for p in offered {
            // Only real store paths may become bind-mount sources; a
            // compromised hub must not get the worker's own files
            // (signing key, TLS key) mounted into a sandbox.
            let sp: StorePath = store_dir
                .parse(p)
                .map_err(err_ctx(format!("offered path {p:?} is not a store path")))?;
            set.insert(sp.clone());
            parsed.push((p, sp));
        }
        // Temp roots must exist before the validity check so the
        // daemon cannot GC a path between check and build start. They
        // die with this connection, which the build keeps open. A temp
        // root on a valid path protects its whole closure, so with the
        // reference graph from the store database only the closure
        // roots (plus paths the database doesn't know) need their own
        // AddTempRoot round trip. Without the graph, every path does.
        let plan = {
            let offered = offered.to_vec();
            match tokio::task::spawn_blocking(move || {
                let db = pins::StoreDb::open_readonly(pins::nix_db_path())?;
                pins::plan_pins(&db, &offered)
            })
            .await?
            {
                Ok(plan) => Some(plan),
                Err(e) => {
                    tracing::debug!("store db unavailable, pinning all inputs: {}", chain(&e));
                    None
                }
            }
        };
        let mut pinned = HashSet::new();
        for (p, sp) in &parsed {
            if plan.as_ref().is_none_or(|plan| plan.pins.contains(*p)) {
                add_temp_root(&mut daemon, p, sp).await?;
                pinned.insert(*p);
            }
        }
        // One bulk validity query instead of a round trip per path.
        let mut valid = daemon
            .query_valid_paths(&set, false)
            .await
            .map_err(err_ctx("querying valid paths"))?;
        // If the database called a path valid but the daemon does not,
        // a GC raced our snapshot and the pinned closure roots may no
        // longer cover everything. Root every path and re-check, which
        // restores the root-before-check guarantee.
        if let Some(plan) = &plan
            && parsed
                .iter()
                .any(|(p, sp)| plan.db_valid.contains(*p) && !valid.contains(sp))
        {
            tracing::warn!("garbage collection raced input pinning. Pinning all inputs");
            for (p, sp) in &parsed {
                if !pinned.contains(*p) {
                    add_temp_root(&mut daemon, p, sp).await?;
                }
            }
            valid = daemon
                .query_valid_paths(&set, false)
                .await
                .map_err(err_ctx("re-querying valid paths"))?;
        }
        let mut missing = Vec::new();
        // One check-and-insert under the lock, so of several builds
        // negotiating the same missing path exactly one requests it.
        let mut inflight = self.ctx.staging_inflight.lock().unwrap();
        for (p, sp) in parsed {
            if valid.contains(&sp) {
                self.inputs.push(p.clone());
            } else if inflight.contains(p) {
                // Another build is importing it; re-checked in
                // complete_staging.
                self.deferred.push(p.clone());
            } else {
                inflight.insert(p.clone());
                self.registered.insert(p.clone());
                self.pending.insert(p.clone(), None);
                missing.push(p.clone());
            }
        }
        self.daemon = Some(daemon);
        Ok(missing)
    }

    /// Drop a path's claim in the in-flight registry so other builds
    /// stop deferring to it.
    fn deregister(&mut self, path: &str) {
        if self.registered.remove(path) {
            self.ctx.staging_inflight.lock().unwrap().remove(path);
        }
    }

    fn deregister_all(&mut self) {
        if self.registered.is_empty() {
            return;
        }
        let mut inflight = self.ctx.staging_inflight.lock().unwrap();
        for p in self.registered.drain() {
            inflight.remove(&p);
        }
    }

    /// Unrequested paths (already valid here, or deferred to
    /// another build's import) arrive anyway and are dropped.
    fn tolerated(&self, path: &str) -> bool {
        self.inputs.iter().any(|p| p == path) || self.deferred.iter().any(|p| p == path)
    }

    pub(super) fn feed_path_info(&mut self, pi: &PathInfoMsg) -> Result<()> {
        let Some(slot) = self.pending.get_mut(&pi.store_path) else {
            if self.tolerated(&pi.store_path) {
                return Ok(());
            }
            return Err(err_msg(format!(
                "hub sent path info for unrequested path {}",
                pi.store_path
            )));
        };
        if pi.nar_size > MAX_NAR_BYTES {
            return Err(err_msg(format!(
                "input {} exceeds the {MAX_NAR_BYTES} byte NAR limit",
                pi.store_path
            )));
        }
        *slot =
            Some(parse_path_info(pi).map_err(err_ctx(format!("path info for {}", pi.store_path)))?);
        Ok(())
    }

    pub(super) async fn feed_nar(&mut self, n: NarTransfer) -> Result<StagingStatus> {
        if !self.imports.contains_key(&n.store_path) {
            let info = match self.pending.remove(&n.store_path) {
                Some(Some(info)) => info,
                Some(None) => {
                    return Err(err_msg(format!(
                        "hub sent NAR before path info for {}",
                        n.store_path
                    )));
                }
                None => {
                    if self.tolerated(&n.store_path) {
                        return Ok(StagingStatus::InProgress);
                    }
                    return Err(err_msg(format!(
                        "hub sent NAR for unrequested path {}",
                        n.store_path
                    )));
                }
            };
            let store_dir = StoreDir::default();
            let gates = info
                .info
                .references
                .iter()
                .filter_map(|r| self.imports.get(&store_dir.display(r).to_string()))
                .map(|h| h.done.clone())
                .collect();
            let (tx, rx) = mpsc::channel::<bytes::Bytes>(8);
            let (done_tx, done_rx) = watch::channel(ImportState::Running);
            let jobs = self.ctx.import_jobs;
            let pool = self.pool.get_or_insert_with(|| ImportPool::spawn(jobs));
            pool.job_tx
                .send(ImportJob {
                    info,
                    rx,
                    gates,
                    done: done_tx,
                })
                .await
                .map_err(|_| err_msg("import pool gone"))?;
            self.imports.insert(
                n.store_path.clone(),
                ImportHandle {
                    tx: Some(tx),
                    done: done_rx,
                },
            );
        }
        let handle = self.imports.get_mut(&n.store_path).unwrap();
        let send_failed = match n.payload {
            Some(nar_transfer::Payload::ZstdNarChunk(chunk)) => match &handle.tx {
                Some(tx) => tx.send(chunk.into()).await.is_err(),
                None => {
                    return Err(err_msg(format!(
                        "hub sent a NAR chunk after eof for {}",
                        n.store_path
                    )));
                }
            },
            None => false,
        };
        if send_failed {
            // The import task died early. Surface its error.
            let state = handle
                .done
                .wait_for(|s| !matches!(s, ImportState::Running))
                .await
                .map_err(|_| err_msg("import task abandoned"))?
                .clone();
            return Err(match state {
                ImportState::Failed(e) => err_msg(e),
                _ => err_msg(format!("input import ended early for {}", n.store_path)),
            });
        }
        if n.eof {
            // Import completion is reaped when staging finishes. The
            // next NAR dispatches to another pool connection now.
            handle.tx = None;
            return self.try_complete().await;
        }
        Ok(StagingStatus::InProgress)
    }

    /// Reports staging progress; the tmp dir eof completes round one.
    pub(super) async fn feed_tmp_dir(&mut self, t: TmpDirArchive) -> Result<StagingStatus> {
        let (tx, _) = self.tmp_unpacker.get_or_insert_with(|| {
            let dest = self.dir.join("top/build");
            let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
            let task = tokio::task::spawn_blocking(move || -> Result<()> {
                let dec = zstd::stream::read::Decoder::new(ChannelReader::new(rx))?;
                unpack_tmp_dir(dec, &dest).map_err(err_ctx("unpacking the tmp dir"))
            });
            (tx, task)
        });
        if !t.zstd_chunk.is_empty() && tx.send(t.zstd_chunk).await.is_err() {
            // The unpacker only stops early on error; report that error.
            let (_, task) = self.tmp_unpacker.take().unwrap();
            let err = task
                .await?
                .err()
                .unwrap_or_else(|| err_msg("tmp dir unpacker exited early"));
            return Err(err);
        }
        if t.eof {
            let (tx, task) = self.tmp_unpacker.take().unwrap();
            drop(tx);
            task.await??;
            self.tmp_dir_done = true;
            return self.try_complete().await;
        }
        Ok(StagingStatus::InProgress)
    }

    /// End of a staging round (tmp dir eof or StagingComplete): every
    /// requested NAR must have arrived; deferred paths that are still
    /// invalid are re-requested instead of failing the build.
    pub(super) async fn complete_staging(&mut self) -> Result<StagingStatus> {
        if self.awaiting_resend {
            return Ok(StagingStatus::InProgress);
        }
        if !self.tmp_dir_done {
            return Err(err_msg(
                "hub signalled staging completion before the tmp dir arrived",
            ));
        }
        // Chunked paths whose chunks never all arrived fall back to
        // plain NAR resends instead of failing the build.
        if let Some(cs) = &mut self.chunks {
            let stuck = cs.take_undispatched();
            if !stuck.is_empty() {
                if self.resend_rounds >= MAX_RESEND_ROUNDS {
                    return Err(err_msg(format!(
                        "chunks for {} never arrived after {} rounds",
                        stuck[0], self.resend_rounds
                    )));
                }
                self.resend_rounds += 1;
                self.awaiting_resend = true;
                tracing::warn!(
                    count = stuck.len(),
                    "chunked paths incomplete, requesting plain NARs"
                );
                return Ok(StagingStatus::NeedResend(stuck));
            }
        }
        if let Some(p) = self.pending.keys().next() {
            return Err(err_msg(format!(
                "hub never sent a NAR for requested input {p}"
            )));
        }
        if let Some((p, _)) = self.imports.iter().find(|(_, h)| h.tx.is_some()) {
            return Err(err_msg(format!(
                "staging round ended during the NAR transfer of {p}"
            )));
        }
        self.finish_staging().await
    }

    /// Staging finishes once the tmp dir is unpacked and every
    /// requested NAR is fully fed, checked from both eof paths.
    async fn try_complete(&mut self) -> Result<StagingStatus> {
        if !self.tmp_dir_done
            || !self.pending.is_empty()
            || self.imports.values().any(|h| h.tx.is_some())
        {
            return Ok(StagingStatus::InProgress);
        }
        self.finish_staging().await
    }

    async fn finish_staging(&mut self) -> Result<StagingStatus> {
        self.awaiting_resend = false;
        let imports: Vec<(String, ImportHandle)> = self.imports.drain().collect();
        for (path, mut h) in imports {
            let state = h
                .done
                .wait_for(|s| !matches!(s, ImportState::Running))
                .await
                .map_err(|_| err_msg("import task abandoned"))?
                .clone();
            if let ImportState::Failed(e) = state {
                return Err(err_msg(e));
            }
            self.deregister(&path);
            self.inputs.push(path);
        }
        if self.deferred.is_empty() {
            return Ok(StagingStatus::Ready);
        }
        let store_dir = StoreDir::default();
        let mut set = StorePathSet::new();
        for p in &self.deferred {
            set.insert(store_dir.parse(p)?);
        }
        let daemon = self
            .daemon
            .as_mut()
            .ok_or_else(|| err_msg("daemon connection missing (no negotiation?)"))?;
        let valid = daemon
            .query_valid_paths(&set, false)
            .await
            .map_err(err_ctx("re-checking inputs another build was importing"))?;
        let mut still_missing = Vec::new();
        for p in mem::take(&mut self.deferred) {
            if valid.contains(&store_dir.parse(&p)?) {
                self.inputs.push(p);
            } else {
                still_missing.push(p);
            }
        }
        if still_missing.is_empty() {
            return Ok(StagingStatus::Ready);
        }
        if self.resend_rounds >= MAX_RESEND_ROUNDS {
            return Err(err_msg(format!(
                "input {} was expected from another build's import but never became valid",
                still_missing[0]
            )));
        }
        self.resend_rounds += 1;
        self.awaiting_resend = true;
        // This build imports them itself now: claim and expect them.
        let mut inflight = self.ctx.staging_inflight.lock().unwrap();
        for p in &still_missing {
            if inflight.insert(p.clone()) {
                self.registered.insert(p.clone());
            }
            self.pending.insert(p.clone(), None);
        }
        Ok(StagingStatus::NeedResend(still_missing))
    }

    /// Tear down a build abandoned before execution: stop the import
    /// and unpacker tasks and remove everything staged on disk. The
    /// daemon connection (and with it the temp roots) drops here; a
    /// half-imported path is the daemon's to clean up.
    pub(super) async fn abort(mut self) {
        self.deregister_all();
        self.imports.clear();
        if let Some(pool) = self.pool.take() {
            pool.shutdown().await;
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

#[path = "build/agent_exec.rs"]
mod agent_exec;
#[path = "build/chunks.rs"]
mod chunks;
#[path = "build/validate.rs"]
mod validate;
pub(super) use validate::validate_assignment;
#[path = "build/import_pool.rs"]
mod import_pool;
mod outputs;
pub(super) use agent_exec::supervise_agent;
pub(super) use outputs::pack_outputs_and_extras;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{STORE_DIR, valid_store_path};

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
}
