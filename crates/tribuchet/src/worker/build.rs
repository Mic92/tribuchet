//! One build on this worker: input staging, sandbox execution, output packing.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::mem;
use std::path::PathBuf;
use std::sync::Arc;

use harmonia_store_path::{StoreDir, StorePath, StorePathSet};
use harmonia_store_path_info::ValidPathInfo;
use harmonia_store_remote::{DaemonClient, DaemonStore};
use tokio::sync::mpsc;

use chunks::ChunkStaging;
use import_pool::{ImportHandle, ImportPool, ImportState};

use super::pins;
use super::{DaemonConn, WorkerCtx, unix_now};
use crate::chunkio::ChannelReader;
use crate::errors::chain;
use crate::errors::{Result, err_ctx, err_msg};
use crate::fsutil::io_ctx;
use crate::proto::{BuildAssignment, MAX_RESEND_ROUNDS, Need, TmpDirArchive};
use crate::tmpdir::unpack_tmp_dir;

/// Where staging of one build stands after a hub message.
pub(super) enum StagingStatus {
    InProgress,
    /// Everything staged; start the build.
    Ready,
    /// Deferred paths never became valid; ask the hub for them.
    NeedResend(Need),
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
    /// Paths this build imports, removed at dispatch.
    pending: HashSet<String>,
    infos: HashMap<String, ValidPathInfo>,
    /// Complete paths waiting for a reference to dispatch.
    parked: HashSet<String>,
    /// Missing paths another build is importing; not requested from
    /// the hub, re-checked when staging completes.
    deferred: Vec<String>,
    /// Paths this build claimed in `WorkerCtx::staging_inflight`.
    registered: HashSet<String>,
    /// True once the tmp dir stream finished unpacking.
    tmp_dir_done: bool,
    resend_rounds: u32,
    /// Needs with hashes the hub has not answered with eof yet.
    needs_outstanding: u32,
    /// Daemon connection; carries this build's temp roots, so it must
    /// outlive the build.
    daemon: Option<DaemonConn>,
    imports: HashMap<String, ImportHandle>,
    pool: Option<ImportPool>,
    chunks: ChunkStaging,
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
        let chunks = ChunkStaging::new(ctx.chunks.clone());
        Ok(Self {
            assignment,
            dir,
            ctx,
            permit: None,
            inputs: Vec::new(),
            pending: HashSet::new(),
            infos: HashMap::new(),
            parked: HashSet::new(),
            deferred: Vec::new(),
            registered: HashSet::new(),
            tmp_dir_done: false,
            resend_rounds: 0,
            needs_outstanding: 0,
            daemon: None,
            imports: HashMap::new(),
            pool: None,
            chunks,
            tmp_unpacker: None,
        })
    }

    /// Pin and check the inputs, take inline manifests, and answer
    /// with the first Need listing every path this build imports.
    pub(super) async fn negotiate(&mut self) -> Result<(Option<Need>, StagingStatus)> {
        let inputs = mem::take(&mut self.assignment.inputs);
        let offered: Vec<String> = inputs.iter().map(|m| m.store_path.clone()).collect();
        let missing = self.check_inputs(&offered).await?;
        let mut hashes = Vec::new();
        for m in inputs {
            if m.info.is_some() {
                hashes.extend(self.take_manifest(m).await?);
            }
        }
        if !hashes.is_empty() {
            self.needs_outstanding += 1;
        }
        let need = Need {
            build_id: self.assignment.build_id.clone(),
            paths: missing,
            hashes,
        };
        Ok((Some(need), self.try_complete().await?))
    }

    async fn check_inputs(&mut self, offered: &[String]) -> Result<Vec<String>> {
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
            let offered = offered.to_owned();
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
                self.pending.insert(p.clone());
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

    /// Inline manifests for paths already valid here or deferred to
    /// another build's import are dropped.
    fn tolerated(&self, path: &str) -> bool {
        self.inputs.iter().any(|p| p == path) || self.deferred.iter().any(|p| p == path)
    }

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

    /// Wait for the dispatched imports. Imports that failed on corrupt
    /// or vanished chunks are staged again instead of failing the
    /// build. Returns the Need of that retry.
    async fn collect_imports(&mut self) -> Result<Option<Need>> {
        let mut failed = Vec::new();
        let mut bad_chunks = 0;
        let mut error = None;
        for (path, handle) in mem::take(&mut self.imports) {
            let (state, bad) = handle.finish().await?;
            if let ImportState::Failed(e) = state {
                bad_chunks += bad.len();
                error.get_or_insert(e);
                failed.push(path);
                continue;
            }
            self.chunks.forget_path(&path);
            self.infos.remove(&path);
            self.deregister(&path);
            self.inputs.push(path);
        }
        let Some(e) = error else {
            return Ok(None);
        };
        // Without a bad chunk to blame a retry would fail the same way.
        if bad_chunks == 0 || self.resend_rounds >= MAX_RESEND_ROUNDS {
            return Err(err_msg(e));
        }
        self.resend_rounds += 1;
        tracing::warn!(
            paths = failed.len(),
            bad_chunks,
            "staging failed imports again: {e}"
        );
        self.restage(failed).await
    }

    /// Staging finishes once the tmp dir is unpacked and every
    /// pending path is dispatched and imported.
    async fn try_complete(&mut self) -> Result<StagingStatus> {
        if !self.tmp_dir_done || !self.pending.is_empty() {
            return Ok(StagingStatus::InProgress);
        }
        while !self.imports.is_empty() {
            if let Some(need) = self.collect_imports().await? {
                return Ok(StagingStatus::NeedResend(need));
            }
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
            .ok_or_else(|| err_msg("daemon connection missing"))?;
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
        let mut inflight = self.ctx.staging_inflight.lock().unwrap();
        for p in &still_missing {
            if inflight.insert(p.clone()) {
                self.registered.insert(p.clone());
            }
            self.pending.insert(p.clone());
        }
        Ok(StagingStatus::NeedResend(Need {
            build_id: self.assignment.build_id.clone(),
            paths: still_missing,
            hashes: Vec::new(),
        }))
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
            inputs: vec![],
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
