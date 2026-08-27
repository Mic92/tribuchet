//! Input staging: manifests inline in the assignment where cheap, late
//! manifests as recipes complete, chunks on every Need.

use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::future::pending;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures_util::StreamExt as _;
use futures_util::stream::FuturesUnordered;
use harmonia_store_path::{StoreDir, StorePath};
use harmonia_store_remote::DaemonStore as _;
use tokio::sync::{Semaphore, mpsc};
use tonic::Status;

use super::send;
use super::serve::{compute_recipe, serve_need};
use crate::chunker::parse_hashes;
use crate::chunkio;
use crate::chunkstore::Hash;
use crate::errors::{Result, err_ctx, err_msg};
use crate::hub::chunkcache::Recipe;
use crate::hub::state::{HubState, Job};
use crate::proto::{
    ChunkFrame, HubMessage, Manifest, Need, PathInfoMsg, TmpDirArchive, hub_message,
};

/// Forget everything rather than track LRU. A miss costs one round trip.
const KNOWN_CAP: usize = 1 << 18;

/// Per worker session, shared by its jobs.
pub(in crate::hub) struct WorkerSession {
    /// One job serves chunks at a time so imports see earlier shared
    /// inputs as valid and fetch only their delta.
    pub(super) serving: Semaphore,
    /// Store paths the worker reported having.
    pub(super) known: Mutex<HashSet<String>>,
}

impl WorkerSession {
    pub(in crate::hub) fn new() -> Self {
        Self {
            serving: Semaphore::new(1),
            known: Mutex::new(HashSet::new()),
        }
    }
}

type Computing<'a> = Pin<Box<dyn Future<Output = Result<(Info, Recipe)>> + Send + 'a>>;
type Serving<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

pub(super) struct Staging<'a> {
    state: &'a HubState,
    job: &'a Job,
    sess: &'a WorkerSession,
    offered: HashSet<&'a str>,
    /// Manifests sent, in send order.
    sent: Vec<Arc<(Info, Recipe)>>,
    /// Computed, not yet on the wire. Paths stay in `computing` meanwhile.
    unsent: VecDeque<(Info, Recipe)>,
    computing: HashSet<String>,
    tasks: FuturesUnordered<Computing<'a>>,
    /// Chunk requests are answered one at a time while the relay keeps
    /// reading the worker, so neither side blocks on a full peer.
    queued: VecDeque<HashSet<Hash>>,
    serving: Option<Serving<'a>>,
    first_need: bool,
}

impl<'a> Staging<'a> {
    pub(super) fn new(state: &'a HubState, job: &'a Job, sess: &'a WorkerSession) -> Self {
        Self {
            state,
            job,
            sess,
            offered: job.req.input_paths.iter().map(String::as_str).collect(),
            sent: Vec::new(),
            unsent: VecDeque::new(),
            computing: HashSet::new(),
            tasks: FuturesUnordered::new(),
            queued: VecDeque::new(),
            serving: None,
            first_need: true,
        }
    }

    /// Inputs for the assignment: a manifest where the recipe is
    /// cached and the worker is not known to have the path.
    pub(super) async fn assignment_inputs(&mut self) -> Result<Vec<Manifest>> {
        let upfront: Vec<String> = {
            let known = self.sess.known.lock().unwrap();
            self.job
                .req
                .input_paths
                .iter()
                .filter(|p| !known.contains(*p) && self.state.chunks.has_recipe(p))
                .cloned()
                .collect()
        };
        let infos = order_by_references(query_path_infos(&self.state.daemon_pool, &upfront).await?);
        let mut manifests: HashMap<String, Manifest> = HashMap::new();
        for info in infos {
            let Some(recipe) = self
                .state
                .chunks
                .recipe(&info.store_path, &info.msg.nar_sha256)
            else {
                continue;
            };
            manifests.insert(info.store_path.clone(), manifest("", &info, &recipe));
            self.sent.push(Arc::new((info, recipe)));
        }
        Ok(self
            .job
            .req
            .input_paths
            .iter()
            .map(|p| {
                manifests.remove(p).unwrap_or_else(|| Manifest {
                    store_path: p.clone(),
                    ..Default::default()
                })
            })
            .collect())
    }

    pub(super) fn busy(&self) -> bool {
        !self.tasks.is_empty() || !self.unsent.is_empty() || self.serving.is_some()
    }

    /// Send the next late manifest or finish answering a Need,
    /// whichever comes first. Cancel-safe: run_job drops this future
    /// whenever another select! branch wins, so state only changes
    /// once nothing is left to await (spec/protocol.qnt, HUB = queue).
    pub(super) async fn progress(
        &mut self,
        out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    ) -> Result<()> {
        tokio::select! {
            permit = out_tx.reserve(), if !self.unsent.is_empty() => {
                let permit = permit.map_err(|_| err_msg("worker connection lost"))?;
                let (info, recipe) = self.unsent.pop_front().expect("guarded");
                let m = manifest(&self.job.id, &info, &recipe);
                self.computing.remove(&info.store_path);
                self.sent.push(Arc::new((info, recipe)));
                permit.send(Ok(HubMessage { msg: Some(hub_message::Msg::Manifest(m)) }));
                Ok(())
            }
            Some(r) = self.tasks.next(), if !self.tasks.is_empty() => {
                self.unsent.push_back(r?);
                Ok(())
            }
            r = poll_opt(&mut self.serving), if self.serving.is_some() => {
                self.serving = None;
                r?;
                self.serve_next(out_tx);
                Ok(())
            }
        }
    }

    fn serve_next(&mut self, out_tx: &mpsc::Sender<Result<HubMessage, Status>>) {
        let Some(needed) = self.queued.pop_front() else {
            return;
        };
        let cache = &self.state.chunks;
        let job = self.job;
        let sess = self.sess;
        // Snapshot suffices: a Need only names chunks of manifests
        // sent before it.
        let sent = self.sent.clone();
        let out_tx = out_tx.clone();
        self.serving = Some(Box::pin(async move {
            let _permit = sess.serving.acquire().await.expect("never closed");
            serve_need(cache, job, &sent, needed, &out_tx).await?;
            send(
                &out_tx,
                hub_message::Msg::Chunk(ChunkFrame {
                    build_id: job.id.clone(),
                    eof: true,
                    ..Default::default()
                }),
            )
            .await
        }));
    }

    pub(super) async fn handle_need(
        &mut self,
        n: Need,
        out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    ) -> Result<()> {
        for p in &n.paths {
            if !self.offered.contains(p.as_str()) {
                return Err(err_msg(format!("worker requested unoffered path {p}")));
            }
        }
        let first = self.first_need;
        self.update_known(&n.paths);
        self.first_need = false;
        if first {
            tracing::info!(
                id = self.job.id,
                total = self.offered.len(),
                missing = n.paths.len(),
                "input path negotiation done"
            );
        }
        // A path asked for again (deferred to another build's import
        // that failed) gets its manifest re-sent.
        let mut new = Vec::new();
        for p in n.paths {
            if let Some(e) = self.sent.iter().find(|e| e.0.store_path == p) {
                if !first {
                    let m = manifest(&self.job.id, &e.0, &e.1);
                    send(out_tx, hub_message::Msg::Manifest(m)).await?;
                }
            } else if self.computing.insert(p.clone()) {
                new.push(p);
            }
        }
        let cache = &self.state.chunks;
        for info in order_by_references(query_path_infos(&self.state.daemon_pool, &new).await?) {
            self.tasks.push(Box::pin(async move {
                let recipe = compute_recipe(cache, &info.store_path, &info.msg.nar_sha256).await?;
                Ok((info, recipe))
            }));
        }
        if n.hashes.is_empty() {
            return Ok(());
        }
        self.queued
            .push_back(parse_hashes(&n.hashes)?.into_iter().collect());
        if self.serving.is_none() {
            self.serve_next(out_tx);
        }
        Ok(())
    }

    fn update_known(&self, missing: &[String]) {
        let mut known = self.sess.known.lock().unwrap();
        if self.first_need {
            if known.len() > KNOWN_CAP {
                known.clear();
            }
            let missing: HashSet<&str> = missing.iter().map(String::as_str).collect();
            known.extend(
                self.offered
                    .iter()
                    .filter(|p| !missing.contains(*p))
                    .map(|p| (*p).to_string()),
            );
        } else {
            for p in missing {
                known.remove(p);
            }
        }
    }
}

async fn poll_opt(f: &mut Option<Serving<'_>>) -> Result<()> {
    match f {
        Some(f) => f.await,
        None => pending().await,
    }
}

pub(super) struct Info {
    pub(super) store_path: String,
    pub(super) msg: PathInfoMsg,
}

fn manifest(build_id: &str, info: &Info, recipe: &Recipe) -> Manifest {
    let mut hashes = Vec::with_capacity(recipe.len() * 32);
    let mut sizes = Vec::with_capacity(recipe.len());
    for (h, s) in recipe.iter() {
        hashes.extend_from_slice(h);
        sizes.push(*s);
    }
    Manifest {
        build_id: build_id.to_string(),
        store_path: info.store_path.clone(),
        info: Some(info.msg.clone()),
        hashes,
        sizes,
    }
}

/// References before referrers, largest nar_size first among ready
/// paths (Kahn's algorithm, max-heap) so the biggest import starts
/// earliest. Tolerates self-refs, cycle members go last.
pub(super) fn order_by_references(infos: Vec<Info>) -> Vec<Info> {
    let mut nodes: HashMap<String, Info> = infos
        .into_iter()
        .map(|i| (i.store_path.clone(), i))
        .collect();
    let mut indegree: HashMap<&str, usize> = HashMap::new();
    let mut referrers: HashMap<&str, Vec<&str>> = HashMap::new();
    for (path, info) in &nodes {
        indegree.entry(path).or_default();
        for r in &info.msg.references {
            if r != path && nodes.contains_key(r) {
                *indegree.entry(path).or_default() += 1;
                referrers.entry(r).or_default().push(path);
            }
        }
    }
    let mut ready: BinaryHeap<(u64, &str)> = indegree
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(p, _)| (nodes[*p].msg.nar_size, *p))
        .collect();
    let mut order: Vec<String> = Vec::with_capacity(nodes.len());
    while let Some((_, p)) = ready.pop() {
        order.push(p.to_string());
        for r in referrers.remove(p).unwrap_or_default() {
            let d = indegree.get_mut(r).unwrap();
            *d -= 1;
            if *d == 0 {
                ready.push((nodes[r].msg.nar_size, r));
            }
        }
    }
    let mut rest: Vec<&str> = indegree
        .iter()
        .filter(|(_, d)| **d > 0)
        .map(|(p, _)| *p)
        .collect();
    rest.sort_unstable();
    order.extend(rest.into_iter().map(str::to_string));
    order
        .into_iter()
        .map(|p| nodes.remove(&p).unwrap())
        .collect()
}

async fn query_path_info_chunk(
    pool: &harmonia_store_remote::ConnectionPool,
    paths: &[String],
) -> Result<Vec<Info>> {
    let store_dir = StoreDir::default();
    let mut guard = pool
        .acquire()
        .await
        .map_err(err_ctx("connecting to the local nix-daemon"))?;
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        let sp: StorePath = store_dir.parse(p)?;
        let info = guard
            .execute(|c| c.query_path_info(&sp))
            .await
            .map_err(err_ctx(format!("querying path info for {p}")))?
            .ok_or_else(|| err_msg(format!("{p} is not a valid path in the local store")))?;
        out.push(Info {
            store_path: p.clone(),
            msg: PathInfoMsg {
                nar_sha256: info.nar_hash.digest_bytes().to_vec(),
                nar_size: info.nar_size,
                references: info
                    .references
                    .iter()
                    .map(|r| store_dir.display(r).to_string())
                    .collect(),
                signatures: info.signatures.iter().map(ToString::to_string).collect(),
                deriver: info
                    .deriver
                    .map(|d| store_dir.display(&d).to_string())
                    .unwrap_or_default(),
                ca: info.ca.map(|c| c.to_string()).unwrap_or_default(),
            },
        });
    }
    Ok(out)
}

/// Path info over the daemon protocol, not db.sqlite:
/// harmonia-store-db opens the db with immutable=1, so WAL-only rows
/// (freshly registered inputs, the common case) would be invisible.
async fn query_path_infos(
    pool: &harmonia_store_remote::ConnectionPool,
    paths: &[String],
) -> Result<Vec<Info>> {
    const PARALLELISM: usize = 8;
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let chunk_size = paths.len().div_ceil(PARALLELISM).max(1);
    let chunks = paths
        .chunks(chunk_size)
        .map(|chunk| query_path_info_chunk(pool, chunk));
    let results = futures_util::future::try_join_all(chunks).await?;
    Ok(results.into_iter().flatten().collect())
}

/// Forward the client-shipped build tmp dir (structured attrs,
/// passAsFile files) to the worker.
pub(super) async fn stream_tmp_dir(
    build_id: &str,
    tmp_dir_pack: &[u8],
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
) -> Result<()> {
    for chunk in tmp_dir_pack.chunks(chunkio::CHUNK_SIZE) {
        send(
            out_tx,
            hub_message::Msg::TmpDir(TmpDirArchive::chunk(build_id, chunk.to_vec())),
        )
        .await?;
    }
    send(
        out_tx,
        hub_message::Msg::TmpDir(TmpDirArchive::eof(build_id)),
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::hub::state::Replay;
    use crate::proto::{BuildRequest, CancelBuild};

    fn sized(path: &str, refs: &[&str], nar_size: u64) -> Info {
        Info {
            store_path: path.into(),
            msg: PathInfoMsg {
                nar_size,
                references: refs.iter().map(ToString::to_string).collect(),
                ..Default::default()
            },
        }
    }

    fn info(path: &str, refs: &[&str]) -> Info {
        sized(path, refs, 0)
    }

    fn seq(infos: &[Info]) -> Vec<&str> {
        infos.iter().map(|i| i.store_path.as_str()).collect()
    }

    #[test]
    fn largest_ready_path_streams_first() {
        let big = "/nix/store/aaa-chromium";
        let small = "/nix/store/bbb-sed";
        let dep = "/nix/store/ccc-glibc";
        let ordered = order_by_references(vec![
            sized(small, &[], 10),
            sized(big, &[dep], 1000),
            sized(dep, &[], 1),
        ]);
        assert_eq!(seq(&ordered), vec![small, dep, big]);
    }

    #[test]
    fn references_are_streamed_before_referrers() {
        let dep = "/nix/store/aaa-more-itertools";
        let lib = "/nix/store/bbb-keyring";
        let ordered = order_by_references(vec![info(lib, &[dep, lib]), info(dep, &[])]);
        assert_eq!(seq(&ordered), vec![dep, lib]);
    }

    fn test_job() -> Job {
        Job {
            id: "0123456789abcdef0123456789abcdef".into(),
            key: "k".into(),
            req: BuildRequest::default(),
            tmp_dir_pack: Arc::new(Vec::new()),
            features: vec![],
            replay: Arc::new(Replay::default()),
            listing: Default::default(),
            attempts: 0,
            requeued_at: None,
        }
    }

    /// A manifest computed while the session channel is full must still
    /// reach the worker once it drains, though run_job's select! keeps
    /// dropping progress() meanwhile, and run_job must not block on it.
    #[tokio::test]
    async fn manifest_survives_full_channel() {
        let state = HubState::for_test(Duration::from_secs(1));
        let job = test_job();
        let sess = WorkerSession::new();
        let mut staging = Staging::new(&state, &job, &sess);
        let path = "/nix/store/00000000000000000000000000000000-x";
        staging.computing.insert(path.into());
        staging.tasks.push(Box::pin(async move {
            Ok((info(path, &[]), Arc::new(Vec::new())))
        }));

        let (out_tx, mut out_rx) = mpsc::channel(1);
        let filler = hub_message::Msg::Cancel(CancelBuild::default());
        send(&out_tx, filler).await.unwrap();

        // Same shape as run_job's loop. The tick stands in for in_rx.
        let mut tick = tokio::time::interval(Duration::from_millis(5));
        let mut ticks = 0;
        while ticks < 10 {
            tokio::select! {
                r = staging.progress(&out_tx), if staging.busy() => r.unwrap(),
                _ = tick.tick() => ticks += 1,
            }
        }
        assert!(staging.busy(), "manifest lost");
        out_rx.recv().await.unwrap().unwrap();
        staging.progress(&out_tx).await.unwrap();
        drop(out_tx);
        match out_rx.recv().await.expect("manifest lost").unwrap().msg {
            Some(hub_message::Msg::Manifest(m)) => assert_eq!(m.store_path, path),
            other => panic!("expected manifest, got {other:?}"),
        }
        assert_eq!(staging.sent.len(), 1);
        assert!(!staging.computing.contains(path));
    }

    #[test]
    fn reference_cycles_do_not_loop() {
        let a = "/nix/store/aaa";
        let b = "/nix/store/bbb";
        let ordered = order_by_references(vec![info(a, &[b]), info(b, &[a])]);
        assert_eq!(ordered.len(), 2);
    }
}
