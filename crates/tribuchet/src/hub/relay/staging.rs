//! Input staging: path-info queries and NAR/tmp-dir streaming to the worker.

mod chunked;
pub(super) use chunked::stage_chunked;

use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::io::Write as _;
use std::mem;
use std::sync::{Arc, Mutex};

use harmonia_store_path::{StoreDir, StorePath};
use harmonia_store_remote::DaemonStore as _;
use tokio::sync::{mpsc, watch};
use tonic::Status;

use super::{WorkerStaging, send};
use crate::chunker::{Chunk, chunk_store_path};
use crate::chunkio;
use crate::errors::{Result, err_ctx, err_msg};
use crate::hub::chunkcache::{ChunkCache, Disposition};
use crate::hub::state::{HubState, Job};
use crate::proto::{
    HubMessage, NarTransfer, PathInfoMsg, StagingComplete, TmpDirArchive, hub_message,
};
use tokio::task::spawn_blocking;
use zstd::stream::write::Encoder;

/// Reject paths we never offered and dedupe the rest.
pub(super) fn validate_missing(
    offered_paths: &[String],
    requested: Vec<String>,
) -> Result<Vec<String>> {
    let offered: HashSet<&String> = offered_paths.iter().collect();
    let mut missing = Vec::new();
    let mut seen = HashSet::new();
    for p in requested {
        if !offered.contains(&p) {
            return Err(err_msg(format!("worker requested unoffered path {p}")));
        }
        if seen.insert(p.clone()) {
            missing.push(p);
        }
    }
    Ok(missing)
}

/// Tmp dir first, then the offer minus the sent-set. With no
/// session knowledge of the offer, wait for MissingPaths instead of
/// blasting a possibly warm worker. Streamed paths are recorded for
/// the caller's delta.
pub(super) async fn stage_optimistic(
    state: &HubState,
    job: &Job,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    staging: &WorkerStaging,
    streamed: &Mutex<HashSet<String>>,
    mut missing_rx: watch::Receiver<Option<Vec<String>>>,
) -> Result<()> {
    let _permit = staging
        .permits
        .acquire()
        .await
        .expect("staging semaphore closed");
    stream_tmp_dir(&job.id, &job.tmp_dir_pack, out_tx).await?;
    // Chunk sessions stage missing paths as recipes after the answer,
    // so there is nothing to stream optimistically here.
    if staging.chunked {
        return Ok(());
    }
    let complement: Vec<String> = job
        .req
        .input_paths
        .iter()
        .filter(|p| !staging.holds(p))
        .cloned()
        .collect();
    let candidates = if complement.len() == job.req.input_paths.len() {
        let missing = missing_rx
            .wait_for(Option::is_some)
            .await
            .map_err(|_| err_msg("build gone before the MissingPaths answer"))?;
        missing.clone().unwrap()
    } else {
        complement
    };
    stream_inputs(state, job, out_tx, &candidates, &mut |p| {
        if staging.mark_sent(p) {
            streamed.lock().unwrap().insert(p.to_string());
            true
        } else {
            false
        }
    })
    .await
}

/// Stream inputs the worker asked for beyond the optimistic stream,
/// then send StagingComplete.
pub(super) async fn restage_inputs(
    state: &HubState,
    job: &Job,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    staging: &WorkerStaging,
    missing: &[String],
) -> Result<()> {
    let _permit = staging
        .permits
        .acquire()
        .await
        .expect("staging semaphore closed");
    stream_inputs(state, job, out_tx, missing, &mut |_| true).await?;
    staging.mark_all_sent(missing.iter());
    send(
        out_tx,
        hub_message::Msg::StagingComplete(StagingComplete {
            build_id: job.id.clone(),
        }),
    )
    .await
}

/// Packs compressed ahead of the in-order send: one zstd-3 encoder
/// cannot fill a 1 Gbit link on its own, eight measured 1.5x and
/// deeper buys nothing.
const PACK_PIPELINE: usize = 8;

async fn stream_inputs(
    state: &HubState,
    job: &Job,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    paths: &[String],
    admit: &mut (dyn FnMut(&str) -> bool + Send),
) -> Result<()> {
    let infos = order_by_references(query_path_infos(&state.daemon_pool, paths).await?);
    let mut infos = infos.into_iter();
    let mut inflight: VecDeque<(PathInfoMsg, Pack)> = VecDeque::new();
    loop {
        while inflight.len() < PACK_PIPELINE {
            let Some(info) = infos.next() else { break };
            if !admit(&info.store_path) {
                continue;
            }
            let pack = spawn_pack(state.chunks.clone(), &info.store_path);
            inflight.push_back((info, pack));
        }
        let Some((mut info, pack)) = inflight.pop_front() else {
            break;
        };
        let path = info.store_path.clone();
        info.build_id = job.id.clone();
        send(out_tx, hub_message::Msg::PathInfo(info)).await?;
        let res = forward_pack(&job.id, &path, pack, out_tx).await;
        if res.is_err() {
            for (_, pack) in inflight {
                pack.task.abort();
                let _ = pack.task.await;
            }
            return res;
        }
    }
    Ok(())
}

/// References before referrers, largest nar_size first among ready
/// paths (Kahn's algorithm, max-heap): with parallel worker imports
/// this starts the biggest import earliest so it hides behind the
/// rest of the transfer. Tolerates self-refs. Cycle members are
/// appended at the end in arbitrary order.
pub(super) fn order_by_references(infos: Vec<PathInfoMsg>) -> Vec<PathInfoMsg> {
    let mut nodes: HashMap<String, PathInfoMsg> = infos
        .into_iter()
        .map(|i| (i.store_path.clone(), i))
        .collect();
    let mut indegree: HashMap<&str, usize> = HashMap::new();
    let mut referrers: HashMap<&str, Vec<&str>> = HashMap::new();
    for (path, info) in &nodes {
        indegree.entry(path).or_default();
        for r in &info.references {
            if r != path && nodes.contains_key(r) {
                *indegree.entry(path).or_default() += 1;
                referrers.entry(r).or_default().push(path);
            }
        }
    }
    let mut ready: BinaryHeap<(u64, &str)> = indegree
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(p, _)| (nodes[*p].nar_size, *p))
        .collect();
    let mut order: Vec<String> = Vec::with_capacity(nodes.len());
    while let Some((_, p)) = ready.pop() {
        order.push(p.to_string());
        for r in referrers.remove(p).unwrap_or_default() {
            let d = indegree.get_mut(r).unwrap();
            *d -= 1;
            if *d == 0 {
                ready.push((nodes[r].nar_size, r));
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

/// Per-path query info from one daemon connection, for a slice of paths.
async fn query_path_info_chunk(
    pool: &harmonia_store_remote::ConnectionPool,
    paths: &[String],
) -> Result<Vec<PathInfoMsg>> {
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
        out.push(PathInfoMsg {
            build_id: String::new(), // filled in by the caller
            store_path: p.clone(),
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
        });
    }
    Ok(out)
}

/// Path info over the daemon protocol, not db.sqlite:
/// harmonia-store-db opens the db with immutable=1, so WAL-only rows
/// (freshly registered inputs, the common case) would be invisible.
pub(super) async fn query_path_infos(
    pool: &harmonia_store_remote::ConnectionPool,
    paths: &[String],
) -> Result<Vec<PathInfoMsg>> {
    // Spread the per-path query_path_info round trips over several
    // daemon connections; the pool caps real concurrency (one per CPU).
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

struct Pack {
    rx: mpsc::Receiver<Vec<u8>>,
    task: tokio::task::JoinHandle<Result<()>>,
}

/// NAR-pack a store path on the blocking pool, chunk it and feed
/// zstd frames into a bounded channel: cached chunks as their stored
/// frame (no compression CPU), everything between two cache hits as
/// one fresh run frame at the full streaming-window ratio. Without a
/// cache the whole NAR is a single run, exactly the old behavior.
fn spawn_pack(cache: Option<Arc<ChunkCache>>, store_path: &str) -> Pack {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
    let path = store_path.to_string();
    let task = spawn_blocking(move || -> Result<()> {
        let mut run = RunEncoder::default();
        let mut gone = false;
        chunk_store_path(&path, async |c| {
            gone = !emit_chunk(cache.as_deref(), c, &mut run, &tx).await?;
            Ok(!gone)
        })?;
        if !gone && let Some(out) = run.finish()? {
            let _ = tx.blocking_send(out);
        }
        Ok(())
    });
    Pack { rx, task }
}

/// Route one chunk: cache hits and admissions ship as their own
/// frame, first-sightings join the current run. Returns false when
/// the consumer is gone.
async fn emit_chunk(
    cache: Option<&ChunkCache>,
    chunk: Chunk,
    run: &mut RunEncoder,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<bool> {
    let frame = match cache.map(|c| c.classify(&chunk.hash)) {
        None | Some(Disposition::FirstSeen) => return run.write(&chunk.data, tx).await,
        Some(Disposition::Cached(fref)) => match fref.read() {
            Ok(frame) => frame,
            Err(_) => return run.write(&chunk.data, tx).await,
        },
        Some(Disposition::Admit) => {
            let frame =
                zstd::bulk::compress(&chunk.data, 3).map_err(err_ctx("compressing chunk frame"))?;
            cache.unwrap().admit(chunk.hash, &frame);
            frame
        }
    };
    if !run.flush(tx).await? {
        return Ok(false);
    }
    Ok(tx.send(frame).await.is_ok())
}

/// One zstd frame per run of consecutive uncached chunks, drained to
/// the channel in message-sized pieces as it grows.
#[derive(Default)]
struct RunEncoder {
    enc: Option<Encoder<'static, Vec<u8>>>,
}

impl RunEncoder {
    async fn write(&mut self, data: &[u8], tx: &mpsc::Sender<Vec<u8>>) -> Result<bool> {
        let enc = match &mut self.enc {
            Some(enc) => enc,
            None => self
                .enc
                .insert(Encoder::new(Vec::new(), 3).map_err(err_ctx("creating zstd encoder"))?),
        };
        enc.write_all(data).map_err(err_ctx("zstd write"))?;
        if enc.get_ref().len() >= chunkio::CHUNK_SIZE {
            let out = mem::take(enc.get_mut());
            return Ok(tx.send(out).await.is_ok());
        }
        Ok(true)
    }

    async fn flush(&mut self, tx: &mpsc::Sender<Vec<u8>>) -> Result<bool> {
        match self.finish()? {
            Some(out) => Ok(tx.send(out).await.is_ok()),
            None => Ok(true),
        }
    }

    /// End the current frame and hand back its remaining bytes.
    fn finish(&mut self) -> Result<Option<Vec<u8>>> {
        let Some(enc) = self.enc.take() else {
            return Ok(None);
        };
        let out = enc.finish().map_err(err_ctx("finishing zstd frame"))?;
        Ok((!out.is_empty()).then_some(out))
    }
}

async fn forward_pack(
    build_id: &str,
    store_path: &str,
    mut pack: Pack,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
) -> Result<()> {
    while let Some(chunk) = pack.rx.recv().await {
        send(
            out_tx,
            hub_message::Msg::Nar(NarTransfer::chunk(build_id, store_path, chunk)),
        )
        .await?;
    }
    pack.task.await??;
    send(
        out_tx,
        hub_message::Msg::Nar(NarTransfer::eof(build_id, store_path)),
    )
    .await
}

/// Forward the client-shipped build tmp dir entries (structured attrs,
/// passAsFile files) to the worker. Always sent last: its EOF tells
/// the worker to start the build.
async fn stream_tmp_dir(
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
    use super::*;

    fn sized(path: &str, refs: &[&str], nar_size: u64) -> PathInfoMsg {
        PathInfoMsg {
            build_id: String::new(),
            store_path: path.into(),
            nar_sha256: Vec::new(),
            nar_size,
            references: refs.iter().map(ToString::to_string).collect(),
            signatures: Vec::new(),
            deriver: String::new(),
            ca: String::new(),
        }
    }

    fn info(path: &str, refs: &[&str]) -> PathInfoMsg {
        sized(path, refs, 0)
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
        let seq: Vec<&str> = ordered.iter().map(|i| i.store_path.as_str()).collect();
        // dep unblocks big, which then outranks small.
        assert_eq!(seq, vec![small, dep, big]);
    }

    #[test]
    fn references_are_streamed_before_referrers() {
        // keyring references more-itertools; offered in referrer-first
        // order, as Nix's inputPaths can be.
        let dep = "/nix/store/aaa-more-itertools";
        let lib = "/nix/store/bbb-keyring";
        let ordered = order_by_references(vec![info(lib, &[dep, lib]), info(dep, &[])]);
        let seq: Vec<&str> = ordered.iter().map(|i| i.store_path.as_str()).collect();
        assert_eq!(seq, vec![dep, lib]);
    }

    #[test]
    fn missing_paths_are_validated_against_the_offer() {
        let offered = vec!["/nix/store/aaa".to_string(), "/nix/store/bbb".to_string()];
        let dup = vec![
            "/nix/store/aaa".to_string(),
            "/nix/store/aaa".to_string(),
            "/nix/store/bbb".to_string(),
        ];
        assert_eq!(validate_missing(&offered, dup).unwrap(), offered);
        assert!(validate_missing(&offered, vec!["/etc/shadow".into()]).is_err());
    }

    #[test]
    fn reference_cycles_do_not_loop() {
        let a = "/nix/store/aaa";
        let b = "/nix/store/bbb";
        let ordered = order_by_references(vec![info(a, &[b]), info(b, &[a])]);
        assert_eq!(ordered.len(), 2);
    }
}
