//! Input staging: path-info queries and NAR/tmp-dir streaming to the worker.

use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use harmonia_store_path::{StoreDir, StorePath};
use harmonia_store_remote::DaemonStore as _;
use tokio::io::AsyncReadExt as _;
use tokio::sync::mpsc;
use tonic::Status;

use super::super::state::{HubState, Job};
use super::{WorkerStaging, send};
use crate::errors::{Result, err_ctx, err_msg};
use crate::proto::{
    HubMessage, NarTransfer, PathInfoMsg, StagingComplete, TmpDirArchive, hub_message,
};
use crate::{chunkio, rt};

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

/// Stream this build's missing inputs and tmp dir under the session's
/// staging permit.
pub(super) async fn stage_inputs(
    state: &HubState,
    job: &Job,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    staging: &WorkerStaging,
    missing: &[String],
) -> Result<()> {
    // Serialize only the import: negotiation before this is read-only
    // on the worker store, so it runs in parallel (bounded by
    // RequestJob credits) instead of gating throughput on its
    // round-trip.
    let _permit = staging
        .permits
        .acquire()
        .await
        .expect("staging semaphore closed");
    stream_inputs(state, job, out_tx, missing).await?;
    stream_tmp_dir(&job.id, &job.tmp_dir_pack, out_tx).await
}

/// Stream inputs re-requested after staging, then send StagingComplete.
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
    stream_inputs(state, job, out_tx, missing).await?;
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
) -> Result<()> {
    let infos = order_by_references(query_path_infos(&state.daemon_pool, paths).await?);
    let mut infos = infos.into_iter();
    let mut inflight: VecDeque<(PathInfoMsg, Pack)> = VecDeque::new();
    loop {
        while inflight.len() < PACK_PIPELINE {
            let Some(info) = infos.next() else { break };
            let pack = spawn_pack(&info.store_path);
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
fn order_by_references(infos: Vec<PathInfoMsg>) -> Vec<PathInfoMsg> {
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
async fn query_path_infos(
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

/// NAR-pack a store path and zstd-compress on the blocking pool,
/// feeding a bounded channel.
fn spawn_pack(store_path: &str) -> Pack {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
    let path = store_path.to_string();
    let task = tokio::task::spawn_blocking(move || -> Result<()> {
        rt::name_current_thread("trib-pack");
        // harmonia's NAR pack is async-only; drive it on a current-thread
        // runtime here so its blocking file reads stay off the shared
        // runtime workers.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(err_ctx("building NAR pack runtime"))?;
        rt.block_on(async move {
            let nar = harmonia_file_nar::archive::NarByteStream::new(PathBuf::from(&path));
            let mut enc = async_compression::tokio::bufread::ZstdEncoder::with_quality(
                tokio_util::io::StreamReader::new(nar),
                async_compression::Level::Precise(3),
            );
            let mut buf = vec![0u8; chunkio::CHUNK_SIZE];
            loop {
                let n = enc
                    .read(&mut buf)
                    .await
                    .map_err(err_ctx(format!("packing {path}")))?;
                if n == 0 {
                    break;
                }
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    break; // consumer gone
                }
            }
            Ok(())
        })
    });
    Pack { rx, task }
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
