//! Chunk-recipe staging: recipes for every missing path, one
//! NeedChunks answer, then only the chunks the worker lacks (warm
//! deltas dedup 55-87% against earlier closures). Any chunk failure
//! degrades to plain NARs via the NeedResend fallback.

use std::collections::HashSet;
use std::io;
use std::mem;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc;
use tonic::Status;

use super::{WorkerStaging, order_by_references, query_path_infos};
use crate::chunker::{Chunk, chunk_store_path};
use crate::chunkstore::Hash;
use crate::errors::{Result, err_ctx, err_msg};
use crate::hub::chunkcache::{ChunkCache, Disposition, Recipe};
use crate::hub::relay::{msg_name, recv, send};
use crate::hub::state::{HubState, Job};
use crate::proto::{
    ChunkRun, HubMessage, PathRecipe, StagingComplete, attach_event, hub_message, worker_message,
};
use tokio::task::{JoinHandle, spawn_blocking};

/// Input bytes per run frame: the zstd level 3 window, so splitting
/// costs almost no ratio, and it bounds the message size.
const RUN_BYTES: usize = 2 * 1024 * 1024;

pub(in crate::hub) async fn stage_chunked(
    state: &HubState,
    job: &Job,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    staging: &WorkerStaging,
    missing: &[String],
    in_rx: &mut mpsc::Receiver<worker_message::Msg>,
) -> Result<()> {
    let _permit = staging
        .permits
        .acquire()
        .await
        .expect("staging semaphore closed");
    let t0 = Instant::now();
    let infos = order_by_references(query_path_infos(&state.daemon_pool, missing).await?);
    let cache = state.chunks.as_deref();
    let last = infos.len().saturating_sub(1);
    // Chunking packs each NAR: fan the paths out before the ordered
    // send loop below.
    let recipes: Vec<Recipe> = futures_util::future::try_join_all(
        infos
            .iter()
            .map(|info| compute_recipe(cache, &info.store_path)),
    )
    .await?;
    for (i, info) in infos.iter().enumerate() {
        let recipe = &recipes[i];
        let mut info = info.clone();
        info.build_id = job.id.clone();
        send(out_tx, hub_message::Msg::PathInfo(info)).await?;
        let mut hashes = Vec::with_capacity(recipe.len() * 32);
        let mut sizes = Vec::with_capacity(recipe.len());
        for (h, s) in recipe.iter() {
            hashes.extend_from_slice(h);
            sizes.push(*s);
        }
        send(
            out_tx,
            hub_message::Msg::Recipe(PathRecipe {
                build_id: job.id.clone(),
                store_path: infos[i].store_path.clone(),
                hashes,
                sizes,
                last: i == last,
            }),
        )
        .await?;
    }
    tracing::debug!(
        paths = infos.len(),
        elapsed_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        "recipes sent"
    );

    let needed = await_need_chunks(job, in_rx).await?;
    tracing::debug!(
        needed = needed.len(),
        elapsed_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        "need-chunks received"
    );
    let mut served: HashSet<Hash> = HashSet::new();
    let mut run = RunFrames::default();
    for (info, recipe) in infos.iter().zip(&recipes) {
        // Each needed chunk ships once, from the first path holding it.
        let todo: HashSet<Hash> = recipe
            .iter()
            .map(|(h, _)| *h)
            .filter(|h| needed.contains(h) && !served.contains(h))
            .collect();
        if todo.is_empty() {
            continue;
        }
        served.extend(&todo);
        stream_path_chunks(cache, job, &info.store_path, todo, &mut run, out_tx).await?;
    }
    run.flush(&job.id, out_tx).await?;
    tracing::debug!(
        elapsed_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        "chunk streaming done"
    );
    send(
        out_tx,
        hub_message::Msg::ChunkRun(ChunkRun {
            build_id: job.id.clone(),
            eof: true,
            ..Default::default()
        }),
    )
    .await?;
    send(
        out_tx,
        hub_message::Msg::StagingComplete(StagingComplete {
            build_id: job.id.clone(),
        }),
    )
    .await
}

async fn await_need_chunks(
    job: &Job,
    in_rx: &mut mpsc::Receiver<worker_message::Msg>,
) -> Result<HashSet<Hash>> {
    loop {
        match recv(in_rx).await? {
            worker_message::Msg::NeedChunks(n) => {
                if !n.hashes.len().is_multiple_of(32) {
                    return Err(err_msg("misaligned NeedChunks hashes"));
                }
                return Ok(n
                    .hashes
                    .chunks_exact(32)
                    .map(|h| h.try_into().unwrap())
                    .collect());
            }
            worker_message::Msg::Log(l) => {
                job.replay.publish(attach_event::Event::Log(l.data)).await;
            }
            other => {
                return Err(err_msg(format!(
                    "unexpected worker message while awaiting NeedChunks: {}",
                    msg_name(&other)
                )));
            }
        }
    }
}

/// Serve a recipe from the in-memory cache or pack and chunk the NAR.
async fn compute_recipe(cache: Option<&ChunkCache>, store_path: &str) -> Result<Recipe> {
    if let Some(c) = cache
        && let Some(r) = c.recipe(store_path)
    {
        return Ok(r);
    }
    let t0 = Instant::now();
    let path = store_path.to_string();
    let recipe = spawn_blocking(move || -> Result<Vec<(Hash, u64)>> {
        let mut out = Vec::new();
        chunk_store_path(&path, async |c| {
            out.push((c.hash, c.data.len() as u64));
            Ok(true)
        })?;
        Ok(out)
    })
    .await
    .map_err(err_ctx("recipe task panicked"))??;
    tracing::debug!(
        path = store_path,
        chunks = recipe.len(),
        elapsed_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        "recipe computed"
    );
    let recipe = Arc::new(recipe);
    if let Some(c) = cache {
        c.store_recipe(store_path.to_string(), recipe.clone());
    }
    Ok(recipe)
}

/// Re-pack the path and route its needed chunks: cache hits as their
/// stored frame, admissions individually, the rest into run frames.
async fn stream_path_chunks(
    cache: Option<&ChunkCache>,
    job: &Job,
    store_path: &str,
    todo: HashSet<Hash>,
    run: &mut RunFrames,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<Chunk>(8);
    let path = store_path.to_string();
    let task = spawn_blocking(move || {
        chunk_store_path(&path, async |c| {
            if todo.contains(&c.hash) && tx.send(c).await.is_err() {
                return Err(err_msg("chunk consumer gone"));
            }
            Ok(true)
        })
    });
    while let Some(chunk) = rx.recv().await {
        let frame = match cache.map(|c| c.classify(&chunk.hash)) {
            None | Some(Disposition::FirstSeen) => {
                run.write(&job.id, &chunk.hash, &chunk.data, out_tx).await?;
                continue;
            }
            Some(Disposition::Cached(fref)) => {
                let Ok(frame) = fref.read() else {
                    run.write(&job.id, &chunk.hash, &chunk.data, out_tx).await?;
                    continue;
                };
                frame
            }
            Some(Disposition::Admit) => {
                let frame = zstd::bulk::compress(&chunk.data, 3)
                    .map_err(err_ctx("compressing chunk frame"))?;
                cache.unwrap().admit(chunk.hash, &frame);
                frame
            }
        };
        run.flush(&job.id, out_tx).await?;
        send(
            out_tx,
            hub_message::Msg::ChunkRun(ChunkRun {
                build_id: job.id.clone(),
                hashes: chunk.hash.to_vec(),
                zstd_data: frame,
                eof: false,
            }),
        )
        .await?;
    }
    task.await.map_err(err_ctx("pack task panicked"))?
}

/// One zstd frame per run of consecutive uncached chunks, capped at
/// RUN_BYTES of input per frame. Compression runs one frame behind
/// the packing loop so the two overlap.
#[derive(Default)]
struct RunFrames {
    raw: Vec<u8>,
    hashes: Vec<u8>,
    pending: Option<JoinHandle<io::Result<Vec<u8>>>>,
    pending_hashes: Vec<u8>,
    pending_raw: usize,
}

impl RunFrames {
    async fn write(
        &mut self,
        build_id: &str,
        hash: &Hash,
        data: &[u8],
        out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    ) -> Result<()> {
        self.raw.extend_from_slice(data);
        self.hashes.extend_from_slice(hash);
        if self.raw.len() >= RUN_BYTES {
            self.rotate(build_id, out_tx).await?;
        }
        Ok(())
    }

    /// Send the compressed previous frame and start compressing the
    /// current one in the background.
    async fn rotate(
        &mut self,
        build_id: &str,
        out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    ) -> Result<()> {
        self.drain(build_id, out_tx).await?;
        if self.raw.is_empty() {
            return Ok(());
        }
        let raw = mem::take(&mut self.raw);
        self.pending_hashes = mem::take(&mut self.hashes);
        self.pending_raw = raw.len();
        self.pending = Some(spawn_blocking(move || zstd::bulk::compress(&raw, 3)));
        Ok(())
    }

    async fn drain(
        &mut self,
        build_id: &str,
        out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    ) -> Result<()> {
        let Some(task) = self.pending.take() else {
            return Ok(());
        };
        let data = task
            .await
            .map_err(err_ctx("compress task panicked"))?
            .map_err(err_ctx("compressing run frame"))?;
        let hashes = mem::take(&mut self.pending_hashes);
        tracing::debug!(
            chunks = hashes.len() / 32,
            raw = self.pending_raw,
            compressed = data.len(),
            "run frame sent"
        );
        send(
            out_tx,
            hub_message::Msg::ChunkRun(ChunkRun {
                build_id: build_id.to_string(),
                hashes,
                zstd_data: data,
                eof: false,
            }),
        )
        .await
    }

    async fn flush(
        &mut self,
        build_id: &str,
        out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    ) -> Result<()> {
        self.rotate(build_id, out_tx).await?;
        self.drain(build_id, out_tx).await
    }
}
