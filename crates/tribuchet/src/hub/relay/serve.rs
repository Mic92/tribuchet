//! Serving the chunks of a Need: cached frames as stored, uncached
//! chunks by re-serializing the path that holds them.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::thread;
use std::time::Instant;

use futures_util::StreamExt as _;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::spawn_blocking;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use zstd::bulk::compress;

use crate::chunker::{Chunk, chunk_store_path};
use crate::chunkstore::Hash;
use crate::errors::{Result, err_ctx, err_msg};
use crate::hub::chunkcache::{ChunkCache, Disposition, Recipe};
use crate::hub::relay::send;
use crate::hub::relay::staging::Info;
use crate::hub::state::Job;
use crate::proto::{ChunkFrame, HubMessage, hub_message};

/// Each needed chunk ships once, from the first manifest holding it.
pub(super) async fn serve_need(
    cache: &Arc<ChunkCache>,
    job: &Job,
    sent: &[(Info, Recipe)],
    needed: HashSet<Hash>,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
) -> Result<()> {
    let t0 = Instant::now();
    let mut served: HashSet<Hash> = HashSet::new();
    for (info, recipe) in sent {
        let todo: HashSet<Hash> = recipe
            .iter()
            .map(|(h, _)| *h)
            .filter(|h| needed.contains(h) && !served.contains(h))
            .collect();
        if todo.is_empty() {
            continue;
        }
        served.extend(&todo);
        let rest = serve_cached(cache, &job.id, todo, out_tx).await?;
        if rest.is_empty() {
            continue;
        }
        stream_path_chunks(cache, job, &info.store_path, rest, out_tx).await?;
    }
    if served.len() != needed.len() {
        return Err(err_msg("worker needs chunks outside every manifest"));
    }
    tracing::debug!(
        chunks = served.len(),
        elapsed_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        "need served"
    );
    Ok(())
}

fn cores() -> usize {
    thread::available_parallelism().map_or(4, usize::from)
}

/// One core per pack: a large closure must not flood the blocking pool.
static PACK_PERMITS: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(cores()));

/// Serve a recipe from the in-memory cache or pack and chunk the NAR.
pub(super) async fn compute_recipe(cache: &ChunkCache, store_path: &str) -> Result<Recipe> {
    if let Some(r) = cache.recipe(store_path) {
        return Ok(r);
    }
    let _permit = PACK_PERMITS.acquire().await.expect("pack semaphore closed");
    let t0 = Instant::now();
    let path = store_path.to_string();
    let recipe = spawn_blocking(move || -> Result<Vec<(Hash, u64)>> {
        let mut out = Vec::new();
        chunk_store_path(Path::new(&path), |c| {
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
    cache.store_recipe(store_path.to_string(), recipe.clone());
    Ok(recipe)
}

async fn send_frame(
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    build_id: &str,
    hash: &Hash,
    zstd: Vec<u8>,
) -> Result<()> {
    send(
        out_tx,
        hub_message::Msg::Chunk(ChunkFrame {
            build_id: build_id.to_string(),
            hash: hash.to_vec(),
            zstd,
            eof: false,
        }),
    )
    .await
}

/// Serve needed chunks from the cache, returning what still needs a repack.
async fn serve_cached(
    cache: &ChunkCache,
    build_id: &str,
    todo: HashSet<Hash>,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
) -> Result<HashSet<Hash>> {
    let Some(frames) = cache.locate_all(&todo) else {
        return Ok(todo);
    };
    let mut rest = todo;
    for (hash, fref) in frames {
        // Evicted between locate and read: the repack picks it up.
        let Ok(frame) = fref.read() else { break };
        send_frame(out_tx, build_id, &hash, frame).await?;
        rest.remove(&hash);
    }
    Ok(rest)
}

/// Re-pack the path and send its needed chunks in recipe order,
/// compressing up to one chunk per core in parallel.
async fn stream_path_chunks(
    cache: &Arc<ChunkCache>,
    job: &Job,
    store_path: &str,
    todo: HashSet<Hash>,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
) -> Result<()> {
    let (tx, rx) = mpsc::channel::<Chunk>(cores());
    let path = store_path.to_string();
    let packer = spawn_blocking(move || {
        chunk_store_path(Path::new(&path), |c| {
            if todo.contains(&c.hash) && tx.blocking_send(c).is_err() {
                return Err(err_msg("chunk consumer gone"));
            }
            Ok(true)
        })
    });
    let mut frames = ReceiverStream::new(rx)
        .map(|chunk| {
            let cache = cache.clone();
            spawn_blocking(move || frame_for(&cache, &chunk).map(|f| (chunk.hash, f)))
        })
        .buffered(cores());
    while let Some(frame) = frames.next().await {
        let (hash, frame) = frame.map_err(err_ctx("compress task panicked"))??;
        send_frame(out_tx, &job.id, &hash, frame).await?;
    }
    packer.await.map_err(err_ctx("pack task panicked"))?
}

/// The cached frame if there is one, else compress, admitting to the
/// cache on second sighting.
fn frame_for(cache: &ChunkCache, chunk: &Chunk) -> Result<Vec<u8>> {
    let admit = match cache.classify(&chunk.hash) {
        Disposition::Cached(fref) => match fref.read() {
            Ok(frame) => return Ok(frame),
            Err(_) => false,
        },
        Disposition::FirstSeen => false,
        Disposition::Admit => true,
    };
    let frame = compress(&chunk.data, 3).map_err(err_ctx("compressing chunk"))?;
    if admit {
        cache.admit(chunk.hash, &frame);
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn serve_cached_skips_repack_and_reports_leftovers() {
        let dir = tempfile::tempdir().unwrap();
        let cache = ChunkCache::open(dir.path().to_path_buf(), 1 << 20).unwrap();
        let a: Hash = [1; 32];
        let b: Hash = [2; 32];
        cache.admit(a, &compress(b"hello", 3).unwrap());

        let (tx, mut rx) = mpsc::channel(8);

        let todo: HashSet<Hash> = [a, b].into();
        let rest = serve_cached(&cache, "b1", todo.clone(), &tx).await.unwrap();
        assert_eq!(rest, todo);

        let rest = serve_cached(&cache, "b1", [a].into(), &tx).await.unwrap();
        assert!(rest.is_empty());
        let msg = rx.recv().await.unwrap().unwrap();
        let Some(hub_message::Msg::Chunk(c)) = msg.msg else {
            panic!("expected ChunkFrame");
        };
        assert_eq!(c.hash, a.to_vec());
        assert_eq!(zstd::bulk::decompress(&c.zstd, 1 << 20).unwrap(), b"hello");
    }
}
