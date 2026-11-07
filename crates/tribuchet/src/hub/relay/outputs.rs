//! Output delivery: ask the worker for the recipe chunks the cache
//! lacks, then assemble each NAR from cache frames plus arriving
//! chunks, verifying every chunk's BLAKE3 against the recipe.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::spawn_blocking;
use tonic::Status;

use super::extras::{ExtraImport, start_extra};
use super::{msg_name, recv, send};
use crate::chunker::{Recipe, decode_chunk, parse_recipe};
use crate::chunkstore::{Hash, PinGuard};
use crate::errors::{Result, err_ctx, err_msg};
use crate::hub::chunkcache::ChunkCache;
use crate::hub::state::{HubState, Job};
use crate::proto::{
    HubMessage, Manifest, Need, OutputNar, attach_event, hub_message, worker_message,
};

pub(super) struct Announced {
    store_path: String,
    recipe: Recipe,
}

impl Announced {
    fn new(store_path: String, hashes: &[u8], sizes: &[u64]) -> Result<Self> {
        let recipe = parse_recipe(&store_path, hashes, sizes)?;
        Ok(Self { store_path, recipe })
    }
}

/// Checked to be exactly the requested set: a missing output is a
/// build failure, an extra one would let a worker plant arbitrary
/// store paths on the client.
pub(super) fn verify_set(
    reported: Vec<Manifest>,
    requested: &BTreeMap<String, String>,
) -> Result<Vec<Announced>> {
    let mut out = Vec::with_capacity(reported.len());
    let mut seen = HashSet::new();
    for o in reported {
        if !requested.values().any(|r| *r == o.store_path) || !seen.insert(o.store_path.clone()) {
            return Err(err_msg(format!(
                "worker result contains unrequested output {}",
                o.store_path
            )));
        }
        out.push(Announced::new(o.store_path, &o.hashes, &o.sizes)?);
    }
    if let Some(missing) = requested.values().find(|r| !seen.contains(*r)) {
        return Err(err_msg(format!(
            "worker result is missing output {missing}"
        )));
    }
    Ok(out)
}

pub(super) fn parse_extras(reported: Vec<Manifest>) -> Result<Vec<(Announced, Manifest)>> {
    reported
        .into_iter()
        .map(|e| {
            Ok((
                Announced::new(e.store_path.clone(), &e.hashes, &e.sizes)?,
                e,
            ))
        })
        .collect()
}

/// Chunks arrive in the order `send_chunks` on the worker emits them:
/// recipe order across outputs then extras, each needed hash once.
struct ChunkSource<'a> {
    cache: &'a Arc<ChunkCache>,
    needed: HashSet<Hash>,
    _pin: PinGuard,
    in_rx: &'a mut mpsc::Receiver<worker_message::Msg>,
}

impl ChunkSource<'_> {
    /// The chunk's zstd frame, plaintext verified against the recipe.
    /// The delivery's hashes are pinned, so repeats read back from the
    /// cache. Cache I/O runs on the blocking pool.
    async fn get(&mut self, hash: &Hash, size: usize) -> Result<Vec<u8>> {
        let (cache, h) = (self.cache.clone(), *hash);
        let frame = if self.needed.remove(hash) {
            let frame = self.receive(hash).await?;
            decode_chunk(&frame, hash, size).map_err(err_ctx("output chunk"))?;
            spawn_blocking(move || cache.admit(h, &frame).map(|()| frame))
                .await
                .map_err(err_ctx("cache admit task panicked"))?
                .map_err(|e| err_msg(format!("caching output chunk: {e}")))?
        } else {
            let frame = spawn_blocking(move || cache.locate(&h).and_then(|f| f.read().ok()))
                .await
                .map_err(err_ctx("cache read task panicked"))?
                .ok_or_else(|| err_msg("pinned output chunk missing from the cache"))?;
            decode_chunk(&frame, hash, size).map_err(err_ctx("cached output chunk"))?;
            frame
        };
        Ok(frame)
    }

    async fn receive(&mut self, hash: &Hash) -> Result<Vec<u8>> {
        let c = match recv(self.in_rx).await? {
            worker_message::Msg::Chunk(c) if !c.eof => c,
            other => {
                return Err(err_msg(format!(
                    "expected output chunk, got {}",
                    msg_name(&other)
                )));
            }
        };
        if c.hash != hash[..] {
            return Err(err_msg("worker sent output chunks out of recipe order"));
        }
        Ok(c.zstd)
    }

    async fn finish(self) -> Result<()> {
        match recv(self.in_rx).await? {
            worker_message::Msg::Chunk(c) if c.eof => Ok(()),
            other => Err(err_msg(format!(
                "expected end of output chunks, got {}",
                msg_name(&other)
            ))),
        }
    }
}

pub(super) async fn deliver_outputs(
    state: &HubState,
    job: &Job,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    in_rx: &mut mpsc::Receiver<worker_message::Msg>,
    outputs: Vec<Announced>,
    extras: Vec<(Announced, Manifest)>,
) -> Result<()> {
    let cache = &state.chunks;
    let all: Vec<Hash> = outputs
        .iter()
        .chain(extras.iter().map(|(a, _)| a))
        .flat_map(|a| a.recipe.iter().map(|(h, _)| *h))
        .collect();
    let c = cache.clone();
    let (pin, needed, hashes) = spawn_blocking(move || {
        let pin = c.pin(all.iter().copied());
        let mut needed = HashSet::new();
        let mut hashes = Vec::new();
        for h in &all {
            if !needed.contains(h) && c.locate(h).is_none() {
                needed.insert(*h);
                hashes.extend_from_slice(h);
            }
        }
        (pin, needed, hashes)
    })
    .await
    .map_err(err_ctx("cache lookup task panicked"))?;
    tracing::debug!(
        id = job.id,
        needed = needed.len(),
        "requesting output chunks"
    );
    send(
        out_tx,
        hub_message::Msg::Need(Need {
            build_id: job.id.clone(),
            hashes,
            paths: Vec::new(),
        }),
    )
    .await?;
    let mut src = ChunkSource {
        cache,
        needed,
        _pin: pin,
        in_rx,
    };
    for a in &outputs {
        for (hash, size) in &a.recipe {
            let frame = src.get(hash, *size).await?;
            job.replay
                .publish(attach_event::Event::Output(OutputNar {
                    store_path: a.store_path.clone(),
                    zstd_nar_chunk: frame,
                    eof: false,
                }))
                .await;
        }
        job.replay
            .publish(attach_event::Event::Output(OutputNar {
                store_path: a.store_path.clone(),
                zstd_nar_chunk: Vec::new(),
                eof: true,
            }))
            .await;
    }
    for (a, e) in extras {
        let ExtraImport { tx, task } = start_extra(state, e)?;
        for (hash, size) in &a.recipe {
            let frame = src.get(hash, *size).await?;
            if tx.send(frame.into()).await.is_err() {
                break;
            }
        }
        drop(tx);
        // The daemon checks nar_sha256 against the bytes it imported.
        task.await??;
        job.replay
            .publish(attach_event::Event::AddedPath(a.store_path))
            .await;
    }
    src.finish().await
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;
    use std::time::{Duration, Instant};

    use zstd::bulk::compress;

    use super::*;
    use crate::chunkstore::probe;
    use crate::hub::state::Replay;
    use crate::proto::{BuildRequest, ChunkFrame};

    /// Delivery admits a received chunk and reads its repeat back on the
    /// blocking pool: the runtime's thread, the test's own, does no store
    /// I/O and takes no store lock.
    #[tokio::test]
    async fn delivery_keeps_store_io_off_the_runtime() {
        let state = HubState::for_test(Duration::ZERO);
        let job = Job {
            id: "b1".into(),
            key: "k1".into(),
            req: BuildRequest::default(),
            tmp_dir_pack: Arc::new(Vec::new()),
            features: vec![],
            replay: Arc::new(Replay::default()),
            listing: StdMutex::default(),
            attempts: 0,
            queued_at: Instant::now(),
        };
        let data = b"an output chunk".to_vec();
        let hash: Hash = *blake3::hash(&data).as_bytes();
        let size = data.len() as u64;
        let out = "/nix/store/00000000000000000000000000000000-out".to_string();
        let announced = Announced::new(out, &[hash, hash].concat(), &[size, size]).unwrap();
        let (out_tx, mut out_rx) = mpsc::channel(8);
        let (in_tx, mut in_rx) = mpsc::channel(8);
        for (zstd, eof) in [(compress(&data, 3).unwrap(), false), (Vec::new(), true)] {
            let c = ChunkFrame {
                build_id: "b1".into(),
                hash: hash.to_vec(),
                zstd,
                eof,
            };
            in_tx.send(worker_message::Msg::Chunk(c)).await.unwrap();
        }
        let io_here = probe::record(|| true);
        deliver_outputs(
            &state,
            &job,
            &out_tx,
            &mut in_rx,
            vec![announced],
            Vec::new(),
        )
        .await
        .unwrap();
        assert!(io_here.borrow().is_empty(), "store I/O on the runtime");
        let Some(hub_message::Msg::Need(need)) = out_rx.recv().await.unwrap().unwrap().msg else {
            panic!("expected a Need");
        };
        assert_eq!(need.hashes, hash.to_vec(), "the Need lists the chunk once");
    }
}
