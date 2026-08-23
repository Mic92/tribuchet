//! Worker-side chunk staging. A path dispatches to the import pool
//! once every recipe chunk sits in the store, fed the stored zstd
//! frames as-is (the import decoder is multi-frame).

use std::collections::HashMap;
use std::num::NonZero;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use harmonia_store_path::StoreDir;
use tokio::sync::{mpsc, watch};
use tokio::task::spawn_blocking;

use super::import_pool::{ImportHandle, ImportJob, ImportPool, ImportState};
use super::{ActiveBuild, StagingStatus};
use crate::chunkstore::{ChunkStore, Hash};
use crate::errors::{Result, err_ctx, err_msg};
use crate::proto::{ChunkRun as ChunkRunMsg, PathRecipe};

pub(super) struct ChunkStaging {
    store: Arc<Mutex<ChunkStore>>,
    /// path -> ordered recipe, removed at dispatch
    recipes: HashMap<String, Vec<(Hash, u64)>>,
    /// chunk -> paths waiting on it
    waiters: HashMap<Hash, Vec<String>>,
    /// path -> distinct chunks still missing from the store
    remaining: HashMap<String, usize>,
    /// uncompressed sizes for re-splitting run frames
    sizes: HashMap<Hash, u64>,
}

/// Verify, compress and store a run's chunks, fanned over threads:
/// zstd-3 at ~330 MB/s per core is otherwise the staging bottleneck.
fn store_chunks(store: &Mutex<ChunkStore>, raw: &[u8], expect: &[(Hash, usize)]) -> Result<()> {
    let mut jobs = Vec::with_capacity(expect.len());
    let mut off = 0;
    for &(hash, size) in expect {
        jobs.push((hash, &raw[off..off + size]));
        off += size;
    }
    let threads = thread::available_parallelism()
        .map_or(1, NonZero::get)
        .clamp(1, 4);
    let next = AtomicUsize::new(0);
    thread::scope(|s| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                s.spawn(|| -> Result<()> {
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(&(hash, chunk)) = jobs.get(i) else {
                            return Ok(());
                        };
                        if *blake3::hash(chunk).as_bytes() != hash {
                            return Err(err_msg("chunk hash mismatch"));
                        }
                        let frame =
                            zstd::bulk::compress(chunk, 3).map_err(err_ctx("compressing chunk"))?;
                        // This build reassembles from the store, so unlike
                        // a cache fill a write failure must fail the round.
                        if let Err(e) = store.lock().unwrap().insert(hash, &frame) {
                            return Err(err_msg(format!("chunk store write failed: {e}")));
                        }
                    }
                })
            })
            .collect();
        workers
            .into_iter()
            .try_for_each(|w| w.join().map_err(|_| err_msg("chunk worker panicked"))?)
    })
}

impl ChunkStaging {
    pub(super) fn new(store: Arc<Mutex<ChunkStore>>) -> Self {
        Self {
            store,
            recipes: HashMap::new(),
            waiters: HashMap::new(),
            remaining: HashMap::new(),
            sizes: HashMap::new(),
        }
    }

    pub(super) fn add_recipe(&mut self, path: String, hashes: &[u8], sizes: &[u64]) -> Result<()> {
        if !hashes.len().is_multiple_of(32) || hashes.len() / 32 != sizes.len() {
            return Err(err_msg(format!("malformed recipe for {path}")));
        }
        let mut recipe = Vec::with_capacity(sizes.len());
        for (h, s) in hashes.chunks_exact(32).zip(sizes) {
            let hash: Hash = h.try_into().unwrap();
            // The same content always chunks the same way, so a size
            // conflict means a corrupt or malicious recipe.
            if *self.sizes.entry(hash).or_insert(*s) != *s {
                return Err(err_msg(format!("conflicting chunk sizes for {path}")));
            }
            recipe.push((hash, *s));
        }
        self.recipes.insert(path, recipe);
        Ok(())
    }

    /// After the last recipe: the union of chunks the store lacks
    /// (concatenated hashes for NeedChunks) and the paths that can
    /// dispatch right away.
    pub(super) fn seal(&mut self) -> (Vec<u8>, Vec<String>) {
        let store = self.store.lock().unwrap();
        let mut needed: Vec<u8> = Vec::new();
        let mut ready = Vec::new();
        for (path, recipe) in &self.recipes {
            let mut missing = 0;
            for (hash, _) in recipe {
                if store.contains(hash) {
                    continue;
                }
                let waiters = self.waiters.entry(*hash).or_default();
                if waiters.is_empty() {
                    needed.extend_from_slice(hash);
                }
                if !waiters.contains(path) {
                    waiters.push(path.clone());
                    missing += 1;
                }
            }
            if missing == 0 {
                ready.push(path.clone());
            } else {
                self.remaining.insert(path.clone(), missing);
            }
        }
        (needed, ready)
    }

    /// Ingest one run frame: decompress, split at the recipe sizes,
    /// verify each BLAKE3, re-compress per chunk and store. Returns
    /// the paths whose last missing chunk arrived.
    pub(super) async fn ingest(&mut self, hashes: &[u8], data: &[u8]) -> Result<Vec<String>> {
        if !hashes.len().is_multiple_of(32) {
            return Err(err_msg("misaligned ChunkRun hashes"));
        }
        let mut expect: Vec<(Hash, usize)> = Vec::with_capacity(hashes.len() / 32);
        let mut total = 0usize;
        for h in hashes.chunks_exact(32) {
            let hash: Hash = h.try_into().unwrap();
            let size = *self
                .sizes
                .get(&hash)
                .ok_or_else(|| err_msg("ChunkRun chunk outside every recipe"))?;
            let size = usize::try_from(size).map_err(|_| err_msg("oversized chunk"))?;
            expect.push((hash, size));
            total += size;
        }
        let store = self.store.clone();
        let data = data.to_vec();
        let t0 = Instant::now();
        spawn_blocking(move || -> Result<()> {
            let raw =
                zstd::bulk::decompress(&data, total).map_err(err_ctx("decompressing chunk run"))?;
            if raw.len() != total {
                return Err(err_msg("chunk run size mismatch"));
            }
            let dec_us = u64::try_from(t0.elapsed().as_micros()).unwrap_or(u64::MAX);
            let r = store_chunks(&store, &raw, &expect);
            tracing::debug!(
                raw = raw.len(),
                dec_us,
                store_us = u64::try_from(t0.elapsed().as_micros()).unwrap_or(u64::MAX) - dec_us,
                "chunk run ingested"
            );
            r
        })
        .await
        .map_err(err_ctx("chunk ingest task panicked"))??;
        let mut ready = Vec::new();
        for h in hashes.chunks_exact(32) {
            let hash: Hash = h.try_into().unwrap();
            for path in self.waiters.remove(&hash).unwrap_or_default() {
                let left = self
                    .remaining
                    .get_mut(&path)
                    .ok_or_else(|| err_msg("waiter without remaining count"))?;
                *left -= 1;
                if *left == 0 {
                    self.remaining.remove(&path);
                    ready.push(path);
                }
            }
        }
        Ok(ready)
    }

    /// Remove and return a ready path's recipe for dispatch.
    pub(super) fn take_recipe(&mut self, path: &str) -> Result<Vec<(Hash, u64)>> {
        self.recipes
            .remove(path)
            .ok_or_else(|| err_msg(format!("no recipe for ready path {path}")))
    }

    /// Paths whose chunks never all arrived, handed to the plain
    /// NAR resend fallback.
    pub(super) fn take_undispatched(&mut self) -> Vec<String> {
        self.waiters.clear();
        self.remaining.clear();
        self.recipes.drain().map(|(p, _)| p).collect()
    }

    pub(super) fn store(&self) -> Arc<Mutex<ChunkStore>> {
        self.store.clone()
    }
}

impl ActiveBuild {
    /// Returns the NeedChunks hash union once the last recipe arrived.
    pub(in crate::worker) async fn feed_recipe(
        &mut self,
        r: PathRecipe,
    ) -> Result<(Option<Vec<u8>>, StagingStatus)> {
        let store = self
            .ctx
            .chunks
            .clone()
            .ok_or_else(|| err_msg("hub sent a recipe but the chunk store is disabled"))?;
        let cs = self.chunks.get_or_insert_with(|| ChunkStaging::new(store));
        if matches!(self.pending.get(&r.store_path), Some(Some(_))) {
            cs.add_recipe(r.store_path, &r.hashes, &r.sizes)?;
        } else if !self.tolerated(&r.store_path) {
            return Err(err_msg(format!(
                "hub sent a recipe for unrequested path {}",
                r.store_path
            )));
        }
        if !r.last {
            return Ok((None, StagingStatus::InProgress));
        }
        let (needed, ready) = self.chunks.as_mut().unwrap().seal();
        tracing::debug!(
            needed = needed.len() / 32,
            ready = ready.len(),
            "recipes sealed"
        );
        for p in ready {
            self.start_chunk_import(&p).await?;
        }
        let status = self.try_complete().await?;
        Ok((Some(needed), status))
    }

    pub(in crate::worker) async fn feed_chunk_run(
        &mut self,
        c: ChunkRunMsg,
    ) -> Result<StagingStatus> {
        if self.chunks.is_none() {
            return Err(err_msg("hub sent a ChunkRun without any recipe"));
        }
        if !c.eof {
            let ready = self
                .chunks
                .as_mut()
                .unwrap()
                .ingest(&c.hashes, &c.zstd_data)
                .await?;
            for p in ready {
                self.start_chunk_import(&p).await?;
            }
        }
        self.try_complete().await
    }

    /// Feed a fully-present path's stored frames to the import pool.
    /// Completion tracks through `done` like an eof'd NAR (tx None).
    async fn start_chunk_import(&mut self, path: &str) -> Result<()> {
        let recipe = self.chunks.as_mut().unwrap().take_recipe(path)?;
        let Some(Some(info)) = self.pending.remove(path) else {
            return Err(err_msg(format!("chunk-ready path {path} was not pending")));
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
            path.to_string(),
            ImportHandle {
                tx: None,
                done: done_rx,
            },
        );
        let store = self.chunks.as_ref().unwrap().store();
        spawn_blocking(move || {
            for (hash, _) in recipe {
                let fref = store.lock().unwrap().locate(&hash);
                // A chunk evicted between readiness and here truncates
                // the stream. The daemon rejects the short NAR and the
                // import surfaces the failure.
                let Some(frame) = fref.and_then(|f| f.read().ok()) else {
                    return;
                };
                if tx.blocking_send(frame.into()).is_err() {
                    return;
                }
            }
        });
        Ok(())
    }
}
