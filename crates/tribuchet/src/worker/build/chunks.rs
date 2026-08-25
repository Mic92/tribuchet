//! Worker-side chunk staging. A path dispatches to the import pool
//! once every recipe chunk sits in the store, fed the stored zstd
//! frames as-is (the import decoder is multi-frame).

use std::collections::HashMap;
use std::mem;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use zstd::bulk::decompress;

use harmonia_store_path::StoreDir;
use tokio::sync::{mpsc, watch};
use tokio::task::spawn_blocking;

use super::import_pool::{ImportHandle, ImportJob, ImportPool, ImportState};
use super::{ActiveBuild, StagingStatus};
use crate::chunkstore::{ChunkStore, Hash};
use crate::errors::{Result, err_ctx, err_msg};
use crate::proto::{ChunkFrame, MAX_NAR_BYTES, MAX_RESEND_ROUNDS, Manifest, Need};
use crate::store::parse_path_info;

pub(super) struct ChunkStaging {
    store: Arc<Mutex<ChunkStore>>,
    /// path -> ordered recipe, kept until the import succeeded
    recipes: HashMap<String, Vec<(Hash, u64)>>,
    /// chunk -> paths waiting on it
    waiters: HashMap<Hash, Vec<String>>,
    /// path -> distinct chunks still missing from the store
    remaining: HashMap<String, usize>,
}

impl ChunkStaging {
    pub(super) fn new(store: Arc<Mutex<ChunkStore>>) -> Self {
        Self {
            store,
            recipes: HashMap::new(),
            waiters: HashMap::new(),
            remaining: HashMap::new(),
        }
    }

    /// Register a recipe. Returns the hashes to request (not in the
    /// store, not already awaited) and whether the path is complete.
    fn add_recipe(
        &mut self,
        path: String,
        hashes: &[u8],
        sizes: &[u64],
    ) -> Result<(Vec<u8>, bool)> {
        if !hashes.len().is_multiple_of(32) || hashes.len() / 32 != sizes.len() {
            return Err(err_msg(format!("malformed manifest for {path}")));
        }
        let recipe: Vec<(Hash, u64)> = hashes
            .chunks_exact(32)
            .zip(sizes)
            .map(|(h, s)| (h.try_into().unwrap(), *s))
            .collect();
        let need = self.await_missing(&path, &recipe);
        let ready = !self.remaining.contains_key(&path);
        self.recipes.insert(path, recipe);
        Ok((need, ready))
    }

    fn await_missing(&mut self, path: &str, recipe: &[(Hash, u64)]) -> Vec<u8> {
        let store = self.store.lock().unwrap();
        let mut need: Vec<u8> = Vec::new();
        let mut missing = 0;
        for (hash, _) in recipe {
            if store.contains(hash) {
                continue;
            }
            let waiters = self.waiters.entry(*hash).or_default();
            if waiters.is_empty() {
                need.extend_from_slice(hash);
            }
            if !waiters.iter().any(|p| p == path) {
                waiters.push(path.to_string());
                missing += 1;
            }
        }
        if missing > 0 {
            *self.remaining.entry(path.to_string()).or_default() += missing;
        }
        need
    }

    /// Paths still waiting on chunks after every Need was answered
    /// (evicted, or stored by another build without waking us):
    /// re-request what the store lacks now, report what is complete.
    fn reawait_stuck(&mut self) -> (Vec<u8>, Vec<String>) {
        self.waiters.clear();
        let stuck: Vec<String> = self.remaining.drain().map(|(p, _)| p).collect();
        let mut need = Vec::new();
        let mut ready = Vec::new();
        for path in stuck {
            let recipe = self.recipes[&path].clone();
            need.extend(self.await_missing(&path, &recipe));
            if !self.remaining.contains_key(&path) {
                ready.push(path);
            }
        }
        (need, ready)
    }

    /// Store one frame as received, integrity is checked at import.
    /// Returns the paths whose last missing chunk arrived.
    pub(super) fn ingest(&mut self, hash: &[u8], frame: &[u8]) -> Result<Vec<String>> {
        let hash: Hash = hash
            .try_into()
            .map_err(|_| err_msg("malformed chunk hash"))?;
        self.store
            .lock()
            .unwrap()
            .insert(hash, frame)
            .map_err(|e| err_msg(format!("chunk store write failed: {e}")))?;
        let mut ready = Vec::new();
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
        Ok(ready)
    }

    fn recipe(&self, path: &str) -> Result<Vec<(Hash, u64)>> {
        self.recipes
            .get(path)
            .cloned()
            .ok_or_else(|| err_msg(format!("no recipe for ready path {path}")))
    }

    pub(super) fn forget_path(&mut self, path: &str) {
        self.recipes.remove(path);
    }
}

impl ActiveBuild {
    pub(super) fn need(&mut self, paths: Vec<String>, hashes: Vec<u8>) -> Option<Need> {
        if paths.is_empty() && hashes.is_empty() {
            return None;
        }
        if !hashes.is_empty() {
            self.needs_outstanding += 1;
        }
        Some(Need {
            build_id: self.assignment.build_id.clone(),
            paths,
            hashes,
        })
    }

    pub(in crate::worker) async fn feed_manifest(
        &mut self,
        m: Manifest,
    ) -> Result<(Option<Need>, StagingStatus)> {
        let hashes = self.take_manifest(m).await?;
        let need = self.need(Vec::new(), hashes);
        Ok((need, self.try_complete().await?))
    }

    /// A manifest for a pending path: dispatch it if complete, else
    /// return the chunk hashes to request.
    pub(super) async fn take_manifest(&mut self, m: Manifest) -> Result<Vec<u8>> {
        if !self.pending.contains(&m.store_path) {
            if self.tolerated(&m.store_path) {
                return Ok(Vec::new());
            }
            return Err(err_msg(format!(
                "hub sent a manifest for unrequested path {}",
                m.store_path
            )));
        }
        let info = m
            .info
            .as_ref()
            .ok_or_else(|| err_msg(format!("manifest for {} lacks path info", m.store_path)))?;
        if info.nar_size > MAX_NAR_BYTES {
            return Err(err_msg(format!(
                "input {} exceeds the {MAX_NAR_BYTES} byte NAR limit",
                m.store_path
            )));
        }
        let parsed = parse_path_info(&m.store_path, info)
            .map_err(err_ctx(format!("path info for {}", m.store_path)))?;
        self.infos.insert(m.store_path.clone(), parsed);
        let (hashes, ready) = self
            .chunks
            .add_recipe(m.store_path.clone(), &m.hashes, &m.sizes)?;
        if ready {
            self.start_chunk_import(&m.store_path).await?;
        }
        Ok(hashes)
    }

    /// Put imported-but-failed paths back to pending and await their
    /// chunks again: forgotten ones are re-requested, paths still
    /// complete dispatch right away.
    pub(super) async fn restage(&mut self, paths: Vec<String>) -> Result<Option<Need>> {
        let mut hashes = Vec::new();
        let mut ready = Vec::new();
        for path in paths {
            let recipe = self.chunks.recipe(&path)?;
            hashes.extend(self.chunks.await_missing(&path, &recipe));
            if !self.chunks.remaining.contains_key(&path) {
                ready.push(path.clone());
            }
            self.pending.insert(path);
        }
        for path in ready {
            self.start_chunk_import(&path).await?;
        }
        Ok(self.need(Vec::new(), hashes))
    }

    pub(in crate::worker) async fn feed_chunk(
        &mut self,
        c: ChunkFrame,
    ) -> Result<(Option<Need>, StagingStatus)> {
        let mut need = None;
        if c.eof {
            self.needs_outstanding = self
                .needs_outstanding
                .checked_sub(1)
                .ok_or_else(|| err_msg("chunk eof without a Need"))?;
            if self.needs_outstanding == 0 && !self.chunks.remaining.is_empty() {
                let (hashes, ready) = self.chunks.reawait_stuck();
                if !hashes.is_empty() {
                    if self.resend_rounds >= MAX_RESEND_ROUNDS {
                        return Err(err_msg("input chunks keep going missing"));
                    }
                    self.resend_rounds += 1;
                    tracing::warn!(chunks = hashes.len() / 32, "chunks lost, requesting again");
                }
                for p in ready {
                    self.start_chunk_import(&p).await?;
                }
                need = self.need(Vec::new(), hashes);
            }
        } else {
            for p in self.chunks.ingest(&c.hash, &c.zstd)? {
                self.start_chunk_import(&p).await?;
            }
        }
        Ok((need, self.try_complete().await?))
    }

    /// The daemon rejects an import with an invalid reference, so a
    /// complete path is parked until every reference is an input or
    /// an own import dispatched before it (the pool gates on those).
    async fn start_chunk_import(&mut self, path: &str) -> Result<()> {
        let mut queue = vec![path.to_string()];
        while let Some(path) = queue.pop() {
            if self.unstaged_ref(&path)?.is_some() {
                self.parked.insert(path);
                continue;
            }
            self.dispatch_import(&path).await?;
            queue.extend(self.parked.drain());
        }
        Ok(())
    }

    pub(super) async fn retry_parked(&mut self) -> Result<()> {
        for p in mem::take(&mut self.parked) {
            self.start_chunk_import(&p).await?;
        }
        Ok(())
    }

    fn unstaged_ref(&self, path: &str) -> Result<Option<String>> {
        let store_dir = StoreDir::default();
        for r in &self.infos[path].info.references {
            let r = store_dir.display(r).to_string();
            if r == path || self.inputs.contains(&r) || self.imports.contains_key(&r) {
                continue;
            }
            if self.pending.contains(&r) || self.waits.contains_key(&r) {
                return Ok(Some(r));
            }
            return Err(err_msg(format!(
                "reference {r} of {path} is outside the input closure"
            )));
        }
        Ok(None)
    }

    async fn dispatch_import(&mut self, path: &str) -> Result<()> {
        let recipe = self.chunks.recipe(path)?;
        if !self.pending.remove(path) {
            return Err(err_msg(format!("chunk-ready path {path} was not pending")));
        }
        let info = self.infos[path].clone();
        let store_dir = StoreDir::default();
        let gates = info
            .info
            .references
            .iter()
            .filter_map(|r| self.imports.get(&store_dir.display(r).to_string()))
            .map(|h| h.done.clone())
            .collect();
        let (tx, rx) = mpsc::channel::<Bytes>(8);
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
        let store = self.chunks.store.clone();
        let feeder = spawn_blocking(move || feed_import(&store, &recipe, &tx));
        self.imports.insert(
            path.to_string(),
            ImportHandle {
                done: done_rx,
                feeder,
            },
        );
        Ok(())
    }
}

/// Stream a recipe's chunks, decompressed and verified, to the import.
/// Returns the chunks found corrupt or missing, after forgetting them
/// in the store so a retry requests them again.
fn feed_import(
    store: &Mutex<ChunkStore>,
    recipe: &[(Hash, u64)],
    tx: &mpsc::Sender<Bytes>,
) -> Vec<Hash> {
    let mut bad = Vec::new();
    for (hash, size) in recipe {
        let Some(raw) = read_verified(store, hash, *size) else {
            tracing::warn!(chunk = hex::encode(hash), "stored chunk corrupt or missing");
            store.lock().unwrap().forget(hash);
            bad.push(*hash);
            continue;
        };
        // One bad chunk dooms the import. Keep checking the rest so a
        // single retry covers them all, but stop feeding.
        if bad.is_empty() && tx.blocking_send(raw.into()).is_err() {
            break;
        }
    }
    bad
}

fn read_verified(store: &Mutex<ChunkStore>, hash: &Hash, size: u64) -> Option<Vec<u8>> {
    let frame = store.lock().unwrap().locate(hash)?.read().ok()?;
    let raw = decompress(&frame, usize::try_from(size).ok()?).ok()?;
    (raw.len() as u64 == size && blake3::hash(&raw).as_bytes() == hash).then_some(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zstd::bulk::compress;

    #[test]
    fn feed_import_forgets_corrupt_and_missing_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let store = Mutex::new(ChunkStore::open(dir.path().to_path_buf(), 1 << 20).unwrap());
        let good = b"good chunk".to_vec();
        let good_hash: Hash = *blake3::hash(&good).as_bytes();
        let liar: Hash = [7; 32];
        let missing: Hash = [9; 32];
        {
            let mut s = store.lock().unwrap();
            s.insert(good_hash, &compress(&good, 3).unwrap()).unwrap();
            s.insert(liar, &compress(b"not what the hash says", 3).unwrap())
                .unwrap();
        }
        let recipe = [(good_hash, good.len() as u64), (liar, 22), (missing, 1)];
        let (tx, mut rx) = mpsc::channel(8);
        let bad = feed_import(&store, &recipe, &tx);
        assert_eq!(bad, vec![liar, missing]);
        assert_eq!(rx.try_recv().unwrap().as_ref(), good.as_slice());
        assert!(rx.try_recv().is_err());
        let s = store.lock().unwrap();
        assert!(s.contains(&good_hash));
        assert!(!s.contains(&liar));
    }
}
