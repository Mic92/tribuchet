//! Hub chunk cache for staging fan-out: without it the hub
//! re-compresses the shared base paths for every worker and build.
//! Cached chunks ship as their stored zstd frame. Only chunks seen
//! at least twice are admitted, so one-off leaf paths never fill it.

use std::collections::{HashSet, VecDeque};
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

use std::collections::HashMap;
use std::sync::Arc;

use crate::chunkstore::{ChunkStore, FrameRef, Hash};

/// Bound on remembered first-sightings, ~16 MB of RAM.
const SEEN_CAP: usize = 256 * 1024;

/// Bound on cached recipes. Store paths are immutable, so entries
/// never invalidate, only age out.
const RECIPE_CAP: usize = 64 * 1024;

/// Ordered (hash, uncompressed size) chunk list of one NAR.
pub type Recipe = Arc<Vec<(Hash, u64)>>;

pub enum Disposition {
    /// A stored frame, read outside the cache lock. A failed read
    /// degrades to shipping the chunk inside the run.
    Cached(FrameRef),
    /// Seen before: compress individually and hand the frame to
    /// `admit`.
    Admit,
    /// First sighting: ship inside the current run frame.
    FirstSeen,
}

pub struct ChunkCache {
    inner: Mutex<Inner>,
}

struct Inner {
    store: ChunkStore,
    seen: VecDeque<Hash>,
    seen_set: HashSet<Hash>,
    /// keyed with the nar_sha256 it was computed for
    recipes: HashMap<String, (Vec<u8>, Recipe)>,
    recipe_order: VecDeque<String>,
}

impl ChunkCache {
    pub fn open(dir: PathBuf, budget: u64) -> io::Result<Self> {
        Ok(Self {
            inner: Mutex::new(Inner {
                store: ChunkStore::open(dir, budget)?,
                seen: VecDeque::new(),
                seen_set: HashSet::new(),
                recipes: HashMap::new(),
                recipe_order: VecDeque::new(),
            }),
        })
    }

    pub fn classify(&self, hash: &Hash) -> Disposition {
        let mut inner = self.inner.lock().unwrap();
        if let Some(frame) = inner.store.locate(hash) {
            return Disposition::Cached(frame);
        }
        if inner.seen_set.remove(hash) {
            return Disposition::Admit;
        }
        inner.seen_set.insert(*hash);
        inner.seen.push_back(*hash);
        while inner.seen.len() > SEEN_CAP {
            let old = inner.seen.pop_front().unwrap();
            inner.seen_set.remove(&old);
        }
        Disposition::FirstSeen
    }

    pub fn locate(&self, hash: &Hash) -> Option<FrameRef> {
        self.inner.lock().unwrap().store.locate(hash)
    }

    /// Locate every hash under one lock. None unless all are cached.
    pub fn locate_all(&self, hashes: &HashSet<Hash>) -> Option<Vec<(Hash, FrameRef)>> {
        let mut inner = self.inner.lock().unwrap();
        hashes
            .iter()
            .map(|h| inner.store.locate(h).map(|f| (*h, f)))
            .collect()
    }

    pub fn has_recipe(&self, store_path: &str) -> bool {
        self.inner.lock().unwrap().recipes.contains_key(store_path)
    }

    pub fn recipe(&self, store_path: &str, nar_sha256: &[u8]) -> Option<Recipe> {
        let inner = self.inner.lock().unwrap();
        let (h, r) = inner.recipes.get(store_path)?;
        (h == nar_sha256).then(|| r.clone())
    }

    pub fn store_recipe(&self, store_path: String, nar_sha256: Vec<u8>, recipe: Recipe) {
        let mut inner = self.inner.lock().unwrap();
        if inner
            .recipes
            .insert(store_path.clone(), (nar_sha256, recipe))
            .is_none()
        {
            inner.recipe_order.push_back(store_path);
        }
        while inner.recipe_order.len() > RECIPE_CAP {
            let old = inner.recipe_order.pop_front().unwrap();
            inner.recipes.remove(&old);
        }
    }

    /// A cache write failure only loses future hits.
    pub fn admit(&self, hash: Hash, frame: &[u8]) {
        let mut inner = self.inner.lock().unwrap();
        if let Err(e) = inner.store.insert(hash, frame) {
            tracing::warn!(error = %e, "chunk cache write failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn recipe_is_bound_to_nar_hash() {
        let dir = tempfile::tempdir().unwrap();
        let c = ChunkCache::open(dir.path().to_path_buf(), 1 << 20).unwrap();
        let r: Recipe = Arc::new(vec![([1; 32], 5)]);
        c.store_recipe("/nix/store/p".into(), vec![1], r.clone());
        assert!(c.recipe("/nix/store/p", &[1]).is_some());
        assert!(c.recipe("/nix/store/p", &[2]).is_none());
    }
}
