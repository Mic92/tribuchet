//! Hub chunk cache for staging fan-out: without it the hub
//! re-compresses the shared base paths for every worker and build.
//! Cached chunks ship as their stored zstd frame. Only chunks seen
//! at least twice are admitted, so one-off leaf paths never fill it.

use std::collections::{HashSet, VecDeque};
use std::io;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use std::collections::HashMap;
use std::sync::Arc;

use crate::chunkstore::{ChunkStore, FrameRef, Hash, PinGuard};
#[cfg(test)]
use crate::rt::drives_tasks;

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

/// Every method but the recipe ones takes the store lock, which an
/// admit holds across pack writes, fsyncs and eviction: call them
/// from the blocking pool, never from an async task.
pub struct ChunkCache {
    inner: Mutex<Inner>,
    /// Apart from the store, so the runtime's lookups never wait on it.
    recipes: Mutex<Recipes>,
}

struct Inner {
    store: ChunkStore,
    seen: VecDeque<Hash>,
    seen_set: HashSet<Hash>,
}

#[derive(Default)]
struct Recipes {
    /// keyed with the nar_sha256 it was computed for
    by_path: HashMap<String, (Vec<u8>, Recipe)>,
    order: VecDeque<String>,
}

impl ChunkCache {
    pub fn open(dir: PathBuf, budget: u64) -> io::Result<Self> {
        Ok(Self {
            inner: Mutex::new(Inner {
                store: ChunkStore::open(dir, budget)?,
                seen: VecDeque::new(),
                seen_set: HashSet::new(),
            }),
            recipes: Mutex::default(),
        })
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        #[cfg(test)]
        assert!(!drives_tasks(), "chunk store locked in an async context");
        self.inner.lock().unwrap()
    }

    pub fn classify(&self, hash: &Hash) -> Disposition {
        let mut inner = self.inner();
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

    pub fn pin(&self, hashes: impl IntoIterator<Item = Hash>) -> PinGuard {
        self.inner().store.pin(hashes)
    }

    pub fn locate(&self, hash: &Hash) -> Option<FrameRef> {
        self.inner().store.locate(hash)
    }

    /// Locate every hash under one lock. None unless all are cached.
    pub fn locate_all(&self, hashes: &HashSet<Hash>) -> Option<Vec<(Hash, FrameRef)>> {
        let mut inner = self.inner();
        hashes
            .iter()
            .map(|h| inner.store.locate(h).map(|f| (*h, f)))
            .collect()
    }

    pub fn has_recipe(&self, store_path: &str) -> bool {
        self.recipes
            .lock()
            .unwrap()
            .by_path
            .contains_key(store_path)
    }

    pub fn recipe(&self, store_path: &str, nar_sha256: &[u8]) -> Option<Recipe> {
        let recipes = self.recipes.lock().unwrap();
        let (h, r) = recipes.by_path.get(store_path)?;
        (h == nar_sha256).then(|| r.clone())
    }

    pub fn store_recipe(&self, store_path: String, nar_sha256: Vec<u8>, recipe: Recipe) {
        let mut recipes = self.recipes.lock().unwrap();
        if recipes
            .by_path
            .insert(store_path.clone(), (nar_sha256, recipe))
            .is_none()
        {
            recipes.order.push_back(store_path);
        }
        while recipes.order.len() > RECIPE_CAP {
            let old = recipes.order.pop_front().unwrap();
            recipes.by_path.remove(&old);
        }
    }

    pub fn admit(&self, hash: Hash, frame: &[u8]) -> io::Result<()> {
        self.inner().store.insert(hash, frame)
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;

    use super::*;
    use crate::chunkstore::probe;

    #[test]
    fn recipe_is_bound_to_nar_hash() {
        let dir = tempfile::tempdir().unwrap();
        let c = ChunkCache::open(dir.path().to_path_buf(), 1 << 20).unwrap();
        let r: Recipe = Arc::new(vec![([1; 32], 5)]);
        c.store_recipe("/nix/store/p".into(), vec![1], r.clone());
        assert!(c.recipe("/nix/store/p", &[1]).is_some());
        assert!(c.recipe("/nix/store/p", &[2]).is_none());
    }

    /// Staging looks recipes up on the runtime, so they must not share a
    /// lock with the store: an admit holds that one across file I/O.
    /// An admit that dies inside its pack write poisons what it holds.
    #[test]
    fn recipes_share_no_lock_with_store_io() {
        let dir = tempfile::tempdir().unwrap();
        let c = ChunkCache::open(dir.path().to_path_buf(), 1 << 20).unwrap();
        c.store_recipe("/nix/store/p".into(), vec![1], Arc::new(Vec::new()));
        probe::record(|| panic!("dies inside a pack write"));
        assert!(catch_unwind(AssertUnwindSafe(|| c.admit([1; 32], b"frame"))).is_err());
        probe::record(|| true);
        let lookups = catch_unwind(AssertUnwindSafe(|| {
            c.store_recipe("/nix/store/q".into(), vec![2], Arc::new(Vec::new()));
            (
                c.has_recipe("/nix/store/q"),
                c.recipe("/nix/store/p", &[1]).is_some(),
            )
        }));
        assert_eq!(
            lookups.ok(),
            Some((true, true)),
            "a recipe lookup took the lock the admit held across file I/O"
        );
    }
}
