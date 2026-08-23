//! Hub chunk cache for staging fan-out: without it the hub
//! re-compresses the shared base paths for every worker and build.
//! Cached chunks ship as their stored zstd frame. Only chunks seen
//! at least twice are admitted, so one-off leaf paths never fill it.

use std::collections::{HashSet, VecDeque};
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::chunkstore::{ChunkStore, FrameRef, Hash};

/// Bound on remembered first-sightings, ~16 MB of RAM.
const SEEN_CAP: usize = 256 * 1024;

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
}

impl ChunkCache {
    pub fn open(dir: PathBuf, budget: u64) -> io::Result<Self> {
        Ok(Self {
            inner: Mutex::new(Inner {
                store: ChunkStore::open(dir, budget)?,
                seen: VecDeque::new(),
                seen_set: HashSet::new(),
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

    /// A cache write failure only loses future hits.
    pub fn admit(&self, hash: Hash, frame: &[u8]) {
        let mut inner = self.inner.lock().unwrap();
        if let Err(e) = inner.store.insert(hash, frame) {
            tracing::warn!(error = %e, "chunk cache write failed");
        }
    }
}
