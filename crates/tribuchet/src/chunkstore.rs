//! Log-structured chunk cache with S3-FIFO eviction, shared by hub
//! and worker. Never a source of truth: losing a chunk costs a
//! re-transfer, the daemon's NAR-hash check backstops correctness.
//!
//! S3-FIFO because cold stagings are one-hit-wonder scans that would
//! evict the hot working set under LRU. Its FIFO queues merge with
//! append-only pack files (queue order = pack order): eviction
//! retires the oldest pack with one unlink, and only re-hit chunks
//! are ever copied forward.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

mod pack;

use pack::PackWriter;

/// BLAKE3 of the uncompressed chunk bytes.
pub type Hash = [u8; 32];

/// A located frame, read without holding the store lock.
pub struct FrameRef {
    file: Arc<File>,
    offset: u64,
    len: u32,
}

impl FrameRef {
    /// A read error is a miss, like `get`.
    pub fn read(&self) -> io::Result<Vec<u8>> {
        pack::read_frame(&self.file, self.offset, self.len)
    }
}

const SMALL_FRACTION: u64 = 10;
const FREQ_MAX: u8 = 3;

/// Ghosts are an admission hint: a truncated-key collision at worst
/// promotes one cold chunk, so 8 bytes suffice.
fn ghost_key(hash: &Hash) -> u64 {
    u64::from_le_bytes(hash[..8].try_into().expect("hash is 32 bytes"))
}

#[derive(Clone, Copy, PartialEq)]
enum Queue {
    Small,
    Main,
}

struct Entry {
    pack: u64,
    offset: u64,
    len: u32,
    freq: u8,
}

pub struct ChunkStore {
    dir: PathBuf,
    budget: u64,
    seal_bytes: u64,
    map: HashMap<Hash, Entry>,
    /// sealed pack id -> file size
    packs: HashMap<u64, u64>,
    /// Lazily opened read handles, dropped with their pack. The Arc
    /// keeps an evicted pack readable for in-flight FrameRefs.
    readers: HashMap<u64, Arc<File>>,
    small: VecDeque<u64>,
    main: VecDeque<u64>,
    active_small: Option<PackWriter>,
    active_main: Option<PackWriter>,
    small_bytes: u64,
    main_bytes: u64,
    ghost: VecDeque<u64>,
    ghost_set: HashSet<u64>,
    pins: Arc<Mutex<HashMap<Hash, u32>>>,
    next_id: u64,
}

/// Keeps a set of hashes exempt from eviction while alive.
pub struct PinGuard {
    pins: Arc<Mutex<HashMap<Hash, u32>>>,
    hashes: Vec<Hash>,
}

impl Drop for PinGuard {
    fn drop(&mut self) {
        let mut pins = self.pins.lock().unwrap();
        for h in &self.hashes {
            if let Some(n) = pins.get_mut(h) {
                *n -= 1;
                if *n == 0 {
                    pins.remove(h);
                }
            }
        }
    }
}

impl ChunkStore {
    pub fn open(dir: PathBuf, budget: u64) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        // 64 MiB packs for small budgets keep eviction fine-grained.
        let seal_bytes = (budget / 16).clamp(4 << 20, 256 << 20);
        let mut store = Self {
            dir,
            budget,
            seal_bytes,
            map: HashMap::new(),
            packs: HashMap::new(),
            readers: HashMap::new(),
            small: VecDeque::new(),
            main: VecDeque::new(),
            active_small: None,
            active_main: None,
            small_bytes: 0,
            main_bytes: 0,
            ghost: VecDeque::new(),
            ghost_set: HashSet::new(),
            pins: Arc::default(),
            next_id: 0,
        };
        store.load()?;
        Ok(store)
    }

    /// Everything on disk loads into main with freq 0.
    fn load(&mut self) -> io::Result<()> {
        let mut ids: Vec<u64> = Vec::new();
        for e in fs::read_dir(&self.dir)? {
            let name = e?.file_name();
            if let Some(hex) = name.to_str().and_then(|n| n.strip_suffix(".pack"))
                && let Ok(id) = u64::from_str_radix(hex, 16)
            {
                ids.push(id);
            }
        }
        ids.sort_unstable();
        for id in ids {
            let entries = match pack::load_index(&self.dir, id) {
                Ok(entries) => entries,
                Err(e) if e.kind() == io::ErrorKind::NotFound => pack::recover(&self.dir, id)?,
                Err(e) => return Err(e),
            };
            let size = fs::metadata(pack::pack_path(&self.dir, id))?.len();
            for (hash, offset, len) in entries {
                self.map.insert(
                    hash,
                    Entry {
                        pack: id,
                        offset,
                        len,
                        freq: 0,
                    },
                );
            }
            self.packs.insert(id, size);
            self.main.push_back(id);
            self.main_bytes += size;
            self.next_id = self.next_id.max(id + 1);
        }
        Ok(())
    }

    /// Existence only. No frequency bump, so probing for a Need
    /// does not fake reuse.
    pub fn contains(&self, hash: &Hash) -> bool {
        self.map.contains_key(hash)
    }

    /// Drop a chunk found corrupt or unreadable. The bytes stay dead in
    /// their pack until eviction. On reopen the pack index resurrects
    /// the entry, and the next import check forgets it again.
    pub fn forget(&mut self, hash: &Hash) {
        self.map.remove(hash);
    }

    /// Locate a frame for reading outside the store lock: the pread
    /// dominates get() and would otherwise convoy concurrent callers.
    pub fn locate(&mut self, hash: &Hash) -> Option<FrameRef> {
        let entry = self.map.get_mut(hash)?;
        entry.freq = (entry.freq + 1).min(FREQ_MAX);
        self.peek(hash)
    }

    pub fn peek(&mut self, hash: &Hash) -> Option<FrameRef> {
        let entry = self.map.get(hash)?;
        let (pack, offset, len) = (entry.pack, entry.offset, entry.len);
        let file = self.reader(pack).ok()?.clone();
        Some(FrameRef { file, offset, len })
    }

    /// Exempt `hashes` (present or admitted later) from eviction until
    /// the guard drops.
    pub fn pin(&self, hashes: impl IntoIterator<Item = Hash>) -> PinGuard {
        let hashes: Vec<Hash> = hashes.into_iter().collect();
        let mut pins = self.pins.lock().unwrap();
        for h in &hashes {
            *pins.entry(*h).or_default() += 1;
        }
        drop(pins);
        PinGuard {
            pins: self.pins.clone(),
            hashes,
        }
    }

    /// Admit one zstd frame. A ghost hit goes straight to main.
    pub fn insert(&mut self, hash: Hash, frame: &[u8]) -> io::Result<()> {
        if self.map.contains_key(&hash) {
            return Ok(());
        }
        let queue = if self.ghost_remove(&hash) {
            Queue::Main
        } else {
            Queue::Small
        };
        self.append(queue, &hash, frame, 0)?;
        self.evict()?;
        self.trim_ghost();
        Ok(())
    }

    fn append(&mut self, queue: Queue, hash: &Hash, frame: &[u8], freq: u8) -> io::Result<()> {
        let (dir, next_id) = (&self.dir, &mut self.next_id);
        let writer = match queue {
            Queue::Small => &mut self.active_small,
            Queue::Main => &mut self.active_main,
        };
        if writer.is_none() {
            let id = *next_id;
            *next_id += 1;
            *writer = Some(PackWriter::create(dir, id)?);
        }
        let w = writer.as_mut().unwrap();
        let before = w.len;
        let offset = w.append(hash, frame)?;
        let (pack, grown, full) = (w.id, w.len - before, w.len >= self.seal_bytes);
        self.map.insert(
            *hash,
            Entry {
                pack,
                offset,
                len: u32::try_from(frame.len()).expect("append checked the frame size"),
                freq,
            },
        );
        match queue {
            Queue::Small => self.small_bytes += grown,
            Queue::Main => self.main_bytes += grown,
        }
        if full {
            self.seal(queue)?;
        }
        Ok(())
    }

    fn seal(&mut self, queue: Queue) -> io::Result<()> {
        let writer = match queue {
            Queue::Small => &mut self.active_small,
            Queue::Main => &mut self.active_main,
        };
        let Some(w) = writer.take() else {
            return Ok(());
        };
        let (id, size) = (w.id, w.len);
        w.seal(&self.dir)?;
        self.packs.insert(id, size);
        match queue {
            Queue::Small => self.small.push_back(id),
            Queue::Main => self.main.push_back(id),
        }
        Ok(())
    }

    /// Stops once a full round over main freed nothing (all pinned or
    /// hot).
    fn evict(&mut self) -> io::Result<()> {
        let mut unfreed_round = 0;
        while self.small_bytes + self.main_bytes > self.budget {
            if self.small_bytes > self.budget / SMALL_FRACTION {
                if self.small.is_empty() {
                    self.seal(Queue::Small)?;
                }
                if let Some(id) = self.small.pop_front() {
                    self.retire(id, Queue::Small)?;
                    continue;
                }
            }
            if self.main.is_empty() {
                self.seal(Queue::Main)?;
            }
            let Some(id) = self.main.pop_front() else {
                // Only unsealed small data left. Nothing to evict.
                break;
            };
            let before = self.small_bytes + self.main_bytes;
            self.retire(id, Queue::Main)?;
            if self.small_bytes + self.main_bytes < before {
                unfreed_round = 0;
            } else {
                unfreed_round += 1;
                if unfreed_round > self.main.len() {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Evict one pack: small survivors (freq > 0) promote to main,
    /// the rest leave a ghost. Main survivors are copied forward with
    /// freq - 1 (S3-FIFO reinsertion as log compaction).
    fn retire(&mut self, id: u64, queue: Queue) -> io::Result<()> {
        let entries = pack::load_index(&self.dir, id)?;
        let mut promoted = false;
        let pins = self.pins.clone();
        let pins = pins.lock().unwrap();
        for (hash, ..) in entries {
            // Promotion rewrites entry.pack. Only current owners count.
            let Some(entry) = self.map.get(&hash) else {
                continue;
            };
            if entry.pack != id {
                continue;
            }
            if entry.freq == 0 && !pins.contains_key(&hash) {
                self.map.remove(&hash);
                if queue == Queue::Small {
                    self.ghost_push(hash);
                }
                continue;
            }
            let freq = match queue {
                Queue::Small => entry.freq,
                Queue::Main => entry.freq.saturating_sub(1),
            };
            let (pack, offset, len) = (entry.pack, entry.offset, entry.len);
            let frame = self.frame(pack, offset, len)?;
            self.map.remove(&hash);
            self.append(Queue::Main, &hash, &frame, freq)?;
            promoted = true;
        }
        let size = self.packs.remove(&id).expect("retiring an unknown pack");
        match queue {
            Queue::Small => self.small_bytes -= size,
            Queue::Main => self.main_bytes -= size,
        }
        // Fsync survivors before unlinking their source, so a crash
        // never loses a chunk the map claims to have.
        if promoted && let Some(w) = &self.active_main {
            w.sync()?;
        }
        self.readers.remove(&id);
        fs::remove_file(pack::pack_path(&self.dir, id))?;
        let _ = fs::remove_file(pack::index_path(&self.dir, id));
        Ok(())
    }

    fn frame(&mut self, pack: u64, offset: u64, len: u32) -> io::Result<Vec<u8>> {
        let file = self.reader(pack)?.clone();
        pack::read_frame(&file, offset, len).inspect_err(|_| {
            self.readers.remove(&pack);
        })
    }

    fn reader(&mut self, pack: u64) -> io::Result<&Arc<File>> {
        if !self.readers.contains_key(&pack) {
            self.readers
                .insert(pack, Arc::new(pack::open_pack(&self.dir, pack)?));
        }
        Ok(self.readers.get(&pack).expect("just inserted"))
    }

    fn ghost_push(&mut self, hash: Hash) {
        let key = ghost_key(&hash);
        if self.ghost_set.insert(key) {
            self.ghost.push_back(key);
        }
    }

    fn ghost_remove(&mut self, hash: &Hash) -> bool {
        // Lazy removal: the queue entry stays and is skipped at trim.
        self.ghost_set.remove(&ghost_key(hash))
    }

    fn trim_ghost(&mut self) {
        let cap = self.map.len().max(1024);
        while self.ghost.len() > cap {
            let key = self.ghost.pop_front().unwrap();
            self.ghost_set.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn h(n: u8) -> Hash {
        let mut hash = [0u8; 32];
        hash[0] = n;
        hash
    }

    fn store(dir: &Path, budget: u64) -> ChunkStore {
        ChunkStore::open(dir.to_path_buf(), budget).unwrap()
    }

    fn get(s: &mut ChunkStore, hash: &Hash) -> Option<Vec<u8>> {
        s.locate(hash)?.read().ok()
    }

    #[test]
    fn roundtrip_and_contains() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path(), 1 << 20);
        s.insert(h(1), b"frame-one").unwrap();
        assert!(get(&mut s, &h(2)).is_none());
        assert_eq!(get(&mut s, &h(1)).unwrap(), b"frame-one");
    }

    /// blake3 hash and zstd frame of `data`, as production inserts
    /// store them. Recovery verifies both.
    fn frame(data: &[u8]) -> (Hash, Vec<u8>) {
        let hash = *blake3::hash(data).as_bytes();
        (hash, zstd::stream::encode_all(data, 3).unwrap())
    }

    fn pack_file(dir: &Path) -> PathBuf {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "pack"))
            .unwrap()
    }

    #[test]
    fn survives_reopen_via_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let (ha, fa) = frame(b"aaa");
        let (hb, fb) = frame(b"bbb");
        let mut s = store(dir.path(), 1 << 20);
        s.insert(ha, &fa).unwrap();
        s.insert(hb, &fb).unwrap();
        drop(s);
        let mut s = store(dir.path(), 1 << 20);
        assert_eq!(get(&mut s, &ha).unwrap(), fa);
        assert_eq!(get(&mut s, &hb).unwrap(), fb);
    }

    #[test]
    fn reopen_truncates_torn_tail() {
        let dir = tempfile::tempdir().unwrap();
        let (ha, fa) = frame(b"aaa");
        let mut s = store(dir.path(), 1 << 20);
        s.insert(ha, &fa).unwrap();
        drop(s);
        let pack = pack_file(dir.path());
        let mut data = fs::read(&pack).unwrap();
        data.extend_from_slice(&[7, 0, 0, 0, 9]); // half a record
        fs::write(&pack, data).unwrap();
        let mut s = store(dir.path(), 1 << 20);
        assert_eq!(get(&mut s, &ha).unwrap(), fa);
    }

    /// A torn write can leave a record with intact framing but a
    /// corrupt payload. Recovery must drop it, not just short tails.
    #[test]
    fn reopen_drops_corrupt_payload() {
        let dir = tempfile::tempdir().unwrap();
        let (ha, fa) = frame(b"aaa");
        let (hb, fb) = frame(b"bbb");
        let mut s = store(dir.path(), 1 << 20);
        s.insert(ha, &fa).unwrap();
        s.insert(hb, &fb).unwrap();
        drop(s);
        let pack = pack_file(dir.path());
        let mut data = fs::read(&pack).unwrap();
        let tail = data.len() - fb.len();
        for b in &mut data[tail..] {
            *b = 0;
        }
        fs::write(&pack, data).unwrap();
        let mut s = store(dir.path(), 1 << 20);
        assert_eq!(get(&mut s, &ha).unwrap(), fa);
        assert!(get(&mut s, &hb).is_none());
    }

    #[test]
    fn pinned_survives_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path(), 64 << 20);
        s.seal_bytes = 64 << 10;
        let frame = vec![0u8; 8 << 10];
        let pinned: Vec<Hash> = (0..20u8).map(h).collect();
        for p in &pinned {
            s.insert(*p, &frame).unwrap();
        }
        let guard = s.pin(pinned.clone());
        s.budget = 128 << 10;
        for n in 20..200u8 {
            s.insert(h(n), &frame).unwrap();
        }
        assert!(
            pinned.iter().all(|p| s.peek(p).is_some()),
            "pinned chunk evicted"
        );
        assert!(s.peek(&h(20)).is_none());
        drop(guard);
        for n in 200..255u8 {
            s.insert(h(n), &frame).unwrap();
        }
        assert!(
            pinned.iter().any(|p| s.peek(p).is_none()),
            "unpinned chunks never evicted"
        );
    }

    /// One-hit wonders age out with zero copies while a re-hit chunk
    /// is promoted and survives the same eviction wave.
    #[test]
    fn scan_resistance() {
        let dir = tempfile::tempdir().unwrap();
        let budget = 64 << 20;
        let mut s = store(dir.path(), budget);
        s.seal_bytes = 64 << 10;
        let frame = vec![0u8; 8 << 10];
        s.insert(h(255), &frame).unwrap();
        get(&mut s, &h(255)).unwrap(); // freq bump: hot
        // scan: enough one-hit chunks to overflow the small queue
        for n in 0..200u8 {
            let mut hash = h(n);
            hash[1] = 1;
            s.insert(hash, &frame).unwrap();
        }
        // force eviction pressure well past the budget
        s.budget = 128 << 10;
        s.insert(h(254), &frame).unwrap();
        assert!(
            get(&mut s, &h(255)).is_some(),
            "hot chunk evicted by the scan"
        );
        let survivors = (0..200u8)
            .filter(|n| {
                let mut hash = h(*n);
                hash[1] = 1;
                get(&mut s, &hash).is_some()
            })
            .count();
        assert!(survivors < 200, "scan chunks were never evicted");
    }

    /// A ghost hit admits straight to main and survives small-queue
    /// pressure afterwards.
    #[test]
    fn ghost_readmission_goes_to_main() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path(), 256 << 10);
        s.seal_bytes = 32 << 10;
        let frame = vec![0u8; 8 << 10];
        s.insert(h(1), &frame).unwrap();
        // push it out of small without a hit -> ghost
        for n in 10..80u8 {
            s.insert(h(n), &frame).unwrap();
        }
        assert!(
            get(&mut s, &h(1)).is_none(),
            "expected h(1) evicted to ghost"
        );
        s.insert(h(1), &frame).unwrap();
        // another scan. A small-queue resident would be evicted again
        for n in 100..170u8 {
            s.insert(h(n), &frame).unwrap();
        }
        assert!(
            get(&mut s, &h(1)).is_some(),
            "ghost readmission did not stick"
        );
    }
}
