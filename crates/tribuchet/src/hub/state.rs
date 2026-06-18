//! In-memory hub state: replay buffers, the job queue, worker capabilities.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::sync::atomic;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, Mutex, Notify};
use tonic::Status;

/// How long a submission waits for a capable worker before being
/// rejected; covers the re-registration gap after a hub restart.
pub(super) const WORKER_GRACE: Duration = Duration::from_secs(30);

use crate::proto::{attach_event, AttachEvent, BuildRequest};

type EventTx = mpsc::Sender<Result<AttachEvent, Status>>;

/// Cap on the replay buffer of one build. Without it a worker that
/// streams chunks forever grows root-hub memory without bound.
const MAX_REPLAY_BYTES: usize = 256 * 1024 * 1024;

/// Per-subscriber channel headroom beyond the buffered backlog. A
/// stalled attach client is dropped once it falls this far behind
/// instead of buffering the whole build a second time.
const SUB_CHANNEL_SLACK: usize = 1024;

/// Buffered event log of one in-flight build; late identical submissions
/// (dedupe) replay the buffer and then follow live. The buffer holds the
/// compressed output chunks too, capped at MAX_REPLAY_BYTES.
#[derive(Default)]
pub(super) struct Replay {
    inner: Mutex<ReplayInner>,
}

#[derive(Default)]
struct ReplayInner {
    events: Vec<AttachEvent>,
    bytes: usize,
    /// Buffer cap hit: the backlog is incomplete, so late dedupe
    /// subscribers must error instead of getting a truncated stream.
    overflowed: bool,
    subs: Vec<EventTx>,
    done: bool,
}

fn event_size(ev: &attach_event::Event) -> usize {
    match ev {
        attach_event::Event::Log(d) => d.len(),
        attach_event::Event::Output(o) => o.zstd_nar_chunk.len(),
        attach_event::Event::OutputRestart(p) | attach_event::Event::AddedPath(p) => p.len(),
        attach_event::Event::Error(e) => e.len(),
        attach_event::Event::ExitCode(_) => 0,
    }
    .saturating_add(64)
}

impl Replay {
    pub(super) async fn publish(&self, ev: attach_event::Event) {
        let sz = event_size(&ev);
        let ev = AttachEvent { event: Some(ev) };
        let mut inner = self.inner.lock().await;
        // try_send: a subscriber that stopped reading is dropped (its
        // attach errors out) instead of buffering unboundedly.
        inner.subs.retain(|tx| tx.try_send(Ok(ev.clone())).is_ok());
        if inner.overflowed {
            return;
        }
        if inner.bytes + sz > MAX_REPLAY_BYTES {
            tracing::warn!("replay buffer cap reached; late dedupe subscribers will be rejected");
            inner.overflowed = true;
            inner.events.clear();
            inner.bytes = 0;
            return;
        }
        inner.bytes += sz;
        inner.events.push(ev);
    }

    pub(super) async fn subscribe(&self) -> mpsc::Receiver<Result<AttachEvent, Status>> {
        let mut inner = self.inner.lock().await;
        if inner.overflowed {
            let (tx, rx) = mpsc::channel(1);
            let _ = tx.try_send(Err(Status::resource_exhausted(
                "build output exceeded the replay buffer; retry after it finishes",
            )));
            return rx;
        }
        // Enough capacity for the whole backlog plus live slack (and
        // one error slot), so the snapshot below cannot drop events.
        let (tx, rx) = mpsc::channel(inner.events.len() + SUB_CHANNEL_SLACK);
        for ev in &inner.events {
            let _ = tx.try_send(Ok(ev.clone()));
        }
        if inner.done {
            // Finished without a verdict in the backlog (e.g. the job
            // was dropped as abandoned between the dedupe lookup and
            // this subscribe): an error beats a silently empty stream.
            let concluded = inner.events.iter().any(|e| {
                matches!(
                    e.event,
                    Some(attach_event::Event::ExitCode(_) | attach_event::Event::Error(_))
                )
            });
            if !concluded {
                let _ = tx.try_send(Err(Status::unavailable(
                    "build is no longer in flight; resubmit",
                )));
            }
        } else {
            inner.subs.push(tx);
        }
        rx
    }

    /// Close all subscriber streams.
    pub(super) async fn finish(&self) {
        let mut inner = self.inner.lock().await;
        inner.done = true;
        inner.subs.clear();
    }

    /// Any attach client still listening? Subscribers whose stream was
    /// dropped count as gone even before publish() prunes them.
    pub(super) async fn has_subscribers(&self) -> bool {
        let inner = self.inner.lock().await;
        inner.subs.iter().any(|tx| !tx.is_closed())
    }
}

pub(super) struct Job {
    pub(super) id: String,
    pub(super) key: String,
    pub(super) req: BuildRequest,
    /// The topTmpDir as validated at submission time, held open so the
    /// later tar step cannot be redirected by swapping the path for a
    /// symlink while the job is queued.
    pub(super) tmp_dir: Arc<fs::File>,
    /// requiredSystemFeatures; only workers advertising them get the job.
    pub(super) features: Vec<String>,
    pub(super) replay: Arc<Replay>,
    /// Times the job went back to the queue after its worker session
    /// died; capped so a crash-looping build cannot bounce forever.
    pub(super) attempts: u32,
    /// Set on requeue: protects the job from fail_unservable() while
    /// its worker reconnects (reload or crash respawn).
    pub(super) requeued_at: Option<Instant>,
}

#[derive(Default)]
pub(super) struct Inflight {
    /// Dedupe key (hash of the full request) -> replay buffer.
    pub(super) by_key: HashMap<String, Arc<Replay>>,
    /// Scratch output path -> dedupe key; different requests naming the
    /// same scratch path would unpack into the same destination.
    pub(super) by_path: HashMap<String, String>,
}

pub(super) struct HubState {
    pub(super) queue: Mutex<VecDeque<Job>>,
    pub(super) inflight: Mutex<Inflight>,
    pub(super) notify: Notify,
    /// Pooled connections to the local nix-daemon (path metadata
    /// queries); jobs are frequent enough that per-job handshakes
    /// would add up.
    pub(super) daemon_pool: harmonia_store_remote::ConnectionPool,
    /// Connected workers' capabilities, keyed by a per-connection id;
    /// submissions no worker can serve fail fast instead of queueing
    /// forever.
    pub(super) worker_caps: std::sync::Mutex<HashMap<u64, WorkerCaps>>,
    pub(super) next_worker_id: atomic::AtomicU64,
    /// Grace period before an unservable build is declined or failed.
    pub(super) worker_grace: Duration,
    /// Build lifecycle counters scraped by the metrics endpoint.
    pub(super) metrics: super::metrics::Metrics,
}

#[derive(Clone)]
pub(super) struct WorkerCaps {
    /// Registered worker name, used as the hostname metrics label.
    pub(super) name: String,
    /// system -> features the worker honors for it
    pub(super) systems: HashMap<String, HashSet<String>>,
}

impl WorkerCaps {
    pub(super) fn serves(&self, system: &str, features: &[String]) -> bool {
        self.systems
            .get(system)
            .is_some_and(|have| features.iter().all(|f| have.contains(f)))
    }
}

impl Default for HubState {
    fn default() -> Self {
        Self::new(WORKER_GRACE)
    }
}

impl HubState {
    pub(super) fn new(worker_grace: Duration) -> Self {
        Self {
            queue: Mutex::default(),
            inflight: Mutex::default(),
            notify: Notify::default(),
            daemon_pool: harmonia_store_remote::ConnectionPool::new(
                "/nix/var/nix/daemon-socket/socket",
                harmonia_store_remote::PoolConfig::default(),
            ),
            worker_caps: std::sync::Mutex::default(),
            next_worker_id: atomic::AtomicU64::default(),
            worker_grace,
            metrics: super::metrics::Metrics::default(),
        }
    }
}

impl HubState {
    pub(super) async fn take_job(&self, caps: &WorkerCaps) -> Option<Job> {
        let job = {
            let mut queue = self.queue.lock().await;
            let pos = queue
                .iter()
                .position(|j| caps.serves(&j.req.system, &j.features))?;
            queue.remove(pos)?
        };
        // Abandoned while queued (every attach client gone): drop it
        // here, at the moment it would have occupied a build slot.
        if !job.replay.has_subscribers().await {
            tracing::info!(id = job.id, "dropping queued build: no client attached");
            self.finish(&job).await;
            return None;
        }
        Some(job)
    }

    /// Take a queued job whose dedupe key is in `keys` (builds the
    /// calling worker can resume), regardless of RequestJob credits.
    pub(super) async fn take_job_by_key(&self, keys: &HashSet<String>) -> Option<Job> {
        if keys.is_empty() {
            return None;
        }
        let mut queue = self.queue.lock().await;
        let pos = queue.iter().position(|j| keys.contains(&j.key))?;
        queue.remove(pos)
    }

    /// Put a job back in the queue after its worker session died,
    /// telling attach clients to drop any half-streamed output NARs
    /// (the next attempt re-streams them from the start). A delayed
    /// fail_unservable() covers the case where no worker ever returns.
    pub(super) async fn requeue(self: &Arc<Self>, mut job: Job) {
        job.attempts += 1;
        job.requeued_at = Some(Instant::now());
        for path in job.req.outputs.values() {
            job.replay
                .publish(attach_event::Event::OutputRestart(path.clone()))
                .await;
        }
        self.queue.lock().await.push_back(job);
        self.notify.notify_waiters();
        let state = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(state.worker_grace + Duration::from_secs(1)).await;
            state.fail_unservable().await;
        });
    }

    pub(super) async fn finish(&self, job: &Job) {
        let mut inflight = self.inflight.lock().await;
        inflight.by_key.remove(&job.key);
        for p in job.req.outputs.values() {
            inflight.by_path.remove(p);
        }
        drop(inflight);
        job.replay.finish().await;
    }

    /// Fail queued jobs no connected worker can serve. The submission
    /// check alone is not enough: the capable worker can disconnect
    /// while the job sits in the queue, which would strand it forever.
    pub(super) async fn fail_unservable(&self) {
        let caps: Vec<WorkerCaps> = self.worker_caps.lock().unwrap().values().cloned().collect();
        let mut queue = self.queue.lock().await;
        let mut kept = VecDeque::with_capacity(queue.len());
        let mut failed = Vec::new();
        for j in queue.drain(..) {
            // Requeued jobs get a grace period: their worker is mid
            // reload/restart and will re-announce them; a delayed
            // recheck is scheduled at requeue time.
            let protected = j
                .requeued_at
                .is_some_and(|t| t.elapsed() < self.worker_grace);
            if protected || caps.iter().any(|c| c.serves(&j.req.system, &j.features)) {
                kept.push_back(j);
            } else {
                failed.push(j);
            }
        }
        *queue = kept;
        drop(queue);
        for job in failed {
            tracing::warn!(
                id = job.id,
                "failing queued build: last capable worker left"
            );
            job.replay
                .publish(attach_event::Event::Error(format!(
                    "no connected worker builds for system {}",
                    job.req.system
                )))
                .await;
            self.finish(&job).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn queued_job_fails_when_last_capable_worker_leaves() {
        let state = HubState::default();
        let replay = Arc::new(Replay::default());
        let job = Job {
            id: "j1".into(),
            key: "k1".into(),
            req: BuildRequest {
                system: "x86_64-linux".into(),
                ..Default::default()
            },
            tmp_dir: Arc::new(fs::File::open(std::env::temp_dir()).unwrap()),
            features: vec![],
            replay: replay.clone(),
            attempts: 0,
            requeued_at: None,
        };
        state.queue.lock().await.push_back(job);
        state.fail_unservable().await;
        assert!(state.queue.lock().await.is_empty());
        let mut rx = replay.subscribe().await;
        match rx.recv().await {
            Some(Ok(AttachEvent {
                event: Some(attach_event::Event::Error(e)),
            })) => assert!(e.contains("no connected worker"), "{e}"),
            other => panic!("expected error event, got {other:?}"),
        }
    }

    #[test]
    fn worker_caps_feature_matching() {
        let caps = WorkerCaps {
            name: "w1".into(),
            systems: [
                ("x86_64-linux".to_owned(), ["kvm".to_owned()].into()),
                ("aarch64-linux".to_owned(), [].into()),
            ]
            .into(),
        };
        assert!(caps.serves("x86_64-linux", &[]));
        assert!(caps.serves("x86_64-linux", &["kvm".into()]));
        assert!(!caps.serves("x86_64-linux", &["kvm".into(), "uid-range".into()]));
        assert!(caps.serves("aarch64-linux", &[]));
        // emulated system must not inherit the host's kvm
        assert!(!caps.serves("aarch64-linux", &["kvm".into()]));
        assert!(!caps.serves("i686-linux", &[]));
    }
}
