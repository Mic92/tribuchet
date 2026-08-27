//! In-memory hub state: replay buffers, the job queue, worker capabilities.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, Notify, mpsc};
use tonic::Status;

use super::chunkcache::ChunkCache;
use super::metrics::Metrics;
use crate::config::NixConfig;
use crate::fsutil::io_ctx;

use crate::proto::{AttachEvent, BuildRequest, attach_event};

#[path = "state/inflight.rs"]
mod inflight;
#[path = "state/replay.rs"]
mod replay;

pub(super) use inflight::{Inflight, Listing};
pub(super) use replay::Replay;

type EventTx = mpsc::Sender<Result<AttachEvent, Status>>;

/// Cap on the replay buffer of one build. Without it a worker that
/// streams chunks forever grows root-hub memory without bound.
const MAX_REPLAY_BYTES: usize = 256 * 1024 * 1024;

/// Per-subscriber channel headroom beyond the buffered backlog. A
/// stalled attach client is dropped once it falls this far behind
/// instead of buffering the whole build a second time.
const SUB_CHANNEL_SLACK: usize = 1024;

pub(super) struct Job {
    pub(super) id: String,
    pub(super) key: String,
    pub(super) req: BuildRequest,
    /// The client's zstd-packed build tmp dir, buffered so redispatch can
    /// resend it without another round-trip to the client.
    pub(super) tmp_dir_pack: Arc<Vec<u8>>,
    /// requiredSystemFeatures; only workers advertising them get the job.
    pub(super) features: Vec<String>,
    pub(super) replay: Arc<Replay>,
    /// Dedupe registration, dropped on cancel or with the job.
    pub(super) listing: StdMutex<Option<Listing>>,
    /// Times the job went back to the queue after its worker session
    /// died; capped so a crash-looping build cannot bounce forever.
    pub(super) attempts: u32,
    /// Set on requeue: protects the job from fail_unservable() while
    /// its worker reconnects (reload or crash respawn).
    pub(super) requeued_at: Option<Instant>,
}

impl Job {
    /// Stop deduping new submissions onto this job.
    pub(super) fn unlist(&self) {
        drop(self.listing.lock().unwrap().take());
    }
}

pub(super) struct HubState {
    pub(super) queue: Mutex<VecDeque<Job>>,
    pub(super) inflight: Arc<StdMutex<Inflight>>,
    pub(super) notify: Notify,
    /// Pooled connections to the local nix-daemon (path metadata
    /// queries); jobs are frequent enough that per-job handshakes
    /// would add up.
    pub(super) daemon_pool: harmonia_store_remote::ConnectionPool,
    /// Connected workers' capabilities, keyed by a per-connection id;
    /// submissions no worker can serve fail fast instead of queueing
    /// forever.
    pub(super) worker_caps: StdMutex<HashMap<u64, WorkerCaps>>,
    pub(super) next_worker_id: atomic::AtomicU64,
    /// How long a build waits for a platform expected back (hub
    /// restart, worker reconnect). Never-seen platforms decline at once.
    pub(super) worker_grace: Duration,
    /// Hub start time and the capabilities of workers whose session
    /// ended: together they tell `expected_deadline` which platforms are
    /// still worth waiting for after a restart or a worker drop.
    pub(super) started_at: Instant,
    pub(super) departed: StdMutex<Vec<(WorkerCaps, Instant)>>,
    /// worker id -> dedupe keys it can resume
    pub(super) held: StdMutex<HashMap<u64, HashSet<String>>>,
    /// Woken when worker capabilities change so waiting submissions
    /// re-check servability without polling.
    pub(super) caps_changed: Notify,
    /// Build lifecycle counters scraped by the metrics endpoint.
    pub(super) metrics: Metrics,
    /// When set, the connected-worker set is mirrored to this nix.conf
    /// fragment on every register/deregister.
    pub(super) nix_config: Option<NixConfig>,
    pub(super) chunks: Arc<ChunkCache>,
}

#[derive(Clone)]
pub(super) struct WorkerCaps {
    /// Registered worker name, used as the hostname metrics label.
    pub(super) name: String,
    /// system -> features the worker honors for it
    pub(super) systems: HashMap<String, HashSet<String>>,
    /// Advisory concurrent-build capacity, summed to size the
    /// generated nix.conf max-jobs.
    pub(super) max_jobs: u32,
}

/// nix.conf fragment for the connected workers: external-builders over
/// every served system, and max-jobs at the oversubscribed, capped
/// aggregate capacity. max-jobs is omitted with no workers, leaving the
/// base nix.conf default to govern local fallback builds.
fn render_nix_config(caps: &HashMap<u64, WorkerCaps>, cfg: &NixConfig) -> String {
    let systems: BTreeSet<&str> = caps
        .values()
        .flat_map(|c| c.systems.keys().map(String::as_str))
        .collect();
    // System names are peer-supplied; Rust Debug is not valid JSON.
    let builders = serde_json::json!([{
        "systems": systems,
        "program": cfg.attach_program.to_string_lossy(),
        "args": [],
    }]);
    let mut out = format!("external-builders = {builders}\n");
    let capacity: u64 = caps.values().map(|c| u64::from(c.max_jobs)).sum();
    if capacity > 0 {
        let scaled = capacity * u64::from(cfg.oversubscribe_percent) / 100;
        let jobs = scaled.clamp(1, u64::from(cfg.max_jobs_cap));
        let _ = writeln!(out, "max-jobs = {jobs}");
    }
    out
}

fn write_atomic(path: &Path, content: &str) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp).map_err(io_ctx("creating", &tmp))?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).map_err(io_ctx("renaming into", path))
}

impl WorkerCaps {
    pub(super) fn serves(&self, system: &str, features: &[String]) -> bool {
        self.systems
            .get(system)
            .is_some_and(|have| features.iter().all(|f| have.contains(f)))
    }
}

impl HubState {
    pub(super) fn new(
        worker_grace: Duration,
        nix_config: Option<NixConfig>,
        chunks: Arc<ChunkCache>,
    ) -> Self {
        Self {
            queue: Mutex::default(),
            inflight: Arc::default(),
            notify: Notify::default(),
            daemon_pool: harmonia_store_remote::ConnectionPool::new(
                "/nix/var/nix/daemon-socket/socket",
                harmonia_store_remote::PoolConfig::default(),
            ),
            worker_caps: StdMutex::default(),
            next_worker_id: atomic::AtomicU64::default(),
            worker_grace,
            started_at: Instant::now(),
            departed: StdMutex::default(),
            held: StdMutex::default(),
            caps_changed: Notify::default(),
            metrics: Metrics::default(),
            nix_config,
            chunks,
        }
    }

    /// Mirror the connected-worker set to the nix.conf fragment. Called
    /// after a register/deregister mutates `worker_caps`.
    pub(super) fn regen_nix_config(&self) {
        let Some(cfg) = &self.nix_config else {
            return;
        };
        // Render and write under the lock so concurrent register/
        // deregister serialize and never leave stale content behind.
        let caps = self.worker_caps.lock().unwrap();
        let content = render_nix_config(&caps, cfg);
        // Skip the write, and the daemon restart the watching path unit
        // would trigger, when nothing changed (e.g. a worker reconnects
        // with the same capabilities).
        if fs::read_to_string(&cfg.path).is_ok_and(|cur| cur == content) {
            return;
        }
        if let Err(e) = write_atomic(&cfg.path, &content) {
            tracing::warn!(
                error = %e,
                path = %cfg.path.display(),
                "failed to write nix.conf fragment"
            );
        }
    }
}

impl HubState {
    /// Remember a departed worker's capabilities so a build for the
    /// platform it served waits for it to reconnect rather than
    /// declining at once.
    pub(super) fn record_departed(&self, caps: WorkerCaps) {
        let now = Instant::now();
        let mut departed = self.departed.lock().unwrap();
        // Prune here: expected_deadline() only runs for unservable
        // submissions, so a healthy fleet would otherwise accumulate
        // an entry per worker reconnect indefinitely.
        departed.retain(|(_, at)| now < *at + self.worker_grace);
        departed.push((caps, now));
    }

    /// If this platform is not servable right now but we expect a
    /// capable worker back, the instant to wait until; `None` means
    /// nothing we know of will ever serve it, so decline immediately.
    pub(super) fn expected_deadline(&self, system: &str, features: &[String]) -> Option<Instant> {
        let now = Instant::now();
        // During the startup window no worker has re-registered yet, so
        // every platform is awaited; afterwards only one a worker served
        // until it dropped within the reconnect window (reload/crash).
        let startup = self.started_at + self.worker_grace;
        if now < startup {
            return Some(startup);
        }
        let mut departed = self.departed.lock().unwrap();
        departed.retain(|(_, at)| now < *at + self.worker_grace);
        departed
            .iter()
            .filter(|(c, _)| c.serves(system, features))
            .map(|(_, at)| *at + self.worker_grace)
            .max()
    }

    pub(super) async fn take_job(&self, caps: &WorkerCaps, worker: u64) -> Option<Job> {
        loop {
            let job = {
                let mut queue = self.queue.lock().await;
                let held = self.held.lock().unwrap();
                let elsewhere = |key: &str| {
                    held.iter()
                        .any(|(id, keys)| *id != worker && keys.contains(key))
                };
                let pos = queue
                    .iter()
                    .position(|j| caps.serves(&j.req.system, &j.features) && !elsewhere(&j.key))?;
                queue.remove(pos)?
            };
            // Abandoned while queued (every attach client gone): drop it
            // here, at the moment it would have occupied a build slot.
            if job.replay.has_subscribers().await {
                return Some(job);
            }
            tracing::info!(id = job.id, "dropping queued build: no client attached");
            self.finish(&job).await;
        }
    }

    /// Take a queued job `worker` can resume, regardless of RequestJob
    /// credits. Each held key is honoured once.
    pub(super) async fn take_job_by_key(&self, worker: u64) -> Option<Job> {
        let mut queue = self.queue.lock().await;
        let mut held = self.held.lock().unwrap();
        let keys = held.get_mut(&worker)?;
        let pos = queue.iter().position(|j| keys.contains(&j.key))?;
        let job = queue.remove(pos)?;
        keys.remove(&job.key);
        Some(job)
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
        self.recheck_unservable();
    }

    /// Re-run fail_unservable once the grace of protected jobs lapsed.
    fn recheck_unservable(self: &Arc<Self>) {
        let state = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(state.worker_grace + Duration::from_secs(1)).await;
                if !state.fail_unservable_now().await {
                    break;
                }
            }
        });
    }

    pub(super) async fn fail_unservable(self: &Arc<Self>) {
        if self.fail_unservable_now().await {
            self.recheck_unservable();
        }
    }

    pub(super) async fn finish(&self, job: &Job) {
        job.unlist();
        job.replay.finish().await;
    }

    /// Fail queued jobs no connected worker can serve. The submission
    /// check alone is not enough: the capable worker can disconnect
    /// while the job sits in the queue, which would strand it forever.
    /// True if jobs were kept only because of a grace period.
    async fn fail_unservable_now(&self) -> bool {
        let caps: Vec<WorkerCaps> = self.worker_caps.lock().unwrap().values().cloned().collect();
        let mut queue = self.queue.lock().await;
        let mut kept = VecDeque::with_capacity(queue.len());
        let mut failed = Vec::new();
        let mut recheck = false;
        for j in queue.drain(..) {
            let protected = j
                .requeued_at
                .is_some_and(|t| t.elapsed() < self.worker_grace)
                || self.expected_deadline(&j.req.system, &j.features).is_some();
            if caps.iter().any(|c| c.serves(&j.req.system, &j.features)) {
                kept.push_back(j);
            } else if protected {
                recheck = true;
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
        recheck
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl HubState {
        pub(in crate::hub) fn for_test(worker_grace: Duration) -> Self {
            let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
            let cache = ChunkCache::open(dir.path().to_path_buf(), 1 << 20).unwrap();
            Self::new(worker_grace, None, Arc::new(cache))
        }
    }

    fn queued(system: &str, replay: Arc<Replay>) -> Job {
        Job {
            id: "j1".into(),
            key: "k1".into(),
            req: BuildRequest {
                system: system.into(),
                ..Default::default()
            },
            tmp_dir_pack: Arc::new(Vec::new()),
            features: vec![],
            replay,
            listing: StdMutex::default(),
            attempts: 0,
            requeued_at: None,
        }
    }

    #[tokio::test]
    async fn queued_job_survives_worker_restart_within_grace() {
        let mut state = Arc::new(HubState::for_test(Duration::from_secs(30)));
        Arc::get_mut(&mut state).unwrap().started_at =
            Instant::now().checked_sub(Duration::from_mins(1)).unwrap();
        let replay = Arc::new(Replay::default());
        let _rx = replay.subscribe().await;
        state
            .queue
            .lock()
            .await
            .push_back(queued("x86_64-linux", replay));
        state.record_departed(caps("x86_64-linux", &[]));
        state.fail_unservable().await;
        assert_eq!(state.queue.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn take_job_leaves_held_keys_to_their_holder() {
        let state = HubState::for_test(Duration::ZERO);
        let replay = Arc::new(Replay::default());
        let _rx = replay.subscribe().await;
        state
            .queue
            .lock()
            .await
            .push_back(queued("x86_64-linux", replay));
        state
            .held
            .lock()
            .unwrap()
            .insert(7, ["k1".to_string()].into());
        let c = caps("x86_64-linux", &[]);
        assert!(state.take_job(&c, 8).await.is_none());
        assert!(state.take_job(&c, 7).await.is_some());
    }

    #[tokio::test]
    async fn queued_job_fails_when_last_capable_worker_leaves() {
        let state = Arc::new(HubState::for_test(Duration::ZERO));
        let replay = Arc::new(Replay::default());
        state
            .queue
            .lock()
            .await
            .push_back(queued("x86_64-linux", replay.clone()));
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

    fn caps(system: &str, features: &[&str]) -> WorkerCaps {
        WorkerCaps {
            name: "w".into(),
            systems: [(
                system.to_owned(),
                features.iter().map(|f| (*f).to_owned()).collect(),
            )]
            .into(),
            max_jobs: 1,
        }
    }

    #[test]
    fn startup_window_awaits_then_unseen_platform_declines() {
        // Within the startup window any platform is awaited (workers
        // have not re-registered yet); once it lapses a never-seen
        // platform with no departed worker declines at once.
        let within = HubState::for_test(Duration::from_secs(30));
        assert!(within.expected_deadline("aarch64-linux", &[]).is_some());
        let lapsed = HubState::for_test(Duration::ZERO);
        assert!(lapsed.expected_deadline("aarch64-linux", &[]).is_none());
    }

    #[test]
    fn departed_worker_keeps_its_platform_expected() {
        // Past the startup window but inside the reconnect window.
        let mut state = HubState::for_test(Duration::from_secs(30));
        state.started_at = Instant::now().checked_sub(Duration::from_mins(1)).unwrap();
        state.record_departed(caps("x86_64-linux", &["kvm"]));
        let kvm = vec!["kvm".to_owned()];
        let kvm_bp = vec!["kvm".to_owned(), "big-parallel".to_owned()];
        // The exact platform it served is still awaited.
        assert!(state.expected_deadline("x86_64-linux", &kvm).is_some());
        // A feature it never offered, or another system, is not.
        assert!(state.expected_deadline("x86_64-linux", &kvm_bp).is_none());
        assert!(state.expected_deadline("aarch64-linux", &[]).is_none());
    }

    #[test]
    fn nix_config_union_systems_and_capped_oversubscribed_jobs() {
        let cfg = NixConfig {
            path: "/run/x".into(),
            attach_program: "/nix/store/attach".into(),
            oversubscribe_percent: 200,
            max_jobs_cap: 256,
        };
        let mut workers = HashMap::new();
        workers.insert(1, {
            let mut c = caps("x86_64-linux", &[]);
            c.max_jobs = 100;
            c
        });
        workers.insert(2, {
            let mut c = caps("aarch64-linux", &[]);
            c.max_jobs = 50;
            c
        });
        let out = render_nix_config(&workers, &cfg);
        assert!(
            out.contains(r#""systems":["aarch64-linux","x86_64-linux"]"#),
            "{out}"
        );
        assert!(out.contains(r#""program":"/nix/store/attach""#), "{out}");
        // (100 + 50) * 2 = 300, clamped to the cap.
        assert!(out.contains("max-jobs = 256\n"), "{out}");
    }

    #[test]
    fn nix_config_json_escapes_peer_supplied_systems() {
        let cfg = NixConfig {
            path: "/run/x".into(),
            attach_program: r"/nix/store/at\tach".into(),
            oversubscribe_percent: 100,
            max_jobs_cap: 1,
        };
        let mut workers = HashMap::new();
        workers.insert(1, caps("x86_64-linux\u{2028}\"", &[]));
        let out = render_nix_config(&workers, &cfg);
        let json = out
            .strip_prefix("external-builders = ")
            .and_then(|s| s.lines().next())
            .unwrap();
        // Nix parses this as JSON; must be valid regardless of what a
        // worker registered or how the attach path is spelled.
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(v[0]["systems"][0], "x86_64-linux\u{2028}\"");
        assert_eq!(v[0]["program"], r"/nix/store/at\tach");
    }

    #[test]
    fn nix_config_without_workers_omits_max_jobs() {
        let cfg = NixConfig {
            path: "/run/x".into(),
            attach_program: "/nix/store/attach".into(),
            oversubscribe_percent: 200,
            max_jobs_cap: 256,
        };
        let out = render_nix_config(&HashMap::new(), &cfg);
        assert!(out.contains(r#""systems":[]"#), "{out}");
        // No worker -> leave max-jobs to the base nix.conf default so a
        // local fallback build is not run at the offload capacity.
        assert!(!out.contains("max-jobs"), "{out}");
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
            max_jobs: 1,
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
