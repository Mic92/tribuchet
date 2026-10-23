//! `tribuchet hub`: scheduler and NAR relay, colocated with nix-daemon.
//!
//! - accepts build submissions from `attach` over a unix socket (gRPC/UDS)
//! - dedupes in-flight builds by scratch-output set; later identical
//!   submissions replay buffered events and then follow live
//! - queues per system type; submitters block until a worker is free
//! - serves the WorkerHub gRPC service over mTLS; workers dial in
//! - reads input store paths directly from local disk
//! - verifies output chunks against their manifest while relaying

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::TcpConnectInfo;
use tonic::{Request, Response, Status, Streaming};

use crate::proto::worker_hub_server::WorkerHub;
use crate::tailscale;

use crate::proto::{
    CancelBuild, HubMessage, Register, WorkerMessage, attach_event, hub_message, worker_message,
};

mod chunkcache;
mod metrics;
mod relay;
mod serve;
mod state;
mod submit;
pub use serve::run;

use crate::errors::{Result, chain};
use metrics::Metrics;
use relay::{WorkerSession, run_job, send};
use state::{HubState, Job, WorkerCaps};

/// No worker message for this long tears the session down and fails
/// its builds: heartbeats flow every 30s, so silence means a dead
/// worker that would otherwise pin its builds (and dedupe keys) forever.
const WORKER_SILENCE_TIMEOUT: Duration = Duration::from_mins(3);
/// A worker-session loss requeues a job at most this many times.
const MAX_JOB_ATTEMPTS: u32 = 3;

/// In tailscale mode the hub asks tailscaled who the peer is on every
/// session and uses that as the worker name; mTLS mode trusts the
/// transport layer (only certs signed by our CA can connect) and the
/// self-reported name.
enum PeerAuth {
    Mtls,
    Tailscale {
        socket: PathBuf,
        allowed_tags: Vec<String>,
    },
}

struct WorkerSvc {
    state: Arc<HubState>,
    auth: Arc<PeerAuth>,
}

/// Registers the worker's capabilities while alive; removes them on
/// drop so admission control tracks actual capacity.
struct CapsGuard {
    state: Arc<HubState>,
    id: u64,
    caps: WorkerCaps,
}

impl CapsGuard {
    fn new(state: Arc<HubState>, caps: WorkerCaps) -> Self {
        let id = state.next_worker_id.fetch_add(1, Ordering::Relaxed);
        state.worker_caps.lock().unwrap().insert(id, caps.clone());
        // Wake submissions waiting for a capable worker to appear.
        state.caps_changed.notify_waiters();
        state.regen_nix_config();
        Self { state, id, caps }
    }
}

impl Drop for CapsGuard {
    fn drop(&mut self) {
        self.state.worker_caps.lock().unwrap().remove(&self.id);
        self.state.held.lock().unwrap().remove(&self.id);
        self.state.regen_nix_config();
        // Remember the platform so a build for it briefly waits for the
        // worker to reconnect instead of declining immediately.
        self.state.record_departed(self.caps.clone());
    }
}

/// Routes the single worker stream to per-build channels so multiple
/// jobs share one session. Dropping a sender closes the job's receiver,
/// which it observes as the worker going away.
#[derive(Default, Clone)]
struct Router {
    builds: Arc<Mutex<HashMap<String, mpsc::Sender<worker_message::Msg>>>>,
    closed: Arc<AtomicBool>,
}

impl Router {
    fn register(&self, build_id: &str) -> mpsc::Receiver<worker_message::Msg> {
        let (tx, rx) = mpsc::channel(64);
        self.builds.lock().unwrap().insert(build_id.to_string(), tx);
        rx
    }

    fn unregister(&self, build_id: &str) {
        self.builds.lock().unwrap().remove(build_id);
    }

    fn close_all(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.builds.lock().unwrap().clear();
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

fn msg_build_id(msg: &worker_message::Msg) -> Option<&str> {
    match msg {
        worker_message::Msg::Log(l) => Some(&l.build_id),
        worker_message::Msg::Result(r) => Some(&r.build_id),
        worker_message::Msg::Chunk(c) => Some(&c.build_id),
        worker_message::Msg::Resumed(r) => Some(&r.build_id),
        worker_message::Msg::Need(n) => Some(&n.build_id),
        worker_message::Msg::Register(_)
        | worker_message::Msg::Heartbeat(_)
        | worker_message::Msg::RequestJob(_) => None,
    }
}

/// Demux worker messages to their builds and enforce the session-wide
/// silence deadline; closes every build channel on the way out.
async fn route_loop(
    mut in_rx: mpsc::Receiver<WorkerMessage>,
    router: Router,
    capacity: Arc<AtomicU32>,
    state: Arc<HubState>,
    worker: u64,
) {
    loop {
        let m = match tokio::time::timeout(WORKER_SILENCE_TIMEOUT, in_rx.recv()).await {
            Err(_) => {
                tracing::warn!(
                    "worker sent nothing for {}s; assuming it is dead",
                    WORKER_SILENCE_TIMEOUT.as_secs()
                );
                break;
            }
            Ok(None) => break,
            Ok(Some(WorkerMessage { msg: Some(m) })) => m,
            Ok(Some(WorkerMessage { msg: None })) => continue,
        };
        state
            .metrics
            .count_msg(relay::msg_name(&m), m.encoded_len());
        if let worker_message::Msg::RequestJob(r) = &m {
            capacity.store(r.capacity, Ordering::SeqCst);
            state.notify.notify_waiters();
            continue;
        }
        if let worker_message::Msg::Heartbeat(h) = &m {
            let keys: HashSet<String> = h.resumable_keys.iter().cloned().collect();
            state.held.lock().unwrap().insert(worker, keys);
        }
        let Some(id) = msg_build_id(&m).map(str::to_string) else {
            continue;
        };
        // clone outside the lock: a send must not block other routing
        let tx = router.builds.lock().unwrap().get(&id).cloned();
        if let Some(tx) = tx {
            // send error = job already ended; drop the message
            drop(tx.send(m).await);
        } else {
            tracing::warn!(id, "dropping worker message for unknown build");
        }
    }
    router.close_all();
}

#[tonic::async_trait]
impl WorkerHub for WorkerSvc {
    type SessionStream = ReceiverStream<Result<HubMessage, Status>>;

    async fn session(
        &self,
        request: Request<Streaming<WorkerMessage>>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        let remote = request
            .extensions()
            .get::<TcpConnectInfo>()
            .and_then(|i| i.remote_addr);
        let mut inbound = request.into_inner();
        let Some(WorkerMessage {
            msg: Some(worker_message::Msg::Register(mut register)),
        }) = inbound.message().await?
        else {
            return Err(Status::invalid_argument("first message must be Register"));
        };
        if let PeerAuth::Tailscale {
            socket,
            allowed_tags,
        } = self.auth.as_ref()
        {
            let Some(addr) = remote else {
                return Err(Status::unauthenticated("no peer address"));
            };
            let who = tailscale::whois(socket, addr).await.map_err(|e| {
                tracing::warn!(%addr, "tailscale whois failed: {}", chain(&e));
                Status::unauthenticated("peer is not on the tailnet")
            })?;
            if !allowed_tags.is_empty() && !who.tags.iter().any(|t| allowed_tags.contains(t)) {
                tracing::warn!(
                    node = who.node_name,
                    tags = ?who.tags,
                    "rejecting worker without an allowed tailscale tag"
                );
                return Err(Status::permission_denied(
                    "tailscale node tag not in tailscale-allowed-tags",
                ));
            }
            // The tailnet-asserted name is authoritative; the worker's
            // self-reported one would let any tailnet peer impersonate
            // another in logs and metrics.
            register.worker_name = who.node_name;
        }
        tracing::info!(
            worker = register.worker_name,
            caps = ?register.caps,
            "worker registered"
        );

        let (out_tx, out_rx) = mpsc::channel::<Result<HubMessage, Status>>(64);
        let (in_tx, in_rx) = mpsc::channel::<WorkerMessage>(64);
        tokio::spawn(async move {
            while let Ok(Some(m)) = inbound.message().await {
                if in_tx.send(m).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(worker_loop(self.state.clone(), register, out_tx, in_rx));
        Ok(Response::new(ReceiverStream::new(out_rx)))
    }
}

async fn worker_loop(
    state: Arc<HubState>,
    register: Register,
    out_tx: mpsc::Sender<Result<HubMessage, Status>>,
    in_rx: mpsc::Receiver<WorkerMessage>,
) {
    let caps = WorkerCaps {
        name: register.worker_name.clone(),
        connected_at: Instant::now(),
        systems: register
            .caps
            .iter()
            .map(|c| (c.system.clone(), c.features.iter().cloned().collect()))
            .collect(),
        max_jobs: register.max_jobs,
    };
    let caps_guard = CapsGuard::new(state.clone(), caps.clone());
    let router = Router::default();
    // Builds this worker still holds from before a hub restart; jobs
    // with these keys go to it regardless of capacity (their slots are
    // already occupied by them).
    let worker_id = caps_guard.id;
    state
        .held
        .lock()
        .unwrap()
        .insert(worker_id, register.resumable_keys.iter().cloned().collect());
    // The worker's last declared free capacity, decremented per
    // dispatch until its next declaration replaces it.
    let capacity = Arc::new(AtomicU32::new(0));
    let mut route = tokio::spawn(route_loop(
        in_rx,
        router.clone(),
        capacity.clone(),
        state.clone(),
        worker_id,
    ));
    let sess = Arc::new(WorkerSession::new());

    'outer: loop {
        let job = loop {
            if out_tx.is_closed() || route.is_finished() {
                break 'outer;
            }
            // resumed builds already occupy their slot on the worker
            if let Some(job) = state.take_job_by_key(worker_id).await {
                break job;
            }
            if capacity.load(Ordering::SeqCst) > 0
                && let Some(job) = state.take_job(&caps, worker_id).await
            {
                capacity.fetch_sub(1, Ordering::SeqCst);
                break job;
            }
            // notify_waiters() wakes only current waiters; the timeout
            // closes the race between checking the queue and awaiting.
            tokio::select! {
                () = state.notify.notified() => {}
                () = tokio::time::sleep(Duration::from_secs(1)) => {}
                _ = &mut route => break 'outer,
            }
        };
        tracing::info!(
            id = job.id,
            worker = register.worker_name,
            "dispatching build"
        );
        // Tell the attach client where its build runs.
        job.replay
            .publish(attach_event::Event::Dispatched(
                register.worker_name.clone(),
            ))
            .await;
        state
            .metrics
            .observe_queue(&job.req.system, job.queued_at.elapsed());
        let in_rx = router.register(&job.id);
        tokio::spawn(supervise_job(
            state.clone(),
            job,
            router.clone(),
            out_tx.clone(),
            in_rx,
            sess.clone(),
            (worker_id, register.worker_name.clone()),
        ));
    }
    // Builds in flight fail through their closed router channels.
    route.abort();
    router.close_all();
    drop(caps_guard);
    state.fail_unservable().await;
    tracing::info!(worker = register.worker_name, "worker disconnected");
}

/// A requeued build kept for the worker whose session died while it ran
/// the build: the worker likely still runs it and re-registers shortly.
struct Reservation {
    /// Name the worker registers with, the identity a reconnect keeps.
    worker: String,
    /// Id of the session that died.
    session: u64,
    until: Instant,
}

impl Reservation {
    /// Within the grace and the worker is not back. Back means
    /// registered with its held keys: from then on those route the job.
    fn awaited(
        &self,
        workers: &HashMap<u64, WorkerCaps>,
        held: &HashMap<u64, HashSet<String>>,
    ) -> bool {
        Instant::now() < self.until
            && !workers.iter().any(|(id, c)| {
                *id != self.session && c.name == self.worker && held.contains_key(id)
            })
    }
}

/// Run one dispatched job and settle it: finish, requeue or fail.
/// `worker` is the session's id and worker name.
async fn supervise_job(
    state: Arc<HubState>,
    mut job: Job,
    router: Router,
    out_tx: mpsc::Sender<Result<HubMessage, Status>>,
    in_rx: mpsc::Receiver<worker_message::Msg>,
    sess: Arc<WorkerSession>,
    worker: (u64, String),
) {
    let _running = state.metrics.running(&job.req.system);
    let mut dispatched = false;
    let res = run_job(&state, &job, &out_tx, in_rx, sess, &mut dispatched).await;
    router.unregister(&job.id);
    // run_job counts the build verdict. Only session/hub-side errors
    // reach the branches below.
    let Err(err) = res else {
        state.finish(&job).await;
        return;
    };
    let err = chain(&err);
    // Neither a dead session nor a failure before the worker saw the
    // assignment is a build verdict: requeue so this worker (by dedupe
    // key) or another one picks it up.
    let session_dead = router.is_closed() || out_tx.is_closed();
    if (session_dead || !dispatched) && job.attempts < MAX_JOB_ATTEMPTS {
        tracing::warn!(id = job.id, "dispatch lost, requeueing build: {err}");
        Metrics::inc(&state.metrics.requeued);
        // A worker restart drops the session but not the build: keep
        // it for that worker until it re-registers, or the grace ends,
        // instead of running it a second time elsewhere.
        let (session, worker) = worker;
        job.reserved = (session_dead && dispatched).then(|| Reservation {
            worker,
            session,
            until: Instant::now() + state.worker_grace,
        });
        state.requeue(job).await;
    } else {
        tracing::warn!(id = job.id, "build failed: {err}");
        Metrics::inc(&state.metrics.failed);
        // The session is still up and may hold a half-staged or
        // running build for this id. Cancel frees that slot.
        let _ = send(
            &out_tx,
            hub_message::Msg::Cancel(CancelBuild {
                build_id: job.id.clone(),
                dedupe_key: job.key.clone(),
            }),
        )
        .await;
        job.replay.publish(attach_event::Event::Error(err)).await;
        state.finish(&job).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    use state::Replay;

    use crate::proto::{AttachEvent, BuildRequest};

    fn caps(name: &str) -> WorkerCaps {
        WorkerCaps {
            name: name.into(),
            connected_at: Instant::now(),
            systems: [("x86_64-linux".to_owned(), HashSet::new())].into(),
            max_jobs: 1,
        }
    }

    /// A worker session as worker_loop registers it.
    fn register(state: &Arc<HubState>, name: &str, held: &[&str]) -> CapsGuard {
        let guard = CapsGuard::new(state.clone(), caps(name));
        let keys = held.iter().map(|k| (*k).to_owned()).collect();
        state.held.lock().unwrap().insert(guard.id, keys);
        guard
    }

    fn job(replay: Arc<Replay>) -> Job {
        Job {
            id: "0123456789abcdef0123456789abcdef".into(),
            key: "k1".into(),
            req: BuildRequest {
                system: "x86_64-linux".into(),
                ..Default::default()
            },
            tmp_dir_pack: Arc::new(Vec::new()),
            features: vec![],
            replay,
            listing: StdMutex::default(),
            attempts: 0,
            queued_at: Instant::now(),
            reserved: None,
        }
    }

    /// Dispatch `job` to `worker`, whose session then dies while the
    /// build runs, as when the worker unit restarts.
    async fn lose_session(state: &Arc<HubState>, job: Job, worker: CapsGuard) {
        let router = Router::default();
        let in_rx = router.register(&job.id);
        let (out_tx, _out_rx) = mpsc::channel(64);
        let session = (worker.id, worker.caps.name.clone());
        router.close_all();
        drop(worker);
        let sess = Arc::new(WorkerSession::new());
        supervise_job(state.clone(), job, router, out_tx, in_rx, sess, session).await;
    }

    #[tokio::test]
    async fn restarted_worker_gets_its_build_back() {
        let state = Arc::new(HubState::for_test(Duration::from_secs(30)));
        let other = register(&state, "w2", &[]);
        let replay = Arc::new(Replay::default());
        let _client = replay.subscribe().await;
        lose_session(&state, job(replay), register(&state, "w1", &[])).await;
        assert!(
            state.take_job(&caps("w2"), other.id).await.is_none(),
            "build handed to another worker while its own reconnects"
        );
        let back = register(&state, "w1", &["k1"]);
        assert!(state.take_job(&caps("w2"), other.id).await.is_none());
        let resumed = state.take_job_by_key(back.id).await;
        assert_eq!(resumed.map(|j| j.attempts), Some(1));
    }

    #[tokio::test]
    async fn build_goes_elsewhere_once_the_grace_ends() {
        let state = Arc::new(HubState::for_test(Duration::from_secs(1)));
        let other = register(&state, "w2", &[]);
        let replay = Arc::new(Replay::default());
        let _client = replay.subscribe().await;
        lose_session(&state, job(replay), register(&state, "w1", &[])).await;
        assert!(state.take_job(&caps("w2"), other.id).await.is_none());
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(state.take_job(&caps("w2"), other.id).await.is_some());
    }

    /// The worker came back without the build (it was still staging):
    /// no reason to keep it from the others any longer.
    #[tokio::test]
    async fn build_is_released_when_its_worker_returns_without_it() {
        let state = Arc::new(HubState::for_test(Duration::from_secs(30)));
        let other = register(&state, "w2", &[]);
        let replay = Arc::new(Replay::default());
        let _client = replay.subscribe().await;
        lose_session(&state, job(replay), register(&state, "w1", &[])).await;
        let _back = register(&state, "w1", &[]);
        assert!(state.take_job(&caps("w2"), other.id).await.is_some());
    }

    /// No worker returns and none other serves the system: the client
    /// sees an error once the grace ends rather than waiting forever.
    #[tokio::test]
    async fn client_is_failed_when_no_worker_returns() {
        let mut state = Arc::new(HubState::for_test(Duration::from_millis(200)));
        Arc::get_mut(&mut state).unwrap().started_at =
            Instant::now().checked_sub(Duration::from_mins(1)).unwrap();
        let replay = Arc::new(Replay::default());
        let mut client = replay.subscribe().await;
        let worker = register(&state, "w1", &[]);
        lose_session(&state, job(replay), worker).await;
        let failed = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(Ok(AttachEvent { event: Some(e) })) = client.recv().await {
                if let attach_event::Event::Error(e) = e {
                    return e;
                }
            }
            String::new()
        })
        .await
        .expect("the client was left waiting");
        assert!(failed.contains("no connected worker"), "{failed}");
    }
}
