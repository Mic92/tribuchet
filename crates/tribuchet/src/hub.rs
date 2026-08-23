//! `tribuchet hub`: scheduler and NAR relay, colocated with nix-daemon.
//!
//! - accepts build submissions from `attach` over a unix socket (gRPC/UDS)
//! - dedupes in-flight builds by scratch-output set; later identical
//!   submissions replay buffered events and then follow live
//! - queues per system type; submitters block until a worker is free
//! - serves the WorkerHub gRPC service over mTLS; workers dial in
//! - reads input store paths directly from local disk
//! - verifies worker output signatures while relaying compressed chunks

use std::collections::{HashMap, HashSet};
#[cfg(target_os = "macos")]
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use harmonia_utils_signature::PublicKey;
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
use relay::{WorkerStaging, run_job, send};
use state::{HubState, WorkerCaps};

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
    /// Operator-pinned worker signing keys; when configured, a worker
    /// registering an unknown key is rejected. Without it the signature
    /// check only proves the NARs came from whoever registered the key,
    /// which the transport auth already guarantees.
    trusted_keys: Option<Arc<Vec<PublicKey>>>,
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
        self.builds.lock().unwrap().clear();
    }
}

fn msg_build_id(msg: &worker_message::Msg) -> Option<&str> {
    match msg {
        worker_message::Msg::Log(l) => Some(&l.build_id),
        worker_message::Msg::Result(r) => Some(&r.build_id),
        worker_message::Msg::Nar(n) => Some(&n.build_id),
        worker_message::Msg::MissingPaths(m) => Some(&m.build_id),
        worker_message::Msg::Resumed(r) => Some(&r.build_id),
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
    req_tx: mpsc::Sender<()>,
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
        if matches!(m, worker_message::Msg::RequestJob(_)) {
            // try_send: routing must never block behind a request flood;
            // a worker with more outstanding requests than the channel
            // holds is misbehaving and only loses its own slots
            let _ = req_tx.try_send(());
            continue;
        }
        let Some(id) = msg_build_id(&m).map(str::to_string) else {
            continue; // heartbeat: any traffic counts as liveness
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
        let vkey: PublicKey = register
            .signing_public_key
            .parse()
            .map_err(|e| Status::invalid_argument(format!("bad signing key: {e}")))?;
        if let Some(trusted) = &self.trusted_keys
            && !trusted.contains(&vkey)
        {
            tracing::warn!(
                worker = register.worker_name,
                key = %vkey,
                "rejecting worker with unpinned signing key"
            );
            return Err(Status::permission_denied(
                "signing key not in the hub's trusted-signing-keys",
            ));
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
        tokio::spawn(worker_loop(
            self.state.clone(),
            register,
            Arc::new(vkey),
            out_tx,
            in_rx,
        ));
        Ok(Response::new(ReceiverStream::new(out_rx)))
    }
}

async fn worker_loop(
    state: Arc<HubState>,
    register: Register,
    vkey: Arc<PublicKey>,
    out_tx: mpsc::Sender<Result<HubMessage, Status>>,
    in_rx: mpsc::Receiver<WorkerMessage>,
) {
    let caps = WorkerCaps {
        name: register.worker_name.clone(),
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
    // with these keys go to it credit-free (it is the only worker that
    // can resume them, and its slots are already occupied by them).
    // Each key is honored once: dedupe keys are stable per derivation,
    // so a later identical submission must go through the normal
    // credit and capability checks, not this fast path.
    let mut resumable: HashSet<String> = register.resumable_keys.iter().cloned().collect();
    // each received RequestJob funds at most one assignment
    let (req_tx, mut req_rx) = mpsc::channel::<()>(1024);
    let route = tokio::spawn(route_loop(in_rx, router.clone(), req_tx));
    // Stage one build's inputs at a time per worker: the worker imports
    // each closure in isolation (references before referrers, no
    // shared-path lock contention) and a later build sees earlier shared
    // inputs as valid, so it fetches only its delta.
    let staging = Arc::new(WorkerStaging::new());

    let mut credits: usize = 0;
    'outer: loop {
        let job = loop {
            if out_tx.is_closed() || route.is_finished() {
                break 'outer;
            }
            while req_rx.try_recv().is_ok() {
                credits += 1;
            }
            if let Some(job) = state.take_job_by_key(&resumable).await {
                resumable.remove(&job.key);
                break job;
            }
            if credits > 0
                && let Some(job) = state.take_job(&caps).await
            {
                credits -= 1;
                break job;
            }
            // notify_waiters() wakes only current waiters; the timeout
            // closes the race between checking the queue and awaiting.
            tokio::select! {
                () = state.notify.notified() => {}
                () = tokio::time::sleep(Duration::from_secs(1)) => {}
                r = req_rx.recv() => match r {
                    Some(()) => credits += 1,
                    None => break 'outer, // route_loop ended: worker gone
                },
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
        Metrics::inc(&state.metrics.dispatched);
        let in_rx = router.register(&job.id);
        let state = state.clone();
        let router = router.clone();
        let out_tx = out_tx.clone();
        let vkey = vkey.clone();
        let staging = staging.clone();
        tokio::spawn(async move {
            let res = run_job(&state, &job, &vkey, &out_tx, in_rx, staging).await;
            router.unregister(&job.id);
            // run_job counts the build verdict; only session/hub-side
            // errors reach the branches below.
            let Err(err) = res else {
                state.finish(&job).await;
                return;
            };
            // A dead worker session is not a build verdict: requeue so
            // the worker (or its replacement) can resume the build by
            // dedupe key, or another worker can start over.
            if out_tx.is_closed() && job.attempts < MAX_JOB_ATTEMPTS {
                let err = chain(&err);
                tracing::warn!(id = job.id, "worker session lost; requeueing build: {err}");
                Metrics::inc(&state.metrics.requeued);
                state.requeue(job).await;
            } else {
                let err = chain(&err);
                tracing::warn!(id = job.id, "build failed: {err}");
                Metrics::inc(&state.metrics.failed);
                // The worker session is still up: it may hold a
                // half-staged or running build (and its job credit) for
                // this id. Cancelling lets it tear that down and send
                // the next RequestJob; without it every hub-side
                // failure permanently costs the worker one slot.
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
        });
    }
    // Builds in flight fail through their closed router channels.
    route.abort();
    router.close_all();
    drop(caps_guard);
    state.fail_unservable().await;
    tracing::info!(worker = register.worker_name, "worker disconnected");
}
