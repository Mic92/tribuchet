//! `tribuchet hub`: scheduler and NAR relay, colocated with nix-daemon.
//!
//! - accepts build submissions from `attach` over a unix socket (gRPC/UDS)
//! - dedupes in-flight builds by scratch-output set; later identical
//!   submissions replay buffered events and then follow live
//! - queues per system type; submitters block until a worker is free
//! - serves the WorkerHub gRPC service over mTLS; workers dial in
//! - reads input store paths and topTmpDir directly from local disk
//! - verifies worker output signatures while relaying compressed chunks

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use harmonia_utils_signature::PublicKey;
use nix::sys::stat;
use nix::unistd::Group;
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};

use crate::proto::{
    attach_event, attach_hub_server, hub_message, worker_message, CancelBuild, HubMessage,
    Register, WorkerMessage, MAX_MSG_SIZE,
};

mod relay;
mod state;
mod submit;

use relay::{run_job, send};
use state::{HubState, WorkerCaps};
use submit::AttachSvc;

/// No worker message for this long tears the session down and fails
/// its builds: heartbeats flow every 30s, so silence means a dead
/// worker that would otherwise pin its builds (and dedupe keys) forever.
const WORKER_SILENCE_TIMEOUT: Duration = Duration::from_mins(3);
/// A worker-session loss requeues a job at most this many times.
const MAX_JOB_ATTEMPTS: u32 = 3;

struct WorkerSvc {
    state: Arc<HubState>,
    /// Operator-pinned worker signing keys; when configured, a worker
    /// registering an unknown key is rejected. Without it the signature
    /// check only proves the NARs came from whoever registered the key,
    /// which mTLS already guarantees.
    trusted_keys: Option<Arc<Vec<PublicKey>>>,
}

/// Registers the worker's capabilities while alive; removes them on
/// drop so admission control tracks actual capacity.
struct CapsGuard {
    state: Arc<HubState>,
    id: u64,
}

impl CapsGuard {
    fn new(state: Arc<HubState>, caps: WorkerCaps) -> Self {
        let id = state
            .next_worker_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        state.worker_caps.lock().unwrap().insert(id, caps);
        Self { state, id }
    }
}

impl Drop for CapsGuard {
    fn drop(&mut self) {
        self.state.worker_caps.lock().unwrap().remove(&self.id);
    }
}

/// Routes the single worker stream to per-build channels so multiple
/// jobs share one session. Dropping a sender closes the job's receiver,
/// which it observes as the worker going away.
#[derive(Default, Clone)]
struct Router {
    builds: Arc<std::sync::Mutex<HashMap<String, mpsc::Sender<worker_message::Msg>>>>,
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
impl crate::proto::worker_hub_server::WorkerHub for WorkerSvc {
    type SessionStream = ReceiverStream<Result<HubMessage, Status>>;

    async fn session(
        &self,
        request: Request<Streaming<WorkerMessage>>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        let mut inbound = request.into_inner();
        let Some(WorkerMessage {
            msg: Some(worker_message::Msg::Register(register)),
        }) = inbound.message().await?
        else {
            return Err(Status::invalid_argument("first message must be Register"));
        };
        let vkey: PublicKey = register
            .signing_public_key
            .parse()
            .map_err(|e| Status::invalid_argument(format!("bad signing key: {e}")))?;
        if let Some(trusted) = &self.trusted_keys {
            if !trusted.contains(&vkey) {
                tracing::warn!(
                    worker = register.worker_name,
                    key = %vkey,
                    "rejecting worker with unpinned signing key"
                );
                return Err(Status::permission_denied(
                    "signing key not in the hub's trusted-signing-keys",
                ));
            }
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
        systems: register
            .caps
            .iter()
            .map(|c| (c.system.clone(), c.features.iter().cloned().collect()))
            .collect(),
    };
    let caps_guard = CapsGuard::new(state.clone(), caps.clone());
    let router = Router::default();
    // Builds this worker still holds from before a hub restart; jobs
    // with these keys go to it credit-free (it is the only worker that
    // can resume them, and its slots are already occupied by them).
    // Each key is honored once: dedupe keys are stable per derivation,
    // so a later identical submission must go through the normal
    // credit and capability checks, not this fast path.
    let mut resumable: std::collections::HashSet<String> =
        register.resumable_keys.iter().cloned().collect();
    // each received RequestJob funds at most one assignment
    let (req_tx, mut req_rx) = mpsc::channel::<()>(1024);
    let route = tokio::spawn(route_loop(in_rx, router.clone(), req_tx));

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
            if credits > 0 {
                if let Some(job) = state.take_job(&caps).await {
                    credits -= 1;
                    break job;
                }
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
        let in_rx = router.register(&job.id);
        let state = state.clone();
        let router = router.clone();
        let out_tx = out_tx.clone();
        let vkey = vkey.clone();
        tokio::spawn(async move {
            let res = run_job(&state, &job, &vkey, &out_tx, in_rx).await;
            router.unregister(&job.id);
            let Err(err) = res else {
                state.finish(&job).await;
                return;
            };
            // A dead worker session is not a build verdict: requeue so
            // the worker (or its replacement) can resume the build by
            // dedupe key, or another worker can start over.
            if out_tx.is_closed() && job.attempts < MAX_JOB_ATTEMPTS {
                tracing::warn!(
                    id = job.id,
                    "worker session lost; requeueing build: {err:#}"
                );
                state.requeue(job).await;
            } else {
                tracing::warn!(id = job.id, "build failed: {err:#}");
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
                job.replay
                    .publish(attach_event::Event::Error(format!("{err:#}")))
                    .await;
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

/// Bind the attach socket ourselves (no socket activation).
///
/// attach runs as a nix build user: restrict the socket to that group
/// (anyone who can reach it can have store paths packed and shipped).
/// Resolve the group *before* binding and bind with a tight umask so
/// the socket is never connectable by others, not even briefly.
fn bind_attach_socket(socket: &Path) -> Result<tokio::net::UnixListener> {
    if let Some(parent) = socket.parent() {
        fs::create_dir_all(parent)?;
    }
    // Refuse to replace the socket of a live hub: unlinking it would
    // leave all new attaches with ECONNREFUSED while the old hub runs.
    if std::os::unix::net::UnixStream::connect(socket).is_ok() {
        bail!("another hub is already serving {}", socket.display());
    }
    let _ = fs::remove_file(socket);
    let Ok(Some(group)) = Group::from_name("nixbld") else {
        bail!("group nixbld not found; refusing to serve a hub socket without a group to restrict it to");
    };
    let old_umask = stat::umask(stat::Mode::from_bits_truncate(0o117));
    let uds = tokio::net::UnixListener::bind(socket);
    stat::umask(old_umask);
    let uds = uds?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::os::unix::fs::chown(socket, None, Some(group.gid.as_raw()))?;
        fs::set_permissions(socket, fs::Permissions::from_mode(0o660))?;
    }
    Ok(uds)
}

/// Restrict an attach socket path bound by launchd to the nixbld group
/// with mode 0660, like bind_attach_socket() does for self-bound and
/// systemd does for socket-activated ones; launchd's `Sockets` plist
/// dictionary has a mode key but no owner/group key.
#[cfg(target_os = "macos")]
fn restrict_attach_socket(socket: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let Some(group) = Group::from_name("nixbld")? else {
        bail!("group nixbld not found; refusing to serve a hub socket without a group to restrict it to");
    };
    std::os::unix::fs::chown(socket, None, Some(group.gid.as_raw()))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o660))?;
    Ok(())
}

pub fn run(socket: &Path, listen: &str, config_dir: &Path) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(socket, listen, config_dir))
}

async fn run_async(socket: &Path, listen: &str, config_dir: &Path) -> Result<()> {
    let state = Arc::new(HubState::default());

    let ca_dir = config_dir.join("ca");
    let identity = Identity::from_pem(
        fs::read(ca_dir.join("hub.crt")).context("reading hub.crt")?,
        fs::read(ca_dir.join("hub.key")).context("reading hub.key")?,
    );
    let ca = Certificate::from_pem(fs::read(ca_dir.join("ca.crt")).context("reading ca.crt")?);
    let tls = ServerTlsConfig::new().identity(identity).client_ca_root(ca);

    // Optional operator pinning of worker signing keys (one Nix-format
    // "name:base64" public key per line, '#' comments; same syntax as
    // nix.conf trusted-public-keys). Without it, output signatures only
    // authenticate the TLS channel, not a particular worker.
    let trusted_keys = match fs::read_to_string(config_dir.join("trusted-signing-keys")) {
        Ok(data) => {
            let mut keys = Vec::new();
            for line in data.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                keys.push(line.parse::<PublicKey>().map_err(|e| {
                    anyhow::anyhow!("bad key in trusted-signing-keys: {line}: {e}")
                })?);
            }
            tracing::info!(count = keys.len(), "worker signing keys pinned");
            Some(Arc::new(keys))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                "no trusted-signing-keys file in {}; accepting any signing key from \
                 mTLS-authenticated workers",
                config_dir.display()
            );
            None
        }
        Err(e) => return Err(e).context("reading trusted-signing-keys"),
    };

    // Listeners come from systemd socket activation when available
    // (they survive hub restarts; clients queue instead of getting
    // ECONNREFUSED), otherwise we bind ourselves.
    let activated = crate::sd::activated_sockets()?;
    let tcp = match activated.tcp {
        Some(l) => tokio::net::TcpListener::from_std(l).context("adopting activated TCP socket")?,
        // Bind TCP eagerly: a second hub instance must fail here on
        // EADDRINUSE *before* it clobbers the live hub's unix socket
        // below.
        None => tokio::net::TcpListener::bind(
            listen
                .parse::<std::net::SocketAddr>()
                .context("parsing listen address")?,
        )
        .await
        .context("binding worker listen address")?,
    };
    let worker_server = Server::builder()
        .tls_config(tls)?
        // Detect dead/half-open worker connections instead of relying on
        // the workers' own traffic.
        .http2_keepalive_interval(Some(Duration::from_secs(30)))
        .http2_keepalive_timeout(Some(Duration::from_secs(20)))
        .add_service(
            crate::proto::worker_hub_server::WorkerHubServer::new(WorkerSvc {
                state: state.clone(),
                trusted_keys,
            })
            .max_decoding_message_size(MAX_MSG_SIZE)
            .max_encoding_message_size(MAX_MSG_SIZE),
        )
        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(tcp));

    let uds = match activated.unix {
        // Activated socket: systemd owns the path, mode and group
        // (SocketGroup=/SocketMode= in the .socket unit). launchd has
        // no group key, so on macOS the hub restricts the path itself.
        Some(l) => {
            #[cfg(target_os = "macos")]
            restrict_attach_socket(socket)?;
            tokio::net::UnixListener::from_std(l).context("adopting activated unix socket")?
        }
        None => bind_attach_socket(socket)?,
    };
    let attach_server = Server::builder()
        .add_service(
            attach_hub_server::AttachHubServer::new(AttachSvc {
                state: state.clone(),
            })
            .max_decoding_message_size(MAX_MSG_SIZE)
            .max_encoding_message_size(MAX_MSG_SIZE),
        )
        .serve_with_incoming(UnixListenerStream::new(uds));

    tracing::info!(listen, socket = %socket.display(), "hub running");
    crate::sd::notify_ready();
    crate::sd::spawn_watchdog();
    let servers = async {
        tokio::try_join!(
            async { worker_server.await.context("worker gRPC server") },
            async { attach_server.await.context("attach gRPC server") },
        )
    };
    // No drain on SIGTERM: hub state is reconstructed by the
    // replacement instance from worker re-registration (resumable
    // build keys) and attach resubmission (deterministic dedupe
    // keys), so exiting immediately cancels nothing.
    tokio::select! {
        res = servers => res.map(|_| ()),
        () = crate::sd::stop_requested() => {
            tracing::info!("SIGTERM: exiting, builds resume against the replacement instance");
            Ok(())
        }
    }
}
