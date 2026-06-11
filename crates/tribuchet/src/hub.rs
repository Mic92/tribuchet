//! `tribuchet hub`: scheduler and NAR relay, colocated with nix-daemon.
//!
//! - accepts build submissions from `attach` over a unix socket (gRPC/UDS)
//! - dedupes in-flight builds by scratch-output set; later identical
//!   submissions replay buffered events and then follow live
//! - queues per system type; submitters block until a worker is free
//! - serves the WorkerHub gRPC service over mTLS; workers dial in
//! - reads input store paths and topTmpDir directly from local disk
//! - verifies worker output signatures while relaying compressed chunks

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};

use crate::chunkio::ChunkWriter;
use crate::nar;
use crate::proto::{
    attach_event, attach_hub_server, hub_message, nar_transfer, worker_message, AttachEvent,
    BuildAssignment, BuildRequest, HubMessage, NarTransfer, OutputNar, PathOffer, Register,
    TmpDirArchive, WorkerMessage,
};

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
struct Replay {
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
        attach_event::Event::Error(e) => e.len(),
        attach_event::Event::ExitCode(_) => 0,
    }
    .saturating_add(64)
}

impl Replay {
    async fn publish(&self, ev: attach_event::Event) {
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

    async fn subscribe(&self) -> mpsc::Receiver<Result<AttachEvent, Status>> {
        let mut inner = self.inner.lock().await;
        if inner.overflowed {
            let (tx, rx) = mpsc::channel(1);
            let _ = tx.try_send(Err(Status::resource_exhausted(
                "build output exceeded the replay buffer; retry after it finishes",
            )));
            return rx;
        }
        // Enough capacity for the whole backlog plus live slack, so the
        // snapshot below cannot drop events.
        let (tx, rx) = mpsc::channel(inner.events.len() + SUB_CHANNEL_SLACK);
        for ev in &inner.events {
            let _ = tx.try_send(Ok(ev.clone()));
        }
        if !inner.done {
            inner.subs.push(tx);
        }
        rx
    }

    /// Close all subscriber streams.
    async fn finish(&self) {
        let mut inner = self.inner.lock().await;
        inner.done = true;
        inner.subs.clear();
    }
}

struct Job {
    id: String,
    key: String,
    req: BuildRequest,
    replay: Arc<Replay>,
}

#[derive(Default)]
struct Inflight {
    /// Dedupe key (hash of the full request) -> replay buffer.
    by_key: HashMap<String, Arc<Replay>>,
    /// Scratch output path -> dedupe key; different requests naming the
    /// same scratch path would unpack into the same destination.
    by_path: HashMap<String, String>,
}

#[derive(Default)]
struct HubState {
    queue: Mutex<VecDeque<Job>>,
    inflight: Mutex<Inflight>,
    notify: Notify,
    /// system -> number of connected workers serving it; submissions
    /// for systems with no worker fail fast instead of queueing forever.
    worker_systems: std::sync::Mutex<HashMap<String, usize>>,
}

impl HubState {
    async fn take_job(&self, systems: &[String]) -> Option<Job> {
        let mut queue = self.queue.lock().await;
        let pos = queue.iter().position(|j| systems.contains(&j.req.system))?;
        queue.remove(pos)
    }

    async fn finish(&self, job: &Job) {
        let mut inflight = self.inflight.lock().await;
        inflight.by_key.remove(&job.key);
        for p in job.req.outputs.values() {
            inflight.by_path.remove(p);
        }
        drop(inflight);
        job.replay.finish().await;
    }
}

/// If no worker message arrives for this long the job is failed:
/// heartbeats flow every 30s, so silence means a dead or wedged worker
/// that would otherwise pin the build (and its dedupe key) forever.
const WORKER_SILENCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// The hub serves exactly the canonical Nix store; clients must not
/// anchor path validation at an arbitrary prefix.
pub(crate) const STORE_DIR: &str = "/nix/store";

/// gRPC message size cap. Metadata messages (BuildRequest, PathOffer)
/// carry the whole input closure; tonic's 4 MiB default rejects large
/// but legitimate closures.
pub(crate) const MAX_MSG_SIZE: usize = 64 * 1024 * 1024;

/// A store path basename restricted to Nix's name character set
/// (`checkName` in nix); this also keeps peer-supplied strings free of
/// shell/SBPL metacharacters, control bytes, and leading dots.
pub(crate) fn valid_store_name(base: &str) -> bool {
    !base.is_empty()
        && !base.starts_with('.')
        && base.len() <= 211
        && base
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-._?=".contains(&b))
}

/// A store path directly under the store dir: absolute, exactly one
/// component, no tricks. The hub runs as root and reads these from disk,
/// so anything else would be an arbitrary-file-read primitive.
pub(crate) fn valid_store_path(store_dir: &str, path: &str) -> bool {
    path.strip_prefix(store_dir)
        .and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(valid_store_name)
}

#[allow(clippy::result_large_err)] // tonic::Status is what the caller needs
fn validate_request(req: &BuildRequest) -> Result<(), Status> {
    let bad = |what: &str, p: &str| {
        Status::invalid_argument(format!("{what} is not a valid store path: {p}"))
    };
    // A client-chosen store_dir would turn the root hub into an
    // arbitrary-file-read (and the worker sandbox into worse).
    if req.store_dir != STORE_DIR {
        return Err(Status::invalid_argument("invalid store dir"));
    }
    let mut seen_inputs = std::collections::HashSet::new();
    for p in &req.input_paths {
        if !valid_store_path(&req.store_dir, p) {
            return Err(bad("input path", p));
        }
        if !seen_inputs.insert(p) {
            return Err(Status::invalid_argument(format!(
                "duplicate input path {p}"
            )));
        }
    }
    let mut seen_outputs = std::collections::HashSet::new();
    for p in req.outputs.values() {
        if !valid_store_path(&req.store_dir, p) {
            return Err(bad("output path", p));
        }
        if !seen_outputs.insert(p) {
            return Err(Status::invalid_argument(format!(
                "duplicate output path {p}"
            )));
        }
        if seen_inputs.contains(p) {
            return Err(Status::invalid_argument(format!(
                "output path {p} is also an input"
            )));
        }
    }
    // Nix builders are absolute store paths; anything else would also be
    // option-injectable into sandbox-exec on Darwin workers.
    if !req.builder.starts_with('/') {
        return Err(Status::invalid_argument("builder must be an absolute path"));
    }
    // The worker mounts/symlinks the shipped build dir here and chdirs
    // into it after chroot; pin it to Nix's sandbox-build-dir default.
    if req.tmp_dir_in_sandbox != "/build" {
        return Err(Status::invalid_argument("invalid tmpDirInSandbox"));
    }
    let tmp = Path::new(&req.top_tmp_dir);
    if !tmp.is_absolute()
        || tmp
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Status::invalid_argument("invalid topTmpDir"));
    }
    Ok(())
}

/// The root hub tars `top_tmp_dir` off local disk; require it to be a
/// real directory owned by the connecting peer so a client cannot have
/// the hub ship `/root` or another user's build dir.
#[allow(clippy::result_large_err)]
fn validate_top_tmp_dir(top_tmp_dir: &str, peer_uid: u32) -> Result<(), Status> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(top_tmp_dir)
        .map_err(|e| Status::invalid_argument(format!("topTmpDir {top_tmp_dir}: {e}")))?;
    if !meta.is_dir() {
        return Err(Status::invalid_argument("topTmpDir is not a directory"));
    }
    if meta.uid() != peer_uid {
        return Err(Status::permission_denied(
            "topTmpDir is not owned by the requesting user",
        ));
    }
    Ok(())
}

/// Dedupe key: hash of the full canonicalized request, so only truly
/// identical submissions share a build. A key built from output paths
/// alone would let a colliding (or crafted) request attach to another
/// client's build.
fn dedupe_key(req: &BuildRequest) -> String {
    let mut h = Sha256::new();
    let mut feed = |s: &str| {
        h.update((s.len() as u64).to_le_bytes());
        h.update(s.as_bytes());
    };
    feed(&req.system);
    feed(&req.builder);
    for a in &req.args {
        feed(a);
    }
    let mut env: Vec<_> = req.env.iter().collect();
    env.sort();
    for (k, v) in env {
        feed(k);
        feed(v);
    }
    let mut outs: Vec<_> = req.outputs.iter().collect();
    outs.sort();
    for (k, v) in outs {
        feed(k);
        feed(v);
    }
    let mut inputs: Vec<_> = req.input_paths.iter().collect();
    inputs.sort();
    for p in inputs {
        feed(p);
    }
    feed(&req.store_dir);
    feed(&req.tmp_dir_in_sandbox);
    h.update([req.fixed_output as u8]);
    hex::encode(h.finalize())
}

fn new_id() -> String {
    let mut buf = [0u8; 16];
    rand::Rng::fill(&mut rand::thread_rng(), &mut buf);
    hex::encode(buf)
}

struct AttachSvc {
    state: Arc<HubState>,
}

#[tonic::async_trait]
impl attach_hub_server::AttachHub for AttachSvc {
    type BuildStream = ReceiverStream<Result<AttachEvent, Status>>;

    async fn build(
        &self,
        request: Request<BuildRequest>,
    ) -> Result<Response<Self::BuildStream>, Status> {
        let peer_uid = request
            .extensions()
            .get::<tonic::transport::server::UdsConnectInfo>()
            .and_then(|info| info.peer_cred)
            .map(|cred| cred.uid())
            .ok_or_else(|| Status::internal("missing unix peer credentials"))?;
        let req = request.into_inner();
        if req.outputs.is_empty() {
            return Err(Status::invalid_argument("build request without outputs"));
        }
        validate_request(&req)?;
        validate_top_tmp_dir(&req.top_tmp_dir, peer_uid)?;
        let key = dedupe_key(&req);

        {
            let systems = self.state.worker_systems.lock().unwrap();
            if systems.get(&req.system).copied().unwrap_or(0) == 0 {
                return Err(Status::failed_precondition(format!(
                    "no connected worker builds for system {}",
                    req.system
                )));
            }
        }

        let mut inflight = self.state.inflight.lock().await;
        let replay = if let Some(replay) = inflight.by_key.get(&key) {
            tracing::info!(key, "deduplicating build submission");
            replay.clone()
        } else {
            // A different request claiming an in-flight scratch path
            // would race the other client's unpack at the same dest.
            for p in req.outputs.values() {
                if inflight.by_path.contains_key(p) {
                    return Err(Status::failed_precondition(format!(
                        "output path {p} is part of a different in-flight build"
                    )));
                }
            }
            let replay = Arc::new(Replay::default());
            inflight.by_key.insert(key.clone(), replay.clone());
            for p in req.outputs.values() {
                inflight.by_path.insert(p.clone(), key.clone());
            }
            let job = Job {
                id: new_id(),
                key,
                req,
                replay: replay.clone(),
            };
            tracing::info!(id = job.id, system = job.req.system, "queueing build");
            self.state.queue.lock().await.push_back(job);
            self.state.notify.notify_waiters();
            replay
        };
        // Subscribe outside the global inflight lock: the snapshot clone
        // of a large backlog must not stall every other submission.
        drop(inflight);
        let rx = replay.subscribe().await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

struct WorkerSvc {
    state: Arc<HubState>,
    /// Operator-pinned worker signing keys; when configured, a worker
    /// registering an unknown key is rejected. Without it the signature
    /// check only proves the NARs came from whoever registered the key,
    /// which mTLS already guarantees.
    trusted_keys: Option<Arc<std::collections::HashSet<[u8; 32]>>>,
}

/// Registers the worker's systems while alive; removes them on drop so
/// admission control tracks actual capacity.
struct SystemsGuard {
    state: Arc<HubState>,
    systems: Vec<String>,
}

impl SystemsGuard {
    fn new(state: Arc<HubState>, systems: Vec<String>) -> Self {
        let mut map = state.worker_systems.lock().unwrap();
        for s in &systems {
            *map.entry(s.clone()).or_insert(0) += 1;
        }
        drop(map);
        Self { state, systems }
    }
}

impl Drop for SystemsGuard {
    fn drop(&mut self) {
        let mut map = self.state.worker_systems.lock().unwrap();
        for s in &self.systems {
            if let Some(n) = map.get_mut(s) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    map.remove(s);
                }
            }
        }
    }
}

#[tonic::async_trait]
impl crate::proto::worker_hub_server::WorkerHub for WorkerSvc {
    type SessionStream = ReceiverStream<Result<HubMessage, Status>>;

    async fn session(
        &self,
        request: Request<Streaming<WorkerMessage>>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        let mut inbound = request.into_inner();
        let register = match inbound.message().await? {
            Some(WorkerMessage {
                msg: Some(worker_message::Msg::Register(r)),
            }) => r,
            _ => return Err(Status::invalid_argument("first message must be Register")),
        };
        let key: [u8; 32] = register
            .signing_public_key
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("signing key must be 32 bytes"))?;
        let vkey = VerifyingKey::from_bytes(&key)
            .map_err(|e| Status::invalid_argument(format!("bad signing key: {e}")))?;
        if let Some(trusted) = &self.trusted_keys {
            if !trusted.contains(&key) {
                tracing::warn!(
                    worker = register.worker_name,
                    key = hex::encode(key),
                    "rejecting worker with unpinned signing key"
                );
                return Err(Status::permission_denied(
                    "signing key not in the hub's trusted-signing-keys",
                ));
            }
        }
        tracing::info!(
            worker = register.worker_name,
            systems = ?register.systems,
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
            vkey,
            out_tx,
            in_rx,
        ));
        Ok(Response::new(ReceiverStream::new(out_rx)))
    }
}

async fn worker_loop(
    state: Arc<HubState>,
    register: Register,
    vkey: VerifyingKey,
    out_tx: mpsc::Sender<Result<HubMessage, Status>>,
    mut in_rx: mpsc::Receiver<WorkerMessage>,
) {
    let _systems_guard = SystemsGuard::new(state.clone(), register.systems.clone());
    loop {
        let job = loop {
            if let Some(job) = state.take_job(&register.systems).await {
                break job;
            }
            // Drain heartbeats while idle, or the bounded channel (and
            // then HTTP/2 flow control) would stall the worker stream.
            while in_rx.try_recv().is_ok() {}
            // notify_waiters() wakes only current waiters; the timeout
            // closes the race between checking the queue and awaiting.
            tokio::select! {
                _ = state.notify.notified() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            }
            if out_tx.is_closed() {
                tracing::info!(worker = register.worker_name, "worker disconnected");
                return;
            }
        };
        tracing::info!(
            id = job.id,
            worker = register.worker_name,
            "dispatching build"
        );
        match run_job(&job, &vkey, &out_tx, &mut in_rx).await {
            Ok(()) => {}
            Err(e) => {
                tracing::warn!(id = job.id, "build failed: {e:#}");
                job.replay
                    .publish(attach_event::Event::Error(format!("{e:#}")))
                    .await;
            }
        }
        state.finish(&job).await;
        if out_tx.is_closed() {
            tracing::info!(worker = register.worker_name, "worker disconnected");
            return;
        }
    }
}

async fn send(
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    msg: hub_message::Msg,
) -> Result<()> {
    out_tx
        .send(Ok(HubMessage { msg: Some(msg) }))
        .await
        .map_err(|_| anyhow::anyhow!("worker connection lost"))
}

async fn run_job(
    job: &Job,
    vkey: &VerifyingKey,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    in_rx: &mut mpsc::Receiver<WorkerMessage>,
) -> Result<()> {
    let req = &job.req;
    send(
        out_tx,
        hub_message::Msg::Assignment(BuildAssignment {
            build_id: job.id.clone(),
            system: req.system.clone(),
            builder: req.builder.clone(),
            args: req.args.clone(),
            env: req.env.clone(),
            outputs: req.outputs.clone(),
            tmp_dir_in_sandbox: req.tmp_dir_in_sandbox.clone(),
            store_dir: req.store_dir.clone(),
            fixed_output: req.fixed_output,
        }),
    )
    .await?;
    send(
        out_tx,
        hub_message::Msg::PathOffer(PathOffer {
            build_id: job.id.clone(),
            store_paths: req.input_paths.clone(),
        }),
    )
    .await?;

    let missing = loop {
        match recv(in_rx).await? {
            worker_message::Msg::MissingPaths(m) if m.build_id == job.id => {
                // Only ever pack paths we offered: anything else would let
                // a compromised worker read arbitrary host files. Dedupe,
                // so a repeated entry cannot amplify pack work either.
                let offered: std::collections::HashSet<&String> = req.input_paths.iter().collect();
                let mut missing = Vec::new();
                let mut seen = std::collections::HashSet::new();
                for p in m.store_paths {
                    if !offered.contains(&p) {
                        bail!("worker requested unoffered path {p}");
                    }
                    if seen.insert(p.clone()) {
                        missing.push(p);
                    }
                }
                break missing;
            }
            worker_message::Msg::Heartbeat(_) => {}
            other => {
                if is_stale(&other, &job.id) {
                    tracing::warn!(id = job.id, "dropping stale worker message");
                    continue;
                }
                bail!(
                    "unexpected worker message while negotiating paths: {}",
                    msg_name(&other)
                );
            }
        }
    };
    tracing::info!(
        id = job.id,
        total = req.input_paths.len(),
        missing = missing.len(),
        "input path negotiation done"
    );

    for path in &missing {
        stream_store_path(&job.id, path, out_tx).await?;
    }
    stream_tmp_dir(&job.id, Path::new(&req.top_tmp_dir), out_tx).await?;

    relay_build(job, vkey, out_tx, in_rx).await
}

/// Messages that belong to a different (earlier, abandoned) build must
/// not abort the current one.
/// Log/error-safe name of a worker message variant. The messages embed
/// peer-controlled bytes (NAR chunks, log data); Debug-formatting them
/// into error strings would balloon logs and replay buffers.
fn msg_name(msg: &worker_message::Msg) -> &'static str {
    match msg {
        worker_message::Msg::Register(_) => "Register",
        worker_message::Msg::Heartbeat(_) => "Heartbeat",
        worker_message::Msg::MissingPaths(_) => "MissingPaths",
        worker_message::Msg::Log(_) => "Log",
        worker_message::Msg::Result(_) => "Result",
        worker_message::Msg::Nar(_) => "Nar",
    }
}

fn is_stale(msg: &worker_message::Msg, build_id: &str) -> bool {
    let id = match msg {
        worker_message::Msg::Log(l) => &l.build_id,
        worker_message::Msg::Result(r) => &r.build_id,
        worker_message::Msg::Nar(n) => &n.build_id,
        worker_message::Msg::MissingPaths(m) => &m.build_id,
        _ => return false,
    };
    id != build_id
}

async fn recv(in_rx: &mut mpsc::Receiver<WorkerMessage>) -> Result<worker_message::Msg> {
    loop {
        let m = tokio::time::timeout(WORKER_SILENCE_TIMEOUT, in_rx.recv())
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "worker sent nothing for {}s; assuming it is dead",
                    WORKER_SILENCE_TIMEOUT.as_secs()
                )
            })?;
        match m {
            Some(WorkerMessage { msg: Some(m) }) => return Ok(m),
            Some(WorkerMessage { msg: None }) => {}
            None => bail!("worker connection lost"),
        }
    }
}

/// NAR-pack a local store path, zstd-compress, and stream it to the worker.
async fn stream_store_path(
    build_id: &str,
    store_path: &str,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8);
    let path = PathBuf::from(store_path);
    let task = tokio::task::spawn_blocking(move || -> Result<()> {
        let mut enc = zstd::stream::write::Encoder::new(ChunkWriter::new(tx), 3)?;
        nar::pack(&path, &mut enc)?;
        enc.finish()?.flush()?;
        Ok(())
    });
    while let Some(chunk) = rx.recv().await {
        send(
            out_tx,
            hub_message::Msg::Nar(NarTransfer {
                build_id: build_id.into(),
                store_path: store_path.into(),
                payload: Some(nar_transfer::Payload::ZstdNarChunk(chunk)),
                eof: false,
            }),
        )
        .await?;
    }
    task.await?
        .with_context(|| format!("packing {store_path}"))?;
    send(
        out_tx,
        hub_message::Msg::Nar(NarTransfer {
            build_id: build_id.into(),
            store_path: store_path.into(),
            payload: None,
            eof: true,
        }),
    )
    .await
}

/// Tar+zstd the topTmpDir (structured attrs, passAsFile files) to the
/// worker. Always sent last: its EOF tells the worker to start the build.
async fn stream_tmp_dir(
    build_id: &str,
    top_tmp_dir: &Path,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8);
    let dir = top_tmp_dir.to_owned();
    let task = tokio::task::spawn_blocking(move || -> Result<()> {
        let enc = zstd::stream::write::Encoder::new(ChunkWriter::new(tx), 3)?;
        let mut tar = tar::Builder::new(enc);
        tar.follow_symlinks(false);
        tar.append_dir_all(".", &dir)?;
        tar.into_inner()?.finish()?.flush()?;
        Ok(())
    });
    while let Some(chunk) = rx.recv().await {
        send(
            out_tx,
            hub_message::Msg::TmpDir(TmpDirArchive {
                build_id: build_id.into(),
                zstd_tar_chunk: chunk,
                eof: false,
            }),
        )
        .await?;
    }
    task.await??;
    send(
        out_tx,
        hub_message::Msg::TmpDir(TmpDirArchive {
            build_id: build_id.into(),
            zstd_tar_chunk: Vec::new(),
            eof: true,
        }),
    )
    .await
}

/// Hashes the decompressed NAR while the compressed chunks are relayed
/// untouched, so signature verification adds no extra buffering or
/// recompression.
struct OutputVerify {
    decoder: zstd::stream::write::Decoder<'static, HashWriter>,
    signature: Signature,
}

struct HashWriter {
    hasher: Sha256,
    /// Decompressed byte budget: zstd RLE amplifies ~30,000:1, so a
    /// sub-4MiB message could otherwise expand without bound on the hub
    /// (and later fill the client's disk).
    remaining: u64,
}

impl Default for HashWriter {
    fn default() -> Self {
        Self {
            hasher: Sha256::new(),
            remaining: MAX_OUTPUT_NAR_BYTES,
        }
    }
}

/// Decompressed size cap per output NAR, matching the worker's pack cap.
const MAX_OUTPUT_NAR_BYTES: u64 = 64 * 1024 * 1024 * 1024;

impl Write for HashWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() as u64 > self.remaining {
            return Err(std::io::Error::other(format!(
                "output NAR exceeds the {MAX_OUTPUT_NAR_BYTES} byte limit"
            )));
        }
        self.remaining -= buf.len() as u64;
        self.hasher.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn relay_build(
    job: &Job,
    vkey: &VerifyingKey,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    in_rx: &mut mpsc::Receiver<WorkerMessage>,
) -> Result<()> {
    let _ = out_tx; // cancellation not implemented yet
    let mut pending: HashMap<String, OutputVerify> = HashMap::new();
    let mut awaiting_outputs = false;

    loop {
        match recv(in_rx).await? {
            worker_message::Msg::Heartbeat(_) => {}
            worker_message::Msg::Log(l) if l.build_id == job.id => {
                job.replay.publish(attach_event::Event::Log(l.data)).await;
            }
            worker_message::Msg::Result(res) if res.build_id == job.id => {
                if awaiting_outputs {
                    bail!("worker sent a duplicate build result");
                }
                if res.exit_code != 0 {
                    // Unix exposes only the low 8 bits to the parent; a
                    // nonzero multiple of 256 would look like success.
                    if !(1..=255).contains(&res.exit_code) {
                        bail!("worker sent invalid exit code {}", res.exit_code);
                    }
                    if !res.error.is_empty() {
                        job.replay
                            .publish(attach_event::Event::Log(
                                format!("tribuchet worker error: {}\n", res.error).into_bytes(),
                            ))
                            .await;
                    }
                    job.replay
                        .publish(attach_event::Event::ExitCode(res.exit_code))
                        .await;
                    return Ok(());
                }
                for out in res.outputs {
                    let sig = Signature::from_slice(&out.signature)
                        .context("malformed output signature")?;
                    pending.insert(
                        out.store_path,
                        OutputVerify {
                            decoder: zstd::stream::write::Decoder::new(HashWriter::default())?,
                            signature: sig,
                        },
                    );
                }
                for scratch in job.req.outputs.values() {
                    if !pending.contains_key(scratch) {
                        bail!("worker result is missing output {scratch}");
                    }
                }
                // ... and nothing besides the requested outputs, or the
                // worker could plant arbitrary store paths on the client.
                if pending.len() != job.req.outputs.len() {
                    let extra: Vec<&String> = pending
                        .keys()
                        .filter(|p| !job.req.outputs.values().any(|o| o == *p))
                        .collect();
                    bail!("worker result contains unrequested outputs: {extra:?}");
                }
                awaiting_outputs = true;
            }
            worker_message::Msg::Nar(n) if n.build_id == job.id && awaiting_outputs => {
                let Some(verify) = pending.get_mut(&n.store_path) else {
                    bail!("worker sent unexpected output {}", n.store_path);
                };
                if let Some(nar_transfer::Payload::ZstdNarChunk(chunk)) = &n.payload {
                    // CPU work off the shared executor threads
                    tokio::task::block_in_place(|| verify.decoder.write_all(chunk))?;
                    job.replay
                        .publish(attach_event::Event::Output(OutputNar {
                            store_path: n.store_path.clone(),
                            zstd_nar_chunk: chunk.clone(),
                            eof: false,
                        }))
                        .await;
                }
                if n.eof {
                    let mut verify = pending.remove(&n.store_path).unwrap();
                    verify.decoder.flush()?;
                    let hash = verify.decoder.into_inner().hasher.finalize();
                    let msg = format!("{}:{}", n.store_path, hex::encode(hash));
                    vkey.verify(msg.as_bytes(), &verify.signature)
                        .with_context(|| {
                            format!("signature verification failed for {}", n.store_path)
                        })?;
                    job.replay
                        .publish(attach_event::Event::Output(OutputNar {
                            store_path: n.store_path.clone(),
                            zstd_nar_chunk: Vec::new(),
                            eof: true,
                        }))
                        .await;
                    if pending.is_empty() {
                        job.replay.publish(attach_event::Event::ExitCode(0)).await;
                        return Ok(());
                    }
                }
            }
            other => {
                if is_stale(&other, &job.id) {
                    tracing::warn!(id = job.id, "dropping stale worker message");
                    continue;
                }
                bail!("unexpected worker message: {}", msg_name(&other));
            }
        }
    }
}

pub fn run(socket: &Path, listen: &str, config_dir: &Path) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(socket, listen, config_dir))
}

async fn run_async(socket: &Path, listen: &str, config_dir: &Path) -> Result<()> {
    let state = Arc::new(HubState::default());

    let ca_dir = config_dir.join("ca");
    let identity = Identity::from_pem(
        std::fs::read(ca_dir.join("hub.crt")).context("reading hub.crt")?,
        std::fs::read(ca_dir.join("hub.key")).context("reading hub.key")?,
    );
    let ca = Certificate::from_pem(std::fs::read(ca_dir.join("ca.crt")).context("reading ca.crt")?);
    let tls = ServerTlsConfig::new().identity(identity).client_ca_root(ca);

    // Optional operator pinning of worker signing keys (one hex ed25519
    // public key per line, '#' comments). Without it, output signatures
    // only authenticate the TLS channel, not a particular worker.
    let trusted_keys = match std::fs::read_to_string(config_dir.join("trusted-signing-keys")) {
        Ok(data) => {
            let mut keys = std::collections::HashSet::new();
            for line in data.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let bytes: [u8; 32] = hex::decode(line)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .with_context(|| format!("bad key in trusted-signing-keys: {line}"))?;
                keys.insert(bytes);
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

    // Bind TCP eagerly: a second hub instance must fail here on
    // EADDRINUSE *before* it clobbers the live hub's unix socket below.
    let tcp = tokio::net::TcpListener::bind(
        listen
            .parse::<std::net::SocketAddr>()
            .context("parsing listen address")?,
    )
    .await
    .context("binding worker listen address")?;
    let worker_server = Server::builder()
        .tls_config(tls)?
        // Detect dead/half-open worker connections instead of relying on
        // the workers' own traffic.
        .http2_keepalive_interval(Some(std::time::Duration::from_secs(30)))
        .http2_keepalive_timeout(Some(std::time::Duration::from_secs(20)))
        .add_service(
            crate::proto::worker_hub_server::WorkerHubServer::new(WorkerSvc {
                state: state.clone(),
                trusted_keys,
            })
            .max_decoding_message_size(MAX_MSG_SIZE)
            .max_encoding_message_size(MAX_MSG_SIZE),
        )
        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(tcp));

    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Refuse to replace the socket of a live hub: unlinking it would
    // leave all new attaches with ECONNREFUSED while the old hub runs.
    if std::os::unix::net::UnixStream::connect(socket).is_ok() {
        bail!("another hub is already serving {}", socket.display());
    }
    let _ = std::fs::remove_file(socket);
    // attach runs as a nix build user: restrict the socket to that group
    // (anyone who can reach it can have store paths packed and shipped).
    // Resolve the group *before* binding and bind with a tight umask so
    // the socket is never connectable by others, not even briefly.
    let group = match nix::unistd::Group::from_name("nixbld") {
        Ok(Some(group)) => group,
        _ => bail!(
            "group nixbld not found; refusing to serve a hub socket without a group to restrict it to"
        ),
    };
    let old_umask = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o117));
    let uds = tokio::net::UnixListener::bind(socket);
    nix::sys::stat::umask(old_umask);
    let uds = uds?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::os::unix::fs::chown(socket, None, Some(group.gid.as_raw()))?;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o660))?;
    }
    let attach_server = Server::builder()
        .add_service(
            attach_hub_server::AttachHubServer::new(AttachSvc { state })
                .max_decoding_message_size(MAX_MSG_SIZE)
                .max_encoding_message_size(MAX_MSG_SIZE),
        )
        .serve_with_incoming(UnixListenerStream::new(uds));

    tracing::info!(listen, socket = %socket.display(), "hub running");
    tokio::try_join!(
        async { worker_server.await.context("worker gRPC server") },
        async { attach_server.await.context("attach gRPC server") },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_path_validation() {
        let ok = |p| valid_store_path("/nix/store", p);
        assert!(ok("/nix/store/abc-foo"));
        assert!(ok("/nix/store/abc-foo_1.2+x?=y"));
        assert!(!ok("/nix/store/"));
        assert!(!ok("/nix/store/.."));
        assert!(!ok("/nix/store/.hidden"));
        assert!(!ok("/nix/store/abc/../../etc"));
        assert!(!ok("/nix/store/abc/bin/sh"));
        assert!(!ok("/etc/shadow"));
        assert!(!ok("/nix/storeX/abc"));
        // no quotes/parens/control bytes: these strings reach the macOS
        // sandbox profile and log lines verbatim
        assert!(!ok("/nix/store/a\")(allow-default)(\""));
        assert!(!ok("/nix/store/a\nb"));
        assert!(!ok("/nix/store/a,b"));
    }

    fn base_request() -> BuildRequest {
        BuildRequest {
            system: "x86_64-linux".into(),
            builder: "/nix/store/abc-bash/bin/bash".into(),
            args: vec!["-c".into(), "true".into()],
            env: Default::default(),
            outputs: [("out".to_string(), "/nix/store/abc-out".to_string())].into(),
            input_paths: vec!["/nix/store/abc-dep".into()],
            top_tmp_dir: "/tmp/nix-build-x".into(),
            tmp_dir_in_sandbox: "/build".into(),
            store_dir: "/nix/store".into(),
            fixed_output: false,
        }
    }

    #[test]
    fn request_validation() {
        assert!(validate_request(&base_request()).is_ok());

        let mut req = base_request();
        req.store_dir = "/etc".into();
        req.input_paths = vec!["/etc/shadow".into()];
        req.outputs = [("out".to_string(), "/etc/out".to_string())].into();
        assert!(validate_request(&req).is_err());

        let mut req = base_request();
        req.builder = "-p".into();
        assert!(validate_request(&req).is_err());

        let mut req = base_request();
        req.tmp_dir_in_sandbox = "relative".into();
        assert!(validate_request(&req).is_err());

        let mut req = base_request();
        req.input_paths = vec!["/nix/store/abc-dep".into(), "/nix/store/abc-dep".into()];
        assert!(validate_request(&req).is_err());

        let mut req = base_request();
        req.outputs
            .insert("doc".into(), "/nix/store/abc-out".into());
        assert!(validate_request(&req).is_err());

        let mut req = base_request();
        req.outputs = [("out".to_string(), "/nix/store/abc-dep".to_string())].into();
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn dedupe_key_binds_full_request() {
        let a = dedupe_key(&base_request());
        assert_eq!(a, dedupe_key(&base_request()));
        let mut req = base_request();
        req.args = vec!["-c".into(), "false".into()];
        assert_ne!(a, dedupe_key(&req));
        let mut req = base_request();
        req.env.insert("X".into(), "1".into());
        assert_ne!(a, dedupe_key(&req));
    }
}
