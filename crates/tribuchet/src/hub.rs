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
use tokio_stream::wrappers::{ReceiverStream, UnboundedReceiverStream, UnixListenerStream};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};

use crate::chunkio::ChunkWriter;
use crate::nar;
use crate::proto::{
    attach_event, attach_hub_server, hub_message, nar_transfer, worker_message, AttachEvent,
    BuildAssignment, BuildRequest, HubMessage, NarTransfer, OutputNar, PathOffer, Register,
    TmpDirArchive, WorkerMessage,
};

type EventTx = mpsc::UnboundedSender<Result<AttachEvent, Status>>;

/// Buffered event log of one in-flight build; late identical submissions
/// (dedupe) replay the buffer and then follow live. The buffer holds the
/// compressed output chunks too — acceptable for the targeted scale.
#[derive(Default)]
struct Replay {
    inner: Mutex<ReplayInner>,
}

#[derive(Default)]
struct ReplayInner {
    events: Vec<AttachEvent>,
    subs: Vec<EventTx>,
    done: bool,
}

impl Replay {
    async fn publish(&self, ev: attach_event::Event) {
        let ev = AttachEvent { event: Some(ev) };
        let mut inner = self.inner.lock().await;
        inner.subs.retain(|tx| tx.send(Ok(ev.clone())).is_ok());
        inner.events.push(ev);
    }

    async fn subscribe(&self) -> mpsc::UnboundedReceiver<Result<AttachEvent, Status>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut inner = self.inner.lock().await;
        for ev in &inner.events {
            let _ = tx.send(Ok(ev.clone()));
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
struct HubState {
    queue: Mutex<VecDeque<Job>>,
    inflight: Mutex<HashMap<String, Arc<Replay>>>,
    notify: Notify,
}

impl HubState {
    async fn take_job(&self, systems: &[String]) -> Option<Job> {
        let mut queue = self.queue.lock().await;
        let pos = queue.iter().position(|j| systems.contains(&j.req.system))?;
        queue.remove(pos)
    }

    async fn finish(&self, job: &Job) {
        self.inflight.lock().await.remove(&job.key);
        job.replay.finish().await;
    }
}

/// A store path directly under the store dir: absolute, exactly one
/// component, no tricks. The hub runs as root and reads these from disk,
/// so anything else would be an arbitrary-file-read primitive.
fn valid_store_path(store_dir: &str, path: &str) -> bool {
    path.strip_prefix(store_dir)
        .and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(|base| !base.is_empty() && base != "." && base != ".." && !base.contains('/'))
}

#[allow(clippy::result_large_err)] // tonic::Status is what the caller needs
fn validate_request(req: &BuildRequest) -> Result<(), Status> {
    let bad = |what: &str, p: &str| {
        Status::invalid_argument(format!("{what} is not a valid store path: {p}"))
    };
    if !req.store_dir.starts_with('/') || req.store_dir.contains("..") {
        return Err(Status::invalid_argument("invalid store dir"));
    }
    for p in &req.input_paths {
        if !valid_store_path(&req.store_dir, p) {
            return Err(bad("input path", p));
        }
    }
    for p in req.outputs.values() {
        if !valid_store_path(&req.store_dir, p) {
            return Err(bad("output path", p));
        }
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

fn dedupe_key(req: &BuildRequest) -> String {
    let mut outs: Vec<&str> = req.outputs.values().map(|s| s.as_str()).collect();
    outs.sort_unstable();
    outs.join(",")
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
    type BuildStream = UnboundedReceiverStream<Result<AttachEvent, Status>>;

    async fn build(
        &self,
        request: Request<BuildRequest>,
    ) -> Result<Response<Self::BuildStream>, Status> {
        let req = request.into_inner();
        if req.outputs.is_empty() {
            return Err(Status::invalid_argument("build request without outputs"));
        }
        validate_request(&req)?;
        let key = dedupe_key(&req);

        let mut inflight = self.state.inflight.lock().await;
        let replay = if let Some(replay) = inflight.get(&key) {
            tracing::info!(key, "deduplicating build submission");
            replay.clone()
        } else {
            let replay = Arc::new(Replay::default());
            inflight.insert(key.clone(), replay.clone());
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
        let rx = replay.subscribe().await;
        drop(inflight);
        Ok(Response::new(UnboundedReceiverStream::new(rx)))
    }
}

struct WorkerSvc {
    state: Arc<HubState>,
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
    loop {
        let job = loop {
            if let Some(job) = state.take_job(&register.systems).await {
                break job;
            }
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
            worker_message::Msg::MissingPaths(m) if m.build_id == job.id => break m.store_paths,
            worker_message::Msg::Heartbeat(_) => {}
            other => bail!("unexpected worker message while negotiating paths: {other:?}"),
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

async fn recv(in_rx: &mut mpsc::Receiver<WorkerMessage>) -> Result<worker_message::Msg> {
    loop {
        match in_rx.recv().await {
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

#[derive(Default)]
struct HashWriter(Sha256);

impl Write for HashWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
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
                if res.exit_code != 0 {
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
                awaiting_outputs = true;
                if pending.is_empty() {
                    job.replay.publish(attach_event::Event::ExitCode(0)).await;
                    return Ok(());
                }
            }
            worker_message::Msg::Nar(n) if n.build_id == job.id && awaiting_outputs => {
                let Some(verify) = pending.get_mut(&n.store_path) else {
                    bail!("worker sent unexpected output {}", n.store_path);
                };
                if let Some(nar_transfer::Payload::ZstdNarChunk(chunk)) = &n.payload {
                    verify.decoder.write_all(chunk)?;
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
                    let hash = verify.decoder.into_inner().0.finalize();
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
            other => bail!("unexpected worker message: {other:?}"),
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

    let worker_server = Server::builder()
        .tls_config(tls)?
        .add_service(crate::proto::worker_hub_server::WorkerHubServer::new(
            WorkerSvc {
                state: state.clone(),
            },
        ))
        .serve(listen.parse().context("parsing listen address")?);

    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(socket);
    let uds = tokio::net::UnixListener::bind(socket)?;
    // attach runs as a nix build user: restrict the socket to that group
    // (anyone who can reach it can have store paths packed and shipped).
    {
        use std::os::unix::fs::PermissionsExt;
        match nix::unistd::Group::from_name("nixbld") {
            Ok(Some(group)) => {
                std::os::unix::fs::chown(socket, None, Some(group.gid.as_raw()))?;
                std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o660))?;
            }
            _ => {
                tracing::warn!("group nixbld not found; hub socket is world-writable");
                std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o666))?;
            }
        }
    }
    let attach_server = Server::builder()
        .add_service(attach_hub_server::AttachHubServer::new(AttachSvc { state }))
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
        assert!(!ok("/nix/store/"));
        assert!(!ok("/nix/store/.."));
        assert!(!ok("/nix/store/abc/../../etc"));
        assert!(!ok("/nix/store/abc/bin/sh"));
        assert!(!ok("/etc/shadow"));
        assert!(!ok("/nix/storeX/abc"));
    }
}
