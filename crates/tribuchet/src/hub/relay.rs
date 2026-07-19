//! Per-job protocol with a worker: input staging, output relay and verification.

use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use harmonia_utils_signature::{PublicKey, Signature};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tonic::Status;

use super::state::{HubState, Job};
use crate::proto::{
    BuildAssignment, BuildResult, CancelBuild, ExtraPath, HubMessage, NarTransfer, OutputNar,
    OutputSignature, PathInfoMsg, PathOffer, ResultAck, TmpDirArchive, attach_event, hub_message,
    nar_transfer, worker_message,
};

/// How long a dispatched build may run with no attach client listening
/// before the hub cancels it on the worker.
const CANCEL_GRACE: Duration = Duration::from_secs(10);

/// Per-worker-session staging state: one build's inputs stream at a
/// time, and paths already streamed this session are not re-sent.
pub(super) struct WorkerStaging {
    permits: tokio::sync::Semaphore,
    streamed: Mutex<HashSet<String>>,
}

impl WorkerStaging {
    pub(super) fn new() -> Self {
        Self {
            permits: tokio::sync::Semaphore::new(1),
            streamed: Mutex::default(),
        }
    }

    /// Forget paths a build streamed but may not have imported (it
    /// failed or the session errored), so a later build re-streams them.
    fn unstage(&self, paths: &[String]) {
        let mut set = self.streamed.lock().unwrap();
        for p in paths {
            set.remove(p);
        }
    }
}

pub(super) async fn send(
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    msg: hub_message::Msg,
) -> Result<()> {
    out_tx
        .send(Ok(HubMessage { msg: Some(msg) }))
        .await
        .map_err(|_| anyhow::anyhow!("worker connection lost"))
}

pub(super) async fn run_job(
    state: &HubState,
    job: &Job,
    vkey: &PublicKey,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    mut in_rx: mpsc::Receiver<worker_message::Msg>,
    staging: Arc<WorkerStaging>,
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
            dedupe_key: job.key.clone(),
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
        match recv(&mut in_rx).await? {
            // The worker already holds this build (it survived a hub
            // restart); skip staging, its result arrives like any other.
            worker_message::Msg::Resumed(_) => {
                tracing::info!(id = job.id, "worker resumed an in-flight build");
                return relay_build(state, job, vkey, out_tx, &mut in_rx)
                    .await
                    .map(|_| ());
            }
            // A resumed build's log tail can race ahead of its Resumed
            // reply (separate task, same stream); pass the chunk on.
            worker_message::Msg::Log(l) => {
                job.replay.publish(attach_event::Event::Log(l.data)).await;
            }
            worker_message::Msg::MissingPaths(m) => {
                // Only ever pack paths we offered: anything else would let
                // a compromised worker read arbitrary host files. Dedupe,
                // so a repeated entry cannot amplify pack work either.
                let offered: HashSet<&String> = req.input_paths.iter().collect();
                let mut missing = Vec::new();
                let mut seen = HashSet::new();
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
            // Staging failed worker-side (assignment validation, its
            // nix-daemon unreachable, ...): the worker reports it as a
            // Result before ever sending MissingPaths. Pass the error
            // on to the client instead of calling it unexpected.
            worker_message::Msg::Result(res) if res.exit_code != 0 => {
                publish_worker_failure(state, out_tx, job, &res).await?;
                return Ok(());
            }
            other => bail!(
                "unexpected worker message while negotiating paths: {}",
                msg_name(&other)
            ),
        }
    };
    tracing::info!(
        id = job.id,
        total = req.input_paths.len(),
        missing = missing.len(),
        "input path negotiation done"
    );

    let new_paths = stage_inputs(state, job, out_tx, &staging, &missing).await?;
    let res = relay_build(state, job, vkey, out_tx, &mut in_rx).await;
    if !matches!(res, Ok(true)) {
        staging.unstage(&new_paths);
    }
    res.map(|_| ())
}

/// Stream this build's missing inputs and tmp dir under the session's
/// staging permit; returns the paths newly streamed. Paths an earlier
/// build already streamed are skipped: staging phases are serialized
/// and the worker imports NARs in stream order, so those imports are
/// committed before this build's inputs arrive. The worker re-checks
/// skipped paths when its staging completes.
async fn stage_inputs(
    state: &HubState,
    job: &Job,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    staging: &WorkerStaging,
    missing: &[String],
) -> Result<Vec<String>> {
    // Serialize only the import: negotiation before this is read-only
    // on the worker store, so it runs in parallel (bounded by
    // RequestJob credits) instead of gating throughput on its
    // round-trip.
    let _permit = staging
        .permits
        .acquire()
        .await
        .expect("staging semaphore closed");
    let new_paths = select_unstreamed(&staging.streamed, missing);
    if new_paths.len() < missing.len() {
        tracing::info!(
            id = job.id,
            skipped = missing.len() - new_paths.len(),
            "inputs already streamed earlier in this worker session"
        );
    }
    let res = async {
        // The worker imports missing inputs through its Nix daemon, which
        // needs the full ValidPathInfo; ask the local nix-daemon for it.
        // AddToStoreNar also needs a path's references valid first, and
        // Nix's order is not topological, so reorder references before
        // referrers.
        let infos = order_by_references(query_path_infos(&state.daemon_pool, &new_paths).await?);
        for mut info in infos {
            let path = info.store_path.clone();
            info.build_id = job.id.clone();
            send(out_tx, hub_message::Msg::PathInfo(info)).await?;
            stream_store_path(&job.id, &path, out_tx).await?;
        }
        stream_tmp_dir(&job.id, &job.tmp_dir_tar, out_tx).await
    }
    .await;
    if res.is_err() {
        staging.unstage(&new_paths);
    }
    res.map(|()| new_paths)
}

/// Record `missing` in the session's streamed set; return the paths
/// not streamed before.
fn select_unstreamed(staged: &Mutex<HashSet<String>>, missing: &[String]) -> Vec<String> {
    let mut set = staged.lock().unwrap();
    missing
        .iter()
        .filter(|p| set.insert((*p).clone()))
        .cloned()
        .collect()
}

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
        worker_message::Msg::RequestJob(_) => "RequestJob",
        worker_message::Msg::Resumed(_) => "Resumed",
    }
}

/// The channel carries only this build's messages (route_loop filters);
/// it closes when the worker disconnects or goes silent.
pub(super) async fn recv(
    in_rx: &mut mpsc::Receiver<worker_message::Msg>,
) -> Result<worker_message::Msg> {
    in_rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("worker disconnected or went silent"))
}

/// Nix db metadata for input paths, in wire form, queried over the
/// daemon protocol rather than db.sqlite: harmonia-store-db opens the
/// db with sqlite's immutable=1, which skips locking and WAL replay,
/// so rows still in the WAL -- freshly registered inputs, the common
/// case for build requests -- would be invisible and concurrent
/// checkpoints could yield torn reads. The daemon answers from its
/// own consistent view.
/// References before referrers; tolerates self-refs and cycles.
fn order_by_references(infos: Vec<PathInfoMsg>) -> Vec<PathInfoMsg> {
    let roots: Vec<String> = infos.iter().map(|i| i.store_path.clone()).collect();
    let mut nodes: HashMap<String, PathInfoMsg> = infos
        .into_iter()
        .map(|i| (i.store_path.clone(), i))
        .collect();
    crate::store::topo_order(roots, |p| {
        nodes[p]
            .references
            .iter()
            .filter(|r| nodes.contains_key(*r))
            .cloned()
            .collect()
    })
    .into_iter()
    .map(|p| nodes.remove(&p).unwrap())
    .collect()
}

/// Per-path query info from one daemon connection, for a slice of paths.
async fn query_path_info_chunk(
    pool: &harmonia_store_remote::ConnectionPool,
    paths: &[String],
) -> Result<Vec<PathInfoMsg>> {
    use harmonia_store_path::{StoreDir, StorePath};
    use harmonia_store_remote::DaemonStore as _;
    let store_dir = StoreDir::default();
    let mut guard = pool
        .acquire()
        .await
        .context("connecting to the local nix-daemon")?;
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        let sp: StorePath = store_dir.parse(p)?;
        let info = guard
            .execute(|c| c.query_path_info(&sp))
            .await
            .with_context(|| format!("querying path info for {p}"))?
            .with_context(|| format!("{p} is not a valid path in the local store"))?;
        out.push(PathInfoMsg {
            build_id: String::new(), // filled in by the caller
            store_path: p.clone(),
            nar_sha256: info.nar_hash.digest_bytes().to_vec(),
            nar_size: info.nar_size,
            references: info
                .references
                .iter()
                .map(|r| store_dir.display(r).to_string())
                .collect(),
            signatures: info.signatures.iter().map(ToString::to_string).collect(),
            deriver: info
                .deriver
                .map(|d| store_dir.display(&d).to_string())
                .unwrap_or_default(),
            ca: info.ca.map(|c| c.to_string()).unwrap_or_default(),
        });
    }
    Ok(out)
}

async fn query_path_infos(
    pool: &harmonia_store_remote::ConnectionPool,
    paths: &[String],
) -> Result<Vec<PathInfoMsg>> {
    // Spread the per-path query_path_info round trips over several
    // daemon connections; the pool caps real concurrency (one per CPU).
    const PARALLELISM: usize = 8;
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let chunk_size = paths.len().div_ceil(PARALLELISM).max(1);
    let chunks = paths
        .chunks(chunk_size)
        .map(|chunk| query_path_info_chunk(pool, chunk));
    let results = futures_util::future::try_join_all(chunks).await?;
    Ok(results.into_iter().flatten().collect())
}

/// NAR-pack a local store path, zstd-compress, and stream it to the
/// worker. The pack (blocking store reads plus the zstd encode) runs on
/// the blocking pool, overlapping the network send it feeds through the
/// bounded channel and keeping the async workers free.
async fn stream_store_path(
    build_id: &str,
    store_path: &str,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8);
    let path = store_path.to_string();
    let task = tokio::task::spawn_blocking(move || -> Result<()> {
        use tokio::io::AsyncReadExt as _;
        crate::rt::name_current_thread("trib-pack");
        // harmonia's NAR pack is async-only; drive it on a current-thread
        // runtime here so its blocking file reads stay off the shared
        // runtime workers.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .context("building NAR pack runtime")?;
        rt.block_on(async move {
            let nar = harmonia_file_nar::archive::NarByteStream::new(PathBuf::from(&path));
            let mut enc = async_compression::tokio::bufread::ZstdEncoder::with_quality(
                tokio_util::io::StreamReader::new(nar),
                async_compression::Level::Precise(3),
            );
            let mut buf = vec![0u8; crate::chunkio::CHUNK_SIZE];
            loop {
                let n = enc
                    .read(&mut buf)
                    .await
                    .with_context(|| format!("packing {path}"))?;
                if n == 0 {
                    break;
                }
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    break; // consumer gone
                }
            }
            Ok(())
        })
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
    task.await??;
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

/// Forward the client-shipped topTmpDir archive (structured attrs,
/// passAsFile files) to the worker. Always sent last: its EOF tells
/// the worker to start the build.
async fn stream_tmp_dir(
    build_id: &str,
    tmp_dir_tar: &[u8],
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
) -> Result<()> {
    for chunk in tmp_dir_tar.chunks(crate::chunkio::CHUNK_SIZE) {
        send(
            out_tx,
            hub_message::Msg::TmpDir(TmpDirArchive {
                build_id: build_id.into(),
                zstd_tar_chunk: chunk.to_vec(),
                eof: false,
            }),
        )
        .await?;
    }
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
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() as u64 > self.remaining {
            return Err(io::Error::other(format!(
                "output NAR exceeds the {MAX_OUTPUT_NAR_BYTES} byte limit"
            )));
        }
        self.remaining -= buf.len() as u64;
        self.hasher.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Verifier for each output the worker reports, checked to be exactly
/// the requested set: a missing output is a build failure, and an extra
/// one would let a worker plant arbitrary store paths on the client.
fn verify_set(
    reported: Vec<OutputSignature>,
    requested: &HashMap<String, String>,
) -> Result<HashMap<String, OutputVerify>> {
    let mut pending = HashMap::new();
    for out in reported {
        let signature: Signature = out
            .signature
            .parse()
            .context("malformed output signature")?;
        pending.insert(
            out.store_path,
            OutputVerify {
                decoder: zstd::stream::write::Decoder::new(HashWriter::default())?,
                signature,
            },
        );
    }
    for scratch in requested.values() {
        if !pending.contains_key(scratch) {
            bail!("worker result is missing output {scratch}");
        }
    }
    if pending.len() != requested.len() {
        let extra: Vec<&String> = pending
            .keys()
            .filter(|p| !requested.values().any(|o| o == *p))
            .collect();
        bail!("worker result contains unrequested outputs: {extra:?}");
    }
    Ok(pending)
}

/// In-flight AddToStoreNar of one recursive-nix extra. Chunks stream
/// through `tx` into a daemon-pool connection held by `task`.
struct ExtraImport {
    tx: mpsc::Sender<bytes::Bytes>,
    task: tokio::task::JoinHandle<Result<()>>,
}

/// Verify each extra's worker signature over `path:nar_sha256_hex`
/// (the same envelope as outputs) and spawn the daemon import. The
/// daemon then verifies on its end that the NAR matches the signed
/// hash.
fn start_extras(
    state: &HubState,
    vkey: &PublicKey,
    reported: Vec<ExtraPath>,
) -> Result<HashMap<String, ExtraImport>> {
    let mut out = HashMap::with_capacity(reported.len());
    for extra in reported {
        let info = extra
            .info
            .ok_or_else(|| anyhow::anyhow!("extra without PathInfo"))?;
        let path = info.store_path.clone();
        let sig: Signature = extra
            .signature
            .parse()
            .context("malformed extra signature")?;
        let envelope = format!("{}:{}", path, hex::encode(&info.nar_sha256));
        if !vkey.verify(envelope.as_bytes(), &sig) {
            bail!("signature verification failed for extra {path}");
        }
        let parsed = crate::store::parse_path_info(&info).context("parsing extra PathInfo")?;
        let (tx, rx) = mpsc::channel::<bytes::Bytes>(8);
        let pool = state.daemon_pool.clone();
        let task = tokio::spawn(async move { import_extra(&pool, parsed, rx).await });
        out.insert(path, ExtraImport { tx, task });
    }
    Ok(out)
}

async fn import_extra(
    pool: &harmonia_store_remote::ConnectionPool,
    info: harmonia_store_path_info::ValidPathInfo,
    rx: mpsc::Receiver<bytes::Bytes>,
) -> Result<()> {
    use futures_util::StreamExt as _;
    use harmonia_store_remote::DaemonStore as _;
    use tokio::io::AsyncReadExt as _;
    let mut guard = pool
        .acquire()
        .await
        .context("connecting to the local nix-daemon")?;
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(Ok::<_, io::Error>);
    let reader = tokio_util::io::StreamReader::new(stream);
    let dec =
        async_compression::tokio::bufread::ZstdDecoder::new(tokio::io::BufReader::new(reader));
    let limited = tokio::io::BufReader::new(dec.take(info.info.nar_size));
    guard
        .execute(|c| c.add_to_store_nar(&info, limited, false, true))
        .await
        .map_err(|e| anyhow::anyhow!("registering extra {} via daemon: {e}", info.path))
}

async fn relay_output_chunk(
    vkey: &PublicKey,
    pending: &mut HashMap<String, OutputVerify>,
    replay: &super::state::Replay,
    n: &NarTransfer,
) -> Result<()> {
    let verify = pending.get_mut(&n.store_path).unwrap();
    if let Some(nar_transfer::Payload::ZstdNarChunk(chunk)) = &n.payload {
        tokio::task::block_in_place(|| verify.decoder.write_all(chunk))?;
        replay
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
        if !vkey.verify(msg.as_bytes(), &verify.signature) {
            bail!("signature verification failed for {}", n.store_path);
        }
        replay
            .publish(attach_event::Event::Output(OutputNar {
                store_path: n.store_path.clone(),
                zstd_nar_chunk: Vec::new(),
                eof: true,
            }))
            .await;
    }
    Ok(())
}

async fn relay_extra_chunk(
    extras: &mut HashMap<String, ExtraImport>,
    replay: &super::state::Replay,
    n: NarTransfer,
) -> Result<()> {
    let extra = extras.get_mut(&n.store_path).unwrap();
    if let Some(nar_transfer::Payload::ZstdNarChunk(chunk)) = n.payload
        && extra.tx.send(chunk.into()).await.is_err()
    {
        // rx closed does not imply failure: the import reads via
        // take(nar_size) and drops rx once done.
        let extra = extras.remove(&n.store_path).unwrap();
        extra.task.await??;
        bail!("excess extra chunks for {}", n.store_path);
    }
    if n.eof {
        let extra = extras.remove(&n.store_path).unwrap();
        drop(extra.tx);
        extra.task.await??;
        replay
            .publish(attach_event::Event::AddedPath(n.store_path))
            .await;
    }
    Ok(())
}

async fn finish_relay(
    state: &HubState,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    replay: &super::state::Replay,
    job: &Job,
) {
    super::metrics::Metrics::inc(&state.metrics.succeeded);
    replay.publish(attach_event::Event::ExitCode(0)).await;
    ack_result(out_tx, job).await;
}

/// Report a worker-side build failure to attached clients: forward
/// the error text and exit code, count the failure, and ack so the
/// worker can drop the build.
async fn publish_worker_failure(
    state: &HubState,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    job: &Job,
    res: &BuildResult,
) -> Result<()> {
    // Unix exposes only the low 8 bits to the parent; a nonzero
    // multiple of 256 would look like success.
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
    super::metrics::Metrics::inc(&state.metrics.failed);
    job.replay
        .publish(attach_event::Event::ExitCode(res.exit_code))
        .await;
    ack_result(out_tx, job).await;
    Ok(())
}

/// Tell the worker its result (and all output NARs) arrived intact,
/// so it can stop keeping the build for redelivery. Best effort: a
/// lost ack only means the worker holds the build dir until its TTL.
async fn ack_result(out_tx: &mpsc::Sender<Result<HubMessage, Status>>, job: &Job) {
    let _ = send(
        out_tx,
        hub_message::Msg::ResultAck(ResultAck {
            build_id: job.id.clone(),
            dedupe_key: job.key.clone(),
        }),
    )
    .await;
}

/// Relay logs, the result and output NARs for one dispatched build.
/// Returns the build verdict; a failed build is not an `Err`.
async fn relay_build(
    state: &HubState,
    job: &Job,
    vkey: &PublicKey,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    in_rx: &mut mpsc::Receiver<worker_message::Msg>,
) -> Result<bool> {
    let mut pending: HashMap<String, OutputVerify> = HashMap::new();
    let mut extras: HashMap<String, ExtraImport> = HashMap::new();
    let mut awaiting_outputs = false;
    let mut abandoned_since: Option<Instant> = None;
    let mut cancel_sent = false;
    // An interval, not a per-iteration sleep: a build that logs
    // continuously must not starve the abandonment check.
    let mut abandon_check = tokio::time::interval(Duration::from_secs(2));
    abandon_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // Periodically watch for the last attach client going away;
        // after a grace period the worker is told to kill the build.
        // Its "cancelled" result then flows back through the arms
        // below like any other failure.
        let m = tokio::select! {
            m = recv(in_rx) => m?,
            _ = abandon_check.tick(), if !cancel_sent => {
                if job.replay.has_subscribers().await {
                    abandoned_since = None;
                } else if abandoned_since.get_or_insert_with(Instant::now).elapsed()
                    > CANCEL_GRACE
                {
                    tracing::info!(id = job.id, "no attach client left; cancelling build");
                    send(
                        out_tx,
                        hub_message::Msg::Cancel(CancelBuild {
                            build_id: job.id.clone(),
                            dedupe_key: job.key.clone(),
                        }),
                    )
                    .await?;
                    cancel_sent = true;
                }
                continue;
            }
        };
        match m {
            worker_message::Msg::Log(l) => {
                job.replay.publish(attach_event::Event::Log(l.data)).await;
            }
            worker_message::Msg::Result(res) => {
                if awaiting_outputs {
                    bail!("worker sent a duplicate build result");
                }
                if res.exit_code != 0 {
                    publish_worker_failure(state, out_tx, job, &res).await?;
                    return Ok(false);
                }
                pending = verify_set(res.outputs, &job.req.outputs)?;
                extras = start_extras(state, vkey, res.extras)?;
                awaiting_outputs = true;
                if pending.is_empty() && extras.is_empty() {
                    finish_relay(state, out_tx, &job.replay, job).await;
                    return Ok(true);
                }
            }
            worker_message::Msg::Nar(n) if awaiting_outputs => {
                if pending.contains_key(&n.store_path) {
                    relay_output_chunk(vkey, &mut pending, &job.replay, &n).await?;
                } else if extras.contains_key(&n.store_path) {
                    relay_extra_chunk(&mut extras, &job.replay, n).await?;
                } else {
                    bail!("worker sent unexpected store path {}", n.store_path);
                }
                if pending.is_empty() && extras.is_empty() {
                    finish_relay(state, out_tx, &job.replay, job).await;
                    return Ok(true);
                }
            }
            other => bail!("unexpected worker message: {}", msg_name(&other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(path: &str, refs: &[&str]) -> PathInfoMsg {
        PathInfoMsg {
            build_id: String::new(),
            store_path: path.into(),
            nar_sha256: Vec::new(),
            nar_size: 0,
            references: refs.iter().map(ToString::to_string).collect(),
            signatures: Vec::new(),
            deriver: String::new(),
            ca: String::new(),
        }
    }

    #[test]
    fn references_are_streamed_before_referrers() {
        // keyring references more-itertools; offered in referrer-first
        // order, as Nix's inputPaths can be.
        let dep = "/nix/store/aaa-more-itertools";
        let lib = "/nix/store/bbb-keyring";
        let ordered = order_by_references(vec![info(lib, &[dep, lib]), info(dep, &[])]);
        let seq: Vec<&str> = ordered.iter().map(|i| i.store_path.as_str()).collect();
        assert_eq!(seq, vec![dep, lib]);
    }

    #[test]
    fn already_streamed_paths_are_skipped_and_reset_on_failure() {
        let staged = Mutex::new(HashSet::new());
        let a = "/nix/store/aaa".to_string();
        let b = "/nix/store/bbb".to_string();
        assert_eq!(
            select_unstreamed(&staged, &[a.clone(), b.clone()]),
            vec![a.clone(), b.clone()]
        );
        // A later build sharing an input streams only its delta.
        assert_eq!(
            select_unstreamed(&staged, &[a.clone(), b.clone()]),
            Vec::<String>::new()
        );
        // A failed build's paths are removed and get streamed again.
        staged.lock().unwrap().remove(&a);
        assert_eq!(select_unstreamed(&staged, &[a.clone(), b]), vec![a]);
    }

    #[test]
    fn reference_cycles_do_not_loop() {
        let a = "/nix/store/aaa";
        let b = "/nix/store/bbb";
        let ordered = order_by_references(vec![info(a, &[b]), info(b, &[a])]);
        assert_eq!(ordered.len(), 2);
    }

    /// Wrong-key signatures must fail before any daemon contact, so a
    /// compromised worker cannot plant store paths on the client.
    #[tokio::test]
    async fn extras_with_wrong_signature_are_rejected() {
        use harmonia_utils_signature::SecretKey;
        let hub_sk = SecretKey::generate("hub-trusted-key-1".into()).unwrap();
        let attacker_sk = SecretKey::generate("attacker-1".into()).unwrap();
        let vkey = hub_sk.to_public_key();

        let path = format!("/nix/store/{}-extra", "0".repeat(32));
        let nar_sha256 = vec![0u8; 32];
        let envelope = format!("{path}:{}", hex::encode(&nar_sha256));
        let bad = ExtraPath {
            info: Some(PathInfoMsg {
                build_id: String::new(),
                store_path: path.clone(),
                nar_sha256: nar_sha256.clone(),
                nar_size: 1024,
                references: vec![],
                signatures: vec![],
                deriver: String::new(),
                ca: String::new(),
            }),
            signature: attacker_sk.sign(envelope.as_bytes()).to_string(),
        };
        let state = HubState::default();
        let err = start_extras(&state, &vkey, vec![bad])
            .err()
            .expect("expected signature rejection");
        assert!(
            err.to_string().contains("signature verification failed"),
            "{err}"
        );
    }
}
