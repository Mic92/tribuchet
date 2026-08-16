//! Per-job protocol with a worker: input staging, output relay and verification.

mod staging;
use staging::{restage_inputs, stage_inputs, validate_missing};

use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt as _;
use harmonia_store_remote::DaemonStore as _;
use harmonia_utils_signature::{PublicKey, Signature};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt as _;
use tokio::sync::mpsc;
use tonic::Status;

use super::metrics::Metrics;
use super::state::{HubState, Job, Replay};
use crate::errors::{Result, err_ctx, err_msg};
use crate::proto::{
    BuildAssignment, BuildResult, CancelBuild, ExtraPath, HubMessage, MAX_RESEND_ROUNDS,
    NarTransfer, OutputNar, OutputSignature, PathOffer, ResultAck, attach_event, hub_message,
    nar_transfer, worker_message,
};
use crate::store;

/// How long a dispatched build may run with no attach client listening
/// before the hub cancels it on the worker.
const CANCEL_GRACE: Duration = Duration::from_secs(10);

/// Per-worker-session staging state: one build's inputs stream at a
/// time. Dedup of shared inputs happens on the worker.
pub(super) struct WorkerStaging {
    permits: tokio::sync::Semaphore,
}

impl WorkerStaging {
    pub(super) fn new() -> Self {
        Self {
            permits: tokio::sync::Semaphore::new(1),
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
        .map_err(|_| err_msg("worker connection lost"))
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
                return relay_build(state, job, vkey, out_tx, &mut in_rx, &staging)
                    .await
                    .map(|_| ());
            }
            // A resumed build's log tail can race ahead of its Resumed
            // reply (separate task, same stream); pass the chunk on.
            worker_message::Msg::Log(l) => {
                job.replay.publish(attach_event::Event::Log(l.data)).await;
            }
            worker_message::Msg::MissingPaths(m) => {
                break validate_missing(&req.input_paths, m.store_paths)?;
            }
            // Staging failed worker-side (assignment validation, its
            // nix-daemon unreachable, ...): the worker reports it as a
            // Result before ever sending MissingPaths. Pass the error
            // on to the client instead of calling it unexpected.
            worker_message::Msg::Result(res) if res.exit_code != 0 => {
                publish_worker_failure(state, out_tx, job, &res).await?;
                return Ok(());
            }
            other => {
                return Err(err_msg(format!(
                    "unexpected worker message while negotiating paths: {}",
                    msg_name(&other)
                )));
            }
        }
    };
    tracing::info!(
        id = job.id,
        total = req.input_paths.len(),
        missing = missing.len(),
        "input path negotiation done"
    );

    stage_inputs(state, job, out_tx, &staging, &missing).await?;
    relay_build(state, job, vkey, out_tx, &mut in_rx, &staging)
        .await
        .map(|_| ())
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
        .ok_or_else(|| err_msg("worker disconnected or went silent"))
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
            .map_err(err_ctx("malformed output signature"))?;
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
            return Err(err_msg(format!(
                "worker result is missing output {scratch}"
            )));
        }
    }
    if pending.len() != requested.len() {
        let extra: Vec<&String> = pending
            .keys()
            .filter(|p| !requested.values().any(|o| o == *p))
            .collect();
        return Err(err_msg(format!(
            "worker result contains unrequested outputs: {extra:?}"
        )));
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
            .ok_or_else(|| err_msg("extra without PathInfo"))?;
        let path = info.store_path.clone();
        let sig: Signature = extra
            .signature
            .parse()
            .map_err(err_ctx("malformed extra signature"))?;
        let envelope = format!("{}:{}", path, hex::encode(&info.nar_sha256));
        if !vkey.verify(envelope.as_bytes(), &sig) {
            return Err(err_msg(format!(
                "signature verification failed for extra {path}"
            )));
        }
        let parsed = store::parse_path_info(&info).map_err(err_ctx("parsing extra PathInfo"))?;
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
    let mut guard = pool
        .acquire()
        .await
        .map_err(err_ctx("connecting to the local nix-daemon"))?;
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(Ok::<_, io::Error>);
    let reader = tokio_util::io::StreamReader::new(stream);
    let dec =
        async_compression::tokio::bufread::ZstdDecoder::new(tokio::io::BufReader::new(reader));
    let limited = tokio::io::BufReader::new(dec.take(info.info.nar_size));
    guard
        .execute(|c| c.add_to_store_nar(&info, limited, false, true))
        .await
        .map_err(|e| err_msg(format!("registering extra {} via daemon: {e}", info.path)))
}

async fn relay_output_chunk(
    vkey: &PublicKey,
    pending: &mut HashMap<String, OutputVerify>,
    replay: &Replay,
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
            return Err(err_msg(format!(
                "signature verification failed for {}",
                n.store_path
            )));
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
    replay: &Replay,
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
        return Err(err_msg(format!("excess extra chunks for {}", n.store_path)));
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
    replay: &Replay,
    job: &Job,
) {
    Metrics::inc(&state.metrics.succeeded);
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
        return Err(err_msg(format!(
            "worker sent invalid exit code {}",
            res.exit_code
        )));
    }
    if !res.error.is_empty() {
        job.replay
            .publish(attach_event::Event::Log(
                format!("tribuchet worker error: {}\n", res.error).into_bytes(),
            ))
            .await;
    }
    Metrics::inc(&state.metrics.failed);
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
    staging: &WorkerStaging,
) -> Result<bool> {
    let mut pending: HashMap<String, OutputVerify> = HashMap::new();
    let mut extras: HashMap<String, ExtraImport> = HashMap::new();
    let mut awaiting_outputs = false;
    let mut resend_rounds = 0;
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
            // Inputs the worker deferred to another build's import
            // that never became valid: re-stream them.
            worker_message::Msg::MissingPaths(m) if !awaiting_outputs => {
                resend_rounds += 1;
                if resend_rounds > MAX_RESEND_ROUNDS {
                    return Err(err_msg(format!(
                        "worker requested input re-sends more than {MAX_RESEND_ROUNDS} times"
                    )));
                }
                let missing = validate_missing(&job.req.input_paths, m.store_paths)?;
                tracing::info!(
                    id = job.id,
                    round = resend_rounds,
                    count = missing.len(),
                    "re-streaming inputs the worker reported missing after staging"
                );
                restage_inputs(state, job, out_tx, staging, &missing).await?;
            }
            worker_message::Msg::Result(res) => {
                if awaiting_outputs {
                    return Err(err_msg("worker sent a duplicate build result"));
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
                    return Err(err_msg(format!(
                        "worker sent unexpected store path {}",
                        n.store_path
                    )));
                }
                if pending.is_empty() && extras.is_empty() {
                    finish_relay(state, out_tx, &job.replay, job).await;
                    return Ok(true);
                }
            }
            other => {
                return Err(err_msg(format!(
                    "unexpected worker message: {}",
                    msg_name(&other)
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use harmonia_utils_signature::SecretKey;

    use crate::proto::PathInfoMsg;

    use super::*;

    /// Wrong-key signatures must fail before any daemon contact, so a
    /// compromised worker cannot plant store paths on the client.
    #[tokio::test]
    async fn extras_with_wrong_signature_are_rejected() {
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
