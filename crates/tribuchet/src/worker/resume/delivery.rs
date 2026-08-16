//! Finished-result persistence and delivery: results survive worker
//! restarts and dropped hub sessions until the hub acknowledges them.

use std::fs;
use std::io::Read;
use std::panic;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use harmonia_utils_signature::SecretKey;
use tokio::sync::mpsc;

use super::BuildState;
use crate::chunkio::CHUNK_SIZE;
use crate::errors::{Result, chain, err_msg};
use crate::fsutil::io_ctx;
use crate::proto::{
    BuildResult, ExtraPath, NarTransfer, OutputSignature, PathInfoMsg, WorkerMessage, nar_transfer,
    worker_message,
};
use crate::worker::build::ActiveBuild;
use crate::worker::logtail::LogTail;
use crate::worker::{WorkerCtx, msg, remove_build_dir};

/// Forget finished builds nobody resumed. Without a client
/// resubmitting (it gave up or died), the result has no taker; the
/// entry would otherwise pin the build dir forever.
pub(in crate::worker) fn spawn_resumable_reaper(ctx: Arc<WorkerCtx>) {
    const TTL: Duration = Duration::from_mins(5);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_mins(1)).await;
            let mut expired = Vec::new();
            {
                let mut map = ctx.resumable.lock().unwrap();
                map.retain(|key, e| match &e.finished {
                    Some(fin) if !e.delivering && fin.finished_at.elapsed() > TTL => {
                        expired.push((key.clone(), fin.dir.clone()));
                        false
                    }
                    _ => true,
                });
            }
            for (key, dir) in expired {
                remove_build_dir(&dir);
                tracing::warn!(
                    key,
                    "dropping undelivered build result (no resume within TTL)"
                );
            }
        }
    });
}

/// A build past staging: running, or finished with its result not yet
/// delivered to any hub. Keyed by the assignment's dedupe_key, which
/// survives hub restarts (build ids do not).
pub(in crate::worker) struct ResumableBuild {
    /// From the latest assignment; result messages carry this id.
    pub(in crate::worker) build_id: String,
    /// Sender of the session that issued that assignment. Kept here,
    /// not captured by the build thread: the session alive when the
    /// build *finishes* may not be the one that assigned it. None for
    /// a freshly re-adopted build no session has assigned yet.
    pub(in crate::worker) out_tx: Option<mpsc::Sender<WorkerMessage>>,
    pub(in crate::worker) finished: Option<FinishedBuild>,
    /// A delivery is in flight; a concurrent re-assignment must not
    /// start a second one.
    pub(in crate::worker) delivering: bool,
    /// Build dir holding build.log, for log replay on resume.
    pub(in crate::worker) dir: PathBuf,
    /// Replays the log to the resumed session; joined before the
    /// result is delivered so logs arrive first.
    pub(in crate::worker) log_tail: Option<LogTail>,
}

impl ResumableBuild {
    /// Register a build no session has assigned yet.
    pub(in crate::worker) fn insert(
        ctx: &Arc<WorkerCtx>,
        key: String,
        build_id: String,
        dir: PathBuf,
        finished: Option<FinishedBuild>,
    ) {
        ctx.resumable.lock().unwrap().insert(
            key,
            Self {
                build_id,
                out_tx: None,
                finished,
                delivering: false,
                dir,
                log_tail: None,
            },
        );
    }
}

#[derive(Clone)]
pub(in crate::worker) struct FinishedBuild {
    pub(in crate::worker) exit_code: i32,
    pub(in crate::worker) error: String,
    pub(in crate::worker) outputs: Vec<PackedOutput>,
    /// Recursive-nix closure-delta paths the builder registered with
    /// the worker daemon; empty for non-recursive builds.
    pub(in crate::worker) extras: Vec<PackedExtra>,
    /// Build dir holding the packed NARs; removed after delivery.
    pub(in crate::worker) dir: PathBuf,
    pub(in crate::worker) finished_at: Instant,
}

/// One closure-delta path: PathInfo from the worker daemon plus a
/// PackedOutput-shaped signed envelope over `path:hex(nar_sha256)`.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(in crate::worker) struct PackedExtra {
    /// Absolute store path of the registered extra.
    pub(in crate::worker) path: String,
    pub(in crate::worker) nar_file: PathBuf,
    pub(in crate::worker) nar_sha256: Vec<u8>,
    pub(in crate::worker) nar_size: u64,
    pub(in crate::worker) signature: String,
    pub(in crate::worker) references: Vec<String>,
    /// Existing daemon signatures (`name:base64`).
    pub(in crate::worker) sigs: Vec<String>,
    /// Absolute store path or empty.
    pub(in crate::worker) deriver: String,
    /// Content-address string or empty.
    pub(in crate::worker) ca: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(in crate::worker) struct PackedOutput {
    pub(in crate::worker) scratch: String,
    pub(in crate::worker) nar_file: PathBuf,
    pub(in crate::worker) nar_sha256: Vec<u8>,
    pub(in crate::worker) signature: String,
    /// Store paths the NAR references (intersection with the
    /// candidate set: inputs, sibling outputs, proxy-added paths).
    #[serde(default)]
    pub(in crate::worker) references: Vec<String>,
}

/// Record a build's result in the registry (persisted for redelivery
/// across worker generations) and start delivering it. Shared by the
/// normal execute path and re-adopted builds.
pub(in crate::worker) fn record_finished(ctx: &Arc<WorkerCtx>, key: &str, fin: FinishedBuild) {
    {
        let mut map = ctx.resumable.lock().unwrap();
        if let Some(e) = map.get_mut(key) {
            // build_id may have changed via a resume assignment meanwhile
            persist_finished(key, &e.build_id, &fin);
            e.finished = Some(fin);
        }
    }
    // A cancel flag the abort loop did not get to consume (the build
    // beat it to the finish line) must not linger and kill the next
    // build with this dedupe key. Cleared after `finished` is set: the
    // Cancel handler only adds the flag while the entry is unfinished
    // (under the registry lock), so no new flag can appear afterwards.
    ctx.cancelled.lock().unwrap().remove(key);
    try_deliver(ctx, key);
}

/// Persist for redelivery by a replacement worker; the rename
/// atomically supersedes the running state.
fn persist_finished(key: &str, build_id: &str, fin: &FinishedBuild) {
    let state = BuildState::Finished {
        dedupe_key: key.to_string(),
        build_id: build_id.to_string(),
        exit_code: fin.exit_code,
        error: fin.error.clone(),
        outputs: fin.outputs.clone(),
        extras: fin.extras.clone(),
    };
    let tmp = fin.dir.join("state.json.tmp");
    if let Ok(json) = serde_json::to_vec(&state)
        && fs::write(&tmp, json).is_ok()
    {
        let _ = fs::rename(&tmp, fin.dir.join("state.json"));
    }
}

/// Run a build to a FinishedBuild, whatever happens: errors and even
/// panics become a failed result. Nothing else reports it -- the
/// JoinHandle is dropped, so a leaked panic would leave the registry
/// entry unfinished and the client waiting forever.
pub(in crate::worker) fn execute_to_finished(
    build: &ActiveBuild,
    out_tx: &mpsc::Sender<WorkerMessage>,
    signing_key: &SecretKey,
    timeout: Duration,
) -> FinishedBuild {
    panic::catch_unwind(panic::AssertUnwindSafe(|| {
        build.execute(out_tx, signing_key, timeout)
    }))
    .unwrap_or_else(|_| Err(err_msg("build execution panicked")))
    .unwrap_or_else(|e| {
        let e = chain(&e);
        tracing::error!("build execution failed: {e}");
        FinishedBuild {
            exit_code: 1,
            error: e,
            outputs: vec![],
            extras: vec![],
            dir: build.dir.clone(),
            finished_at: Instant::now(),
        }
    })
}

/// Send a finished build's result and output NARs. Blocking; runs on
/// a blocking thread.
fn deliver(
    fin: &FinishedBuild,
    build_id: &str,
    out_tx: &mpsc::Sender<WorkerMessage>,
) -> Result<()> {
    out_tx.blocking_send(msg(worker_message::Msg::Result(BuildResult {
        build_id: build_id.into(),
        exit_code: fin.exit_code,
        extras: fin
            .extras
            .iter()
            .map(|e| ExtraPath {
                info: Some(PathInfoMsg {
                    build_id: build_id.into(),
                    store_path: e.path.clone(),
                    nar_sha256: e.nar_sha256.clone(),
                    nar_size: e.nar_size,
                    references: e.references.clone(),
                    signatures: e.sigs.clone(),
                    deriver: e.deriver.clone(),
                    ca: e.ca.clone(),
                }),
                signature: e.signature.clone(),
            })
            .collect(),
        outputs: fin
            .outputs
            .iter()
            .map(|o| OutputSignature {
                store_path: o.scratch.clone(),
                nar_sha256: o.nar_sha256.clone(),
                signature: o.signature.clone(),
            })
            .collect(),
        error: fin.error.clone(),
    })))?;
    for o in &fin.outputs {
        stream_nar(out_tx, build_id, &o.scratch, &o.nar_file)?;
    }
    for e in &fin.extras {
        stream_nar(out_tx, build_id, &e.path, &e.nar_file)?;
    }
    Ok(())
}

/// Stream one NAR file to the hub in chunks, followed by an eof marker.
fn stream_nar(
    out_tx: &mpsc::Sender<WorkerMessage>,
    build_id: &str,
    store_path: &str,
    nar_file: &Path,
) -> Result<()> {
    let mut f = fs::File::open(nar_file).map_err(io_ctx("opening", nar_file))?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        out_tx.blocking_send(msg(worker_message::Msg::Nar(NarTransfer {
            build_id: build_id.into(),
            store_path: store_path.into(),
            payload: Some(nar_transfer::Payload::ZstdNarChunk(buf[..n].to_vec())),
            eof: false,
        })))?;
    }
    out_tx.blocking_send(msg(worker_message::Msg::Nar(NarTransfer {
        build_id: build_id.into(),
        store_path: store_path.into(),
        payload: None,
        eof: true,
    })))?;
    Ok(())
}

/// Drop a build whose result the hub confirmed: only now is it safe
/// to forget it, a result merely handed to a dying session would
/// otherwise be lost and cost a rebuild. Matched by dedupe key (the
/// stable identity); the ack's build_id may predate a concurrent
/// resume that rotated the entry's id.
pub(in crate::worker) fn ack_delivery(ctx: &Arc<WorkerCtx>, key: &str, build_id: &str) {
    let removed = {
        let mut map = ctx.resumable.lock().unwrap();
        match map.get(key) {
            Some(e) if e.finished.is_some() => map.remove(key),
            _ => None,
        }
    };
    if let Some(e) = removed {
        remove_build_dir(&e.dir);
        tracing::info!(id = build_id, "build result acknowledged");
    }
}

/// Deliver `key`'s finished result if there is one and no other
/// delivery is running, over the session that issued its latest
/// assignment. The build is kept until the hub acknowledges the
/// result; a failed or unacknowledged delivery is retried on the next
/// assignment of the same key.
pub(in crate::worker) fn try_deliver(ctx: &Arc<WorkerCtx>, key: &str) {
    let (build_id, out_tx, fin, log_tail) = {
        let mut map = ctx.resumable.lock().unwrap();
        let Some(e) = map.get_mut(key) else { return };
        if e.delivering {
            return;
        }
        let (Some(fin), Some(out_tx)) = (e.finished.clone(), e.out_tx.clone()) else {
            return;
        };
        e.delivering = true;
        (e.build_id.clone(), out_tx, fin, e.log_tail.take())
    };
    // Flush any log replay first so the result arrives after the log.
    if let Some(t) = log_tail {
        t.stop();
    }
    let result = deliver(&fin, &build_id, &out_tx);
    let mut map = ctx.resumable.lock().unwrap();
    // The ack may already have removed the entry; nothing to update then.
    if let Some(entry) = map.get_mut(key) {
        entry.delivering = false;
    }
    match result {
        Ok(()) => {
            tracing::info!(id = build_id, "build result sent, awaiting ack");
        }
        Err(e) => {
            tracing::warn!(
                id = build_id,
                "result delivery failed, keeping for resume: {}",
                chain(&e)
            );
        }
    }
}
