//! Resumable builds: adoption across worker generations, result persistence and delivery.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use harmonia_store_path::StoreDir;
use harmonia_store_remote::{DaemonClient, DaemonStore};
use harmonia_utils_signature::SecretKey;
use tokio::sync::mpsc;

use super::build::{ActiveBuild, supervise};
use super::logtail::LogTail;
use super::{DaemonConn, WorkerCtx, msg, sandbox};
use crate::chunkio::CHUNK_SIZE;
use crate::proto::{
    BuildResult, ExtraPath, NarTransfer, OutputSignature, PathInfoMsg, WorkerMessage, nar_transfer,
    worker_message,
};

/// Pick up builds a previous worker instance left behind: still
/// running (their sandbox outlives the worker and the exit status
/// lands in the persisted exit-status file) or finished but
/// undelivered. Anything stale is swept.
pub(super) async fn adopt_builds(ctx: &Arc<WorkerCtx>, signing_key: &Arc<SecretKey>) {
    let Ok(entries) = fs::read_dir(ctx.state_dir.join("builds")) else {
        return;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if let Ok(s) = fs::read_to_string(dir.join("finished.json")) {
            let Ok(f) = serde_json::from_str::<FinishedState>(&s) else {
                ctx.remove_build_dir(&dir);
                continue;
            };
            tracing::info!(id = f.build_id, "adopted finished build awaiting delivery");
            ctx.resumable.lock().unwrap().insert(
                f.dedupe_key.clone(),
                ResumableBuild {
                    build_id: f.build_id,
                    out_tx: None,
                    finished: Some(FinishedBuild {
                        exit_code: f.exit_code,
                        error: f.error,
                        outputs: f.outputs,
                        extras: f.extras,
                        dir: dir.clone(),
                        finished_at: Instant::now(),
                    }),
                    delivering: false,
                    dir,
                    log_tail: None,
                },
            );
            continue;
        }
        let Ok(s) = fs::read_to_string(dir.join("resume.json")) else {
            continue; // already swept by sweep_state_dir
        };
        let Ok(st) = serde_json::from_str::<ResumeState>(&s) else {
            ctx.remove_build_dir(&dir);
            continue;
        };
        // Without a leased cgroup there is nothing that ties the
        // persisted pid to this build (macOS until the agent track
        // lands): a recycled pid must not be supervised as a build.
        if st.spec.cgroup.is_none() && sandbox::exit_status(&st.spec).is_none() {
            tracing::warn!(id = st.build_id, "dropping unadoptable running build");
            ctx.remove_build_dir(&dir);
            continue;
        }
        tracing::info!(id = st.build_id, pid = st.pid, "adopted running build");
        // The temp roots taken at negotiation died with the previous
        // generation's daemon connection; without new ones a GC could
        // delete inputs under the still-running build.
        let gc_roots = re_root_inputs(&st.spec).await;
        ctx.resumable.lock().unwrap().insert(
            st.dedupe_key.clone(),
            ResumableBuild {
                build_id: st.build_id.clone(),
                out_tx: None,
                finished: None,
                delivering: false,
                dir: dir.clone(),
                log_tail: None,
            },
        );
        let permit = ctx.slots.clone().try_acquire_owned().ok();
        let task_ctx = ctx.clone();
        let signing_key = signing_key.clone();
        tokio::task::spawn_blocking(move || {
            let ctx = task_ctx;
            let key = st.dedupe_key.clone();
            let fin = supervise(&ctx, &st, dir, &signing_key, None);
            // Roots live until the outputs are packed.
            drop(gc_roots);
            drop(permit);
            record_finished(&ctx, &key, fin);
        });
    }
}

/// Take fresh temp roots for an adopted build's inputs on a new daemon
/// connection (returned; the roots die with it). Best effort: adoption
/// must not fail because the daemon is briefly unavailable.
async fn re_root_inputs(spec: &sandbox::SandboxSpec) -> Option<DaemonConn> {
    let store_dir = StoreDir::default();
    let mut daemon = match DaemonClient::builder().connect_daemon().await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("connecting to nix-daemon for adopted-build GC roots: {e:#}");
            return None;
        }
    };
    for path in &spec.store_inputs {
        let Ok(sp) = store_dir.parse(path) else {
            continue;
        };
        if let Err(e) = daemon.add_temp_root(&sp).await {
            tracing::warn!(path, "re-adding GC root: {e:#}");
        }
    }
    Some(daemon)
}

/// Forget finished builds nobody resumed. Without a client
/// resubmitting (it gave up or died), the result has no taker; the
/// entry would otherwise pin the build dir forever.
pub(super) fn spawn_resumable_reaper(ctx: Arc<WorkerCtx>) {
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
                ctx.remove_build_dir(&dir);
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
pub(super) struct ResumableBuild {
    /// From the latest assignment; result messages carry this id.
    pub(super) build_id: String,
    /// Sender of the session that issued that assignment. Kept here,
    /// not captured by the build thread: the session alive when the
    /// build *finishes* may not be the one that assigned it. None for
    /// a freshly re-adopted build no session has assigned yet.
    pub(super) out_tx: Option<mpsc::Sender<WorkerMessage>>,
    pub(super) finished: Option<FinishedBuild>,
    /// A delivery is in flight; a concurrent re-assignment must not
    /// start a second one.
    pub(super) delivering: bool,
    /// Build dir holding build.log, for log replay on resume.
    pub(super) dir: PathBuf,
    /// Replays the log to the resumed session; joined before the
    /// result is delivered so logs arrive first.
    pub(super) log_tail: Option<LogTail>,
}

#[derive(Clone)]
pub(super) struct FinishedBuild {
    pub(super) exit_code: i32,
    pub(super) error: String,
    pub(super) outputs: Vec<PackedOutput>,
    /// Recursive-nix closure-delta paths the builder registered with
    /// the worker daemon; empty for non-recursive builds.
    pub(super) extras: Vec<PackedExtra>,
    /// Build dir holding the packed NARs; removed after delivery.
    pub(super) dir: PathBuf,
    pub(super) finished_at: Instant,
}

/// One closure-delta path: PathInfo from the worker daemon plus a
/// PackedOutput-shaped signed envelope over `path:hex(nar_sha256)`.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct PackedExtra {
    /// Absolute store path of the registered extra.
    pub(super) path: String,
    pub(super) nar_file: PathBuf,
    pub(super) nar_sha256: Vec<u8>,
    pub(super) nar_size: u64,
    pub(super) signature: String,
    pub(super) references: Vec<String>,
    /// Existing daemon signatures (`name:base64`).
    pub(super) sigs: Vec<String>,
    /// Absolute store path or empty.
    pub(super) deriver: String,
    /// Content-address string or empty.
    pub(super) ca: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct PackedOutput {
    pub(super) scratch: String,
    pub(super) nar_file: PathBuf,
    pub(super) nar_sha256: Vec<u8>,
    pub(super) signature: String,
    /// Store paths the NAR references (intersection with the
    /// candidate set: inputs, sibling outputs, proxy-added paths).
    #[serde(default)]
    pub(super) references: Vec<String>,
}

/// On-disk state for re-adopting a running build after a worker
/// restart. The build's identity across restarts is its leased cgroup
/// (spec.cgroup). The exit code comes from the exit-status file the
/// PID-1 shim persists.
#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct ResumeState {
    pub(super) dedupe_key: String,
    /// Original assignment id: names the cgroup and the log file.
    pub(super) build_id: String,
    /// The spawned shim. Used for process-group kills and, without a
    /// cgroup, as a liveness probe.
    pub(super) pid: i32,
    pub(super) spec: sandbox::SandboxSpec,
    pub(super) deadline_unix: u64,
}

/// On-disk form of a finished-but-undelivered result; the packed NARs
/// sit next to it in the build dir.
#[derive(serde::Serialize, serde::Deserialize)]
struct FinishedState {
    pub(super) dedupe_key: String,
    pub(super) build_id: String,
    pub(super) exit_code: i32,
    pub(super) error: String,
    pub(super) outputs: Vec<PackedOutput>,
    #[serde(default)]
    pub(super) extras: Vec<PackedExtra>,
}

/// Record a build's result in the registry (persisted for redelivery
/// across worker generations) and start delivering it. Shared by the
/// normal execute path and re-adopted builds.
pub(super) fn record_finished(ctx: &Arc<WorkerCtx>, key: &str, fin: FinishedBuild) {
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

/// Persist a finished result so a replacement worker can redeliver
/// it; supersedes the running-build resume state.
fn persist_finished(key: &str, build_id: &str, fin: &FinishedBuild) {
    let state = FinishedState {
        dedupe_key: key.to_string(),
        build_id: build_id.to_string(),
        exit_code: fin.exit_code,
        error: fin.error.clone(),
        outputs: fin.outputs.clone(),
        extras: fin.extras.clone(),
    };
    if let Ok(json) = serde_json::to_vec(&state) {
        let _ = fs::write(fin.dir.join("finished.json"), json);
    }
    let _ = fs::remove_file(fin.dir.join("resume.json"));
}

/// Run a build to a FinishedBuild, whatever happens: errors and even
/// panics become a failed result. Nothing else reports it -- the
/// JoinHandle is dropped, so a leaked panic would leave the registry
/// entry unfinished and the client waiting forever.
pub(super) fn execute_to_finished(
    build: &ActiveBuild,
    out_tx: &mpsc::Sender<WorkerMessage>,
    signing_key: &SecretKey,
    timeout: Duration,
) -> FinishedBuild {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        build.execute(out_tx, signing_key, timeout)
    }))
    .unwrap_or_else(|_| Err(anyhow::anyhow!("build execution panicked")))
    .unwrap_or_else(|e| {
        tracing::error!("build execution failed: {e:#}");
        FinishedBuild {
            exit_code: 1,
            error: format!("{e:#}"),
            outputs: vec![],
            extras: vec![],
            dir: build.dir.clone(),
            finished_at: Instant::now(),
        }
    })
}

/// Send a finished build's result and output NARs. Blocking; runs on
/// a blocking thread.
pub(super) fn deliver(
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
    let mut f = fs::File::open(nar_file)?;
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
pub(super) fn ack_delivery(ctx: &Arc<WorkerCtx>, key: &str, build_id: &str) {
    let removed = {
        let mut map = ctx.resumable.lock().unwrap();
        match map.get(key) {
            Some(e) if e.finished.is_some() => map.remove(key),
            _ => None,
        }
    };
    if let Some(e) = removed {
        ctx.remove_build_dir(&e.dir);
        tracing::info!(id = build_id, "build result acknowledged");
    }
}

/// Deliver `key`'s finished result if there is one and no other
/// delivery is running, over the session that issued its latest
/// assignment. The build is kept until the hub acknowledges the
/// result; a failed or unacknowledged delivery is retried on the next
/// assignment of the same key.
pub(super) fn try_deliver(ctx: &Arc<WorkerCtx>, key: &str) {
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
                "result delivery failed, keeping for resume: {e:#}"
            );
        }
    }
}
