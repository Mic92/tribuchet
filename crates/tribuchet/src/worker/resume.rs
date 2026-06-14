//! Resumable builds: adoption across worker generations, result persistence and delivery.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;
use harmonia_store_path::StoreDir;
use harmonia_store_remote::{DaemonClient, DaemonStore};
use harmonia_utils_signature::SecretKey;
use tokio::sync::mpsc;

use super::build::{pack_outputs, ActiveBuild};
use super::logtail::LogTail;
use super::{cgroup, msg, reaper, sandbox, unix_now, DaemonConn, WorkerCtx};
use crate::chunkio::CHUNK_SIZE;
use crate::fsutil::remove_path_all;
use crate::proto::{
    nar_transfer, worker_message, BuildAssignment, BuildResult, NarTransfer, OutputSignature,
    WorkerMessage,
};

/// Pick up builds a previous worker generation left behind: still
/// running (same reaper, so their pids and exit statuses are valid)
/// or finished but undelivered. Anything stale is swept.
pub(super) async fn adopt_builds(
    ctx: &std::sync::Arc<WorkerCtx>,
    signing_key: &std::sync::Arc<SecretKey>,
) {
    let reaper_id = std::env::var(reaper::ID_ENV).unwrap_or_default();
    let Ok(entries) = std::fs::read_dir(ctx.state_dir.join("builds")) else {
        return;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if let Ok(s) = std::fs::read_to_string(dir.join("finished.json")) {
            let Ok(f) = serde_json::from_str::<FinishedState>(&s) else {
                remove_path_all(&dir);
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
                        dir: dir.clone(),
                        finished_at: std::time::Instant::now(),
                    }),
                    delivering: false,
                    dir,
                    log_tail: None,
                },
            );
            continue;
        }
        let Ok(s) = std::fs::read_to_string(dir.join("resume.json")) else {
            continue; // already swept by sweep_state_dir
        };
        let st = match serde_json::from_str::<ResumeState>(&s) {
            Ok(st) if st.reaper_id == reaper_id => st,
            // Different reaper: the pid is meaningless and the build
            // died with the old unit; the client will resubmit.
            _ => {
                remove_path_all(&dir);
                continue;
            }
        };
        set_uid_slot(ctx, st.uid_slot, true);
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
        ctx.running
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let task_ctx = ctx.clone();
        let signing_key = signing_key.clone();
        tokio::task::spawn_blocking(move || {
            let ctx = task_ctx;
            let key = st.dedupe_key.clone();
            let fin = supervise_adopted(&ctx, &st, dir, &signing_key);
            // Roots live until the outputs are packed.
            drop(gc_roots);
            ctx.running
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
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
    for (src, _) in &spec.binds_ro {
        // non-store binds (e.g. the static /bin/sh) need no root
        let Some(sp) = src.to_str().and_then(|p| store_dir.parse(p).ok()) else {
            continue;
        };
        if let Err(e) = daemon.add_temp_root(&sp).await {
            tracing::warn!(path = %src.display(), "re-adding GC root: {e:#}");
        }
    }
    Some(daemon)
}

/// Wait out a re-adopted build and pack its outputs, mirroring the
/// tail end of execute(). Logs are streamed by the tailer that
/// adopt_assignment starts once a session re-dispatches the build.
fn supervise_adopted(
    ctx: &std::sync::Arc<WorkerCtx>,
    st: &ResumeState,
    dir: PathBuf,
    signing_key: &SecretKey,
) -> FinishedBuild {
    let pgrp = nix::unistd::Pid::from_raw(st.pid);
    let mut aborted: Option<String> = None;
    let log_path = dir.join("build.log");
    // Set when the build process is gone but no status file appears: a
    // previous generation may have consumed the status (take_status
    // deletes it on read) and died before recording the result. Waiting
    // forever would leak the slot and the supervising thread.
    let mut gone_since: Option<std::time::Instant> = None;
    let code = loop {
        if let Some(code) = reaper::take_status(&ctx.status_dir, &st.status_token) {
            break code;
        }
        if nix::sys::signal::kill(pgrp, None).is_err() {
            let since = gone_since.get_or_insert_with(std::time::Instant::now);
            // a couple of reaper sweeps of grace for a status file
            // that is still on its way
            if since.elapsed() > std::time::Duration::from_secs(5) {
                aborted.get_or_insert_with(|| {
                    "build exit status was lost during a worker handover".into()
                });
                break 1;
            }
        } else {
            gone_since = None;
        }
        if aborted.is_none() {
            let timed_out = (unix_now() >= st.deadline_unix).then(|| "build timed out".to_string());
            aborted = ctx.abort_reason(&st.dedupe_key, &log_path, timed_out);
            if aborted.is_some() {
                let _ = nix::sys::signal::killpg(pgrp, nix::sys::signal::Signal::SIGKILL);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    let _ = nix::sys::signal::killpg(pgrp, nix::sys::signal::Signal::SIGKILL);
    // Tear down cgroup and sandbox like teardown() would.
    if let Some(base) = ctx.cgroup_base.as_deref() {
        cgroup::kill_and_remove(base, &st.build_id);
    }
    let synth = BuildAssignment {
        build_id: st.build_id.clone(),
        outputs: st.outputs.clone(),
        ..Default::default()
    };
    sandbox::cleanup(&synth, &dir);
    set_uid_slot(ctx, st.uid_slot, false);
    let (exit_code, error, outputs) = if let Some(reason) = aborted {
        (1, reason, vec![])
    } else if code != 0 {
        (
            code,
            sandbox::setup_error_detail(&st.spec).unwrap_or_default(),
            vec![],
        )
    } else {
        // Fresh deadline: the build's own one bounded execution; this
        // one only stops packing a pathological (e.g. sparse-file)
        // output from running away.
        let deadline = std::time::Instant::now() + std::time::Duration::from_mins(10);
        match pack_outputs(&dir, &st.spec, deadline, signing_key) {
            Ok(outputs) => (0, String::new(), outputs),
            Err(e) => (1, format!("{e:#}"), vec![]),
        }
    };
    FinishedBuild {
        exit_code,
        error,
        outputs,
        dir,
        finished_at: std::time::Instant::now(),
    }
}

/// Forget finished builds nobody resumed. Without a client
/// resubmitting (it gave up or died), the result has no taker; the
/// entry would otherwise pin the build dir forever.
pub(super) fn spawn_resumable_reaper(ctx: std::sync::Arc<WorkerCtx>) {
    const TTL: std::time::Duration = std::time::Duration::from_mins(5);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_mins(1)).await;
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
                let _ = std::fs::remove_dir_all(&dir);
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
    /// Build dir holding the packed NARs; removed after delivery.
    pub(super) dir: PathBuf,
    pub(super) finished_at: std::time::Instant,
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
/// handover. Only valid within one reaper generation: a different
/// reaper never spawned these pids, so their statuses cannot come.
#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct ResumeState {
    pub(super) reaper_id: String,
    pub(super) dedupe_key: String,
    /// Original assignment id: names the cgroup and the log file.
    pub(super) build_id: String,
    pub(super) pid: i32,
    /// Status-file name the reaper records the exit code under.
    pub(super) status_token: String,
    pub(super) spec: sandbox::SandboxSpec,
    /// Assignment outputs (name -> scratch path), for cleanup.
    pub(super) outputs: HashMap<String, String>,
    pub(super) deadline_unix: u64,
    pub(super) uid_slot: Option<usize>,
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
}

/// Record a build's result in the registry (persisted for redelivery
/// across worker generations) and start delivering it. Shared by the
/// normal execute path and re-adopted builds.
pub(super) fn record_finished(ctx: &std::sync::Arc<WorkerCtx>, key: &str, fin: FinishedBuild) {
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

/// Mark or release a leased uid slot by index (re-adopted builds,
/// where no BuildOwner exists to do it on drop).
fn set_uid_slot(ctx: &WorkerCtx, idx: Option<usize>, used: bool) {
    if let Some(idx) = idx {
        if let Some(s) = ctx.uid_slots.lock().unwrap().get_mut(idx) {
            *s = used;
        }
    }
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
    };
    if let Ok(json) = serde_json::to_vec(&state) {
        let _ = std::fs::write(fin.dir.join("finished.json"), json);
    }
    let _ = std::fs::remove_file(fin.dir.join("resume.json"));
}

/// Run a build to a FinishedBuild, whatever happens: errors and even
/// panics become a failed result. Nothing else reports it -- the
/// JoinHandle is dropped, so a leaked panic would leave the registry
/// entry unfinished and the client waiting forever.
pub(super) fn execute_to_finished(
    build: &ActiveBuild,
    out_tx: &mpsc::Sender<WorkerMessage>,
    signing_key: &SecretKey,
    timeout: std::time::Duration,
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
            dir: build.dir.clone(),
            finished_at: std::time::Instant::now(),
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
        extras: Vec::new(),
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
        let mut f = std::fs::File::open(&o.nar_file)?;
        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out_tx.blocking_send(msg(worker_message::Msg::Nar(NarTransfer {
                build_id: build_id.into(),
                store_path: o.scratch.clone(),
                payload: Some(nar_transfer::Payload::ZstdNarChunk(buf[..n].to_vec())),
                eof: false,
            })))?;
        }
        out_tx.blocking_send(msg(worker_message::Msg::Nar(NarTransfer {
            build_id: build_id.into(),
            store_path: o.scratch.clone(),
            payload: None,
            eof: true,
        })))?;
    }
    Ok(())
}

/// Drop a build whose result the hub confirmed: only now is it safe
/// to forget it, a result merely handed to a dying session would
/// otherwise be lost and cost a rebuild. Matched by dedupe key (the
/// stable identity); the ack's build_id may predate a concurrent
/// resume that rotated the entry's id.
pub(super) fn ack_delivery(ctx: &std::sync::Arc<WorkerCtx>, key: &str, build_id: &str) {
    let removed = {
        let mut map = ctx.resumable.lock().unwrap();
        match map.get(key) {
            Some(e) if e.finished.is_some() => map.remove(key),
            _ => None,
        }
    };
    if let Some(e) = removed {
        if let Err(err) = std::fs::remove_dir_all(&e.dir) {
            tracing::warn!("cleaning up {}: {err}", e.dir.display());
        }
        tracing::info!(id = build_id, "build result acknowledged");
    }
}

/// Deliver `key`'s finished result if there is one and no other
/// delivery is running, over the session that issued its latest
/// assignment. The build is kept until the hub acknowledges the
/// result; a failed or unacknowledged delivery is retried on the next
/// assignment of the same key.
pub(super) fn try_deliver(ctx: &std::sync::Arc<WorkerCtx>, key: &str) {
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
