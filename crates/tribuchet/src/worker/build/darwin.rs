//! macOS build execution on the per-uid agents.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{self, Ordering};
use std::time::{Duration, Instant};
use std::{fs, io};

use anyhow::{Context, Result, bail};
use harmonia_utils_signature::SecretKey;
use tokio::sync::mpsc;

use super::{ActiveBuild, pack_outputs_and_extras, unix_now};
use crate::proto::WorkerMessage;
use crate::worker::caps::requires_uid_range;
use crate::worker::logtail::tail_log;
use crate::worker::resume::{FinishedBuild, ResumeState};
use crate::worker::{WorkerCtx, agents, sandbox};

impl ActiveBuild {
    /// macOS: lease a per-uid agent and run the build there. The agent
    /// unpacks the tmp dir into its own scratch dir, applies the
    /// seatbelt profile and owns the builder process. The worker tails
    /// the log fd, polls its abort conditions, and packs the outputs
    /// (written at their real store paths) once the agent made them
    /// readable.
    pub(in crate::worker) fn execute(
        &self,
        out_tx: &mpsc::Sender<WorkerMessage>,
        signing_key: &SecretKey,
        timeout: Duration,
    ) -> Result<FinishedBuild> {
        if requires_uid_range(&self.assignment.env) {
            bail!("the uid-range feature is only supported on Linux workers");
        }
        let socket = self
            .ctx
            .agents
            .acquire()
            .context("no free build agent (max-jobs exceeds the agent count?)")?;
        let result = self.execute_on_agent(&socket, out_tx, signing_key, timeout);
        self.ctx.agents.release(socket);
        result
    }

    fn execute_on_agent(
        &self,
        socket: &Path,
        out_tx: &mpsc::Sender<WorkerMessage>,
        signing_key: &SecretKey,
        timeout: Duration,
    ) -> Result<FinishedBuild> {
        let a = &self.assignment;
        let outputs: Vec<String> = a.outputs.values().cloned().collect();
        let profile = agents::seatbelt_profile(&outputs, &self.ctx.secret_paths, a.fixed_output)?;
        // Re-tar the staged tmp dir: the agent unpacks it into its own
        // scratch dir, since the worker's copy is not agent-writable.
        fs::write(
            self.dir.join("top.tar.zst"),
            crate::tmptar::tar_zstd_dir(&self.dir.join("top"))?,
        )?;
        let req = sandbox_proto::darwin::StartRequest {
            build_id: a.build_id.clone(),
            builder: a.builder.clone(),
            args: a.args.clone(),
            env: a.env.clone(),
            tmp_dir_in_sandbox: a.tmp_dir_in_sandbox.clone(),
            profile,
            outputs: outputs.clone(),
        };
        let build = agents::AgentBuild::start(
            socket,
            &req,
            &fs::File::open(self.dir.join("top.tar.zst"))?,
        )?;
        tracing::info!(
            id = a.build_id,
            pid = build.pid,
            agent = %socket.display(),
            scratch = %build.scratch_dir.display(),
            "builder started on agent"
        );

        // Mirror the agent-side log into dir/build.log so the shared
        // tailing, replay and resume paths work exactly as on Linux.
        let mirror = LogMirror::start(&build.log, self.dir.join("build.log"))?;
        let log_done = Arc::new(atomic::AtomicBool::new(false));
        let tailer = {
            let tx = out_tx.clone();
            let build_id = a.build_id.clone();
            let log_done = log_done.clone();
            let dir = self.dir.clone();
            std::thread::spawn(move || {
                tail_log(&dir, &build_id, &tx, || log_done.load(Ordering::Relaxed));
            })
        };
        // From here a restarted worker can re-adopt the build from
        // its agent.
        let resume = ResumeState {
            dedupe_key: a.dedupe_key.clone(),
            build_id: a.build_id.clone(),
            pid: build.pid,
            spec: sandbox::SandboxSpec {
                outputs,
                store_inputs: self.inputs.clone(),
                recursive_nix: self.ctx.recursive_nix,
                ..sandbox::SandboxSpec::default()
            },
            deadline_unix: unix_now() + timeout.as_secs(),
            agent_socket: Some(socket.to_path_buf()),
        };
        fs::write(self.dir.join("resume.json"), serde_json::to_vec(&resume)?)?;
        let fin = supervise_agent(
            &self.ctx,
            &resume,
            self.dir.clone(),
            socket,
            build,
            signing_key,
        );
        // The mirror is drained before the tailer's final read so no
        // trailing log lines are lost.
        mirror.stop();
        log_done.store(true, Ordering::Relaxed);
        let _ = tailer.join();
        Ok(fin)
    }
}

/// Wait out a build running on an agent (fresh or re-adopted), pack
/// its outputs, and have the agent clean up. The macOS counterpart of
/// `supervise`, driven off the same persisted `ResumeState`.
pub(in crate::worker) fn supervise_agent(
    ctx: &WorkerCtx,
    st: &ResumeState,
    dir: PathBuf,
    socket: &Path,
    build: agents::AgentBuild,
    signing_key: &SecretKey,
) -> FinishedBuild {
    let log_path = dir.join("build.log");
    // The exit notice arrives on the lease connection. Wait for it on
    // its own thread so the abort conditions keep being polled.
    let waiter = std::thread::spawn(move || build.wait_exit());
    let mut aborted: Option<String> = None;
    while !waiter.is_finished() {
        if aborted.is_none() {
            let timed_out = (unix_now() >= st.deadline_unix).then(|| "build timed out".to_string());
            if let Some(r) = ctx.abort_reason(&st.dedupe_key, &log_path, timed_out) {
                aborted = Some(r);
                if let Err(e) = agents::kill(socket, &st.build_id) {
                    tracing::warn!(id = st.build_id, "killing the build via its agent: {e:#}");
                }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let code = match waiter.join() {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => {
            aborted.get_or_insert(format!("agent connection lost: {e:#}"));
            1
        }
        Err(_) => {
            aborted.get_or_insert("agent wait thread panicked".into());
            1
        }
    };
    tracing::info!(id = st.build_id, exit_code = code, aborted = ?aborted, "builder finished");
    let (exit_code, error, outputs, extras) = if let Some(reason) = aborted {
        (1, reason, vec![], vec![])
    } else if code != 0 {
        (code, String::new(), vec![], vec![])
    } else {
        // The outputs are agent-owned files at their real store
        // paths; Finish makes them readable for packing.
        let remaining = Duration::from_secs(st.deadline_unix.saturating_sub(unix_now()));
        let deadline = Instant::now() + remaining.max(Duration::from_mins(10));
        let packed = agents::finish(socket, &st.build_id)
            .context("finishing the build on its agent")
            .and_then(|()| {
                tokio::runtime::Handle::current().block_on(pack_outputs_and_extras(
                    &dir,
                    &st.spec,
                    None,
                    deadline,
                    signing_key,
                    &st.build_id,
                ))
            });
        match packed {
            Ok((o, e)) => (0, String::new(), o, e),
            Err(e) => (1, format!("{e:#}"), vec![], vec![]),
        }
    };
    // The agent removes its scratch dir and the scratch outputs
    // (packing above already read them) and forgets the build.
    if let Err(e) = agents::cleanup(socket, &st.build_id) {
        tracing::warn!(id = st.build_id, "agent cleanup failed: {e:#}");
    }
    FinishedBuild {
        exit_code,
        error,
        outputs,
        extras,
        dir,
        finished_at: Instant::now(),
    }
}

/// Background thread appending everything the agent writes to its log
/// fd into the build dir's build.log, so the path-based tailing,
/// replay and resume machinery works as on Linux.
pub(in crate::worker) struct LogMirror {
    done: Arc<atomic::AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

impl LogMirror {
    /// Start mirroring `log` into `dest_path`, appending where a
    /// previous worker generation's mirror left off.
    pub(in crate::worker) fn start(log: &fs::File, dest_path: PathBuf) -> Result<Self> {
        let mut src = log.try_clone()?;
        let done = Arc::new(atomic::AtomicBool::new(false));
        let thread = {
            let done = done.clone();
            std::thread::spawn(move || {
                use std::io::{Read as _, Seek as _};
                let Ok(mut dest) = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&dest_path)
                else {
                    return;
                };
                let already = dest.metadata().map(|m| m.len()).unwrap_or(0);
                if src.seek(io::SeekFrom::Start(already)).is_err() {
                    return;
                }
                let mut buf = [0u8; 8192];
                loop {
                    match src.read(&mut buf) {
                        Ok(0) => {
                            if done.load(Ordering::Relaxed) {
                                return;
                            }
                            std::thread::sleep(Duration::from_millis(200));
                        }
                        Ok(n) => {
                            if dest.write_all(&buf[..n]).is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            })
        };
        Ok(Self { done, thread })
    }

    /// Drain what is still buffered agent-side, then stop.
    pub(in crate::worker) fn stop(self) {
        self.done.store(true, Ordering::Relaxed);
        let _ = self.thread.join();
    }
}
