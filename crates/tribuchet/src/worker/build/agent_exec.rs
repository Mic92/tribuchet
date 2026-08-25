//! Build execution on the per-uid agents.
//!
//! Both platforms lease one agent per build; the platform difference
//! is confined to the StartRequest: macOS sends a seatbelt profile,
//! Linux the serialized sandbox spec the agent runs the setup stage
//! with.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{self, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::{ActiveBuild, pack_outputs_and_extras, unix_now};
use crate::errors::chain;
use crate::errors::{Result, err_ctx, err_msg};
use crate::fsutil::io_ctx;
use crate::proto::WorkerMessage;
use crate::tmpdir::pack_zstd_dir;
#[cfg(target_os = "linux")]
use crate::worker::caps::requires_uid_range;
#[cfg(target_os = "macos")]
use crate::worker::caps::requires_uid_range;
use crate::worker::logtail::tail_log;
use crate::worker::resume::{FinishedBuild, ResumeState};
use crate::worker::{WorkerCtx, agents, sandbox};

impl ActiveBuild {
    /// Lease a per-uid agent and run the build there. The agent
    /// unpacks the tmp dir into its own scratch dir, confines and owns
    /// the builder process. The worker tails the log fd, polls its
    /// abort conditions, and packs the outputs once the agent made
    /// them readable.
    pub(in crate::worker) fn execute(
        &self,
        out_tx: &mpsc::Sender<WorkerMessage>,
        timeout: Duration,
    ) -> Result<FinishedBuild> {
        #[cfg(target_os = "macos")]
        if requires_uid_range(&self.assignment.env) {
            return Err(err_msg(
                "the uid-range feature is only supported on Linux workers",
            ));
        }
        let socket =
            self.ctx.agents.acquire().ok_or_else(|| {
                err_msg("no free build agent (max-jobs exceeds the agent count?)")
            })?;
        let result = self.execute_on_agent(&socket, out_tx, timeout);
        self.ctx.agents.release(socket);
        result
    }

    fn execute_on_agent(
        &self,
        socket: &Path,
        out_tx: &mpsc::Sender<WorkerMessage>,
        timeout: Duration,
    ) -> Result<FinishedBuild> {
        let a = &self.assignment;
        let outputs: Vec<String> = a.outputs.values().cloned().collect();
        // The agent-side confinement of the builder: a seatbelt
        // profile on macOS, the namespace sandbox spec on Linux. The
        // spec doubles as the packing/resume state, so the Linux one
        // carries the full input and network configuration.
        #[cfg(target_os = "macos")]
        let (profile, sandbox_json, spec) = (
            agents::seatbelt_profile(&outputs, &self.ctx.secret_paths, a.fixed_output)?,
            None,
            sandbox::SandboxSpec {
                outputs: outputs.clone(),
                store_inputs: self.input_list(),
                recursive_nix: self.ctx.recursive_nix,
                ..sandbox::SandboxSpec::default()
            },
        );
        #[cfg(target_os = "linux")]
        let (profile, sandbox_json, mut spec) = {
            let spec = self.build_spec()?;
            (String::new(), Some(serde_json::to_string(&spec)?), spec)
        };
        // Re-pack the staged tmp dir: the agent unpacks it into its own
        // scratch dir, since the worker's copy is not agent-writable.
        fs::write(
            self.dir.join("top.tmpdir.zst"),
            pack_zstd_dir(&self.dir.join("top/build"))?,
        )?;
        let req = sandbox_proto::agent::StartRequest {
            build_id: a.build_id.clone(),
            builder: a.builder.clone(),
            args: a.args.clone(),
            env: a.env.clone(),
            tmp_dir_in_sandbox: a.tmp_dir_in_sandbox.clone(),
            profile,
            sandbox_json,
            outputs: outputs.clone(),
            memory_max_bytes: self.ctx.build_memory_max_bytes,
        };
        // The builder writes dir/build.log directly through this fd.
        let log_w = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("build.log"))?;
        let build = agents::AgentBuild::start(
            socket,
            &req,
            &fs::File::open(self.dir.join("top.tmpdir.zst"))
                .map_err(io_ctx("opening", &self.dir.join("top.tmpdir.zst")))?,
            &log_w,
        )?;
        drop(log_w);
        tracing::info!(
            id = a.build_id,
            pid = build.pid,
            agent = %socket.display(),
            scratch = %build.scratch_dir.display(),
            "builder started on agent"
        );
        // The agent placed the sandbox root in its scratch dir; record
        // it so packing and adopted supervision find the outputs.
        #[cfg(target_os = "linux")]
        {
            spec.root = build
                .scratch_dir
                .parent()
                .ok_or_else(|| err_msg("agent scratch dir has no parent"))?
                .join("root");
        }

        let log_done = Arc::new(atomic::AtomicBool::new(false));
        let tailer = {
            let tx = out_tx.clone();
            let build_id = a.build_id.clone();
            let log_done = log_done.clone();
            let dir = self.dir.clone();
            thread::spawn(move || {
                tail_log(&dir, &build_id, &tx, || log_done.load(Ordering::Relaxed));
            })
        };
        // From here a restarted worker can re-adopt the build from
        // its agent.
        let resume = ResumeState {
            dedupe_key: a.dedupe_key.clone(),
            build_id: a.build_id.clone(),
            pid: build.pid,
            spec,
            deadline_unix: unix_now() + timeout.as_secs(),
            agent_socket: socket.to_path_buf(),
        };
        resume.persist(&self.dir)?;
        let fin = supervise_agent(&self.ctx, &resume, self.dir.clone(), socket, build);
        log_done.store(true, Ordering::Relaxed);
        let _ = tailer.join();
        Ok(fin)
    }

    /// The Linux sandbox spec sent with the StartRequest. The agent
    /// fills in its scratch paths, user namespace and uid block before
    /// spawning the setup stage with it.
    #[cfg(target_os = "linux")]
    fn build_spec(&self) -> Result<sandbox::SandboxSpec> {
        let a = &self.assignment;
        let uid_count = if requires_uid_range(&a.env) { 65536 } else { 1 };
        let spec = sandbox::prepare(
            a,
            &self.dir,
            &self.input_list(),
            &sandbox::PrepareOpts {
                bin_sh: self.ctx.sandbox_bin_sh.as_deref(),
                secrets: &self.ctx.secret_paths,
                leased_userns: None,
                leased_uid_count: Some(uid_count),
                emulator: self.ctx.emulators.get(&a.system).map(PathBuf::as_path),
                net_isolation: self.ctx.fod_isolation,
                net_policy: self.ctx.fod_network.clone(),
                recursive_nix: self.ctx.recursive_nix,
                nix_daemon_socket: None,
            },
        )?;
        tracing::info!(
            id = a.build_id,
            fixed_output = a.fixed_output,
            network = spec.network,
            net_isolation = spec.net_isolation,
            "sandbox network decision"
        );
        Ok(spec)
    }
}

/// Wait out a build running on an agent (fresh or re-adopted), pack
/// its outputs, and have the agent clean up. Driven off the persisted
/// `ResumeState` so fresh and adopted builds share one path.
pub(in crate::worker) fn supervise_agent(
    ctx: &WorkerCtx,
    st: &ResumeState,
    dir: PathBuf,
    socket: &Path,
    build: agents::AgentBuild,
) -> FinishedBuild {
    let log_path = dir.join("build.log");
    // The exit notice arrives on the lease connection. Wait for it on
    // its own thread so the abort conditions keep being polled.
    let waiter = thread::spawn(move || build.wait_exit());
    let mut aborted: Option<String> = None;
    while !waiter.is_finished() {
        if aborted.is_none() {
            let timed_out = (unix_now() >= st.deadline_unix).then(|| "build timed out".to_string());
            if let Some(r) = ctx.abort_reason(&st.dedupe_key, &log_path, timed_out) {
                aborted = Some(r);
                if let Err(e) = agents::kill(socket, &st.build_id) {
                    tracing::warn!(
                        id = st.build_id,
                        "killing the build via its agent: {}",
                        chain(&e)
                    );
                }
            }
        }
        thread::sleep(Duration::from_millis(200));
    }
    let code = match waiter.join() {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => {
            aborted.get_or_insert(format!("agent connection lost: {}", chain(&e)));
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
        // A Linux setup-stage failure leaves its message under the
        // sandbox root; a plain builder failure leaves none.
        #[cfg(target_os = "linux")]
        let detail = sandbox::setup_error_detail(&st.spec).unwrap_or_default();
        #[cfg(target_os = "macos")]
        let detail = String::new();
        (code, detail, vec![], vec![])
    } else {
        // Finish makes the outputs (at their real store paths on
        // macOS, under the sandbox root on Linux) readable for
        // packing.
        let remaining = Duration::from_secs(st.deadline_unix.saturating_sub(unix_now()));
        let deadline = Instant::now() + remaining.max(Duration::from_mins(10));
        let packed = agents::finish(socket, &st.build_id)
            .map_err(err_ctx("finishing the build on its agent"))
            .and_then(|()| {
                tokio::runtime::Handle::current().block_on(pack_outputs_and_extras(
                    &dir,
                    &st.spec,
                    None,
                    deadline,
                    &st.build_id,
                ))
            });
        match packed {
            Ok((o, e)) => (0, String::new(), o, e),
            Err(e) => (1, chain(&e), vec![], vec![]),
        }
    };
    // The agent removes its scratch dir and the scratch outputs
    // (packing above already read them) and forgets the build.
    if let Err(e) = agents::cleanup(socket, &st.build_id) {
        tracing::warn!(id = st.build_id, "agent cleanup failed: {}", chain(&e));
    } else if let Err(e) = agents::shutdown(socket) {
        tracing::warn!(id = st.build_id, "agent shutdown failed: {}", chain(&e));
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
