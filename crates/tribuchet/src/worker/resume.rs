//! Resumable builds: re-adopting still-running builds from their
//! agents after a worker restart.

mod delivery;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use harmonia_store_path::StoreDir;
use harmonia_store_remote::{DaemonClient, DaemonStore};

use super::build::supervise_agent;
use super::{DaemonConn, WorkerCtx, agents, remove_build_dir, sandbox};
use crate::errors::chain;
use crate::fsutil::io_ctx;

pub(super) use delivery::{
    FinishedBuild, OutChunk, PackedExtra, PackedOutput, ResumableBuild, ack_delivery,
    execute_to_finished, record_finished, serve_chunks, spawn_resumable_reaper, try_deliver,
};

/// Pick up builds a previous worker instance left behind: still
/// running (their agent outlives the worker) or finished but
/// undelivered. Anything stale is swept.
pub(super) async fn adopt_builds(ctx: &Arc<WorkerCtx>) {
    let Ok(entries) = fs::read_dir(ctx.state_dir.join("builds")) else {
        return;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let Ok(s) = fs::read_to_string(dir.join("state.json")) else {
            continue; // already swept by sweep_state_dir
        };
        let st = match serde_json::from_str::<BuildState>(&s) {
            Ok(BuildState::Running(st)) => st,
            Ok(BuildState::Finished {
                dedupe_key,
                build_id,
                exit_code,
                error,
                outputs,
                extras,
            }) => {
                tracing::info!(id = build_id, "adopted finished build awaiting delivery");
                let fin = FinishedBuild {
                    exit_code,
                    error,
                    outputs,
                    extras,
                    dir: dir.clone(),
                    finished_at: Instant::now(),
                };
                ResumableBuild::insert(ctx, dedupe_key, build_id, dir, Some(fin));
                continue;
            }
            Err(_) => {
                remove_build_dir(&dir);
                continue;
            }
        };
        // Something must tie the persisted state to live processes,
        // otherwise a recycled pid could be supervised as a build.
        // That tie is the agent that still knows the build.
        let agent = {
            let socket = st.agent_socket.clone();
            ctx.agents.reserve(&socket);
            match agents::AgentBuild::adopt(&socket, &st.build_id) {
                Ok((build, _)) => (socket, build),
                Err(e) => {
                    tracing::warn!(
                        id = st.build_id,
                        "re-adopting build from its agent: {}",
                        chain(&e)
                    );
                    ctx.agents.release(socket);
                    remove_build_dir(&dir);
                    continue;
                }
            }
        };
        tracing::info!(id = st.build_id, pid = st.pid, "adopted running build");
        // The temp roots taken at negotiation died with the previous
        // generation's daemon connection; without new ones a GC could
        // delete inputs under the still-running build.
        let gc_roots = re_root_inputs(&st.spec).await;
        ResumableBuild::insert(
            ctx,
            st.dedupe_key.clone(),
            st.build_id.clone(),
            dir.clone(),
            None,
        );
        let permit = ctx.slots.clone().try_acquire_owned().ok();
        let task_ctx = ctx.clone();
        tokio::task::spawn_blocking(move || {
            let ctx = task_ctx;
            let key = st.dedupe_key.clone();
            let fin = {
                let (socket, build) = agent;
                let fin = supervise_agent(&ctx, &st, dir, &socket, build);
                ctx.agents.release(socket);
                fin
            };
            // Roots live until the outputs are packed.
            drop(gc_roots);
            drop(permit);
            record_finished(&ctx, &key, fin);
        });
    }
}

/// Clean up agent builds without an on-disk record, left by a Start
/// that raced the previous worker's shutdown. They fail every later
/// Start on their agent with Busy. Runs after adoption, so adopted
/// agents are already out of the pool.
pub(super) fn sweep_orphaned_agent_builds(ctx: &Arc<WorkerCtx>) {
    for socket in ctx.agents.idle_sockets() {
        let id = match agents::current_build(&socket) {
            Ok(Some(id)) => id,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!("querying agent {}: {}", socket.display(), chain(&e));
                continue;
            }
        };
        tracing::warn!(id, "cleaning up an orphaned agent build");
        // Cleanup is slow. Run it in the background, with the agent
        // reserved, so the hub connection is not delayed.
        ctx.agents.reserve(&socket);
        let ctx = ctx.clone();
        tokio::task::spawn_blocking(move || {
            let _ = agents::kill(&socket, &id);
            if let Err(e) = agents::cleanup(&socket, &id) {
                tracing::warn!(id, "orphaned build cleanup failed: {}", chain(&e));
            } else if let Err(e) = agents::shutdown(&socket) {
                tracing::warn!(id, "agent shutdown failed: {}", chain(&e));
            }
            ctx.agents.release(socket);
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
            tracing::warn!(
                "connecting to nix-daemon for adopted-build GC roots: {}",
                chain(&e)
            );
            return None;
        }
    };
    for path in &spec.store_inputs {
        let sp = match store_dir.parse(path) {
            Ok(sp) => sp,
            Err(e) => {
                tracing::warn!(path, "skipping GC root for unparsable input: {e}");
                continue;
            }
        };
        if let Err(e) = daemon.add_temp_root(&sp).await {
            tracing::warn!(path, "re-adding GC root: {}", chain(&e));
        }
    }
    Some(daemon)
}

/// On-disk `state.json`: one file, so the running-to-finished
/// transition is a single atomic replacement.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub(super) enum BuildState {
    Running(Box<ResumeState>),
    Finished {
        dedupe_key: String,
        build_id: String,
        exit_code: i32,
        error: String,
        outputs: Vec<PackedOutput>,
        #[serde(default)]
        extras: Vec<PackedExtra>,
    },
}

/// State for re-adopting a running build after a worker restart; the
/// build's identity across restarts is the agent that owns it.
#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct ResumeState {
    pub(super) dedupe_key: String,
    /// Original assignment id: names the cgroup and the log file.
    pub(super) build_id: String,
    /// Agent-side pid of the builder (Linux: its setup stage).
    pub(super) pid: i32,
    pub(super) spec: sandbox::SandboxSpec,
    pub(super) deadline_unix: u64,
    /// Socket of the agent that owns the build, for re-adoption.
    pub(super) agent_socket: PathBuf,
}

impl ResumeState {
    /// Persist as `state.json`; a restarted worker adopts from it.
    pub(in crate::worker) fn persist(&self, dir: &Path) -> io::Result<()> {
        #[derive(serde::Serialize)]
        #[serde(tag = "phase", rename_all = "snake_case")]
        enum Ref<'a> {
            Running(&'a ResumeState),
        }
        fs::write(
            dir.join("state.json"),
            serde_json::to_vec(&Ref::Running(self))?,
        )
        .map_err(io_ctx("writing", &dir.join("state.json")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// persist() serializes through a borrowing mirror of BuildState.
    #[test]
    fn persisted_running_state_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let st = ResumeState {
            dedupe_key: "k".into(),
            build_id: "b1".into(),
            pid: 42,
            spec: sandbox::SandboxSpec::default(),
            deadline_unix: 7,
            agent_socket: PathBuf::from("/run/agent.sock"),
        };
        st.persist(dir.path()).unwrap();
        let json = fs::read_to_string(dir.path().join("state.json")).unwrap();
        let BuildState::Running(back) = serde_json::from_str(&json).unwrap() else {
            panic!("expected Running");
        };
        assert_eq!(back.build_id, "b1");
        assert_eq!(back.agent_socket, st.agent_socket);
        assert_eq!(back.deadline_unix, 7);
    }
}
