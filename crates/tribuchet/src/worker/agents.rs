//! Worker-side client for the macOS per-uid build agents.
//!
//! Each build leases one agent from the fixed list in the worker
//! config. The Start/Adopt connection stays open for the build's
//! lifetime and delivers the exit notice. Kill, Finish and Cleanup go
//! over fresh connections, so they work from any worker generation.

use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use sandbox_proto::darwin::{
    AdoptReply, AdoptRequest, CleanupRequest, ExitNotice, FinishRequest, KillRequest, METHOD_ADOPT,
    METHOD_CLEANUP, METHOD_FINISH, METHOD_KILL, METHOD_START, StartReply, StartRequest,
};
use sandbox_proto::framing;

/// Free agent sockets. One build per agent, so the pool size is the
/// worker's effective max-jobs.
pub(super) struct AgentPool {
    free: Mutex<Vec<PathBuf>>,
}

impl AgentPool {
    pub(super) fn new(sockets: Vec<PathBuf>) -> Self {
        Self {
            free: Mutex::new(sockets),
        }
    }

    /// Take a free agent socket. None when every agent is leased,
    /// which only happens if max-jobs exceeds the agent count.
    pub(super) fn acquire(&self) -> Option<PathBuf> {
        self.free.lock().unwrap().pop()
    }

    pub(super) fn release(&self, socket: PathBuf) {
        self.free.lock().unwrap().push(socket);
    }
}

/// The lease connection of one running build.
pub(super) struct AgentBuild {
    conn: UnixStream,
    pub(super) pid: i32,
    pub(super) scratch_dir: PathBuf,
    /// Read handle on the agent-side log file.
    pub(super) log: fs::File,
}

impl AgentBuild {
    /// Start a build on the agent behind `socket`. `tmp_tar` is the
    /// zstd tar of the build's tmp dir, passed as an fd.
    pub(super) fn start(socket: &Path, req: &StartRequest, tmp_tar: &fs::File) -> Result<Self> {
        let conn = connect(socket)?;
        framing::send_call(&conn, METHOD_START, req, &[tmp_tar.as_raw_fd()])?;
        let (reply, fds): (StartReply, _) = framing::recv_reply(&conn)?;
        Ok(Self {
            conn,
            pid: reply.pid,
            scratch_dir: PathBuf::from(reply.scratch_dir),
            log: log_fd(fds)?,
        })
    }

    /// Reattach to a build a previous worker generation started.
    /// Returns the build plus its exit code if it already finished.
    pub(super) fn adopt(socket: &Path, build_id: &str) -> Result<(Self, Option<i32>)> {
        let conn = connect(socket)?;
        framing::send_call(
            &conn,
            METHOD_ADOPT,
            &AdoptRequest {
                build_id: build_id.into(),
            },
            &[],
        )?;
        let (reply, fds): (AdoptReply, _) = framing::recv_reply(&conn)?;
        let build = Self {
            conn,
            pid: reply.pid,
            scratch_dir: PathBuf::from(reply.scratch_dir),
            log: log_fd(fds)?,
        };
        Ok((build, reply.exit_code))
    }

    /// Block until the agent reports the builder's exit.
    pub(super) fn wait_exit(&self) -> Result<i32> {
        let (notice, _): (ExitNotice, _) = framing::recv_reply(&self.conn)?;
        Ok(notice.exit_code)
    }
}

fn connect(socket: &Path) -> Result<UnixStream> {
    UnixStream::connect(socket)
        .with_context(|| format!("connecting to the build agent at {}", socket.display()))
}

fn log_fd(fds: Vec<std::os::fd::OwnedFd>) -> Result<fs::File> {
    Ok(fs::File::from(
        fds.into_iter()
            .next()
            .context("agent reply without a log fd")?,
    ))
}

/// Fire a control call that replies with an empty object.
fn control<T: serde::Serialize>(socket: &Path, method: &str, req: &T) -> Result<()> {
    let conn = connect(socket)?;
    framing::send_call(&conn, method, req, &[])?;
    let (_, _): (serde_json::Value, _) = framing::recv_reply(&conn)?;
    Ok(())
}

/// Kill the build's processes. The agent keeps the build until Cleanup.
pub(super) fn kill(socket: &Path, build_id: &str) -> Result<()> {
    control(
        socket,
        METHOD_KILL,
        &KillRequest {
            build_id: build_id.into(),
        },
    )
}

/// Make the finished build's outputs readable by the worker.
pub(super) fn finish(socket: &Path, build_id: &str) -> Result<()> {
    control(
        socket,
        METHOD_FINISH,
        &FinishRequest {
            build_id: build_id.into(),
        },
    )
}

/// Remove the build's scratch dir and scratch outputs; the agent
/// forgets the build.
pub(super) fn cleanup(socket: &Path, build_id: &str) -> Result<()> {
    control(
        socket,
        METHOD_CLEANUP,
        &CleanupRequest {
            build_id: build_id.into(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Read;

    /// Full lifecycle against a real agent (same uid, no seatbelt):
    /// Start with a tmp dir tar, exit notice, Adopt of the finished
    /// build, Finish, Cleanup.
    #[test]
    fn agent_runs_a_build_end_to_end() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let socket = dir.path().join("agent.sock");
        let state_dir = dir.path().join("state");
        {
            let socket = socket.clone();
            let state_dir = state_dir.clone();
            std::thread::spawn(move || {
                let _ = super::super::agent::run(super::super::agent::Options {
                    socket: Some(socket),
                    state_dir,
                    worker_uid: None,
                });
            });
        }
        while !socket.exists() {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // tmp dir carrying build/.attrs.json, like the client tar
        let top = dir.path().join("top");
        fs::create_dir_all(top.join("build"))?;
        fs::write(top.join("build/.attrs.json"), "{}")?;
        let tar_path = dir.path().join("top.tar.zst");
        fs::write(&tar_path, crate::tmptar::tar_zstd_dir(&top)?)?;

        let build_id = "0123456789abcdef0123456789abcdef";
        let output = dir.path().join("fake-output");
        let req = StartRequest {
            build_id: build_id.into(),
            builder: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                format!(
                    "test -f .attrs.json || exit 2; \
                     test \"$NIX_BUILD_TOP\" = \"$PWD\" || exit 3; \
                     echo built; mkdir {out}; echo data > {out}/file",
                    out = output.display()
                ),
            ],
            env: HashMap::from([("NIX_BUILD_TOP".into(), "/build".into())]),
            tmp_dir_in_sandbox: "/build".into(),
            profile: String::new(),
            outputs: vec![output.to_string_lossy().into_owned()],
        };
        let build = AgentBuild::start(&socket, &req, &fs::File::open(&tar_path)?)?;
        assert!(build.pid > 0);
        assert_eq!(build.wait_exit()?, 0);

        let mut log = String::new();
        let mut log_file = build.log;
        log_file.read_to_string(&mut log)?;
        assert!(log.contains("built"), "log: {log}");

        let (_, exit) = AgentBuild::adopt(&socket, build_id)?;
        assert_eq!(exit, Some(0));

        finish(&socket, build_id)?;
        assert_eq!(fs::read_to_string(output.join("file"))?, "data\n");

        cleanup(&socket, build_id)?;
        assert!(!output.exists());
        assert!(!build.scratch_dir.exists());
        Ok(())
    }
}
