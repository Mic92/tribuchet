//! Worker-side client for the per-uid build agents.
//!
//! Each build leases one agent from the agent sockets in the worker
//! config. The Start/Adopt connection stays open for the build's
//! lifetime and delivers the exit notice. Kill, Finish and Cleanup go
//! over fresh connections, so they work from any worker generation.

use std::fs;
use std::io;
use std::thread;
use std::time::Duration;

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[cfg(target_os = "macos")]
use std::fmt::Write as _;

#[cfg(target_os = "macos")]
use sandbox_proto::agent::SCRATCH_DIR_PARAM;
use sandbox_proto::agent::{
    AdoptRequest, CleanupRequest, ExitNotice, FinishRequest, KillRequest, ShutdownRequest,
    StartRequest, StatusRequest, call, reply,
};
use sandbox_proto::framing;

use crate::errors::{Error, Result, chain, err_ctx, err_msg};
use crate::sockpath;

/// How long the worker waits on an agent call it bounds (Status,
/// Shutdown): neither the startup sweep nor a rescan waits on an agent
/// that accepts a connection and never answers.
pub(super) const AGENT_ANSWER: Duration = Duration::from_secs(7);

/// SBPL string literal escaping: a quote or backslash in an
/// interpolated path must not terminate the literal and inject
/// profile directives.
#[cfg(target_os = "macos")]
fn sb_escape(s: &str) -> Result<String> {
    if s.bytes().any(|b| b.is_ascii_control()) {
        return Err(err_msg(format!(
            "control character in sandbox profile path {s:?}"
        )));
    }
    Ok(s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Nix's Darwin sandbox profiles, vendored verbatim from
/// `src/libstore/darwin/build/` so updates are a file copy.
#[cfg(target_os = "macos")]
const NIX_SANDBOX_DEFAULTS: &str = include_str!("seatbelt/sandbox-defaults.sb");
#[cfg(target_os = "macos")]
const NIX_SANDBOX_NETWORK: &str = include_str!("seatbelt/sandbox-network.sb");

/// Nix's baseline with its tmp dir parameters bound to the agent's
/// scratch dir ([`SCRATCH_DIR_PARAM`], filled in agent-side), broad
/// reads minus the worker's key material instead of Nix's per-closure
/// list, and writes to the scratch output store paths.
#[cfg(target_os = "macos")]
pub(super) fn seatbelt_profile(
    outputs: &[String],
    deny_read: &[PathBuf],
    network: bool,
    local_network: bool,
) -> Result<String> {
    let scratch = format!("(param \"{SCRATCH_DIR_PARAM}\")");
    let defaults = NIX_SANDBOX_DEFAULTS
        .replace("(param \"_GLOBAL_TMP_DIR\")", &scratch)
        .replace("(param \"_NIX_BUILD_TOP\")", &scratch)
        .replace(
            "(param \"_ALLOW_LOCAL_NETWORKING\")",
            if local_network { "#t" } else { "#f" },
        );
    let mut profile = String::from(
        "(version 1)
",
    );
    profile.push_str(&defaults);
    // tribuchet does not enumerate the input closure
    profile.push_str(
        "(allow file-read* process-exec file-ioctl)
         (allow mach-lookup)
",
    );
    for secret in deny_read {
        // Seatbelt matches path filters against the canonical vnode
        // path; the configured paths usually live under /var, which
        // is a symlink to /private/var, so a deny on the literal
        // alone would never match. Emit both forms.
        let canonical = secret.canonicalize().unwrap_or_else(|_| secret.clone());
        let mut paths = vec![secret];
        if canonical != *secret {
            paths.push(&canonical);
        }
        for path in paths {
            writeln!(
                profile,
                "(deny file-read* (literal \"{}\"))",
                sb_escape(&path.to_string_lossy())?
            )?;
        }
    }
    // Outputs are created fresh at their real store paths, /nix is not
    // a symlink, so the literal form is already the vnode path.
    profile.push_str(
        "(allow file-read* file-write* process-exec
",
    );
    for path in outputs {
        writeln!(profile, "  (subpath \"{}\")", sb_escape(path)?)?;
    }
    profile.push_str(
        ")
",
    );
    if network {
        profile.push_str(NIX_SANDBOX_NETWORK);
    }
    Ok(profile)
}

/// The agent sockets. One build per agent, so the reachable ones bound
/// the worker's concurrency.
pub(super) struct AgentPool(Mutex<Pool>);

struct Pool {
    all: Vec<PathBuf>,
    free: Vec<PathBuf>,
    /// Agents nothing answered on, out of `free` until a probe reaches
    /// them again.
    down: Vec<PathBuf>,
}

impl AgentPool {
    pub(super) fn new(sockets: Vec<PathBuf>) -> Self {
        Self(Mutex::new(Pool {
            all: sockets.clone(),
            free: sockets,
            down: Vec::new(),
        }))
    }

    /// Lease a free agent and start the build on it. An agent nothing
    /// answers on is marked down and the next one tried. With none
    /// free the build waits, calling `waiting` once, until `cancelled`.
    pub(super) fn start(
        &self,
        req: &StartRequest,
        tmp_pack: &fs::File,
        log: &fs::File,
        cancelled: impl Fn() -> bool,
        waiting: impl FnOnce(),
    ) -> Result<(PathBuf, AgentBuild)> {
        let mut waiting = Some(waiting);
        loop {
            let Some(socket) = self.0.lock().unwrap().free.pop() else {
                if cancelled() {
                    return Err(err_msg("build cancelled"));
                }
                if let Some(waiting) = waiting.take() {
                    waiting();
                }
                thread::sleep(Duration::from_secs(1));
                continue;
            };
            match AgentBuild::start(&socket, req, tmp_pack, log) {
                Ok(build) => return Ok((socket, build)),
                Err(e) if unreachable(&e) => {
                    tracing::warn!(id = req.build_id, "{}; trying another agent", chain(&e));
                    self.mark_down(&socket);
                }
                Err(e) => {
                    self.release(socket);
                    return Err(e);
                }
            }
        }
    }

    /// Return an agent to the free list, also one that was down.
    pub(super) fn release(&self, socket: PathBuf) {
        let mut pool = self.0.lock().unwrap();
        if pool.all.contains(&socket) && !pool.free.contains(&socket) {
            pool.down.retain(|s| *s != socket);
            pool.free.push(socket);
        }
    }

    /// Take a specific agent out of the pool: an adopted build already
    /// occupies it, so new builds must not be placed there.
    pub(super) fn reserve(&self, socket: &Path) {
        let mut pool = self.0.lock().unwrap();
        pool.free.retain(|s| s != socket);
        pool.down.retain(|s| s != socket);
    }

    /// Set an agent aside until a probe reaches it again. False if it
    /// already was.
    pub(super) fn mark_down(&self, socket: &Path) -> bool {
        let mut pool = self.0.lock().unwrap();
        pool.free.retain(|s| s != socket);
        if pool.down.iter().any(|s| s == socket) {
            return false;
        }
        pool.down.push(socket.to_path_buf());
        true
    }

    /// Add sockets not seen before, down until a probe reaches them.
    pub(super) fn discover(&self, sockets: Vec<PathBuf>) {
        let mut pool = self.0.lock().unwrap();
        for socket in sockets {
            if !pool.all.contains(&socket) {
                pool.all.push(socket.clone());
                pool.down.push(socket);
            }
        }
    }

    /// Sockets not occupied by an adopted build.
    pub(super) fn idle_sockets(&self) -> Vec<PathBuf> {
        self.0.lock().unwrap().free.clone()
    }

    pub(super) fn down_sockets(&self) -> Vec<PathBuf> {
        self.0.lock().unwrap().down.clone()
    }

    /// Agents that can run a build, leased or not.
    pub(super) fn usable(&self) -> usize {
        let pool = self.0.lock().unwrap();
        pool.all.len() - pool.down.len()
    }
}

/// Nothing listens on the agent socket, or the file is gone: a stopped
/// socket unit leaves its file behind (RemoveOnStop=no). `connect` is
/// the only step of an agent call that yields a context-wrapped
/// io::Error. Or the connection dropped unanswered: the agent service
/// failed. An error the agent replies with is not this.
pub(super) fn unreachable(e: &Error) -> bool {
    match e {
        Error::Context { source, .. } => source.downcast_ref::<io::Error>().is_some_and(|e| {
            matches!(
                e.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            )
        }),
        Error::Framing(framing::Error::ConnectionClosed | framing::Error::Io { .. }) => true,
        _ => false,
    }
}

/// The lease connection of one running build.
pub(super) struct AgentBuild {
    conn: UnixStream,
    pub(super) pid: i32,
    pub(super) scratch_dir: PathBuf,
}

impl AgentBuild {
    /// Start a build on the agent behind `socket`. The fds carry the
    /// packed tmp dir and the builder's stdout/stderr.
    pub(super) fn start(
        socket: &Path,
        req: &StartRequest,
        tmp_pack: &fs::File,
        log: &fs::File,
    ) -> Result<Self> {
        let conn = connect(socket)?;
        framing::send_call(
            &conn,
            call::Call::Start(Box::new(req.clone())),
            &[tmp_pack.as_raw_fd(), log.as_raw_fd()],
        )?;
        let (reply, _fds) = framing::recv_reply(&conn)?;
        let reply::Reply::Start(reply) = reply else {
            return Err(err_msg(format!("unexpected agent reply {reply:?}")));
        };
        Ok(Self {
            conn,
            pid: reply.pid,
            scratch_dir: PathBuf::from(reply.scratch_dir),
        })
    }

    /// Reattach to a build a previous worker generation started.
    /// Returns the build plus its exit code if it already finished.
    pub(super) fn adopt(socket: &Path, build_id: &str) -> Result<(Self, Option<i32>)> {
        let conn = connect(socket)?;
        framing::send_call(
            &conn,
            call::Call::Adopt(AdoptRequest {
                build_id: build_id.into(),
            }),
            &[],
        )?;
        let (reply, _fds) = framing::recv_reply(&conn)?;
        let reply::Reply::Adopt(reply) = reply else {
            return Err(err_msg(format!("unexpected agent reply {reply:?}")));
        };
        let build = Self {
            conn,
            pid: reply.pid,
            scratch_dir: PathBuf::from(reply.scratch_dir),
        };
        Ok((build, reply.exit_code))
    }

    /// Block until the agent reports the builder's exit.
    pub(super) fn wait_exit(&self) -> Result<ExitNotice> {
        let (reply, _) = framing::recv_reply(&self.conn)?;
        let reply::Reply::Exit(notice) = reply else {
            return Err(err_msg(format!("unexpected agent reply {reply:?}")));
        };
        Ok(notice)
    }
}

fn connect(socket: &Path) -> Result<UnixStream> {
    sockpath::connect(socket).map_err(err_ctx(format!(
        "connecting to the build agent at {}",
        socket.display()
    )))
}

/// A connection whose reads and writes give up after AGENT_ANSWER,
/// for calls the agent answers at once. A timeout is a framing I/O
/// error, which `unreachable` counts.
fn connect_bounded(socket: &Path) -> Result<UnixStream> {
    let conn = connect(socket)?;
    bound(&conn, Some(AGENT_ANSWER))?;
    Ok(conn)
}

fn bound(conn: &UnixStream, within: Option<Duration>) -> Result<()> {
    conn.set_read_timeout(within)
        .and_then(|()| conn.set_write_timeout(within))
        .map_err(err_ctx("bounding an agent call"))
}

/// Fire a control call that replies with an empty message.
fn control(socket: &Path, call: call::Call) -> Result<()> {
    control_on(&connect(socket)?, call)
}

fn control_on(conn: &UnixStream, call: call::Call) -> Result<()> {
    framing::send_call(conn, call, &[])?;
    framing::recv_reply(conn)?;
    Ok(())
}

/// The build the agent behind `socket` currently owns, if any, within
/// AGENT_ANSWER.
pub(super) fn current_build(socket: &Path) -> Result<Option<String>> {
    let conn = connect_bounded(socket)?;
    framing::send_call(&conn, call::Call::Status(StatusRequest {}), &[])?;
    let (reply, _) = framing::recv_reply(&conn)?;
    let reply::Reply::Status(reply) = reply else {
        return Err(err_msg(format!("unexpected agent reply {reply:?}")));
    };
    Ok(reply.current)
}

/// Kill the build's processes. The agent keeps the build until Cleanup.
pub(super) fn kill(socket: &Path, build_id: &str) -> Result<()> {
    control(
        socket,
        call::Call::Kill(KillRequest {
            build_id: build_id.into(),
        }),
    )
}

/// Make the finished build's outputs readable by the worker.
pub(super) fn finish(socket: &Path, build_id: &str) -> Result<()> {
    control(
        socket,
        call::Call::Finish(FinishRequest {
            build_id: build_id.into(),
        }),
    )
}

/// Remove the build's scratch dir and scratch outputs; the agent
/// forgets the build.
pub(super) fn cleanup(socket: &Path, build_id: &str) -> Result<()> {
    control(
        socket,
        call::Call::Cleanup(CleanupRequest {
            build_id: build_id.into(),
        }),
    )
}

/// Ask an idle activated agent to exit, within AGENT_ANSWER. Sent
/// while the caller still holds the agent slot, so nothing connects to
/// the dying instance.
pub(super) fn shutdown(socket: &Path) -> Result<()> {
    control_on(
        &connect_bounded(socket)?,
        call::Call::Shutdown(ShutdownRequest {}),
    )
}

#[cfg(test)]
pub(super) mod tests;
