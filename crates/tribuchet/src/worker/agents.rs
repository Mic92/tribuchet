//! Worker-side client for the per-uid build agents.
//!
//! Each build leases one agent from the agent sockets in the worker
//! config. The Start/Adopt connection stays open for the build's
//! lifetime and delivers the exit notice. Kill, Finish and Cleanup go
//! over fresh connections, so they work from any worker generation.

use std::fs;
use std::io;
use std::thread;
use std::time::{Duration, Instant};

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
    /// free the build waits for one until `cancelled` or `deadline`.
    pub(super) fn start(
        &self,
        req: &StartRequest,
        tmp_pack: &fs::File,
        log: &fs::File,
        cancelled: impl Fn() -> bool,
        deadline: Instant,
    ) -> Result<(PathBuf, AgentBuild)> {
        loop {
            let Some(socket) = self.0.lock().unwrap().free.pop() else {
                if cancelled() {
                    return Err(err_msg("build cancelled"));
                }
                if Instant::now() >= deadline {
                    return Err(err_msg("no build agent became reachable"));
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

/// Fire a control call that replies with an empty message.
fn control(socket: &Path, call: call::Call) -> Result<()> {
    let conn = connect(socket)?;
    framing::send_call(&conn, call, &[])?;
    framing::recv_reply(&conn)?;
    Ok(())
}

/// The build the agent behind `socket` currently owns, if any.
pub(super) fn current_build(socket: &Path) -> Result<Option<String>> {
    let conn = connect(socket)?;
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

/// Ask an idle activated agent to exit. Sent while the caller still
/// holds the agent slot, so nothing connects to the dying instance.
pub(super) fn shutdown(socket: &Path) -> Result<()> {
    control(socket, call::Call::Shutdown(ShutdownRequest {}))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::fd::IntoRawFd;
    use std::{env, thread};

    use crate::tmpdir::pack_zstd_dir;
    use crate::worker::agent;

    /// A dev-mode agent: self-bound socket, same uid.
    pub(in crate::worker) fn spawn_agent(socket: &Path, state_dir: PathBuf) -> Result<()> {
        let listener = sockpath::bind(socket)?;
        thread::spawn(move || {
            let _ = agent::run(&agent::Options {
                socket: None,
                listen_fd: Some(listener.into_raw_fd()),
                state_dir,
                worker_uid: None,
                uid_base: None,
                dedicated_uid: false,
            });
        });
        Ok(())
    }

    /// A dev-mode agent plus a staged tmp dir pack for it, shared by
    /// the tests below.
    fn spawn_test_agent(dir: &Path) -> Result<(PathBuf, PathBuf)> {
        let socket = dir.join("agent.sock");
        spawn_agent(&socket, dir.join("state"))?;
        // build dir carrying .attrs.json, like the client pack
        let build = dir.join("top/build");
        fs::create_dir_all(&build)?;
        fs::write(build.join(".attrs.json"), "{}")?;
        let pack_path = dir.join("top.tmpdir.zst");
        fs::write(&pack_path, pack_zstd_dir(&build)?)?;
        Ok((socket, pack_path))
    }

    fn start_request(build_id: &str, script: String, outputs: Vec<String>) -> StartRequest {
        StartRequest {
            build_id: build_id.into(),
            builder: "/bin/sh".into(),
            args: vec!["-c".into(), script],
            // A real assignment's env carries PATH; the scripts here
            // need it for mkdir.
            env: HashMap::from([
                ("NIX_BUILD_TOP".into(), "/build".into()),
                ("PATH".into(), env::var("PATH").unwrap_or_default()),
            ]),
            tmp_dir_in_sandbox: "/build".into(),
            profile: String::new(),
            sandbox_json: None,
            outputs,
            memory_max_bytes: None,
        }
    }

    /// Full lifecycle against a real agent on the same uid, without a
    /// seatbelt profile (not permitted inside the Nix build sandbox):
    /// Start with a tmp dir tar, exit notice, Adopt of the finished
    /// build, Finish, Cleanup.
    #[test]
    fn agent_runs_a_build_end_to_end() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (socket, pack_path) = spawn_test_agent(dir.path())?;
        let build_id = "0123456789abcdef0123456789abcdef";
        let output = dir.path().join("fake-output");
        let req = start_request(
            build_id,
            format!(
                "test -f .attrs.json || exit 2; \
                 test \"$NIX_BUILD_TOP\" = \"$PWD\" || exit 3; \
                 echo built; mkdir {out}; echo data > {out}/file",
                out = output.display()
            ),
            vec![output.to_string_lossy().into_owned()],
        );
        let log_path = dir.path().join("build.log");
        let log_w = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        let build = AgentBuild::start(&socket, &req, &fs::File::open(&pack_path)?, &log_w)?;
        assert!(build.pid > 0);
        let exit = build.wait_exit()?;
        assert_eq!(exit.exit_code, 0);
        assert!(exit.peak_memory_bytes > 0, "no memory reported");

        let log = fs::read_to_string(&log_path)?;
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

    /// A stopped socket unit's file, a missing socket and one that
    /// drops the call unanswered (a failing agent service) sit on top
    /// of the free list. The build skips them and lands on the live
    /// agent. An error the agent replies with leaves it in the pool.
    #[test]
    fn start_skips_unreachable_agents() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (live, pack_path) = spawn_test_agent(dir.path())?;
        let stale = dir.path().join("stale.sock");
        drop(sockpath::bind(&stale)?);
        let missing = dir.path().join("missing.sock");
        let dead = dir.path().join("dead.sock");
        let listener = sockpath::bind(&dead)?;
        thread::spawn(move || drop(listener.accept()));
        let mut sockets = vec![live.clone(), missing.clone(), stale.clone()];
        sockets.push(dead.clone());
        let pool = AgentPool::new(sockets);
        let far = Instant::now() + Duration::from_secs(3600);
        let build_id = "00000000000000000000000000000002";
        let req = start_request(build_id, "true".into(), vec![]);
        let pack = fs::File::open(&pack_path)?;
        let log = fs::File::create(dir.path().join("build.log"))?;
        let (socket, build) = pool.start(&req, &pack, &log, || false, far)?;
        assert_eq!(socket, live);
        assert_eq!(build.wait_exit()?.exit_code, 0);
        assert_eq!(pool.down_sockets(), vec![dead, stale, missing]);
        assert_eq!(pool.usable(), 1);
        pool.release(live.clone());
        let busy = pool.start(&req, &pack, &log, || false, far);
        assert!(busy.is_err());
        assert_eq!(pool.usable(), 1);
        cleanup(&live, build_id)
    }

    /// With no agent reachable a build waits instead of failing, until
    /// it is cancelled, its deadline passes or an agent is back.
    #[test]
    fn start_waits_for_an_agent() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (_, pack_path) = spawn_test_agent(dir.path())?;
        let socket = dir.path().join("down.sock");
        let pool = AgentPool::new(vec![socket.clone()]);
        let build_id = "00000000000000000000000000000003";
        let req = start_request(build_id, "true".into(), vec![]);
        let pack = fs::File::open(&pack_path)?;
        let log = fs::File::create(dir.path().join("build.log"))?;
        let far = Instant::now() + Duration::from_secs(3600);
        let Err(e) = pool.start(&req, &pack, &log, || true, far) else {
            panic!("started on an unreachable agent");
        };
        assert_eq!(chain(&e), "build cancelled");
        let gave_up = pool.start(&req, &pack, &log, || false, Instant::now());
        assert!(gave_up.is_err());
        thread::scope(|s| {
            let started = s.spawn(|| pool.start(&req, &pack, &log, || false, far));
            thread::sleep(Duration::from_millis(1500));
            assert!(!started.is_finished(), "the build did not wait");
            spawn_agent(&socket, dir.path().join("down"))?;
            pool.release(socket.clone());
            let (leased, build) = started.join().unwrap()?;
            assert_eq!(leased, socket);
            assert_eq!(build.wait_exit()?.exit_code, 0);
            cleanup(&socket, build_id)
        })
    }

    /// The generated seatbelt profile, applied by a real agent: the
    /// derivation env arrives, worker secrets are unreadable, writes
    /// stay confined to the scratch dir and the declared output.
    /// Skipped inside the Nix build sandbox (sandbox_init is not
    /// permitted there); `nix develop -c cargo test` runs it.
    #[cfg(target_os = "macos")]
    #[test]
    fn seatbelt_profile_confines_the_builder() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (socket, pack_path) = spawn_test_agent(dir.path())?;
        let build_id = "00000000000000000000000000000001";
        // Canonical paths: the profile's path filters only match
        // canonical paths and macOS temp dirs live under the /var
        // symlink. Real outputs are /nix/store paths, already canonical.
        let dir_path = dir.path().canonicalize()?;
        let output = dir_path.join("fake-output");
        let secret = dir_path.join("secret");
        fs::write(&secret, "key-material")?;
        let outside = dir_path.join("outside");
        let outputs = vec![output.to_string_lossy().into_owned()];
        let mut req = start_request(
            build_id,
            // Each escape attempt exits with its own code so a failure
            // names the broken rule.
            format!(
                "test \"$NIX_BUILD_TOP\" = \"$PWD\" || exit 3; \
                 cat {secret} 2>/dev/null && exit 4; \
                 echo escaped > {outside} 2>/dev/null && exit 5; \
                 echo scratch > scratch-file || exit 6; \
                 mkdir {out} && echo data > {out}/file",
                secret = secret.display(),
                outside = outside.display(),
                out = output.display()
            ),
            outputs.clone(),
        );
        req.profile = seatbelt_profile(&outputs, &[secret], false, false)?;
        let log_w = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir_path.join("build.log"))?;
        let build = AgentBuild::start(&socket, &req, &fs::File::open(&pack_path)?, &log_w)?;
        assert_eq!(build.wait_exit()?.exit_code, 0);
        assert!(!outside.exists());
        finish(&socket, build_id)?;
        assert_eq!(fs::read_to_string(output.join("file"))?, "data\n");
        cleanup(&socket, build_id)?;
        Ok(())
    }
}
