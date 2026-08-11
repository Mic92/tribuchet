//! Worker-side client for the per-uid build agents.
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

#[cfg(target_os = "macos")]
use std::fmt::Write as _;

#[cfg(target_os = "macos")]
use sandbox_proto::agent::SCRATCH_DIR_PARAM;
use sandbox_proto::agent::{
    AdoptRequest, CleanupRequest, FinishRequest, KillRequest, StartRequest, StatusRequest, call,
    reply,
};
use sandbox_proto::framing;

use crate::errors::{Result, err_ctx, err_msg};

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

/// The seatbelt profile the agent applies to the builder. Reads stay
/// broad (matching Nix's Darwin sandbox) except for the worker's key
/// material. Writes are scoped to the agent's scratch dir (via the
/// [`SCRATCH_DIR_PARAM`] parameter, filled in agent-side) and the
/// scratch output store paths. Unfiltered `(allow signal)` would let
/// builds signal other agent-uid processes, most notably the agent.
#[cfg(target_os = "macos")]
pub(super) fn seatbelt_profile(
    outputs: &[String],
    deny_read: &[PathBuf],
    network: bool,
) -> Result<String> {
    let mut profile = String::from(
        "(version 1)\n\
         (deny default)\n\
         (allow process*)\n\
         (allow signal (target same-sandbox))\n\
         (allow sysctl-read)\n\
         (allow mach-lookup)\n\
         (allow file-read*)\n\
         (allow file-ioctl)\n",
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
    writeln!(
        profile,
        "(allow file-write*\n  (subpath (param \"{SCRATCH_DIR_PARAM}\"))"
    )?;
    // Outputs are created fresh at their real store paths, /nix is not
    // a symlink, so the literal form is already the vnode path.
    for path in outputs {
        writeln!(profile, "  (subpath \"{}\")", sb_escape(path)?)?;
    }
    for dev in [
        "/dev/null",
        "/dev/zero",
        "/dev/random",
        "/dev/urandom",
        "/dev/tty",
    ] {
        writeln!(profile, "  (literal \"{dev}\")")?;
    }
    profile.push_str(")\n");
    if network {
        profile.push_str("(allow network*)\n(allow system-socket)\n");
    }
    Ok(profile)
}

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

    /// Take a specific agent out of the pool: an adopted build already
    /// occupies it, so new builds must not be placed there.
    pub(super) fn reserve(&self, socket: &Path) {
        self.free.lock().unwrap().retain(|s| s != socket);
    }

    /// Sockets not occupied by an adopted build.
    pub(super) fn idle_sockets(&self) -> Vec<PathBuf> {
        self.free.lock().unwrap().clone()
    }
}

/// The lease connection of one running build.
pub(super) struct AgentBuild {
    conn: UnixStream,
    pub(super) pid: i32,
    pub(super) scratch_dir: PathBuf,
}

impl AgentBuild {
    /// Start a build on the agent behind `socket`. Two fds are
    /// passed along: `tmp_pack` carries the zstd entry stream of the
    /// build's tmp dir and `log` becomes the builder's stdout and
    /// stderr.
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
    pub(super) fn wait_exit(&self) -> Result<i32> {
        let (reply, _) = framing::recv_reply(&self.conn)?;
        let reply::Reply::Exit(notice) = reply else {
            return Err(err_msg(format!("unexpected agent reply {reply:?}")));
        };
        Ok(notice.exit_code)
    }
}

fn connect(socket: &Path) -> Result<UnixStream> {
    UnixStream::connect(socket).map_err(err_ctx(format!(
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A dev-mode agent (self-bound socket, same uid) plus a staged
    /// tmp dir pack for it, shared by the tests below.
    fn spawn_test_agent(dir: &Path) -> Result<(PathBuf, PathBuf)> {
        let socket = dir.join("agent.sock");
        let state_dir = dir.join("state");
        {
            let socket = socket.clone();
            std::thread::spawn(move || {
                let _ = super::super::agent::run(&super::super::agent::Options {
                    socket: Some(socket),
                    state_dir,
                    worker_uid: None,
                    uid_base: None,
                    dedicated_uid: false,
                });
            });
        }
        while !socket.exists() {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // build dir carrying .attrs.json, like the client pack
        let build = dir.join("top/build");
        fs::create_dir_all(&build)?;
        fs::write(build.join(".attrs.json"), "{}")?;
        let pack_path = dir.join("top.tmpdir.zst");
        fs::write(&pack_path, crate::tmpdir::pack_zstd_dir(&build)?)?;
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
                ("PATH".into(), std::env::var("PATH").unwrap_or_default()),
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
        assert_eq!(build.wait_exit()?, 0);

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
        req.profile = seatbelt_profile(&outputs, &[secret], false)?;
        let build = AgentBuild::start(&socket, &req, &fs::File::open(&pack_path)?)?;
        assert_eq!(build.wait_exit()?, 0);
        assert!(!outside.exists());
        finish(&socket, build_id)?;
        assert_eq!(fs::read_to_string(output.join("file"))?, "data\n");
        cleanup(&socket, build_id)?;
        Ok(())
    }
}
