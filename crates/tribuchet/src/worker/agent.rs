//! `tribuchet agent`: per-uid build agent.
//!
//! One socket-activated daemon per pool user (launchd on macOS,
//! systemd on Linux). The worker leases a build by connecting and
//! sending Start. The agent unpacks the tmp dir, confines the forked
//! child (seatbelt on macOS) and execs the builder as its own
//! (non-worker) uid. The builder is the agent's child, so builds
//! survive worker restarts and the agent holds the log and exit
//! status until the worker adopts them. The protocol lives in
//! crates/sandbox-proto/proto/agent.proto.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use rustix::process::{Pid, Signal, getuid, kill_process, kill_process_group};
use sandbox_proto::agent::{
    AdoptReply, AdoptRequest, CleanupRequest, ERROR_BUSY, ERROR_UNKNOWN_BUILD, Empty, ExitNotice,
    FinishRequest, KillRequest, StartReply, StartRequest, StatusReply, call, reply,
};
use sandbox_proto::framing;

use crate::tmpdir::unpack_tmp_dir;

/// Unpack the zstd-compressed tmp dir stream into the build dir,
/// creating it even for an empty stream. Files belong to whoever runs
/// this: the agent on the direct-exec and macOS paths, in-ns root
/// through the userns helper on the Linux namespace path.
fn stage_scratch(pack: impl std::io::Read, build_dir: &Path) -> Result<()> {
    fs::create_dir_all(build_dir)?;
    let dec = zstd::stream::read::Decoder::new(pack)?;
    unpack_tmp_dir(dec, build_dir).context("unpacking the tmp dir")
}

#[cfg(target_os = "linux")]
mod cgroup;
#[cfg(target_os = "linux")]
#[path = "agent/linux.rs"]
mod platform;
#[cfg(target_os = "macos")]
#[path = "agent/darwin.rs"]
mod platform;
#[cfg(target_os = "linux")]
pub use platform::{FS_HELPER_ARG, fs_helper_stage};

pub struct Options {
    /// Unix socket to bind when launchd did not pass one.
    pub socket: Option<PathBuf>,
    /// Per-agent state dir holding one scratch dir per build.
    pub state_dir: PathBuf,
    /// Uid allowed to lease builds, defaulting to the agent's own uid
    /// for development runs.
    pub worker_uid: Option<u32>,
    /// First uid of this agent's 65536-uid block (Linux). Without it
    /// builds run without a pre-mapped user namespace.
    pub uid_base: Option<u32>,
    /// The agent owns its uid even without socket activation, so it
    /// kill-sweeps the uid and exits after each build.
    pub dedicated_uid: bool,
}

/// The one build this agent holds, from Start until Cleanup.
struct Build {
    id: String,
    /// Builder pid, also its process group.
    pid: i32,
    /// Scratch dir the build runs in (`<state>/<id>/build`).
    dir: PathBuf,
    /// Whole per-build tree removed by Cleanup (`<state>/<id>`).
    scratch_root: PathBuf,
    /// Private sandbox root under the scratch dir (Linux namespace
    /// builds); outputs land below it instead of at their store paths.
    sandbox_root: Option<PathBuf>,
    outputs: Vec<String>,
    /// Exit code once the wait thread reaped the builder. Kept in
    /// agent memory only: the build can write everything on disk here.
    exit: Arc<(Mutex<Option<i32>>, Condvar)>,
}

struct Agent {
    state_dir: PathBuf,
    worker_uid: u32,
    confinement: platform::Confinement,
    current: Mutex<Option<Build>>,
    /// True under a service manager, where the agent owns a dedicated
    /// uid: exit after Cleanup so a fresh agent is started, and sweep
    /// the whole uid when killing. Self-bound sockets (development,
    /// tests) share the developer's uid, where both would be
    /// destructive.
    dedicated_uid: bool,
}

impl Agent {
    fn kill_sweep(&self, pgid: Option<i32>) {
        if let Some(pgid) = pgid.and_then(Pid::from_raw) {
            let _ = kill_process_group(pgid, Signal::KILL);
        }
        if self.dedicated_uid {
            kill_own_uid_processes(self.confinement.exempt_pid());
        }
    }
}

pub fn run(opts: &Options) -> Result<()> {
    let confinement = platform::Confinement::init(opts)?;
    let (listener, activated) = listener(opts.socket.as_deref())?;
    fs::create_dir_all(&opts.state_dir)
        .with_context(|| format!("creating state dir {}", opts.state_dir.display()))?;
    let agent = Arc::new(Agent {
        // Canonical vnode path: scratch dirs derived from it feed the
        // builder's env, cwd and the seatbelt SCRATCH_DIR filter, and
        // Seatbelt only matches canonical paths.
        state_dir: opts
            .state_dir
            .canonicalize()
            .with_context(|| format!("canonicalizing state dir {}", opts.state_dir.display()))?,
        worker_uid: opts.worker_uid.unwrap_or_else(|| getuid().as_raw()),
        confinement,
        current: Mutex::new(None),
        dedicated_uid: activated || opts.dedicated_uid,
    });
    tracing::info!(uid = getuid().as_raw(), "agent listening");
    for conn in listener.incoming() {
        let conn = conn.context("accepting connection")?;
        let agent = agent.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle(&agent, &conn) {
                tracing::warn!("agent request failed: {e:#}");
                let _ = framing::send_error(&conn, &format!("{e:#}"));
            }
        });
    }
    Ok(())
}

/// Service-manager-activated listener (launchd socket named "agent",
/// or the systemd socket unit's fd) or a self-bound one for
/// development and tests. The bool is true for the activated case.
fn listener(socket: Option<&Path>) -> Result<(UnixListener, bool)> {
    if let Some(l) = platform::activated_unix_listener()? {
        return Ok((l, true));
    }
    let path = socket.context("no activated socket and no --socket given")?;
    let _ = fs::remove_file(path);
    let l = UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    Ok((l, false))
}

fn handle(agent: &Arc<Agent>, conn: &UnixStream) -> Result<()> {
    let peer_uid = platform::peer_uid(conn)?;
    ensure!(
        peer_uid == agent.worker_uid,
        "connection from uid {peer_uid}, only the worker uid {} may lease",
        agent.worker_uid
    );
    let (call, fds) = framing::recv_call(conn)?;
    match call {
        call::Call::Start(req) => handle_start(agent, conn, *req, fds),
        call::Call::Adopt(req) => handle_adopt(agent, conn, &req),
        call::Call::Status(_) => {
            let current = agent.current.lock().unwrap().as_ref().map(|b| b.id.clone());
            framing::send_reply(conn, reply::Reply::Status(StatusReply { current }), &[])
                .map_err(Into::into)
        }
        call::Call::Kill(req) => handle_kill(agent, conn, &req),
        call::Call::Finish(req) => handle_finish(agent, conn, &req),
        call::Call::Cleanup(req) => handle_cleanup(agent, conn, &req),
    }
}

fn handle_start(
    agent: &Arc<Agent>,
    conn: &UnixStream,
    req: StartRequest,
    fds: Vec<std::os::fd::OwnedFd>,
) -> Result<()> {
    ensure!(
        req.build_id.len() == 32 && req.build_id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid build id {:?}",
        req.build_id
    );
    let tmp_pack = fds.into_iter().next().context("missing tmp dir fd")?;
    // The lock is held until the build is registered: a losing
    // concurrent Start gets Busy without ever spawning anything.
    let (build_dir, log, exit, pid) = {
        let mut current = agent.current.lock().unwrap();
        if current.is_some() {
            return Ok(framing::send_error(conn, ERROR_BUSY)?);
        }
        // A previous build's leftovers (missed by its kill sweep) must
        // not tamper with this one. The uid holds nothing else.
        agent.kill_sweep(None);

        let scratch_root = agent.state_dir.join(&req.build_id);
        let build_dir = scratch_root.join("build");
        let _ = fs::remove_dir_all(&scratch_root);
        fs::create_dir_all(&scratch_root)?;
        platform::stage_tmp_dir(&agent.confinement, &scratch_root, &build_dir, tmp_pack)
            .context("staging the tmp dir")?;

        let log_path = scratch_root.join("build.log");
        let log_w = fs::File::create(&log_path)?;
        let (child, sandbox_root) =
            platform::spawn_builder(&agent.confinement, &req, &scratch_root, &build_dir, &log_w)?;
        let pid = child.id().cast_signed();
        let exit = Arc::new((Mutex::new(None), Condvar::new()));
        reap_on_exit(agent.clone(), req.build_id.clone(), child, exit.clone());
        *current = Some(Build {
            id: req.build_id.clone(),
            pid,
            dir: build_dir.clone(),
            scratch_root,
            sandbox_root,
            outputs: req.outputs,
            exit: exit.clone(),
        });
        // The worker only needs to read the log.
        (build_dir, fs::File::open(&log_path)?, exit, pid)
    };
    tracing::info!(id = req.build_id, pid, "builder started");
    framing::send_reply(
        conn,
        reply::Reply::Start(StartReply {
            pid,
            scratch_dir: build_dir.to_string_lossy().into_owned(),
        }),
        &[log.as_raw_fd()],
    )?;
    notify_exit(conn, &exit)
}

fn handle_adopt(agent: &Arc<Agent>, conn: &UnixStream, req: &AdoptRequest) -> Result<()> {
    let (pid, build_dir, scratch_root, exit) = {
        let current = agent.current.lock().unwrap();
        match current.as_ref() {
            Some(b) if b.id == req.build_id => {
                (b.pid, b.dir.clone(), b.scratch_root.clone(), b.exit.clone())
            }
            _ => return Ok(framing::send_error(conn, ERROR_UNKNOWN_BUILD)?),
        }
    };
    let log = fs::File::open(scratch_root.join("build.log"))?;
    let exit_code = *exit.0.lock().unwrap();
    framing::send_reply(
        conn,
        reply::Reply::Adopt(AdoptReply {
            pid,
            scratch_dir: build_dir.to_string_lossy().into_owned(),
            exit_code,
        }),
        &[log.as_raw_fd()],
    )?;
    if exit_code.is_some() {
        return Ok(());
    }
    notify_exit(conn, &exit)
}

fn handle_kill(agent: &Arc<Agent>, conn: &UnixStream, req: &KillRequest) -> Result<()> {
    let pid = {
        let current = agent.current.lock().unwrap();
        match current.as_ref() {
            Some(b) if b.id == req.build_id => b.pid,
            _ => return Ok(framing::send_error(conn, ERROR_UNKNOWN_BUILD)?),
        }
    };
    agent.kill_sweep(Some(pid));
    framing::send_reply(conn, reply::Reply::Empty(Empty {}), &[]).map_err(Into::into)
}

fn handle_finish(agent: &Arc<Agent>, conn: &UnixStream, req: &FinishRequest) -> Result<()> {
    let (outputs, root) = {
        let current = agent.current.lock().unwrap();
        match current.as_ref() {
            Some(b) if b.id == req.build_id => (b.outputs.clone(), b.sandbox_root.clone()),
            _ => return Ok(framing::send_error(conn, ERROR_UNKNOWN_BUILD)?),
        }
    };
    platform::finish(&agent.confinement, root.as_deref(), &outputs);
    framing::send_reply(conn, reply::Reply::Empty(Empty {}), &[]).map_err(Into::into)
}

fn handle_cleanup(agent: &Arc<Agent>, conn: &UnixStream, req: &CleanupRequest) -> Result<()> {
    let build = {
        let mut current = agent.current.lock().unwrap();
        match current.as_ref() {
            Some(b) if b.id == req.build_id => current.take().unwrap(),
            _ => return Ok(framing::send_error(conn, ERROR_UNKNOWN_BUILD)?),
        }
    };
    agent.kill_sweep(Some(build.pid));
    platform::cleanup(&agent.confinement, &build);
    framing::send_reply(conn, reply::Reply::Empty(Empty {}), &[])?;
    tracing::info!(id = build.id, "cleanup done");
    if agent.dedicated_uid {
        std::process::exit(0);
    }
    Ok(())
}

/// Fork and exec the builder directly (no namespace sandbox): own
/// process group, stdio on the log file, cwd and env rewritten to the
/// scratch dir, platform confinement applied in the child right
/// before exec.
fn spawn_plain(
    req: &StartRequest,
    build_dir: &Path,
    log: &fs::File,
) -> Result<std::process::Child> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    let build_dir_str = build_dir
        .to_str()
        .context("build dir is not valid UTF-8")?
        .to_owned();
    let mut env = req.env.clone();
    rewrite_tmp_dir_env(&mut env, &req.tmp_dir_in_sandbox, &build_dir_str);

    let mut cmd = Command::new(&req.builder);
    cmd.args(&req.args)
        .env_clear()
        .envs(&env)
        .current_dir(build_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log.try_clone()?));
    cmd.process_group(0);
    platform::confine(&mut cmd, req, &build_dir_str)?;
    cmd.spawn()
        .with_context(|| format!("spawning builder {}", req.builder))
}

/// Rewrite env values referencing the hub's in-sandbox tmp dir (e.g.
/// "/build" from a Linux hub) to the agent's scratch dir; there is no
/// mount namespace to make the original path exist.
fn rewrite_tmp_dir_env(env: &mut HashMap<String, String>, from: &str, to: &str) {
    let prefix = format!("{from}/");
    for v in env.values_mut() {
        if v == from {
            to.clone_into(v);
        } else if let Some(rest) = v.strip_prefix(&prefix) {
            *v = format!("{to}/{rest}");
        }
    }
}

/// Reap the builder on its own thread and publish the exit code.
/// An OOM kill by memory.max is noted in the build log first.
fn reap_on_exit(
    agent: Arc<Agent>,
    build_id: String,
    mut child: std::process::Child,
    exit: Arc<(Mutex<Option<i32>>, Condvar)>,
) {
    std::thread::spawn(move || {
        use std::os::unix::process::ExitStatusExt;
        let code = match child.wait() {
            Ok(status) => status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)),
            Err(_) => 1,
        };
        if platform::oom_killed(&agent.confinement, &build_id) {
            tracing::warn!(id = build_id, "builder killed by the build memory limit");
            let log = agent.state_dir.join(&build_id).join("build.log");
            let _ = fs::OpenOptions::new()
                .append(true)
                .open(log)
                .and_then(|mut f| {
                    f.write_all(b"tribuchet: builder killed by the build memory limit\n")
                });
        }
        tracing::info!(code, "builder exited");
        *exit.0.lock().unwrap() = Some(code);
        exit.1.notify_all();
    });
}

/// Send the exit notice on the leasing connection once the builder is
/// reaped. A vanished worker just closes the connection; the exit code
/// stays available for Adopt.
fn notify_exit(conn: &UnixStream, exit: &(Mutex<Option<i32>>, Condvar)) -> Result<()> {
    let mut code = exit.0.lock().unwrap();
    while code.is_none() {
        code = exit.1.wait(code).unwrap();
    }
    Ok(framing::send_reply(
        conn,
        reply::Reply::Exit(ExitNotice {
            exit_code: code.unwrap(),
        }),
        &[],
    )?)
}

/// Kill every process of the agent's uid except the agent itself and
/// the `exempt` pid: catches setsid escapes from the process-group
/// kill and leftovers from a previous build. kill(-1) would take the
/// agent down too.
fn kill_own_uid_processes(exempt: Option<i32>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let others = platform::own_uid_pids()
            .into_iter()
            .filter(|&pid| pid != std::process::id().cast_signed() && Some(pid) != exempt)
            .collect::<Vec<_>>();
        if others.is_empty() {
            return;
        }
        for pid in others.iter().copied().filter_map(Pid::from_raw) {
            let _ = kill_process(pid, Signal::KILL);
        }
        if Instant::now() > deadline {
            tracing::warn!(?others, "own-uid processes survived the kill sweep");
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Make an output tree readable (and directories searchable) for the
/// worker so it can pack the NAR. Iterative walk with a work list: the
/// tree is build-produced and must not be able to overflow the stack.
/// Symlinks are skipped, the build may have planted links to other
/// agent-uid files.
fn make_readable(path: &Path) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mut queue = vec![path.to_path_buf()];
    while let Some(path) = queue.pop() {
        let Ok(meta) = path.symlink_metadata() else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let extra = if meta.is_dir() { 0o555 } else { 0o444 };
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(meta.mode() | extra));
        if meta.is_dir()
            && let Ok(entries) = fs::read_dir(&path)
        {
            queue.extend(entries.flatten().map(|e| e.path()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_rewrite_replaces_tmp_dir_references() {
        let mut env = HashMap::from([
            ("NIX_BUILD_TOP".to_string(), "/build".to_string()),
            ("ATTRS".to_string(), "/build/.attrs.json".to_string()),
            ("OTHER".to_string(), "/buildings".to_string()),
        ]);
        rewrite_tmp_dir_env(&mut env, "/build", "/scratch/b1/build");
        assert_eq!(env["NIX_BUILD_TOP"], "/scratch/b1/build");
        assert_eq!(env["ATTRS"], "/scratch/b1/build/.attrs.json");
        assert_eq!(env["OTHER"], "/buildings");
    }

    #[test]
    fn make_readable_skips_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("file"), "x").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", out.join("link")).unwrap();
        make_readable(&out);
        assert_ne!(
            fs::metadata(out.join("file")).unwrap().permissions().mode() & 0o444,
            0
        );
    }
}
