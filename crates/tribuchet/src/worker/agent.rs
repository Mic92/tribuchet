//! `tribuchet agent`: macOS per-uid build agent.
//!
//! One socket-activated launchd daemon per pool user. The worker
//! leases a build by connecting and sending Start. The agent unpacks
//! the tmp dir, applies the seatbelt profile in the forked child and
//! execs the builder as its own (non-worker) uid. The builder is the
//! agent's child, so builds survive worker restarts and the agent
//! holds the log and exit status until the worker adopts them. The
//! protocol lives in crates/sandbox-proto/src/darwin.rs.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use sandbox_proto::darwin::{
    AdoptReply, AdoptRequest, CleanupRequest, ERROR_BUSY, ERROR_UNKNOWN_BUILD, ExitNotice,
    FinishRequest, KillRequest, METHOD_ADOPT, METHOD_CLEANUP, METHOD_FINISH, METHOD_KILL,
    METHOD_START, SCRATCH_DIR_PARAM, StartReply, StartRequest,
};
use sandbox_proto::framing;

use crate::sd::launchd_unix_listener;
use crate::tmptar::unpack_tmp_dir_archive;

pub struct Options {
    /// Unix socket to bind when launchd did not pass one.
    pub socket: Option<PathBuf>,
    /// Per-agent state dir holding one scratch dir per build.
    pub state_dir: PathBuf,
    /// Uid allowed to lease builds, defaulting to the agent's own uid
    /// for development runs.
    pub worker_uid: Option<u32>,
}

/// The one build this agent holds, from Start until Cleanup.
struct Build {
    build_id: String,
    /// Builder pid, also its process group.
    pid: i32,
    /// Scratch dir the build runs in (`<state>/<id>/build`).
    build_dir: PathBuf,
    /// Whole per-build tree removed by Cleanup (`<state>/<id>`).
    scratch_root: PathBuf,
    outputs: Vec<String>,
    /// Exit code once the wait thread reaped the builder. Kept in
    /// agent memory only: the build can write everything on disk here.
    exit: Arc<(Mutex<Option<i32>>, Condvar)>,
}

struct Agent {
    state_dir: PathBuf,
    worker_uid: u32,
    current: Mutex<Option<Build>>,
}

pub fn run(opts: Options) -> Result<()> {
    let listener = listener(opts.socket.as_deref())?;
    fs::create_dir_all(&opts.state_dir)
        .with_context(|| format!("creating state dir {}", opts.state_dir.display()))?;
    let agent = Arc::new(Agent {
        state_dir: opts.state_dir,
        worker_uid: opts
            .worker_uid
            .unwrap_or_else(|| nix::unistd::getuid().as_raw()),
        current: Mutex::new(None),
    });
    tracing::info!(uid = nix::unistd::getuid().as_raw(), "agent listening");
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

/// launchd-activated listener (socket named "agent" in the plist) or a
/// self-bound one for development and tests.
fn listener(socket: Option<&Path>) -> Result<UnixListener> {
    if let Some(l) = launchd_unix_listener("agent")? {
        return Ok(l);
    }
    let path = socket.context("no launchd socket and no --socket given")?;
    let _ = fs::remove_file(path);
    UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))
}

fn handle(agent: &Arc<Agent>, conn: &UnixStream) -> Result<()> {
    let (peer_uid, _) = nix::unistd::getpeereid(conn)?;
    ensure!(
        peer_uid.as_raw() == agent.worker_uid,
        "connection from uid {peer_uid}, only the worker uid {} may lease",
        agent.worker_uid
    );
    let (method, params, fds): (_, serde_json::Value, _) = framing::recv_call(conn)?;
    match method.as_str() {
        METHOD_START => handle_start(agent, conn, serde_json::from_value(params)?, fds),
        METHOD_ADOPT => handle_adopt(agent, conn, &serde_json::from_value(params)?),
        METHOD_KILL => handle_kill(agent, conn, &serde_json::from_value(params)?),
        METHOD_FINISH => handle_finish(agent, conn, &serde_json::from_value(params)?),
        METHOD_CLEANUP => handle_cleanup(agent, conn, &serde_json::from_value(params)?),
        m => bail!("unknown method {m}"),
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
    let tmp_tar = fds.into_iter().next().context("missing tmp dir tar fd")?;
    // The lock is held until the build is registered: a losing
    // concurrent Start gets Busy without ever spawning anything.
    let (build_dir, log, exit, pid) = {
        let mut current = agent.current.lock().unwrap();
        if current.is_some() {
            return framing::send_error(conn, ERROR_BUSY);
        }
        // A previous build's leftovers (missed by its kill sweep) must
        // not tamper with this one. The uid holds nothing else.
        kill_own_uid_processes();

        let scratch_root = agent.state_dir.join(&req.build_id);
        let build_dir = scratch_root.join("build");
        let _ = fs::remove_dir_all(&scratch_root);
        fs::create_dir_all(&build_dir)?;
        let dec = zstd::stream::read::Decoder::new(fs::File::from(tmp_tar))?;
        unpack_tmp_dir_archive(dec, &scratch_root).context("unpacking tmp dir archive")?;

        let log_path = scratch_root.join("build.log");
        let log_w = fs::File::create(&log_path)?;
        let child = spawn_builder(&req, &build_dir, &log_w)?;
        let pid = child.id().cast_signed();
        let exit = Arc::new((Mutex::new(None), Condvar::new()));
        reap_on_exit(child, exit.clone());
        *current = Some(Build {
            build_id: req.build_id.clone(),
            pid,
            build_dir: build_dir.clone(),
            scratch_root,
            outputs: req.outputs,
            exit: exit.clone(),
        });
        // The worker only needs to read the log.
        (build_dir, fs::File::open(&log_path)?, exit, pid)
    };
    tracing::info!(id = req.build_id, pid, "builder started");
    framing::send_reply(
        conn,
        &StartReply {
            pid,
            scratch_dir: build_dir.to_string_lossy().into_owned(),
        },
        &[log.as_raw_fd()],
    )?;
    notify_exit(conn, &exit)
}

fn handle_adopt(agent: &Arc<Agent>, conn: &UnixStream, req: &AdoptRequest) -> Result<()> {
    let (pid, build_dir, scratch_root, exit) = {
        let current = agent.current.lock().unwrap();
        match current.as_ref() {
            Some(b) if b.build_id == req.build_id => (
                b.pid,
                b.build_dir.clone(),
                b.scratch_root.clone(),
                b.exit.clone(),
            ),
            _ => return framing::send_error(conn, ERROR_UNKNOWN_BUILD),
        }
    };
    let log = fs::File::open(scratch_root.join("build.log"))?;
    let exit_code = *exit.0.lock().unwrap();
    framing::send_reply(
        conn,
        &AdoptReply {
            pid,
            scratch_dir: build_dir.to_string_lossy().into_owned(),
            exit_code,
        },
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
            Some(b) if b.build_id == req.build_id => b.pid,
            _ => return framing::send_error(conn, ERROR_UNKNOWN_BUILD),
        }
    };
    let _ = nix::sys::signal::killpg(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGKILL,
    );
    kill_own_uid_processes();
    framing::send_reply(conn, &serde_json::json!({}), &[])
}

fn handle_finish(agent: &Arc<Agent>, conn: &UnixStream, req: &FinishRequest) -> Result<()> {
    let outputs = {
        let current = agent.current.lock().unwrap();
        match current.as_ref() {
            Some(b) if b.build_id == req.build_id => b.outputs.clone(),
            _ => return framing::send_error(conn, ERROR_UNKNOWN_BUILD),
        }
    };
    for out in &outputs {
        make_readable(Path::new(out));
    }
    framing::send_reply(conn, &serde_json::json!({}), &[])
}

fn handle_cleanup(agent: &Arc<Agent>, conn: &UnixStream, req: &CleanupRequest) -> Result<()> {
    let build = {
        let mut current = agent.current.lock().unwrap();
        match current.as_ref() {
            Some(b) if b.build_id == req.build_id => current.take().unwrap(),
            _ => return framing::send_error(conn, ERROR_UNKNOWN_BUILD),
        }
    };
    kill_own_uid_processes();
    let _ = fs::remove_dir_all(&build.scratch_root);
    for out in &build.outputs {
        // Scratch outputs live at their real store paths and are
        // agent-owned. The sticky store dir lets the owner delete them.
        let p = Path::new(out);
        let _ = fs::remove_dir_all(p);
        let _ = fs::remove_file(p);
    }
    framing::send_reply(conn, &serde_json::json!({}), &[])?;
    // Socket-activated with no KeepAlive: exit when idle, launchd
    // starts a fresh agent on the next connection.
    tracing::info!(id = build.build_id, "cleanup done, exiting");
    std::process::exit(0);
}

/// Fork and exec the builder: own process group, stdio on the log
/// file, cwd and env rewritten to the scratch dir, seatbelt profile
/// applied in the child right before exec.
fn spawn_builder(
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
    if !req.profile.is_empty() {
        let seatbelt = Seatbelt::new(&req.profile, &[(SCRATCH_DIR_PARAM, &build_dir_str)])?;
        // SAFETY: sandbox_init_with_parameters is called with
        // pointers into memory owned by the moved-in Seatbelt; no
        // allocation happens after fork.
        unsafe {
            cmd.pre_exec(move || seatbelt.apply());
        }
    }
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
            *v = to.to_owned();
        } else if let Some(rest) = v.strip_prefix(&prefix) {
            *v = format!("{to}/{rest}");
        }
    }
}

/// Pre-allocated arguments for `sandbox_init_with_parameters`, so the
/// post-fork hook only makes the libc call.
struct Seatbelt {
    profile: CString,
    // key/value CStrings backing the pointer array
    _params: Vec<CString>,
    param_ptrs: Vec<*const libc::c_char>,
}

// The raw pointers point into the CStrings owned by the same struct.
unsafe impl Send for Seatbelt {}
unsafe impl Sync for Seatbelt {}

impl Seatbelt {
    fn new(profile: &str, params: &[(&str, &str)]) -> Result<Self> {
        let profile = CString::new(profile).context("NUL byte in seatbelt profile")?;
        let mut owned = Vec::new();
        for (k, v) in params {
            owned.push(CString::new(*k)?);
            owned.push(CString::new(*v)?);
        }
        let mut param_ptrs: Vec<*const libc::c_char> = owned.iter().map(|c| c.as_ptr()).collect();
        param_ptrs.push(std::ptr::null());
        Ok(Self {
            profile,
            _params: owned,
            param_ptrs,
        })
    }

    fn apply(&self) -> std::io::Result<()> {
        unsafe extern "C" {
            fn sandbox_init_with_parameters(
                profile: *const libc::c_char,
                flags: u64,
                parameters: *const *const libc::c_char,
                errorbuf: *mut *mut libc::c_char,
            ) -> libc::c_int;
            fn sandbox_free_error(errorbuf: *mut libc::c_char);
        }
        let mut err: *mut libc::c_char = std::ptr::null_mut();
        let rc = unsafe {
            sandbox_init_with_parameters(
                self.profile.as_ptr(),
                0,
                self.param_ptrs.as_ptr(),
                &raw mut err,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        // Post-fork: report the errno-style failure without touching
        // the (heap-allocated) error string beyond freeing it.
        if !err.is_null() {
            unsafe { sandbox_free_error(err) };
        }
        Err(std::io::Error::other("sandbox_init_with_parameters failed"))
    }
}

/// Reap the builder on its own thread and publish the exit code.
fn reap_on_exit(mut child: std::process::Child, exit: Arc<(Mutex<Option<i32>>, Condvar)>) {
    std::thread::spawn(move || {
        use std::os::unix::process::ExitStatusExt;
        let code = match child.wait() {
            Ok(status) => status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)),
            Err(_) => 1,
        };
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
    framing::send_reply(
        conn,
        &ExitNotice {
            exit_code: code.unwrap(),
        },
        &[],
    )
}

/// Kill every process of the agent's uid except the agent itself:
/// catches setsid escapes from the process-group kill and leftovers
/// from a previous build. kill(-1) would take the agent down too.
fn kill_own_uid_processes() {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let others = own_uid_pids()
            .into_iter()
            .filter(|&pid| pid != std::process::id().cast_signed())
            .collect::<Vec<_>>();
        if others.is_empty() {
            return;
        }
        for pid in &others {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(*pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        if Instant::now() > deadline {
            tracing::warn!(?others, "own-uid processes survived the kill sweep");
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Pids owned by this uid, via libproc's proc_listpids (macOS has no
/// /proc to enumerate).
fn own_uid_pids() -> Vec<i32> {
    // From <libproc.h>; the libc crate binds proc_listpids but not the
    // filter constants.
    const PROC_UID_ONLY: u32 = 2;
    let uid = nix::unistd::getuid().as_raw();
    // Sized generously instead of the size-probe round trip: the uid
    // runs one build plus the agent, and a truncated list only means
    // the next sweep iteration picks up the rest.
    let mut pids = vec![0i32; 4096];
    let bytes = unsafe {
        libc::proc_listpids(
            PROC_UID_ONLY,
            uid,
            pids.as_mut_ptr().cast(),
            (pids.len() * size_of::<i32>()) as libc::c_int,
        )
    };
    if bytes <= 0 {
        tracing::warn!("proc_listpids failed, kill sweep degraded to the process group");
        return Vec::new();
    }
    pids.truncate(bytes as usize / size_of::<i32>());
    pids.retain(|&pid| pid > 0);
    pids
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
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("file"), "x").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", out.join("link")).unwrap();
        make_readable(&out);
        use std::os::unix::fs::PermissionsExt;
        assert_ne!(
            fs::metadata(out.join("file")).unwrap().permissions().mode() & 0o444,
            0
        );
    }
}
