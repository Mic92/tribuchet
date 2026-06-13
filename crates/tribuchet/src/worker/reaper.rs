//! Build-spawning reaper: the parent half of the worker process.
//!
//! Before the tokio runtime starts, the worker forks. The parent
//! becomes a tiny single-threaded reaper that spawns builder processes
//! on the child's request and reaps them, writing each exit status to
//! a file. Builds are therefore children of the reaper, not of the
//! worker: a worker restart cannot kill them, and exit statuses are
//! collected by real parentage on both Linux and macOS (no subreaper
//! needed).
//!
//! The interface between the halves is deliberately dumb: a datagram
//! socketpair carrying a JSON spawn request plus fds (SCM_RIGHTS), and
//! a status directory of `<pid>` files containing the exit code. The
//! reaper never parses build specs; those travel through an fd it
//! passes along untouched.
//!
//! The reaper outlives worker generations: SIGHUP makes it hand the
//! worker a fast-exit signal and exec a fresh one (zero-downtime
//! reload), and a crashed worker is respawned. Builds keep running
//! either way; the replacement worker re-adopts them from the state
//! they persisted on disk, matching the reaper generation id.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// What the reaper needs to exec a build; the sandbox details are
/// opaque to it (Linux: re-exec setup stage with the spec on stdin,
/// macOS: sandbox-exec with an inline profile).
#[derive(Serialize, Deserialize)]
pub struct SpawnRequest {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<String>,
    /// fds passed alongside: [log] or [log, stdin]
    pub has_stdin: bool,
    /// Echoed in the reply so a request whose reply was never read
    /// (interrupted recv) cannot shift all later replies by one.
    #[serde(default)]
    pub seq: u64,
}

/// Generous bound for one request datagram (argv + env; the sandbox
/// spec travels by fd, not in-band).
const MAX_MSG: usize = 1 << 20;

#[derive(Serialize, Deserialize)]
struct SpawnReply {
    seq: u64,
    pid: Option<i32>,
    error: String,
}

/// Worker-side handle; one in-flight request at a time.
pub struct Spawner {
    sock: std::sync::Mutex<UnixDatagram>,
    seq: std::sync::atomic::AtomicU64,
}

impl Spawner {
    /// Ask the reaper to spawn a build (own process group). Returns
    /// the pid, whose exit status will appear in the status dir.
    pub fn spawn(
        &self,
        req: &mut SpawnRequest,
        log: &std::fs::File,
        stdin: Option<OwnedFd>,
    ) -> Result<i32> {
        req.seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let sock = self.sock.lock().unwrap();
        let payload = serde_json::to_vec(req)?;
        let mut fds = vec![log.as_raw_fd()];
        if let Some(fd) = &stdin {
            fds.push(fd.as_raw_fd());
        }
        send_with_fds(&sock, &payload, &fds).context("sending spawn request to reaper")?;
        let mut buf = vec![0u8; MAX_MSG];
        let reply = loop {
            let (n, _) = recv_with_fds(&sock, &mut buf).context("reading reaper reply")?;
            let reply: SpawnReply = serde_json::from_slice(&buf[..n])?;
            // Discard replies to earlier requests whose recv failed.
            if reply.seq == req.seq {
                break reply;
            }
        };
        match reply.pid {
            Some(pid) => Ok(pid),
            None => anyhow::bail!("reaper failed to spawn build: {}", reply.error),
        }
    }
}

/// Exit code recorded for `pid`, if it has been reaped. The file is
/// consumed (removed) on read.
pub fn take_status(status_dir: &Path, pid: i32) -> Option<i32> {
    let path = status_dir.join(pid.to_string());
    let code = std::fs::read_to_string(&path).ok()?.trim().parse().ok()?;
    let _ = std::fs::remove_file(&path);
    Some(code)
}

/// Spawner socket fd, handed to exec'd worker children.
pub const FD_ENV: &str = "TRIBUCHET_REAPER_FD";
/// Delegated cgroup base, entered by the reaper before any child.
pub const CGROUP_ENV: &str = "TRIBUCHET_CGROUP_BASE";
/// Identifies the reaper generation: persisted build state is only
/// adoptable while the reaper that spawned those pids is still our
/// parent, otherwise pids and statuses are meaningless.
pub const ID_ENV: &str = "TRIBUCHET_REAPER_ID";

/// Become the reaper, or return the spawner handle if this process
/// already is a worker child exec'd by one. The reaper half never
/// returns: it serves spawn requests and respawns worker generations
/// until told to stop, then exits with the last worker's code.
pub fn ensure(status_dir: PathBuf) -> Result<Spawner> {
    if let Ok(s) = std::env::var(FD_ENV) {
        let fd: RawFd = s.parse().context("parsing TRIBUCHET_REAPER_FD")?;
        let sock = unsafe { UnixDatagram::from_raw_fd(fd) };
        // Drop replies addressed to a previous worker generation.
        sock.set_nonblocking(true)?;
        let mut scratch = [0u8; 64];
        while sock.recv(&mut scratch).is_ok() {}
        sock.set_nonblocking(false)?;
        return Ok(Spawner {
            sock: std::sync::Mutex::new(sock),
            seq: std::sync::atomic::AtomicU64::new(1),
        });
    }
    std::fs::create_dir_all(&status_dir)?;
    // Fresh reaper: previous statuses refer to pids it never spawned.
    if let Ok(entries) = std::fs::read_dir(&status_dir) {
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    // Enter the delegated-cgroup leaf before spawning anything: every
    // process must leave the unit's root cgroup, or enabling
    // subtree_control there fails (no-internal-processes rule).
    #[cfg(target_os = "linux")]
    if let Some(base) = super::cgroup::init() {
        std::env::set_var(CGROUP_ENV, &base);
    }
    std::env::set_var(
        ID_ENV,
        format!("{}-{}", std::process::id(), super::unix_now()),
    );
    let (reaper_sock, worker_sock) = UnixDatagram::pair().context("creating reaper socketpair")?;
    let code = reaper_main(reaper_sock, worker_sock, &status_dir);
    std::process::exit(code);
}

/// Exec a worker generation: the path we were invoked as (argv[0]),
/// same arguments, with the spawner socket passed by fd number. Using
/// argv[0] rather than /proc/self/exe means a reload picks up new
/// code when that path is a stable indirection (profile symlink).
fn spawn_worker(worker_sock: &UnixDatagram) -> Result<i32> {
    let exe = std::env::args_os().next().context("missing argv[0]")?;
    // dup() clears CLOEXEC, so the fd survives the exec.
    let fd = nix::unistd::dup(worker_sock).context("duping spawner socket")?;
    let child = std::process::Command::new(exe)
        .args(std::env::args_os().skip(1))
        .env(FD_ENV, fd.as_raw_fd().to_string())
        .spawn()
        .context("spawning worker")?;
    drop(fd);
    Ok(child.id() as i32)
}

/// The reaper loop: serve spawn requests, reap children, persist
/// statuses, and respawn the worker generation when it exits or is
/// reloaded. Returns the last worker's exit code once a stop was
/// requested and every remaining build has been killed and reaped.
fn reaper_main(sock: UnixDatagram, worker_sock: UnixDatagram, status_dir: &Path) -> i32 {
    // systemd signals the main pid, which is the reaper. SIGTERM is
    // forwarded to the worker, which owns the drain policy; SIGHUP
    // (ExecReload) asks the worker to exit fast and gets a fresh one
    // exec'd while its builds keep running.
    static TERM: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static HUP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    extern "C" fn on_term(_: i32) {
        TERM.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    extern "C" fn on_hup(_: i32) {
        HUP.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    for (sig, handler) in [
        (nix::sys::signal::SIGTERM, on_term as extern "C" fn(i32)),
        (nix::sys::signal::SIGINT, on_term),
        (nix::sys::signal::SIGHUP, on_hup),
    ] {
        let action = nix::sys::signal::SigAction::new(
            nix::sys::signal::SigHandler::Handler(handler),
            nix::sys::signal::SaFlags::SA_RESTART,
            nix::sys::signal::SigSet::empty(),
        );
        unsafe {
            let _ = nix::sys::signal::sigaction(sig, &action);
        }
    }
    let mut worker_pid = match spawn_worker(&worker_sock) {
        Ok(pid) => pid,
        Err(e) => {
            eprintln!("tribuchet reaper: {e:#}");
            return 1;
        }
    };
    let mut builds: Vec<i32> = Vec::new();
    let mut worker_code: Option<i32> = None;
    let mut stopping = false;
    let mut buf = vec![0u8; MAX_MSG];
    sock.set_read_timeout(Some(std::time::Duration::from_millis(200)))
        .ok();
    loop {
        if TERM.swap(false, std::sync::atomic::Ordering::Relaxed) {
            stopping = true;
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(worker_pid),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
        if HUP.swap(false, std::sync::atomic::Ordering::Relaxed) && !stopping {
            // Fast handover: state is already on disk, the builds are
            // ours, the replacement re-adopts them.
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(worker_pid),
                nix::sys::signal::Signal::SIGUSR1,
            );
        }
        // Reap everything that exited.
        loop {
            use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
            let code = match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(pid, code)) => Some((pid.as_raw(), code)),
                Ok(WaitStatus::Signaled(pid, sig, _)) => Some((pid.as_raw(), 128 + sig as i32)),
                Ok(WaitStatus::StillAlive) => None,
                Ok(_) => continue,
                Err(_) => None,
            };
            let Some((pid, code)) = code else { break };
            if pid == worker_pid {
                worker_code = Some(code);
            } else {
                builds.retain(|p| *p != pid);
                let _ = std::fs::write(status_dir.join(pid.to_string()), format!("{code}\n"));
            }
        }
        if let Some(code) = worker_code.take() {
            if stopping {
                // Unit stop: the worker drained first, so normally no
                // builds remain; kill stragglers rather than leak them.
                for pid in &builds {
                    let _ = nix::sys::signal::killpg(
                        nix::unistd::Pid::from_raw(*pid),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                }
                for pid in builds.drain(..) {
                    let _ = nix::sys::wait::waitpid(Some(nix::unistd::Pid::from_raw(pid)), None);
                }
                return code;
            }
            // Reload handover or worker crash: builds keep running,
            // the next generation re-adopts them.
            std::thread::sleep(std::time::Duration::from_secs(1));
            match spawn_worker(&worker_sock) {
                Ok(pid) => worker_pid = pid,
                Err(e) => {
                    eprintln!("tribuchet reaper: respawn failed: {e:#}");
                    return 1;
                }
            }
            continue;
        }
        match recv_with_fds(&sock, &mut buf) {
            Ok((n, fds)) => {
                let seq = serde_json::from_slice::<SpawnRequest>(&buf[..n])
                    .map(|r| r.seq)
                    .unwrap_or(0);
                let reply = match handle_spawn(&buf[..n], fds) {
                    Ok(pid) => {
                        builds.push(pid);
                        // A pid recycled from an abandoned earlier build
                        // must not inherit its stale exit status.
                        let _ = std::fs::remove_file(status_dir.join(pid.to_string()));
                        SpawnReply {
                            seq,
                            pid: Some(pid),
                            error: String::new(),
                        }
                    }
                    Err(e) => SpawnReply {
                        seq,
                        pid: None,
                        error: format!("{e:#}"),
                    },
                };
                let _ = sock.send(&serde_json::to_vec(&reply).unwrap_or_default());
            }
            Err(_) => continue, // timeout or worker not sending; loop re-reaps
        }
    }
}

fn handle_spawn(buf: &[u8], mut fds: Vec<OwnedFd>) -> Result<i32> {
    let req: SpawnRequest = serde_json::from_slice(buf).context("decoding spawn request")?;
    anyhow::ensure!(
        fds.len() == 1 + req.has_stdin as usize,
        "expected {} fds, got {}",
        1 + req.has_stdin as usize,
        fds.len()
    );
    let log = fds.remove(0);
    let stdin = req.has_stdin.then(|| fds.remove(0));
    let (prog, args) = req.argv.split_first().context("empty argv")?;
    let mut cmd = std::process::Command::new(prog);
    cmd.args(args).env_clear().envs(req.env.iter().cloned());
    if let Some(cwd) = &req.cwd {
        cmd.current_dir(cwd);
    }
    // Own process group, so orphaned builder children can be killed
    // after the builder exits (there is no PID namespace to do it).
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let logf = std::fs::File::from(log);
    cmd.stdout(std::process::Stdio::from(logf.try_clone()?))
        .stderr(std::process::Stdio::from(logf));
    cmd.stdin(match stdin {
        Some(fd) => std::process::Stdio::from(std::fs::File::from(fd)),
        None => std::process::Stdio::null(),
    });
    let child = cmd.spawn().context("spawning build")?;
    Ok(child.id() as i32)
}

fn send_with_fds(sock: &UnixDatagram, payload: &[u8], fds: &[RawFd]) -> Result<()> {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
    let iov = [std::io::IoSlice::new(payload)];
    let cmsg = [ControlMessage::ScmRights(fds)];
    sendmsg::<()>(
        sock.as_raw_fd(),
        &iov,
        if fds.is_empty() { &[] } else { &cmsg },
        MsgFlags::empty(),
        None,
    )?;
    Ok(())
}

fn recv_with_fds(sock: &UnixDatagram, buf: &mut [u8]) -> Result<(usize, Vec<OwnedFd>)> {
    use nix::sys::socket::{recvmsg, MsgFlags};
    let mut cmsg_buf = nix::cmsg_space!([RawFd; 8]);
    let mut iov = [std::io::IoSliceMut::new(buf)];
    let msg = recvmsg::<()>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::empty(),
    )?;
    let mut fds = Vec::new();
    for c in msg.cmsgs()? {
        if let nix::sys::socket::ControlMessageOwned::ScmRights(received) = c {
            for fd in received {
                fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }
    Ok((msg.bytes, fds))
}
