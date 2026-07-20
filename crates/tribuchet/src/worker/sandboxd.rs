//! Client for tribuchet-sandboxd.
//!
//! The daemon writes uid/gid maps into a worker-created user namespace
//! (in-ns 0..count backed by a pool block, the worker uid never mapped)
//! and hands back a delegated build cgroup. The daemon reclaims the
//! block once the build cgroup has drained, or when the connection
//! closes before the build ever started; the connection alone ending
//! never kills a running build (they survive worker restarts).

use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sandbox_proto::framing;
use sandbox_proto::linux::{
    AllocateReply, AllocateRequest, METHOD_ALLOCATE, METHOD_PURGE, PurgeRequest,
};

pub use sandbox_proto::linux::SOCKET_PATH;

/// Ask sandboxd (root) to empty a worker-owned dir of leased-uid files.
pub fn purge(socket: &Path, dir: &Path) -> Result<()> {
    let fd = nix::fcntl::open(
        dir,
        nix::fcntl::OFlag::O_DIRECTORY
            | nix::fcntl::OFlag::O_NOFOLLOW
            | nix::fcntl::OFlag::O_RDONLY
            | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .with_context(|| format!("opening {}", dir.display()))?;
    let conn = UnixStream::connect(socket)
        .with_context(|| format!("connecting to sandboxd at {}", socket.display()))?;
    framing::send_call(&conn, METHOD_PURGE, &PurgeRequest {}, &[fd.as_raw_fd()])?;
    let (_, _): (serde_json::Value, _) = framing::recv_reply(&conn)?;
    Ok(())
}

/// One leased sandbox: a mapped user namespace and its build cgroup.
#[derive(Debug)]
pub struct SandboxLease {
    /// Held open for the lease lifetime.
    _conn: UnixStream,
    /// Keeps /proc/self/fd/N valid until the setup stage has setns()'d.
    _userns: OwnedFd,
    cgroup: PathBuf,
    /// First host uid of the leased block (backs in-ns uid 0).
    pub pool_base: u32,
}

impl SandboxLease {
    /// The delegated per-build cgroup directory.
    pub fn cgroup(&self) -> &Path {
        &self.cgroup
    }
}

/// A worker-created, still-unmapped user namespace. Lets the caller
/// spawn the setup stage (which needs [`ns_path`](Self::ns_path))
/// before [`allocate`](Self::allocate) so sandboxd can place it in the
/// build cgroup as part of the one Allocate call.
pub struct SandboxPrep {
    holder: UsernsHolder,
    userns: OwnedFd,
}

impl SandboxPrep {
    pub fn new() -> Result<Self> {
        let (holder, userns) =
            UsernsHolder::new().context("creating an unmapped user namespace")?;
        Ok(Self { holder, userns })
    }

    /// Stays valid across the move into [`SandboxLease`] (same fd).
    pub fn ns_path(&self) -> PathBuf {
        ns_path(&self.userns)
    }

    /// Lease a sandbox with `uid_count` uids (1 or 65536) at in-ns 0
    /// and have sandboxd place `stage` in the build cgroup and chown
    /// `tmp_dir` to the leased base uid.
    pub fn allocate(
        self,
        socket: &Path,
        build_id: &str,
        uid_count: u32,
        stage: nix::unistd::Pid,
        tmp_dir: &Path,
    ) -> Result<SandboxLease> {
        let stage_fd = pidfd_open(stage).context("opening a pidfd of the setup stage")?;
        let tmp_dir_fd = nix::fcntl::open(
            tmp_dir,
            nix::fcntl::OFlag::O_DIRECTORY
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .with_context(|| format!("opening tmp dir {}", tmp_dir.display()))?;
        let conn = UnixStream::connect(socket)
            .with_context(|| format!("connecting to sandboxd at {}", socket.display()))?;
        // The holder must survive until sandboxd has verified the
        // pidfd/userns pair and written maps through /proc/<pid>;
        // afterwards the fd alone pins the namespace.
        framing::send_call(
            &conn,
            METHOD_ALLOCATE,
            &AllocateRequest {
                build_id: build_id.to_owned(),
                uid_count,
            },
            &[
                self.userns.as_raw_fd(),
                self.holder.pidfd.as_raw_fd(),
                stage_fd.as_raw_fd(),
                tmp_dir_fd.as_raw_fd(),
            ],
        )?;
        let (reply, fds): (AllocateReply, Vec<OwnedFd>) =
            framing::recv_reply(&conn).context("leasing a sandbox from tribuchet-sandboxd")?;
        let [cgroup_fd] = <[OwnedFd; 1]>::try_from(fds).map_err(|fds| {
            anyhow::anyhow!("expected 1 fd in the lease reply, got {}", fds.len())
        })?;
        let cgroup = fs::read_link(format!("/proc/self/fd/{}", cgroup_fd.as_raw_fd()))
            .context("resolving the leased cgroup path")?;
        Ok(SandboxLease {
            _conn: conn,
            _userns: self.userns,
            cgroup,
            pool_base: reply.pool_base,
        })
    }
}

/// A forked child that unshared an unmapped user namespace and blocks;
/// killed on drop (the returned fd keeps the namespace alive). Forks
/// because unshare(CLONE_NEWUSER) fails with EINVAL in a multithreaded
/// process; the child runs only async-signal-safe syscalls. No pipe
/// holds the child open: a concurrently forked sibling would inherit
/// the write end and keep it (and us) waiting forever.
struct UsernsHolder {
    child: nix::unistd::Pid,
    pidfd: OwnedFd,
}

impl UsernsHolder {
    fn new() -> Result<(Self, OwnedFd)> {
        use nix::unistd::{self, ForkResult};
        let (sync_r, sync_w) = unistd::pipe()?;
        match unsafe { unistd::fork() }? {
            ForkResult::Child => {
                if nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUSER).is_err() {
                    unsafe { libc::_exit(1) }
                }
                let _ = unistd::write(&sync_w, b"u");
                loop {
                    unistd::pause();
                }
            }
            ForkResult::Parent { child } => {
                drop(sync_w);
                if unistd::read(&sync_r, &mut [0u8; 1]) != Ok(1) {
                    let _ = nix::sys::wait::waitpid(child, None);
                    bail!("child failed to unshare a user namespace");
                }
                let holder = (|| {
                    let userns = fs::File::open(format!("/proc/{child}/ns/user"))
                        .map(OwnedFd::from)
                        .context("opening the child user namespace")?;
                    let pidfd = pidfd_open(child).context("opening a pidfd of the holder")?;
                    Ok((Self { child, pidfd }, userns))
                })();
                if holder.is_err() {
                    let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
                    let _ = nix::sys::wait::waitpid(child, None);
                }
                holder
            }
        }
    }
}

impl Drop for UsernsHolder {
    fn drop(&mut self) {
        let _ = nix::sys::signal::kill(self.child, nix::sys::signal::Signal::SIGKILL);
        let _ = nix::sys::wait::waitpid(self.child, None);
    }
}

fn ns_path(userns: &OwnedFd) -> PathBuf {
    format!("/proc/{}/fd/{}", std::process::id(), userns.as_raw_fd()).into()
}

/// pidfd_open(2); no nix wrapper yet.
fn pidfd_open(pid: nix::unistd::Pid) -> Result<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) };
    let fd = nix::errno::Errno::result(fd).context("pidfd_open")?;
    let fd = RawFd::try_from(fd).context("pidfd_open returned an invalid fd")?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    /// Mock sandboxd: accepts one lease, checks the request, replies
    /// with a cgroup fd, then holds the connection.
    fn mock_server(listener: UnixListener) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            let (method, request, fds): (_, AllocateRequest, _) =
                framing::recv_call(&conn).unwrap();
            assert_eq!(method, METHOD_ALLOCATE);
            assert_eq!(request.uid_count, 65536);
            assert_eq!(
                fds.len(),
                4,
                "userns, holder and stage pidfds plus tmp dir expected"
            );
            let cgroup = std::fs::File::open("/tmp").unwrap();
            framing::send_reply(
                &conn,
                &AllocateReply {
                    pool_base: 3_000_000,
                },
                &[cgroup.as_raw_fd()],
            )
            .unwrap();
            // keep the lease connection open until the client is done
            let _ = framing::recv_call::<serde_json::Value>(&conn);
        })
    }

    #[test]
    fn allocate_lease() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("socket");
        let server = mock_server(UnixListener::bind(&path).unwrap());

        let prep = SandboxPrep::new().unwrap();
        assert!(prep.ns_path().exists());
        let lease = prep
            .allocate(
                &path,
                "b1",
                65536,
                nix::unistd::Pid::this(),
                Path::new("/tmp"),
            )
            .unwrap();
        assert_eq!(lease.pool_base, 3_000_000);
        assert_eq!(lease.cgroup(), Path::new("/tmp"));
        drop(lease);
        server.join().unwrap();
    }

    #[test]
    fn error_reply_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            let _ = framing::recv_call::<AllocateRequest>(&conn).unwrap();
            framing::send_error(&conn, "com.tribuchet.Sandbox.PoolExhausted").unwrap();
        });
        let err = SandboxPrep::new()
            .unwrap()
            .allocate(
                &path,
                "b1",
                65536,
                nix::unistd::Pid::this(),
                Path::new("/tmp"),
            )
            .unwrap_err();
        assert!(format!("{err:#}").contains("PoolExhausted"), "{err:#}");
    }

    #[test]
    fn missing_socket_fails() {
        let prep = SandboxPrep::new().unwrap();
        assert!(
            prep.allocate(
                Path::new("/nonexistent"),
                "b1",
                1,
                nix::unistd::Pid::this(),
                Path::new("/tmp"),
            )
            .is_err()
        );
    }
}
