//! Worker-created user namespaces: the unshare-and-pause holder child
//! plus the pidfd/ns-path helpers shared by the sandboxd client and
//! the Linux build agent.

use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

/// A forked child that unshared an unmapped user namespace and blocks;
/// killed on drop (the returned fd keeps the namespace alive). Forks
/// because unshare(CLONE_NEWUSER) fails with EINVAL in a multithreaded
/// process; the child runs only async-signal-safe syscalls. No pipe
/// holds the child open: a concurrently forked sibling would inherit
/// the write end and keep it (and us) waiting forever.
pub(in crate::worker) struct UsernsHolder {
    child: nix::unistd::Pid,
    pub(in crate::worker) pidfd: OwnedFd,
}

impl UsernsHolder {
    pub(in crate::worker) fn new() -> Result<(Self, OwnedFd)> {
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

    /// Pid of the pausing child, for /proc/<pid>/{uid_map,gid_map}.
    pub(in crate::worker) fn pid(&self) -> nix::unistd::Pid {
        self.child
    }
}

impl Drop for UsernsHolder {
    fn drop(&mut self) {
        let _ = nix::sys::signal::kill(self.child, nix::sys::signal::Signal::SIGKILL);
        let _ = nix::sys::wait::waitpid(self.child, None);
    }
}

pub(in crate::worker) fn ns_path(userns: &OwnedFd) -> PathBuf {
    format!("/proc/{}/fd/{}", std::process::id(), userns.as_raw_fd()).into()
}

/// pidfd_open(2); no nix wrapper yet.
pub(in crate::worker) fn pidfd_open(pid: nix::unistd::Pid) -> Result<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) };
    let fd = nix::errno::Errno::result(fd).context("pidfd_open")?;
    let fd = RawFd::try_from(fd).context("pidfd_open returned an invalid fd")?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
