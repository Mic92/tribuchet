//! The Linux build agent's user namespace: an unshare-and-pause
//! holder child keeps it alive for the agent's lifetime.

use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use rustix::event::pause;
use rustix::io::{FdFlags, fcntl_setfd, read, write};
use rustix::pipe::pipe;
use rustix::process::{Pid, Signal, WaitOptions, kill_process, waitpid};
use rustix::thread::{UnshareFlags, unshare_unsafe};

/// A forked child that unshared an unmapped user namespace and blocks;
/// killed on drop (the returned fd keeps the namespace alive). Forks
/// because unshare(CLONE_NEWUSER) fails with EINVAL in a multithreaded
/// process; the child runs only async-signal-safe syscalls. No pipe
/// holds the child open: a concurrently forked sibling would inherit
/// the write end and keep it (and us) waiting forever.
pub(in crate::worker) struct UsernsHolder {
    child: Pid,
}

impl UsernsHolder {
    pub(in crate::worker) fn new() -> Result<(Self, OwnedFd)> {
        use nix::unistd::{self, ForkResult};
        let (sync_r, sync_w) = pipe()?;
        match unsafe { unistd::fork() }? {
            ForkResult::Child => {
                // SAFETY: only a namespace flag; no fd-table, fs or VM sharing changes.
                if unsafe { unshare_unsafe(UnshareFlags::NEWUSER) }.is_err() {
                    unsafe { libc::_exit(1) }
                }
                let _ = write(&sync_w, b"u");
                loop {
                    pause();
                }
            }
            ForkResult::Parent { child } => {
                let child = Pid::from_raw(child.as_raw()).expect("fork returned pid 0");
                drop(sync_w);
                let mut byte = [0u8; 1];
                if read(&sync_r, &mut byte[..]) != Ok(1) {
                    let _ = waitpid(Some(child), WaitOptions::empty());
                    bail!("child failed to unshare a user namespace");
                }
                let holder = (|| {
                    let userns =
                        fs::File::open(format!("/proc/{}/ns/user", child.as_raw_nonzero()))
                            .map(OwnedFd::from)
                            .context("opening the child user namespace")?;
                    Ok((Self { child }, userns))
                })();
                if holder.is_err() {
                    let _ = kill_process(child, Signal::KILL);
                    let _ = waitpid(Some(child), WaitOptions::empty());
                }
                holder
            }
        }
    }

    /// Pid of the pausing child, for /proc/<pid>/{uid_map,gid_map}.
    pub(in crate::worker) fn pid(&self) -> Pid {
        self.child
    }
}

impl Drop for UsernsHolder {
    fn drop(&mut self) {
        let _ = kill_process(self.child, Signal::KILL);
        let _ = waitpid(Some(self.child), WaitOptions::empty());
    }
}

/// Duplicate the namespace fd without close-on-exec so a spawned child
/// inherits it, plus the /proc/self/fd path the child opens it under.
/// Children cannot go through the agent's /proc instead: the agent
/// keeps CAP_CHOWN, so the ptrace access check denies its cap-less
/// children.
pub(in crate::worker) fn inherited_ns(userns: &OwnedFd) -> Result<(OwnedFd, PathBuf)> {
    let dup = userns.try_clone().context("duplicating the userns fd")?;
    fcntl_setfd(&dup, FdFlags::empty()).context("clearing close-on-exec on the userns fd")?;
    let path = format!("/proc/self/fd/{}", dup.as_raw_fd()).into();
    Ok((dup, path))
}
