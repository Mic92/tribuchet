//! The Linux build agent's user namespace: a re-exec'd holder child
//! (unshared via pre_exec) keeps it alive for the agent's lifetime.

use std::env;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use rustix::event::pause;
use rustix::io::{FdFlags, fcntl_setfd};
use rustix::thread::{UnshareFlags, unshare_unsafe};

#[derive(Debug, thiserror::Error)]
#[error("{step}")]
pub struct Error {
    step: &'static str,
    #[source]
    source: io::Error,
}

fn step<E: Into<io::Error>>(step: &'static str) -> impl FnOnce(E) -> Error {
    move |source| Error {
        step,
        source: source.into(),
    }
}

/// Argv marker for the re-exec'd holder child.
pub const USERNS_HOLD_ARG: &str = "__userns_hold";

/// The holder child's whole job: block until killed.
pub fn hold_stage() -> ! {
    loop {
        pause();
    }
}

/// A re-exec'd child that unshared an unmapped user namespace in
/// pre_exec and blocks; killed on drop (the returned fd keeps the
/// namespace alive). A separate process is needed because
/// unshare(CLONE_NEWUSER) fails with EINVAL in the multithreaded
/// agent; a pre_exec failure surfaces as the spawn error.
pub(in crate::worker) struct UsernsHolder {
    child: Child,
}

impl UsernsHolder {
    pub(in crate::worker) fn new() -> Result<(Self, OwnedFd), Error> {
        let exe = env::current_exe().map_err(step("resolving current executable"))?;
        let mut cmd = Command::new(exe);
        cmd.arg(USERNS_HOLD_ARG)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: a single async-signal-safe syscall; only a namespace flag.
        unsafe {
            cmd.pre_exec(|| unshare_unsafe(UnshareFlags::NEWUSER).map_err(Into::into));
        }
        let mut child = cmd.spawn().map_err(step("spawning the userns holder"))?;
        let userns = fs::File::open(format!("/proc/{}/ns/user", child.id()))
            .map(OwnedFd::from)
            .map_err(step("opening the child user namespace"));
        match userns {
            Ok(userns) => Ok((Self { child }, userns)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(e)
            }
        }
    }

    /// Pid of the holder child, for /proc/<pid>/{uid_map,gid_map}.
    pub(in crate::worker) fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for UsernsHolder {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Duplicate the namespace fd without close-on-exec so a spawned child
/// inherits it, plus the /proc/self/fd path the child opens it under.
/// Children cannot go through the agent's /proc instead: the agent
/// keeps CAP_CHOWN, so the ptrace access check denies its cap-less
/// children.
pub(in crate::worker) fn inherited_ns(userns: &OwnedFd) -> Result<(OwnedFd, PathBuf), Error> {
    let dup = userns
        .try_clone()
        .map_err(step("duplicating the userns fd"))?;
    fcntl_setfd(&dup, FdFlags::empty()).map_err(step("clearing close-on-exec on the userns fd"))?;
    let path = format!("/proc/self/fd/{}", dup.as_raw_fd()).into();
    Ok((dup, path))
}
