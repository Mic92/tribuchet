//! Per-build cgroups under the agent's delegated subtree.
//!
//! The agent unit runs with Delegate=yes, so systemd hands the unit
//! cgroup to the agent user. Each build gets a `build-<id>` child next
//! to the agent's own leaf: the sandbox's cgroup namespace is rooted
//! there and the payload (nspawn, NixOS containers) manages its own
//! subgroups, which is why the cgroup is chowned to the build's
//! mapped root uid; that chown is what the agent keeps CAP_CHOWN for.

use std::fs;
use std::io;
use std::os::unix::fs::chown;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{step}")]
    Step {
        step: String,
        #[source]
        source: io::Error,
    },
    #[error("cgroup did not drain")]
    DidNotDrain,
}

fn step(step: impl Into<String>) -> impl FnOnce(io::Error) -> Error {
    |source| Error::Step {
        step: step.into(),
        source,
    }
}

/// Vacate the delegated unit cgroup (cgroup v2's no-internal-process
/// rule forbids enabling controllers while it holds processes) and
/// enable the memory controller for the build cgroups created next to
/// the leaf. None when the unit is not delegated (development runs):
/// builds then run without a cgroup of their own.
pub(super) fn init() -> Option<PathBuf> {
    let cg = fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = cg.lines().find_map(|l| l.strip_prefix("0::"))?;
    let base = PathBuf::from(format!("/sys/fs/cgroup{}", path.trim()));
    let controllers = fs::read_to_string(base.join("cgroup.controllers")).ok()?;
    let leaf = base.join("agent");
    if fs::create_dir_all(&leaf).is_err() || fs::write(leaf.join("cgroup.procs"), "0").is_err() {
        tracing::info!("no delegated cgroup; builds run without one");
        return None;
    }
    if controllers.split_whitespace().any(|c| c == "memory")
        && let Err(e) = fs::write(base.join("cgroup.subtree_control"), "+memory")
    {
        tracing::warn!("enabling +memory on {}: {e}", base.display());
    }
    Some(base)
}

/// Create the build's cgroup and hand it to the build's mapped root
/// uid so the in-sandbox payload can manage subgroups. cgroup.procs
/// stays agent-owned until [`enter`] moved the setup stage in;
/// cgroup.kill and memory.max stay agent-owned for good.
pub(super) fn create(base: &Path, build_id: &str, owner_uid: u32) -> Result<PathBuf, Error> {
    let dir = base.join(format!("build-{build_id}"));
    fs::create_dir(&dir).map_err(step(format!("creating cgroup {}", dir.display())))?;
    chown(&dir, Some(owner_uid), None)?;
    for f in ["cgroup.subtree_control", "cgroup.threads"] {
        chown(dir.join(f), Some(owner_uid), None)?;
    }
    Ok(dir)
}

/// Cap the build's memory. memory.max stays agent-owned so the
/// payload cannot raise it. oom.group makes the kernel kill the whole
/// build instead of one victim, so it fails instead of hanging.
pub(super) fn set_memory_max(dir: &Path, bytes: u64) -> Result<(), Error> {
    fs::write(dir.join("memory.max"), bytes.to_string())
        .map_err(step(format!("writing memory.max in {}", dir.display())))?;
    fs::write(dir.join("memory.oom.group"), "1").map_err(step("writing memory.oom.group"))
}

/// Move a pid into the build cgroup, then hand cgroup.procs to the
/// build's mapped root uid (the payload migrates processes into its
/// own subgroups). Called on the setup stage before the spec is sent,
/// so its CLONE_NEWCGROUP is rooted there.
pub(super) fn enter(dir: &Path, pid: i32, owner_uid: u32) -> Result<(), Error> {
    fs::write(dir.join("cgroup.procs"), pid.to_string())
        .map_err(step(format!("moving pid {pid} into {}", dir.display())))?;
    chown(dir.join("cgroup.procs"), Some(owner_uid), None)?;
    Ok(())
}

/// Kill everything in the build cgroup, wait for it to drain and
/// remove it, subgroups first (cgroup dirs can only be rmdir'd).
pub(super) fn destroy(dir: &Path) -> Result<(), Error> {
    match fs::write(dir.join("cgroup.kill"), "1") {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        other => other.map_err(step("writing cgroup.kill"))?,
    }
    let deadline = Instant::now() + Duration::from_mins(1);
    // A vanished events file (systemd already removed the cgroup)
    // counts as drained.
    while fs::read_to_string(dir.join("cgroup.events")).is_ok_and(|e| !e.contains("populated 0")) {
        if Instant::now() >= deadline {
            return Err(Error::DidNotDrain);
        }
        thread::sleep(Duration::from_millis(50));
    }
    let mut dirs = vec![dir.to_path_buf()];
    let mut i = 0;
    while i < dirs.len() {
        for entry in fs::read_dir(&dirs[i])?.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                dirs.push(entry.path());
            }
        }
        i += 1;
    }
    for d in dirs.iter().rev() {
        fs::remove_dir(d).map_err(step(format!("removing cgroup {}", d.display())))?;
    }
    Ok(())
}
