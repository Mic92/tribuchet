//! One sandbox lease: userns maps and the delegated build cgroup.

use std::fs;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use nix::unistd::{Gid, Pid, Uid, chown};

/// Pid behind a pidfd, or an error if the process already exited.
pub fn pidfd_pid(pidfd: BorrowedFd) -> Result<Pid> {
    let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))?;
    let pid: i32 = fdinfo
        .lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .context("pidfd without Pid field")?
        .trim()
        .parse()?;
    ensure!(pid > 0, "pidfd process already exited");
    Ok(Pid::from_raw(pid))
}

/// The client must pass the userns of the process its pidfd points to,
/// and that namespace must not have maps yet (we write them).
pub fn verify_userns(pid: Pid, userns: BorrowedFd) -> Result<()> {
    let via_pid = fs::metadata(format!("/proc/{pid}/ns/user")).context("stat pid userns")?;
    let via_fd = nix::sys::stat::fstat(userns).context("stat userns fd")?;
    ensure!(
        via_pid.ino() == via_fd.st_ino && via_pid.dev() == via_fd.st_dev,
        "userns fd does not belong to the pidfd's process"
    );
    let maps = fs::read_to_string(format!("/proc/{pid}/uid_map"))?;
    ensure!(
        maps.trim().is_empty(),
        "user namespace already has uid maps"
    );
    Ok(())
}

/// Map in-ns 0..count onto the pool block at `base` (uid and gid).
pub fn write_maps(pid: Pid, base: u32, count: u32) -> Result<()> {
    let map = format!("0 {base} {count}\n");
    fs::write(format!("/proc/{pid}/uid_map"), &map).context("writing uid_map")?;
    fs::write(format!("/proc/{pid}/gid_map"), &map).context("writing gid_map")?;
    Ok(())
}

/// Create the build cgroup inside the worker's delegated subtree
/// (derived from the requesting process). Owned by the pool base uid so
/// the in-ns-root payload can manage subgroups; cgroup.procs and
/// cgroup.kill are group-writable for the worker.
pub fn create_cgroup(peer_pid: Pid, build_id: &str, base: u32, worker_gid: u32) -> Result<PathBuf> {
    ensure!(
        !build_id.is_empty()
            && build_id.len() <= 64
            && build_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "invalid build id"
    );
    let cgroup = fs::read_to_string(format!("/proc/{peer_pid}/cgroup"))?;
    let rel = cgroup
        .trim()
        .strip_prefix("0::/")
        .context("requester not on cgroup v2")?;
    let dir = Path::new("/sys/fs/cgroup")
        .join(rel)
        .join(format!("build-{build_id}"));
    fs::create_dir(&dir).with_context(|| format!("creating cgroup {}", dir.display()))?;
    let uid = Some(Uid::from_raw(base));
    let gid = Some(Gid::from_raw(worker_gid));
    chown(&dir, uid, gid)?;
    for f in [
        "cgroup.procs",
        "cgroup.subtree_control",
        "cgroup.threads",
        "cgroup.kill",
    ] {
        let _ = chown(&dir.join(f), uid, gid);
    }
    for f in ["cgroup.procs", "cgroup.kill"] {
        fs::set_permissions(dir.join(f), fs::Permissions::from_mode(0o664))?;
    }
    Ok(dir)
}

/// Kill everything in the build cgroup, wait for it to drain, remove it.
/// Must complete before the uid block is reused.
pub fn destroy_cgroup(dir: &Path) -> Result<()> {
    fs::write(dir.join("cgroup.kill"), "1").context("writing cgroup.kill")?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_mins(1);
    while fs::read_to_string(dir.join("cgroup.events"))
        .is_ok_and(|events| !events.contains("populated 0"))
    {
        ensure!(std::time::Instant::now() < deadline, "cgroup did not drain");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    remove_cgroup_tree(dir)
}

/// Cgroup dirs cannot be unlinked, only rmdir'd bottom-up.
fn remove_cgroup_tree(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            remove_cgroup_tree(&entry.path())?;
        }
    }
    fs::remove_dir(dir).with_context(|| format!("removing cgroup {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsFd, FromRawFd, OwnedFd};

    use super::*;

    #[test]
    fn pidfd_pid_of_self() {
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
        assert!(pidfd >= 0);
        #[expect(clippy::cast_possible_truncation, reason = "fds are small")]
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as i32) };
        assert_eq!(pidfd_pid(pidfd.as_fd()).unwrap(), Pid::this());
    }

    #[test]
    fn verify_userns_rejects_already_mapped_ns() {
        let ns = fs::File::open("/proc/self/ns/user").unwrap();
        let err = verify_userns(Pid::this(), OwnedFd::from(ns).as_fd()).unwrap_err();
        assert!(err.to_string().contains("uid maps"), "{err}");
    }

    #[test]
    fn verify_userns_rejects_mismatched_fd() {
        // a non-userns fd forces the inode mismatch
        let ns = fs::File::open("/proc/self/ns/net").unwrap();
        assert!(verify_userns(Pid::this(), OwnedFd::from(ns).as_fd()).is_err());
    }

    #[test]
    fn create_cgroup_rejects_bad_build_id() {
        let err = create_cgroup(Pid::this(), "../escape", 3_000_000, 0).unwrap_err();
        assert!(err.to_string().contains("invalid build id"), "{err}");
    }
}
