//! One sandbox lease: userns maps and the delegated build cgroup.

use std::fs;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{FchmodatFlags, Mode, fchmodat, fstatat, mkdirat};
use nix::unistd::{Gid, Pid, Uid, UnlinkatFlags, fchown, fchownat, unlinkat};

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

/// The build's cgroup, held via directory fds so later operations do
/// not depend on re-resolving worker-influenced paths.
#[derive(Debug)]
pub struct BuildCgroup {
    parent: OwnedFd,
    name: String,
    pub dir: OwnedFd,
}

/// Create the build cgroup under the worker's own cgroup. Owned by the
/// pool base uid so the in-ns-root payload can manage subgroups;
/// memory.max is group-writable so the worker can set the limit.
pub fn create_cgroup(
    peer_pid: Pid,
    build_id: &str,
    base: u32,
    worker_gid: u32,
) -> Result<BuildCgroup> {
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
    let parent_path = Path::new("/sys/fs/cgroup").join(rel);
    let parent = nix::fcntl::open(&parent_path, DIR_FLAGS, Mode::empty())
        .with_context(|| format!("opening cgroup {}", parent_path.display()))?;
    let name = format!("build-{build_id}");
    mkdirat(&parent, name.as_str(), Mode::from_bits_truncate(0o755))
        .with_context(|| format!("creating cgroup {}/{name}", parent_path.display()))?;
    let dir = openat(&parent, name.as_str(), DIR_FLAGS, Mode::empty())
        .context("opening the build cgroup")?;
    let uid = Some(Uid::from_raw(base));
    let gid = Some(Gid::from_raw(worker_gid));
    fchown(&dir, uid, gid)?;
    for f in ["cgroup.subtree_control", "cgroup.threads"] {
        let _ = fchownat(&dir, f, uid, gid, AtFlags::AT_SYMLINK_NOFOLLOW);
    }
    // memory.max only exists when the parent enables the controller
    for f in ["cgroup.procs", "cgroup.kill", "memory.max"] {
        if fstatat(&dir, f, AtFlags::AT_SYMLINK_NOFOLLOW).is_err() {
            continue;
        }
        fchownat(&dir, f, uid, gid, AtFlags::AT_SYMLINK_NOFOLLOW)?;
        fchmodat(
            &dir,
            f,
            Mode::from_bits_truncate(0o664),
            FchmodatFlags::NoFollowSymlink,
        )?;
    }
    Ok(BuildCgroup { parent, name, dir })
}

/// Move the process behind `pidfd` into the build cgroup. Done as root
/// because cgroup v2 migration needs write on the common ancestor's
/// `cgroup.procs`, which the worker lacks outside a `Delegate=yes`
/// unit. Refuses a process not owned by the worker: pidfd_open has no
/// credential check, so otherwise the worker could have sandboxd move
/// (and later `cgroup.kill`) any process.
pub fn enter_cgroup(cg: &BuildCgroup, pidfd: BorrowedFd, worker_uid: Uid) -> Result<()> {
    let pid = pidfd_pid(pidfd)?;
    let uid = fs::metadata(format!("/proc/{pid}"))?.uid();
    ensure!(
        uid == worker_uid.as_raw(),
        "setup stage {pid} is uid {uid}, not the worker"
    );
    // The pidfd staying live across the uid read rules out pid reuse.
    ensure!(pidfd_pid(pidfd)? == pid, "setup stage exited");
    write_at(&cg.dir, "cgroup.procs", &pid.to_string())
        .with_context(|| format!("moving pid {pid} into cgroup {}", cg.name))
}

/// Block until the lease is over: the build cgroup was populated and
/// drained again, or the worker closed the connection without ever
/// spawning into it.
pub fn wait_for_build_end(conn: &std::os::unix::net::UnixStream, cg: &BuildCgroup) -> Result<()> {
    conn.set_nonblocking(true)?;
    let mut reader = conn;
    let mut was_populated = false;
    loop {
        // systemd removes the cgroup when it stops the worker unit;
        // gone means drained
        let events = match read_at(&cg.dir, "cgroup.events") {
            Err(e) if is_enoent(&e) => return Ok(()),
            other => other?,
        };
        let populated = !events.contains("populated 0");
        was_populated |= populated;
        if was_populated && !populated {
            return Ok(());
        }
        match std::io::Read::read(&mut reader, &mut [0u8; 8]) {
            // eof: the worker dropped the lease
            Ok(0) if !was_populated => return Ok(()),
            Ok(0) => {}
            Ok(_) => anyhow::bail!("unexpected data on the lease connection"),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e).context("lease connection"),
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn is_enoent(e: &anyhow::Error) -> bool {
    e.downcast_ref::<nix::errno::Errno>() == Some(&nix::errno::Errno::ENOENT)
        || e.downcast_ref::<std::io::Error>()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

/// Kill everything in the build cgroup, wait for it to drain, remove it.
/// Must complete before the uid block is reused. A cgroup systemd
/// already removed (worker unit stopped) counts as destroyed.
pub fn destroy_cgroup(cg: &BuildCgroup) -> Result<()> {
    match write_at(&cg.dir, "cgroup.kill", "1") {
        Err(e) if is_enoent(&e) => {
            let _ = unlinkat(&cg.parent, cg.name.as_str(), UnlinkatFlags::RemoveDir);
            return Ok(());
        }
        other => other.context("writing cgroup.kill")?,
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_mins(1);
    while !read_at(&cg.dir, "cgroup.events").is_ok_and(|events| events.contains("populated 0")) {
        ensure!(std::time::Instant::now() < deadline, "cgroup did not drain");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    remove_cgroup_tree(&cg.dir).context("removing build subgroups")?;
    unlinkat(&cg.parent, cg.name.as_str(), UnlinkatFlags::RemoveDir)
        .with_context(|| format!("removing cgroup {}", cg.name))
}

const DIR_FLAGS: OFlag = OFlag::O_DIRECTORY
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_RDONLY)
    .union(OFlag::O_CLOEXEC);

fn write_at(dir: &OwnedFd, name: &str, data: &str) -> Result<()> {
    let fd = openat(dir, name, OFlag::O_WRONLY | OFlag::O_CLOEXEC, Mode::empty())?;
    nix::unistd::write(&fd, data.as_bytes())?;
    Ok(())
}

fn read_at(dir: &OwnedFd, name: &str) -> Result<String> {
    let fd = openat(dir, name, OFlag::O_RDONLY | OFlag::O_CLOEXEC, Mode::empty())?;
    let mut out = String::new();
    std::io::Read::read_to_string(&mut fs::File::from(fd), &mut out)?;
    Ok(out)
}

/// Cgroup dirs cannot be unlinked, only rmdir'd bottom-up.
fn remove_cgroup_tree(dir: &OwnedFd) -> Result<()> {
    let mut entries = Vec::new();
    let mut d = nix::dir::Dir::from_fd(dir.try_clone()?)?;
    for entry in d.iter() {
        let entry = entry?;
        if entry.file_type() == Some(nix::dir::Type::Directory) {
            let name = entry.file_name().to_owned();
            if name.to_bytes() != b"." && name.to_bytes() != b".." {
                entries.push(name);
            }
        }
    }
    for name in entries {
        let sub = openat(dir, name.as_c_str(), DIR_FLAGS, Mode::empty())?;
        remove_cgroup_tree(&sub)?;
        unlinkat(dir, name.as_c_str(), UnlinkatFlags::RemoveDir)?;
    }
    Ok(())
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

    /// Fake build cgroup: a plain dir with a writable cgroup.events.
    fn fake_cgroup(dir: &Path) -> BuildCgroup {
        fs::write(dir.join("cgroup.events"), "populated 0\n").unwrap();
        let parent = nix::fcntl::open(dir, DIR_FLAGS, Mode::empty()).unwrap();
        let dir = nix::fcntl::open(dir, DIR_FLAGS, Mode::empty()).unwrap();
        BuildCgroup {
            parent,
            name: "fake".into(),
            dir,
        }
    }

    #[test]
    fn lease_ends_when_the_worker_never_spawned() {
        let dir = tempfile::tempdir().unwrap();
        let cg = fake_cgroup(dir.path());
        let (ours, worker) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(worker);
        wait_for_build_end(&ours, &cg).unwrap();
    }

    #[test]
    fn lease_outlives_the_connection_until_the_cgroup_drains() {
        let dir = tempfile::tempdir().unwrap();
        let cg = fake_cgroup(dir.path());
        let events = dir.path().join("cgroup.events");
        fs::write(&events, "populated 1\n").unwrap();
        let (ours, worker) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(worker);
        let drainer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(500));
            fs::write(&events, "populated 0\n").unwrap();
        });
        let started = std::time::Instant::now();
        wait_for_build_end(&ours, &cg).unwrap();
        assert!(started.elapsed() >= std::time::Duration::from_millis(400));
        drainer.join().unwrap();
    }

    #[test]
    fn read_write_at() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("f"), "").unwrap();
        let fd = nix::fcntl::open(dir.path(), DIR_FLAGS, Mode::empty()).unwrap();
        write_at(&fd, "f", "populated 0\n").unwrap();
        assert_eq!(read_at(&fd, "f").unwrap(), "populated 0\n");
    }
}
