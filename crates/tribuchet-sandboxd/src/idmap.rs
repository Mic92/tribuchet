//! Idmapped mounts of the worker's build directories.
//!
//! The worker packs build outputs as an unprivileged user while the
//! files belong to leased uids. Reading them regardless of their
//! permission bits takes an idmapped mount that presents the leased
//! uids as the worker's. Support is per filesystem (9p and NFS lack
//! it), reported as a distinct error message so the worker can fall
//! back to reading the paths directly.

use std::fs;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

use anyhow::{Context, Result, ensure};
use nix::errno::Errno;
use nix::unistd::User;
use rustix::mount::{OpenTreeFlags, open_tree};
use rustix::process::{PidfdFlags, PidfdGetfdFlags, pidfd_getfd, pidfd_open};

const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;

/// mount_attr from linux/mount.h (not in libc yet).
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// Detached idmapped mount of `dir` presenting the leased uid block
/// (`base`, `count` uids, gids alike) as owned by `worker`. `mntns`
/// is the worker's mount namespace: open_tree only clones mounts of
/// the caller's namespace, and the worker runs under ProtectSystem in
/// its own.
pub fn open(
    dir: BorrowedFd,
    mntns: BorrowedFd,
    worker: &User,
    base: u32,
    count: u32,
) -> Result<OwnedFd> {
    let tree = open_tree_in_ns(mntns, dir)?;
    // An idmapped mount presents a file's on-disk id (matched against
    // the map's first column) as the second column, so the leased
    // block maps onto the worker.
    let uid_map = format!("{base} {} {count}", worker.uid.as_raw());
    let gid_map = format!("{base} {} {count}", worker.gid.as_raw());
    let holder = UsernsHolder::new(&uid_map, &gid_map)?;
    let attr = MountAttr {
        attr_set: MOUNT_ATTR_IDMAP,
        attr_clr: 0,
        propagation: 0,
        userns_fd: u64::try_from(holder.userns.as_raw_fd())?,
    };
    let res = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            tree.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            &raw const attr,
            size_of::<MountAttr>(),
        )
    };
    match Errno::result(res) {
        Ok(_) => Ok(tree),
        // EINVAL: filesystem without FS_ALLOW_IDMAP; ENOSYS: kernel
        // predates mount_setattr. The message is the fallback signal.
        Err(e @ (Errno::EINVAL | Errno::EOPNOTSUPP | Errno::ENOSYS)) => Err(anyhow::anyhow!(
            "filesystem does not support idmapped mounts: {e}"
        )),
        Err(e) => Err(anyhow::Error::from(e).context("mount_setattr(MOUNT_ATTR_IDMAP)")),
    }
}

/// OPEN_TREE_CLONE of `dir`, done from inside the mount namespace
/// `mntns` because the kernel refuses to clone mounts of a foreign
/// namespace. Runs in a forked child (setns needs an unshared
/// fs_struct, ruled out for threads); the resulting fd comes back via
/// pidfd_getfd, keeping the child to async-signal-safe calls.
fn open_tree_in_ns(mntns: BorrowedFd, dir: BorrowedFd) -> Result<OwnedFd> {
    use nix::unistd::{self, ForkResult};
    // The child parks the mount fd here for pidfd_getfd.
    const RESULT_FD: libc::c_int = 444;
    let (sync_r, sync_w) = unistd::pipe()?;
    match unsafe { unistd::fork() }? {
        ForkResult::Child => {
            let flags = OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::AT_EMPTY_PATH;
            let ok = nix::sched::setns(mntns, nix::sched::CloneFlags::CLONE_NEWNS).is_ok()
                && open_tree(dir, "", flags).is_ok_and(|tree| {
                    // Park the mount at RESULT_FD until the parent has
                    // fetched it; the fd must not drop and close.
                    unsafe { unistd::dup2_raw(&tree, RESULT_FD) }
                        .map(std::os::fd::IntoRawFd::into_raw_fd)
                        .is_ok()
                });
            if !ok {
                unsafe { libc::_exit(1) }
            }
            let _ = unistd::write(&sync_w, b"m");
            loop {
                unistd::pause();
            }
        }
        ForkResult::Parent { child } => {
            drop(sync_w);
            let tree = (|| {
                ensure!(
                    unistd::read(&sync_r, &mut [0u8; 1]) == Ok(1),
                    "open_tree in the worker mount namespace failed"
                );
                let pid =
                    rustix::process::Pid::from_raw(child.as_raw()).context("invalid child pid")?;
                let pidfd = pidfd_open(pid, PidfdFlags::empty())?;
                let tree = pidfd_getfd(&pidfd, RESULT_FD, PidfdGetfdFlags::empty())
                    .context("pidfd_getfd of the cloned mount")?;
                Ok(tree)
            })();
            let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(child, None);
            tree
        }
    }
}

/// A forked child holding a user namespace with the requested maps
/// (MOUNT_ATTR_IDMAP takes its mapping from a user namespace). Forked
/// because unshare(CLONE_NEWUSER) is refused in a multithreaded
/// process. The mount keeps the mapping alive, so the namespace only
/// has to outlive mount_setattr.
struct UsernsHolder {
    child: nix::unistd::Pid,
    userns: OwnedFd,
}

impl UsernsHolder {
    fn new(uid_map: &str, gid_map: &str) -> Result<Self> {
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
                let holder = (|| {
                    ensure!(
                        unistd::read(&sync_r, &mut [0u8; 1]) == Ok(1),
                        "idmap child failed to unshare a user namespace"
                    );
                    fs::write(format!("/proc/{child}/uid_map"), uid_map)
                        .context("writing uid_map")?;
                    fs::write(format!("/proc/{child}/gid_map"), gid_map)
                        .context("writing gid_map")?;
                    let userns = fs::File::open(format!("/proc/{child}/ns/user"))
                        .map(OwnedFd::from)
                        .context("opening the idmap user namespace")?;
                    Ok(Self { child, userns })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::fs::MetadataExt;

    /// Creating an idmapped mount needs CAP_SYS_ADMIN in the initial
    /// user namespace, so this only runs as root.
    #[test]
    fn open_presents_the_block_as_the_worker() {
        if !nix::unistd::geteuid().is_root() {
            eprintln!("skipping: not root");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("out"), b"x").unwrap();
        std::os::unix::fs::chown(dir.path().join("out"), Some(1_000_000), Some(1_000_000)).unwrap();
        let worker = User::from_uid(nix::unistd::Uid::from_raw(0))
            .unwrap()
            .unwrap();
        let dirfd = fs::File::open(dir.path()).unwrap();
        let mntns = fs::File::open("/proc/self/ns/mnt").unwrap();
        let mount = open(dirfd.as_fd(), mntns.as_fd(), &worker, 1_000_000, 1).unwrap();
        let meta = fs::metadata(format!("/proc/self/fd/{}/out", mount.as_raw_fd())).unwrap();
        assert_eq!(meta.uid(), worker.uid.as_raw());
    }
}
