//! Linux sandbox implementation: namespaces, bind mounts, pivot_root.

use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(test)]
use std::process::{Child, Stdio};

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::fcntl::{self, AtFlags, OFlag};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, unshare};
use nix::sys::personality::{self, Persona};
use nix::sys::resource::{Resource, getrlimit, setrlimit};
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, recv,
    recvmsg, sendmsg, socketpair,
};
use nix::sys::{prctl, stat, wait};
use nix::unistd::{self, getgid, getuid, pivot_root, sethostname};

use super::{SandboxSpec, binfmt};
use crate::netpolicy::NetPolicy;
use crate::proto::BuildAssignment;

// Interface name for the presto-pasta tap inside the build netns.
// Addressing (link-local guest/gateway, DNS forwarded on the gateway
// address so a loopback host resolver like systemd-resolved's stub
// stays reachable) comes from presto_pasta::Config::default().
const NET_IFNAME: &str = "eth0";

// linux/if_tun.h
const IFF_TAP: i16 = 0x0002;
const IFF_NO_PI: i16 = 0x1000;
const IFF_VNET_HDR: i16 = 0x4000;

nix::ioctl_write_ptr_bad!(
    tun_set_iff,
    nix::request_code_write!(b'T', 202, std::mem::size_of::<libc::c_int>()),
    libc::ifreq
);

pub fn prepare(spec: &mut SandboxSpec) -> Result<()> {
    let root = &spec.root;
    write_skeleton(spec)?;
    populate_dev(root, &mut spec.binds_dev)?;
    if spec.network {
        // Host CA bundle at the standard path for TLS fetches, like
        // Nix's fixed-output setup.
        let ca = Path::new("/etc/ssl/certs/ca-certificates.crt");
        if let Ok(real) = ca.canonicalize() {
            spec.binds_ro.push((real, ca.to_path_buf()));
        }
    }
    if let Some(uid) = spec.fod_uid {
        // The dropped-uid process performs every mount itself, so it
        // must own the whole per-build dir; 0700 keeps other FOD
        // uids out.
        if let Some(build_root) = root.parent() {
            chown_recursive(build_root, uid)?;
            fs::set_permissions(
                build_root,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )?;
        }
    }
    if let Some(base) = spec.uid_range {
        // The builder is root inside the namespace but uid `base`
        // on the host; writable trees must be owned by the range
        // (Nix's chownToBuilder). The sandbox root itself too:
        // container payloads mkdir top-level dirs like /run.
        std::os::unix::fs::lchown(root, Some(base), Some(base))?;
        for dir in [
            root.join("nix/store"),
            root.join("etc"),
            root.join("tmp"),
            spec.build_dir
                .parent()
                .unwrap_or(&spec.build_dir)
                .to_path_buf(),
        ] {
            chown_recursive(&dir, base)?;
        }
    } else if spec.leased_userns.is_some() {
        // A rootless worker cannot chown to the leased range: the
        // sandbox root is recreated on an in-namespace tmpfs instead
        // (mount_filesystems); the on-disk trees the build still
        // writes are opened up. The 0700 per-build parent (see
        // BuildOwner) keeps other local users out.
        use std::os::unix::fs::PermissionsExt;
        for dir in [
            root.join("nix/store"),
            spec.build_dir.clone(),
            spec.build_dir
                .parent()
                .unwrap_or(&spec.build_dir)
                .to_path_buf(),
        ] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o1777))?;
        }
    }
    Ok(())
}

/// Sandbox root skeleton: directories, /etc files, /dev symlinks. Runs
/// on the on-disk root in the worker and again on a leased build's
/// in-namespace tmpfs root.
fn write_skeleton(spec: &SandboxSpec) -> Result<()> {
    let root = &spec.root;
    for sub in [
        "nix/store",
        "build",
        "dev",
        "dev/shm",
        "dev/pts",
        "proc",
        "sys/fs/cgroup",
        "etc",
        "tmp",
    ] {
        fs::create_dir_all(root.join(sub))?;
    }
    fs::write(
        root.join("etc/passwd"),
        "root:x:0:0:Nix build user:/build:/noshell\n\
         nixbld:x:1000:100:Nix build user:/build:/noshell\n\
         nobody:x:65534:65534:Nobody:/:/noshell\n",
    )?;
    fs::write(
        root.join("etc/group"),
        "root:x:0:\nnixbld:x:100:\nnogroup:x:65534:\n",
    )?;
    fs::write(
        root.join("etc/hosts"),
        "127.0.0.1 localhost\n::1 localhost\n",
    )?;
    for (link, target) in [
        ("dev/fd", "/proc/self/fd"),
        ("dev/stdin", "/proc/self/fd/0"),
        ("dev/stdout", "/proc/self/fd/1"),
        ("dev/stderr", "/proc/self/fd/2"),
        ("dev/ptmx", "/dev/pts/ptmx"),
    ] {
        std::os::unix::fs::symlink(target, root.join(link))?;
    }
    if spec.network {
        // Like Nix's fixed-output setup: name resolution via files
        // and DNS only, host resolver/services/hosts copied in.
        fs::write(
            root.join("etc/nsswitch.conf"),
            "hosts: files dns\nservices: files\n",
        )?;
        for f in ["services", "hosts"] {
            if let Ok(data) = fs::read(Path::new("/etc").join(f)) {
                fs::write(root.join("etc").join(f), data)?;
            }
        }
        if spec.net_isolation {
            // presto-pasta answers DNS on the gateway addresses; point
            // the sandbox at them, not the host resolv.conf whose
            // nameserver may be an unreachable loopback stub.
            let net = presto_pasta::Config::default();
            let conf = format!("nameserver {}\nnameserver {}\n", net.gateway4, net.gateway6);
            fs::write(root.join("etc/resolv.conf"), conf)?;
        } else if let Ok(data) = fs::read("/etc/resolv.conf") {
            fs::write(root.join("etc/resolv.conf"), data)?;
        }
    }
    Ok(())
}

/// Mount points for the cwd, bind targets and symlinked store inputs
/// inside the sandbox root. Like `write_skeleton`, runs in the worker
/// and again on a leased build's tmpfs root.
fn create_mount_points(spec: &SandboxSpec) -> Result<()> {
    // The shipped tmp dir is mounted at the request's sandbox build
    // dir; pre-create the mount point inside the private root.
    fs::create_dir_all(
        spec.root.join(
            Path::new(&spec.cwd)
                .strip_prefix("/")
                .unwrap_or(Path::new(&spec.cwd)),
        ),
    )?;
    // Pre-create bind targets matching the source type.
    for (src, dst) in spec.binds_ro.iter().chain(&spec.binds_dev) {
        let target = spec.root.join(dst.strip_prefix("/").unwrap_or(dst));
        if target.exists() || target.symlink_metadata().is_ok() {
            continue;
        }
        if src.is_dir() {
            fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::File::create(&target)?;
        }
    }

    // Symlink store objects cannot be bind-mounted (the mount would
    // resolve them); recreate them inside the private root instead.
    for (dst, target) in &spec.symlink_inputs {
        let link = spec.root.join(dst.strip_prefix("/").unwrap_or(dst));
        if link.symlink_metadata().is_ok() {
            continue;
        }
        if let Some(parent) = link.parent() {
            fs::create_dir_all(parent)?;
        }
        std::os::unix::fs::symlink(target, &link)
            .with_context(|| format!("creating symlink input {}", link.display()))?;
    }
    Ok(())
}

/// A build whose sandbox uid 0 maps to host root (emulated builds on a
/// root worker) could chmod/chown a bind-mounted host device node, so a
/// worker with CAP_MKNOD creates its own nodes instead. Without the
/// capability (rootless worker) it binds the host nodes; there the
/// sandbox never maps to a uid owning them.
fn populate_dev(root: &Path, binds_dev: &mut Vec<(PathBuf, PathBuf)>) -> Result<()> {
    let mut devices = vec!["null", "zero", "full", "random", "urandom", "tty"];
    // Nix's `kvm` system feature (VM builds, NixOS tests).
    if Path::new("/dev/kvm").exists() {
        devices.push("kvm");
    }
    let mut can_mknod = true;
    for dev in devices {
        let host = PathBuf::from("/dev").join(dev);
        let target = root.join("dev").join(dev);
        if can_mknod {
            let rdev = stat::stat(&host)
                .with_context(|| format!("stat {}", host.display()))?
                .st_rdev;
            match stat::mknod(
                &target,
                stat::SFlag::S_IFCHR,
                stat::Mode::from_bits_truncate(0o666),
                rdev,
            ) {
                Ok(()) => {
                    // umask clips mknod's mode; sandbox uids need 0666.
                    fs::set_permissions(
                        &target,
                        std::os::unix::fs::PermissionsExt::from_mode(0o666),
                    )
                    .with_context(|| format!("chmod {}", target.display()))?;
                    continue;
                }
                // Bind-mounting host nodes is only safe when the sandbox
                // cannot map to a host uid owning them; a root worker
                // stripped of CAP_MKNOD must not fall back silently.
                Err(Errno::EPERM) if !unistd::geteuid().is_root() => can_mknod = false,
                Err(Errno::EPERM) => {
                    anyhow::bail!("worker runs as root but lacks CAP_MKNOD to create device nodes")
                }
                Err(e) => {
                    return Err(e).with_context(|| format!("mknod {}", target.display()));
                }
            }
        }
        fs::File::create(&target)?;
        binds_dev.push((host.clone(), host));
    }
    Ok(())
}

fn chown_recursive(path: &Path, uid: u32) -> Result<()> {
    use std::os::unix::fs::lchown;
    lchown(path, Some(uid), Some(uid)).with_context(|| format!("chowning {}", path.display()))?;
    if path.is_dir() && !path.is_symlink() {
        for entry in fs::read_dir(path)? {
            chown_recursive(&entry?.path(), uid)?;
        }
    }
    Ok(())
}

pub fn command(spec: &SandboxSpec) -> Result<Command> {
    create_mount_points(spec)?;

    if spec.emulator.is_some() && binfmt::register_line(&spec.system).is_none() {
        anyhow::bail!("no binfmt magic known for system {}", spec.system);
    }

    // see setup_stage() for why builds re-exec this binary. Resolve it
    // in the worker: the reaper execs this argv, and it outlives worker
    // reloads, so it must not resolve the binary in its own context.
    let exe = std::env::current_exe().context("resolving worker binary path")?;
    let mut cmd = Command::new(exe);
    cmd.arg(SETUP_STAGE_ARG);
    Ok(cmd)
}

// Underscore form so that, in unit tests, libtest interprets it as
// a filter selecting the dispatch test below.
pub const SETUP_STAGE_ARG: &str = "__sandbox_setup";

/// The spec travels via the setup stage's stdin.
pub const SPEC_VIA_STDIN: bool = true;

#[cfg(test)]
pub fn stdin_mode() -> Stdio {
    Stdio::piped() // carries the serialized spec
}

#[cfg(test)]
pub fn send_spec(child: &mut Child, spec: &SandboxSpec) -> Result<()> {
    let stdin = child.stdin.take().context("setup stage stdin missing")?;
    serde_json::to_writer(stdin, spec).context("sending sandbox spec")?;
    Ok(())
}

pub fn setup_stage() -> ! {
    use std::io::{Read, Write};
    let err = (|| -> io::Result<std::convert::Infallible> {
        let mut json = String::new();
        std::io::stdin().read_to_string(&mut json)?;
        let spec: SandboxSpec = serde_json::from_str(&json).map_err(io::Error::other)?;
        // The builder gets /dev/null as stdin, like under Nix.
        let null = fs::File::open("/dev/null")?;
        unistd::dup2_stdin(&null).map_err(ioerr("dup2 stdin"))?;
        // Pre-open the error file: the fd keeps working after
        // pivot_root detaches the host filesystem, a path would not.
        let err_file = fs::File::create(setup_error_file(&spec.root))?;
        enter_and_exec(&spec).inspect_err(|e| {
            let _ = (&err_file).write_all(e.to_string().as_bytes());
        })
    })()
    .unwrap_err();
    // stderr is the build log pipe; the client sees the message.
    // Write to the fd, not via eprintln!: under the unit test the
    // stage runs inside libtest, which captures macro output.
    let _ = writeln!(std::io::stderr(), "sandbox setup: {err}");
    std::process::exit(121);
}

#[expect(clippy::similar_names, reason = "uid/gid pairs are conventional")]
fn enter_and_exec(spec: &SandboxSpec) -> io::Result<std::convert::Infallible> {
    // Enter the build cgroup first, with the worker's full
    // credentials and before any namespace changes.
    if let Some(cg) = &spec.cgroup {
        // A leased cgroup is owned by the sandbox's namespace root;
        // its cgroup.procs is group-writable for the worker.
        fs::write(cg.join("cgroup.procs"), "0")
            .map_err(|e| io::Error::other(format!("entering build cgroup: {e}")))?;
    }
    let binfmt_line = match &spec.emulator {
        Some(_) => Some(binfmt::register_line(&spec.system).ok_or_else(|| {
            io::Error::other(format!("no binfmt magic known for system {}", spec.system))
        })?),
        None => None,
    };
    // Single uid 1000 (Nix default) or, for uid-range builds,
    // in-namespace root over a 65536-uid block. Emulated builds map
    // uid 0 for the binfmt registration, dropped to 1000 in setup().
    // Leased namespaces already carry their maps (in-ns 0..count);
    // host uids are unused and setup becomes in-ns root after joining.
    let backing_uid = spec.fod_uid.unwrap_or_else(|| getuid().as_raw());
    let backing_gid = spec.fod_uid.unwrap_or_else(|| getgid().as_raw());
    let (sandbox_uid, host_uid, uid_count) = match (spec.leased_uid_count, spec.uid_range) {
        (Some(count), _) => (0, 0, count),
        (None, Some(base)) => (0, base, 65536u32),
        (None, None) if binfmt_line.is_some() => (0, backing_uid, 1),
        (None, None) => (1000, backing_uid, 1),
    };
    let (sandbox_gid, host_gid) = match (spec.leased_uid_count, spec.uid_range) {
        (Some(_), _) => (0, 0),
        (None, Some(base)) => (0, base),
        (None, None) if binfmt_line.is_some() => (0, backing_gid),
        (None, None) => (100, backing_gid),
    };
    setup(&SetupParams {
        spec,
        root: &spec.root,
        system: &spec.system,
        binfmt_line: binfmt_line.as_deref(),
        net_isolation: spec.net_isolation,
        net_policy: &spec.net_policy,
        fod_uid: spec.fod_uid,
        leased_userns: spec.leased_userns.as_deref(),
        build_dir: &spec.build_dir,
        binds: &spec.binds_ro,
        binds_dev: &spec.binds_dev,
        cwd: &spec.cwd,
        network: spec.network,
        has_cgroup: spec.cgroup.is_some(),
        sandbox_uid,
        host_uid,
        sandbox_gid,
        host_gid,
        uid_count,
    })?;
    let prog =
        CString::new(spec.builder.as_str()).map_err(|_| io::Error::other("NUL in builder path"))?;
    let args: Vec<CString> = std::iter::once(Ok(prog.clone()))
        .chain(spec.args.iter().map(|a| CString::new(a.as_str())))
        .collect::<Result<_, _>>()
        .map_err(|_| io::Error::other("NUL in builder argument"))?;
    // The setup stage runs with a clean environment; the derivation
    // env is applied only here, to the builder inside the sandbox.
    let env: Vec<CString> = spec
        .env
        .iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")))
        .collect::<Result<_, _>>()
        .map_err(|_| io::Error::other("NUL in builder environment"))?;
    unistd::execve(&prog, &args, &env).map_err(ioerr("exec builder"))
}

fn existing_mount_flags(target: &Path) -> io::Result<MsFlags> {
    use nix::sys::statvfs::{FsFlags, statvfs};
    // statvfs on the bound target fails for some source mounts (ENXIO on a
    // unix socket, ENOENT on an envfs/FUSE mount like NixOS's /bin); the
    // parent describes the same mount, so fall back to it.
    let st = match statvfs(target) {
        Ok(st) => st,
        Err(Errno::ENXIO | Errno::ENOENT) => {
            let parent = target.parent().unwrap_or(target);
            statvfs(parent).map_err(ioerr("statvfs"))?
        }
        Err(e) => return Err(ioerr("statvfs")(e)),
    };
    let f = st.flags();
    let mut flags = MsFlags::empty();
    for (fs, ms) in [
        (FsFlags::ST_NOSUID, MsFlags::MS_NOSUID),
        (FsFlags::ST_NODEV, MsFlags::MS_NODEV),
        (FsFlags::ST_NOEXEC, MsFlags::MS_NOEXEC),
        (FsFlags::ST_NOATIME, MsFlags::MS_NOATIME),
        (FsFlags::ST_NODIRATIME, MsFlags::MS_NODIRATIME),
        (FsFlags::ST_RELATIME, MsFlags::MS_RELATIME),
    ] {
        if f.contains(fs) {
            flags |= ms;
        }
    }
    Ok(flags)
}

fn ioerr(step: &str) -> impl Fn(Errno) -> io::Error + '_ {
    move |e| io::Error::other(format!("{step}: {e}"))
}

fn werr(step: &'static str) -> impl Fn(io::Error) -> io::Error {
    move |e| io::Error::other(format!("{step}: {e}"))
}

/// Unshare and have a forked helper, still in the parent user
/// namespace, write this process's uid/gid maps: multi-uid ranges
/// need CAP_SETUID *there*, which the unshared process no longer
/// has (hence uid-range requires a root worker).
#[expect(clippy::similar_names, reason = "uid/gid pairs are conventional")]
fn map_uid_range_via_helper(
    flags: CloneFlags,
    sandbox_uid: u32,
    host_uid: u32,
    sandbox_gid: u32,
    host_gid: u32,
    uid_count: u32,
) -> io::Result<()> {
    use nix::unistd::{read, write};
    let target = unistd::getpid();
    let (req_r, req_w) = unistd::pipe().map_err(ioerr("pipe"))?;
    let (ack_r, ack_w) = unistd::pipe().map_err(ioerr("pipe"))?;
    match unsafe { unistd::fork() }.map_err(ioerr("fork mapper"))? {
        unistd::ForkResult::Child => {
            // Mapper: wait until the target has unshared, then map.
            let mut buf = [0u8; 1];
            let ok = read(&req_r, &mut buf).is_ok_and(|n| n == 1)
                && fs::write(
                    format!("/proc/{target}/uid_map"),
                    format!("{sandbox_uid} {host_uid} {uid_count}"),
                )
                .is_ok()
                && fs::write(
                    format!("/proc/{target}/gid_map"),
                    format!("{sandbox_gid} {host_gid} {uid_count}"),
                )
                .is_ok();
            let _ = write(&ack_w, if ok { b"K" } else { b"E" });
            unsafe { libc::_exit(0) }
        }
        unistd::ForkResult::Parent { child } => {
            drop(req_r);
            drop(ack_w);
            unshare(flags).map_err(ioerr("unshare"))?;
            write(&req_w, b"x").map_err(ioerr("signaling uid mapper"))?;
            let mut buf = [0u8; 1];
            let n = read(&ack_r, &mut buf).map_err(ioerr("reading uid mapper ack"))?;
            let _ = wait::waitpid(child, None);
            if n != 1 || buf[0] != b'K' {
                return Err(io::Error::other(
                    "uid-range mapping failed (is the worker root?)",
                ));
            }
            Ok(())
        }
    }
}

struct NetHelper {
    sock: OwnedFd,
}

/// Fork a helper that stays in the host namespaces and runs the
/// presto-pasta datapath on the tap fd the sandbox side sends over
/// once its netns exists (see [`NetHelper::attach`]). FOD builds drop
/// the helper to the unprivileged backing uid before any traffic is
/// processed. The helper exits when the build process (its parent)
/// dies, watched via a pidfd.
fn fork_net_helper(policy: NetPolicy, runas: Option<(u32, u32)>) -> io::Result<NetHelper> {
    let target = unistd::getpid();
    let (ours, theirs) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(ioerr("socketpair"))?;
    match unsafe { unistd::fork() }.map_err(ioerr("fork net helper"))? {
        unistd::ForkResult::Child => {
            drop(ours);
            let code = net_helper(&theirs, target, policy, runas);
            unsafe { libc::_exit(code) }
        }
        unistd::ForkResult::Parent { .. } => {
            drop(theirs);
            Ok(NetHelper { sock: ours })
        }
    }
}

/// Helper body: receive the tap fd, drop privileges, start the
/// datapath, acknowledge readiness, then wait for the build process
/// to die.
fn net_helper(
    sock: &OwnedFd,
    build_pid: unistd::Pid,
    policy: NetPolicy,
    runas: Option<(u32, u32)>,
) -> i32 {
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, build_pid.as_raw(), 0) };
    if pidfd < 0 {
        return 1;
    }
    let mut cmsg = nix::cmsg_space!([RawFd; 1]);
    let mut buf = [0u8; 8];
    let mut iov = [io::IoSliceMut::new(&mut buf)];
    let Ok(msg) = recvmsg::<()>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg),
        MsgFlags::empty(),
    ) else {
        return 1;
    };
    let Ok(mut cmsgs) = msg.cmsgs() else { return 1 };
    let Some(ControlMessageOwned::ScmRights(fds)) = cmsgs.next() else {
        // build process died before creating the tap; nothing to do
        return 1;
    };
    let tap = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    if let Some((uid, gid)) = runas {
        let dropped = unistd::setgroups(&[]).is_ok()
            && unistd::setgid(unistd::Gid::from_raw(gid)).is_ok()
            && unistd::setuid(unistd::Uid::from_raw(uid)).is_ok();
        if !dropped {
            return 1;
        }
    }
    let net = presto_pasta::Config {
        allow_flow: Some(std::sync::Arc::new(move |d: &presto_pasta::FlowDst| {
            policy.allows(d.proto, d.ip, d.port)
        })),
        ..presto_pasta::Config::default()
    };
    let presto = presto_pasta::Presto::new(net, tap);
    // Readiness ack: the sandbox side waits for this before building.
    if nix::sys::socket::send(sock.as_raw_fd(), b"ok", MsgFlags::empty()).is_err() {
        return 1;
    }
    std::thread::spawn(move || {
        if let Err(e) = presto.run() {
            tracing::warn!("presto-pasta datapath exited: {e}");
        }
    });
    // Exit (and release the tap, letting the netns go away) once the
    // build process is gone.
    let mut pfd = libc::pollfd {
        #[expect(clippy::cast_possible_truncation, reason = "pidfds are small")]
        fd: pidfd as libc::c_int,
        events: libc::POLLIN,
        revents: 0,
    };
    while unsafe { libc::poll(&raw mut pfd, 1, -1) } < 0 {}
    0
}

/// Open the tap device inside the just-created netns.
fn open_tap(name: &str) -> io::Result<OwnedFd> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    unsafe {
        // ifr_name is [c_char; _]; c_char's signedness is target-dependent,
        // so write the bytes via a u8 pointer instead of an `as` cast.
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            ifr.ifr_name.as_mut_ptr().cast::<u8>(),
            name.len().min(ifr.ifr_name.len() - 1),
        );
        ifr.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR;
        tun_set_iff(file.as_raw_fd(), &raw const ifr).map_err(ioerr("TUNSETIFF"))?;
    }
    Ok(OwnedFd::from(file))
}

impl NetHelper {
    /// Called after unshare: create and configure the tap in the new
    /// netns, hand its fd to the helper and wait until the datapath
    /// runs. The local tap fd is closed afterwards; the helper's copy
    /// keeps the interface carrier up.
    fn attach(self) -> io::Result<()> {
        let net = presto_pasta::Config::default();
        let tap = open_tap(NET_IFNAME)?;
        presto_pasta::netdev::configure(NET_IFNAME, &net)?;
        let fds = [tap.as_raw_fd()];
        sendmsg::<()>(
            self.sock.as_raw_fd(),
            &[io::IoSlice::new(b"tap")],
            &[ControlMessage::ScmRights(&fds)],
            MsgFlags::empty(),
            None,
        )
        .map_err(ioerr("sending tap fd"))?;
        let mut ack = [0u8; 2];
        match recv(self.sock.as_raw_fd(), &mut ack, MsgFlags::empty()) {
            Ok(n) if n > 0 => Ok(()),
            _ => Err(io::Error::other(
                "presto-pasta helper failed to start the datapath",
            )),
        }
    }
}

/// Bring the loopback interface up. A fresh network namespace has
/// `lo` down; builders that talk to 127.0.0.1 (test suites) would
/// otherwise fail, unlike under Nix's own sandbox.
fn loopback_up() -> io::Result<()> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        // ifr_name is [c_char; _]; c_char's signedness is target-dependent,
        // so write the bytes via a u8 pointer instead of an `as` cast.
        std::ptr::copy_nonoverlapping(b"lo".as_ptr(), ifr.ifr_name.as_mut_ptr().cast::<u8>(), 2);
        #[expect(clippy::cast_possible_truncation, reason = "IFF_UP|IFF_RUNNING = 0x41")]
        {
            ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        }
        let res = libc::ioctl(fd, libc::SIOCSIFFLAGS, &ifr);
        let err = io::Error::last_os_error();
        libc::close(fd);
        if res < 0 {
            return Err(err);
        }
    }
    Ok(())
}

/// Fork so the exec'd builder is PID 1 of the new PID namespace;
/// this process becomes a shim that forwards the builder's exit
/// status. When PID 1 dies the kernel kills every namespace member,
/// so daemonized/setsid'd builder children cannot outlive the build.
fn fork_into_pid_ns() -> io::Result<bool> {
    match unsafe { unistd::fork() }.map_err(ioerr("fork"))? {
        unistd::ForkResult::Child => Ok(true),
        unistd::ForkResult::Parent { child } => {
            use wait::{WaitStatus, waitpid};
            // Drop every inherited fd: the long-lived shim must not
            // hold the log pipes (or the setup error file) open for
            // the build's whole lifetime.
            unsafe {
                libc::syscall(libc::SYS_close_range, 3, libc::c_uint::MAX, 0);
            }
            let code = loop {
                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, code)) => break code,
                    Ok(WaitStatus::Signaled(_, sig, _)) => break 128 + sig as i32,
                    Ok(_) | Err(Errno::EINTR) => {}
                    Err(_) => break 1,
                }
            };
            unsafe { libc::_exit(code) }
        }
    }
}

struct SetupParams<'a> {
    spec: &'a SandboxSpec,
    root: &'a Path,
    system: &'a str,
    binfmt_line: Option<&'a str>,
    net_isolation: bool,
    net_policy: &'a NetPolicy,
    fod_uid: Option<u32>,
    /// Leased user namespace to join (rootless uid-range).
    leased_userns: Option<&'a Path>,
    build_dir: &'a Path,
    binds: &'a [(PathBuf, PathBuf)],
    binds_dev: &'a [(PathBuf, PathBuf)],
    cwd: &'a str,
    network: bool,
    has_cgroup: bool,
    sandbox_uid: u32,
    host_uid: u32,
    sandbox_gid: u32,
    host_gid: u32,
    uid_count: u32,
}

fn setup(p: &SetupParams) -> io::Result<()> {
    let mut flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWUTS;
    // Network builds keep the host namespace only without isolation;
    // with it they get a private one plus user-mode NAT.
    let private_net = !p.network || p.net_isolation;
    if private_net {
        flags |= CloneFlags::CLONE_NEWNET;
    }
    // The helper stays in the host namespaces, so it drops to the
    // host-side backing uid of the FOD build.
    let net_helper = if p.net_isolation && p.network {
        Some(fork_net_helper(
            p.net_policy.clone(),
            p.fod_uid.map(|u| (u, u)),
        )?)
    } else {
        None
    };
    if p.has_cgroup {
        // Cgroup namespace rooted at the just-entered build cgroup:
        // the cgroup2 mount below then exposes only the build's own
        // delegated subtree (usable by nspawn inside the sandbox).
        flags |= CloneFlags::CLONE_NEWCGROUP;
    }
    // Mapping onto a host uid other than the worker's own (uid-range,
    // or a FOD's backing uid) needs a still-privileged helper in the
    // parent userns to write the map. Unsharing while root also avoids
    // the unprivileged-userns restriction some kernels enforce (e.g.
    // AppArmor on Ubuntu), which would reject the setgroups write
    // below. Only an unprivileged worker self-maps its own uid.
    if let Some(userns) = p.leased_userns {
        // Rootless: sandboxd already wrote the maps of the leased
        // namespace; join it (allowed: this uid owns it) and unshare
        // the rest inside. Then become in-ns root (backed by the pool
        // base uid): the worker uid is not mapped here, so the file
        // creation and mounts below need mapped credentials.
        let ns = fs::File::open(userns)
            .map_err(|e| io::Error::other(format!("opening leased userns: {e}")))?;
        nix::sched::setns(ns, CloneFlags::CLONE_NEWUSER).map_err(ioerr("joining leased userns"))?;
        unshare(flags & !CloneFlags::CLONE_NEWUSER).map_err(ioerr("unshare"))?;
        unistd::setgroups(&[]).map_err(ioerr("setgroups"))?;
        unistd::setgid(unistd::Gid::from_raw(0)).map_err(ioerr("setgid"))?;
        unistd::setuid(unistd::Uid::from_raw(0)).map_err(ioerr("setuid"))?;
    } else if p.uid_count == 1 && p.fod_uid.is_none() {
        unshare(flags).map_err(ioerr("unshare"))?;
        fs::write("/proc/self/setgroups", "deny").map_err(werr("setgroups"))?;
        fs::write(
            "/proc/self/uid_map",
            format!("{} {} {}", p.sandbox_uid, p.host_uid, p.uid_count),
        )
        .map_err(werr("uid_map"))?;
        fs::write(
            "/proc/self/gid_map",
            format!("{} {} {}", p.sandbox_gid, p.host_gid, p.uid_count),
        )
        .map_err(werr("gid_map"))?;
    } else {
        map_uid_range_via_helper(
            flags,
            p.sandbox_uid,
            p.host_uid,
            p.sandbox_gid,
            p.host_gid,
            p.uid_count,
        )?;
    }
    sethostname("localhost").map_err(ioerr("sethostname"))?;
    // "(none)" is the kernel default; fixed like Nix for determinism
    if unsafe { libc::setdomainname(c"(none)".as_ptr(), 6) } == -1 {
        return Err(io::Error::last_os_error());
    }
    if private_net {
        loopback_up().map_err(werr("bringing lo up"))?;
    }
    if let Some(helper) = net_helper {
        helper.attach()?;
    }

    // CLONE_NEWPID only applies to children: fork so the builder
    // runs as PID 1. Everything below runs in the child.
    if !fork_into_pid_ns()? {
        unreachable!("parent never returns");
    }

    mount_filesystems(p)?;

    // pivot_root + detach the old root: unlike a bare chroot, the
    // host filesystem is no longer reachable in this namespace.
    std::env::set_current_dir(p.root).map_err(werr("chdir to root"))?;
    pivot_root(".", ".").map_err(ioerr("pivot_root"))?;
    umount2(".", MntFlags::MNT_DETACH).map_err(ioerr("detaching old root"))?;
    std::env::set_current_dir("/").map_err(werr("chdir /"))?;
    std::env::set_current_dir(p.cwd)
        .map_err(|e| io::Error::other(format!("chdir {}: {e}", p.cwd)))?;

    if let Some(line) = p.binfmt_line {
        register_binfmt(line)?;
    }
    apply_process_limits(p.system)?;

    // Helper-mapped builds run as the still-root worker, unmapped but
    // holding all caps in the new userns; drop to the in-namespace uid
    // the map promised. A self-mapped worker already runs as it.
    // Leased builds became in-ns root when joining the namespace;
    // single-uid ones must not run the builder with sandbox root's
    // capabilities, so remap to Nix's uid 1000 via a nested userns
    // (any binfmt registration above already ran as root).
    if p.leased_userns.is_some() {
        if p.uid_count == 1 {
            unshare(CloneFlags::CLONE_NEWUSER).map_err(ioerr("nested unshare"))?;
            fs::write("/proc/self/setgroups", "deny").map_err(werr("nested setgroups"))?;
            fs::write("/proc/self/uid_map", "1000 0 1").map_err(werr("nested uid_map"))?;
            fs::write("/proc/self/gid_map", "100 0 1").map_err(werr("nested gid_map"))?;
        }
    } else if p.uid_count > 1 || p.fod_uid.is_some() {
        unistd::setgroups(&[]).map_err(ioerr("setgroups"))?;
        unistd::setgid(unistd::Gid::from_raw(p.sandbox_gid)).map_err(ioerr("setgid"))?;
        unistd::setuid(unistd::Uid::from_raw(p.sandbox_uid)).map_err(ioerr("setuid"))?;
    } else if p.binfmt_line.is_some() {
        // binfmt registration needed in-namespace root; remap to
        // Nix's uid 1000 via a nested userns. Exec lookup falls back
        // to the ancestor namespace's binfmt instance.
        unshare(CloneFlags::CLONE_NEWUSER).map_err(ioerr("nested unshare"))?;
        fs::write("/proc/self/setgroups", "deny").map_err(werr("nested setgroups"))?;
        fs::write("/proc/self/uid_map", "1000 0 1").map_err(werr("nested uid_map"))?;
        fs::write("/proc/self/gid_map", "100 0 1").map_err(werr("nested gid_map"))?;
    }
    Ok(())
}

/// Bind the sandbox root over itself, populate it with input/device
/// binds and the pseudo-filesystems the builder expects. Runs in the
/// PID-1 child after fork, before pivot_root.
fn mount_filesystems(p: &SetupParams) -> io::Result<()> {
    let root = p.root;
    let none: Option<&str> = None;
    mount(none, "/", none, MsFlags::MS_REC | MsFlags::MS_PRIVATE, none)
        .map_err(ioerr("making / private"))?;
    if p.leased_userns.is_some() {
        tmpfs_root(p)?;
    } else {
        mount(
            Some(root),
            root,
            none,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            none,
        )
        .map_err(ioerr("binding root"))?;
    }

    let bind_one = |src: &Path, dst: &Path, ro: bool, extra: MsFlags| -> io::Result<()> {
        let target = root.join(dst.strip_prefix("/").unwrap_or(dst));
        mount(
            Some(src),
            &target,
            none,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            none,
        )
        .map_err(|e| io::Error::other(format!("binding {}: {e}", src.display())))?;
        // In a user namespace, a bind mount keeps its source's
        // locked flags (nosuid, nodev, ...); a remount that drops
        // any of them fails with EPERM, so carry them over.
        let locked = existing_mount_flags(&target)?;
        let mut remount = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | locked | extra;
        if ro {
            remount |= MsFlags::MS_RDONLY;
        }
        mount(none, &target, none, remount, none)
            .map_err(|e| io::Error::other(format!("remounting {}: {e}", src.display())))?;
        Ok(())
    };
    // Request-derived binds are always read-only; only the sandbox's
    // own device nodes stay writable. Keying writability on a path
    // prefix of a client-influenced destination would let a request
    // bind host devices read-write.
    let nosuid_nodev = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
    for (src, dst) in p.binds {
        bind_one(src, dst, true, nosuid_nodev)?;
    }
    for (src, dst) in p.binds_dev {
        bind_one(src, dst, false, MsFlags::MS_NOSUID)?;
    }
    bind_one(p.build_dir, Path::new(p.cwd), false, nosuid_nodev)?;

    mount(
        Some("tmpfs"),
        &root.join("dev/shm"),
        Some("tmpfs"),
        nosuid_nodev,
        Some("mode=1777"),
    )
    .map_err(ioerr("mounting /dev/shm"))?;
    mount(
        Some("devpts"),
        &root.join("dev/pts"),
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,mode=0620,ptmxmode=0666"),
    )
    .map_err(ioerr("mounting /dev/pts"))?;

    // Inside the fresh PID namespace this shows only the build's own
    // processes; the old host-/proc bind fallback exposed every host
    // PID (and /proc/<pid>/root, a chroot escape).
    mount(
        Some("proc"),
        &root.join("proc"),
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        none,
    )
    .map_err(ioerr("mounting /proc"))?;

    // Like Nix: uid-range builds get a real sysfs (the userns owns
    // its netns, so the kernel allows it); container managers fail
    // without one ("VFS: Mount too revealing").
    if p.uid_count > 1 {
        mount(
            Some("sysfs"),
            &root.join("sys"),
            Some("sysfs"),
            MsFlags::empty(),
            none,
        )
        .map_err(ioerr("mounting /sys"))?;
    }

    if p.has_cgroup {
        // the cgroup namespace makes the build's own cgroup the root
        mount(
            Some("cgroup2"),
            &root.join("sys/fs/cgroup"),
            Some("cgroup2"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            none,
        )
        .map_err(ioerr("mounting /sys/fs/cgroup"))?;
    }
    Ok(())
}

/// A leased build cannot own the worker-created on-disk skeleton (the
/// worker uid is unmapped here); recreate it on a tmpfs owned by this
/// namespace (setup runs as in-ns root) so the build can chmod and
/// chown it like under a root worker. Only the scratch store stays on
/// disk: outputs must survive the namespace.
fn tmpfs_root(p: &SetupParams) -> io::Result<()> {
    let root = p.root;
    let none: Option<&str> = None;
    let store = open_tree(&root.join("nix/store")).map_err(ioerr("detaching scratch store"))?;
    mount(Some("tmpfs"), root, Some("tmpfs"), MsFlags::empty(), none)
        .map_err(ioerr("mounting tmpfs root"))?;
    write_skeleton(p.spec)
        .and_then(|()| create_mount_points(p.spec))
        .map_err(|e| io::Error::other(format!("populating tmpfs root: {e:#}")))?;
    move_mount(store.as_fd(), &root.join("nix/store")).map_err(ioerr("attaching scratch store"))
}

/// Detach a directory as a floating bind mount (new mount API; raw
/// syscall, the nix crate has no wrapper yet).
fn open_tree(path: &Path) -> nix::Result<OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| Errno::EINVAL)?;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD,
            c.as_ptr(),
            libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC,
        )
    };
    let fd = Errno::result(fd)?;
    let fd = RawFd::try_from(fd).map_err(|_| Errno::EBADF)?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Attach a floating mount from `open_tree` at `target`.
fn move_mount(from: BorrowedFd, target: &Path) -> nix::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;
    let c = CString::new(target.as_os_str().as_bytes()).map_err(|_| Errno::EINVAL)?;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            from.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_FDCWD,
            c.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    };
    Errno::result(ret).map(drop)
}

/// Fresh per-userns binfmt_misc instance (kernel 6.7+) so emulated
/// builds bind their interpreter without touching the host registry.
fn register_binfmt(line: &str) -> io::Result<()> {
    mount(
        Some("binfmt_misc"),
        "/proc/sys/fs/binfmt_misc",
        Some("binfmt_misc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(ioerr(
        "mounting binfmt_misc (emulated builds need kernel 6.7+)",
    ))?;
    fs::write("/proc/sys/fs/binfmt_misc/register", line).map_err(werr("registering binfmt entry"))
}

/// Match Nix's process environment: no core dumps in outputs, a
/// predictable umask (output modes feed the NAR hash), 32-bit
/// personality for 32-bit systems, no ASLR for determinism, no
/// privilege gain via setuid binaries, and a fork-bomb-braking
/// RLIMIT_NPROC. Hard limits are never raised: the child userns has no
/// CAP_SYS_RESOURCE in the initial namespace, so a host with finite
/// hard limits (e.g. GitHub-hosted runners cap RLIMIT_CORE) would
/// EPERM.
fn apply_process_limits(system: &str) -> io::Result<()> {
    let (_, hard) = getrlimit(Resource::RLIMIT_NPROC).map_err(ioerr("getrlimit NPROC"))?;
    let limit = hard.min(4096);
    setrlimit(Resource::RLIMIT_NPROC, limit, limit).map_err(ioerr("setting RLIMIT_NPROC"))?;
    let (_, hard) = getrlimit(Resource::RLIMIT_CORE).map_err(ioerr("getrlimit CORE"))?;
    setrlimit(Resource::RLIMIT_CORE, 0, hard).map_err(ioerr("setting RLIMIT_CORE"))?;
    stat::umask(stat::Mode::from_bits_truncate(0o022));
    if matches!(
        system,
        "i686-linux" | "armv7l-linux" | "armv6l-linux" | "armv5tel-linux"
    ) {
        // PER_LINUX32 is a base persona, not a flag bit, so the nix
        // crate's Persona bitflags cannot express it.
        if unsafe {
            libc::personality(0x0008 /* PER_LINUX32 */)
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
    }
    if let Ok(persona) = personality::get() {
        let _ = personality::set(persona | Persona::ADDR_NO_RANDOMIZE);
    }
    prctl::set_no_new_privs().map_err(ioerr("PR_SET_NO_NEW_PRIVS"))
}

pub fn setup_error_file(root: &Path) -> PathBuf {
    root.with_file_name("setup-error")
}

pub fn setup_error_detail_impl(spec: &SandboxSpec) -> Option<String> {
    fs::read_to_string(setup_error_file(&spec.root))
        .ok()
        .filter(|s| !s.is_empty())
}

pub fn cleanup(_a: &BuildAssignment, _dir: &Path) {
    // Mounts lived in the child's namespace and died with it; the
    // build dir itself is removed by the caller.
}

pub const CLEANUP_STAGE_ARG: &str = "__lease_cleanup";

/// Files a leased build wrote to disk (scratch store, /build) belong to
/// leased uids the worker cannot delete. Re-exec this binary into the
/// leased namespace as its root and remove them from there, while the
/// lease still pins the namespace.
pub fn cleanup_leased(userns: &Path, paths: &[PathBuf]) -> Result<()> {
    let exe = std::env::current_exe().context("resolving worker binary path")?;
    let status = Command::new(exe)
        .arg(CLEANUP_STAGE_ARG)
        .arg(userns)
        .args(paths)
        .status()
        .context("spawning lease cleanup stage")?;
    anyhow::ensure!(status.success(), "lease cleanup stage failed: {status}");
    Ok(())
}

/// Entry point of the re-exec'd cleanup stage:
/// `__lease_cleanup <userns> <path>...` removes the contents of each
/// path.
pub fn cleanup_stage() -> ! {
    let code = match cleanup_stage_impl() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("lease cleanup: {e:#}");
            1
        }
    };
    std::process::exit(code);
}

fn cleanup_stage_impl() -> Result<()> {
    let mut args = std::env::args_os().skip(2);
    let ns = args.next().context("missing userns path")?;
    let ns = fs::File::open(Path::new(&ns)).context("opening leased userns")?;
    nix::sched::setns(ns, CloneFlags::CLONE_NEWUSER).context("joining leased userns")?;
    // Become in-ns root: it owns the leased uids' files and, unlike the
    // unmapped worker uid, may delete them despite the sticky bit.
    let (uid, gid) = (unistd::Uid::from_raw(0), unistd::Gid::from_raw(0));
    unistd::setresgid(gid, gid, gid).context("setresgid")?;
    unistd::setresuid(uid, uid, uid).context("setresuid")?;
    // Entries the worker created (input mount points, output dirs)
    // appear as the overflow uid here; leave them for the worker's own
    // remove_dir_all.
    let overflow_uid: u32 = fs::read_to_string("/proc/sys/kernel/overflowuid")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(65534);
    for dir in args {
        let dir = PathBuf::from(dir);
        // O_NOFOLLOW + fd-based descent below: the build controlled
        // these trees, symlinks it planted must not redirect the
        // deletion (or the chmod) outside them.
        let fd = fcntl::open(
            &dir,
            OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_RDONLY | OFlag::O_CLOEXEC,
            stat::Mode::empty(),
        )
        .with_context(|| format!("opening {}", dir.display()))?;
        for name in dir_entry_names(&fd)? {
            let st = stat::fstatat(&fd, name.as_c_str(), AtFlags::AT_SYMLINK_NOFOLLOW)?;
            if st.st_uid == overflow_uid {
                continue;
            }
            remove_at(&fd, &name).with_context(|| format!("under {}", dir.display()))?;
        }
    }
    Ok(())
}

/// Directory entry names via an fd, collected before deletion mutates
/// the directory.
fn dir_entry_names(dirfd: &OwnedFd) -> Result<Vec<CString>> {
    let mut names = Vec::new();
    let mut dir = nix::dir::Dir::from_fd(dirfd.try_clone()?)?;
    for entry in dir.iter() {
        let name = entry?.file_name().to_owned();
        if name.as_bytes() != b"." && name.as_bytes() != b".." {
            names.push(name);
        }
    }
    Ok(names)
}

/// unlinkat-based remove_dir_all that also handles read-only
/// directories (store outputs are typically 0555) and never follows
/// symlinks.
fn remove_at(dirfd: &OwnedFd, name: &CStr) -> Result<()> {
    match unistd::unlinkat(dirfd, name, unistd::UnlinkatFlags::NoRemoveDir) {
        Ok(()) => return Ok(()),
        Err(Errno::EISDIR) => {}
        Err(e) => return Err(e).with_context(|| format!("removing {name:?}")),
    }
    let sub = fcntl::openat(
        dirfd,
        name,
        OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        stat::Mode::empty(),
    )
    .with_context(|| format!("opening {name:?}"))?;
    stat::fchmod(&sub, stat::Mode::from_bits_truncate(0o700))
        .with_context(|| format!("unlocking {name:?}"))?;
    for child in dir_entry_names(&sub)? {
        remove_at(&sub, &child).with_context(|| format!("under {name:?}"))?;
    }
    unistd::unlinkat(dirfd, name, unistd::UnlinkatFlags::RemoveDir)
        .with_context(|| format!("removing {name:?}"))?;
    Ok(())
}
