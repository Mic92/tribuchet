//! Linux sandbox implementation: namespaces, bind mounts, pivot_root.

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, unshare};
use nix::sys::resource::{Resource, getrlimit, setrlimit};
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, recv,
    recvmsg, sendmsg, socketpair,
};
use nix::sys::{prctl, stat, wait};
use nix::unistd::{self, pivot_root, sethostname};
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{SandboxSpec, binfmt};
use crate::netpolicy::NetPolicy;

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
    // The worker cannot chown to the leased range: the sandbox root is
    // recreated on an in-namespace tmpfs instead (mount_filesystems);
    // the on-disk trees the build still writes are opened up. The 0700
    // per-build parent (see BuildOwner) keeps other local users out.
    {
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

/// Like Nix: bind-mount the host device nodes instead of mknod'ing
/// copies (impossible in a leased user namespace anyway). The mounts
/// are read-only, so a sandbox mapping a host uid that owns a node
/// cannot chmod/chown it; device I/O is unaffected by MS_RDONLY.
fn populate_dev(root: &Path, binds_dev: &mut Vec<(PathBuf, PathBuf)>) -> Result<()> {
    let mut devices = vec!["null", "zero", "full", "random", "urandom", "tty"];
    // Nix's `kvm` system feature (VM builds, NixOS tests).
    if Path::new("/dev/kvm").exists() {
        devices.push("kvm");
    }
    for dev in devices {
        let host = PathBuf::from("/dev").join(dev);
        fs::File::create(root.join("dev").join(dev))?;
        binds_dev.push((host.clone(), host));
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

pub const SETUP_STAGE_ARG: &str = "__sandbox_setup";

/// The spec travels via the setup stage's stdin.
pub const SPEC_VIA_STDIN: bool = true;

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

const CLOSE_RANGE_CLOEXEC: libc::c_uint = 4;

fn enter_and_exec(spec: &SandboxSpec) -> io::Result<std::convert::Infallible> {
    // sandboxd placed this process in the build cgroup before the spec
    // arrived on stdin; CLONE_NEWCGROUP below roots the namespace there.
    let binfmt_line = match &spec.emulator {
        Some(_) => Some(binfmt::register_line(&spec.system).ok_or_else(|| {
            io::Error::other(format!("no binfmt magic known for system {}", spec.system))
        })?),
        None => None,
    };
    // The leased namespace already carries its maps (in-ns 0..count,
    // written by sandboxd); setup becomes in-ns root after joining.
    let uid_count = spec
        .leased_uid_count
        .ok_or_else(|| io::Error::other("sandbox spec lacks a leased uid count"))?;
    let leased_userns = spec
        .leased_userns
        .as_deref()
        .ok_or_else(|| io::Error::other("sandbox spec lacks a leased user namespace"))?;
    setup(&SetupParams {
        spec,
        root: &spec.root,
        system: &spec.system,
        binfmt_line: binfmt_line.as_deref(),
        net_isolation: spec.net_isolation,
        net_policy: &spec.net_policy,
        leased_userns,
        build_dir: &spec.build_dir,
        binds: &spec.binds_ro,
        binds_dev: &spec.binds_dev,
        cwd: &spec.cwd,
        network: spec.network,
        has_cgroup: spec.cgroup.is_some(),
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
    // Fds the setup stage still holds (error file, leased namespace)
    // must not leak into the builder.
    unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3,
            libc::c_uint::MAX,
            CLOSE_RANGE_CLOEXEC,
        );
    }
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

struct NetHelper {
    sock: OwnedFd,
}

/// Fork a helper that stays outside the sandbox and runs the
/// presto-pasta datapath on the tap fd the sandbox side sends over
/// once its netns exists (see [`NetHelper::attach`]). Before any
/// traffic is processed the helper confines itself to its own
/// single-uid user namespace. The helper exits when the build process
/// (its parent) dies, watched via a pidfd.
fn fork_net_helper(policy: NetPolicy) -> io::Result<NetHelper> {
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
            let code = net_helper(&theirs, target, policy);
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
fn net_helper(sock: &OwnedFd, build_pid: unistd::Pid, policy: NetPolicy) -> i32 {
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
    // Confine the helper to its own self-mapped user namespace; it
    // only needs the tap fd and outbound sockets.
    let uid = unistd::getuid().as_raw();
    let gid = unistd::getgid().as_raw();
    let confined = unshare(CloneFlags::CLONE_NEWUSER).is_ok()
        && fs::write("/proc/self/setgroups", "deny").is_ok()
        && fs::write("/proc/self/uid_map", format!("{uid} {uid} 1")).is_ok()
        && fs::write("/proc/self/gid_map", format!("{gid} {gid} 1")).is_ok();
    if !confined {
        return 1;
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
    /// Leased user namespace to join, mapped by tribuchet-sandboxd.
    leased_userns: &'a Path,
    build_dir: &'a Path,
    binds: &'a [(PathBuf, PathBuf)],
    binds_dev: &'a [(PathBuf, PathBuf)],
    cwd: &'a str,
    network: bool,
    has_cgroup: bool,
    /// Uids mapped in the lease (1 or 65536).
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
    // Forked before the leased userns is joined, so the helper stays
    // outside the sandbox as the worker uid.
    let net_helper = if p.net_isolation && p.network {
        Some(fork_net_helper(p.net_policy.clone())?)
    } else {
        None
    };
    if p.has_cgroup {
        // Cgroup namespace rooted at the just-entered build cgroup:
        // the cgroup2 mount below then exposes only the build's own
        // delegated subtree (usable by nspawn inside the sandbox).
        flags |= CloneFlags::CLONE_NEWCGROUP;
    }
    // sandboxd already wrote the maps of the leased namespace; join it
    // (allowed: this uid owns it) and unshare the rest inside. Then
    // become in-ns root (backed by the pool base uid): the worker uid
    // is not mapped here, so the file creation and mounts below need
    // mapped credentials.
    let ns = fs::File::open(p.leased_userns)
        .map_err(|e| io::Error::other(format!("opening leased userns: {e}")))?;
    nix::sched::setns(ns, CloneFlags::CLONE_NEWUSER).map_err(ioerr("joining leased userns"))?;
    unshare(flags & !CloneFlags::CLONE_NEWUSER).map_err(ioerr("unshare"))?;
    unistd::setgroups(&[]).map_err(ioerr("setgroups"))?;
    unistd::setgid(unistd::Gid::from_raw(0)).map_err(ioerr("setgid"))?;
    unistd::setuid(unistd::Uid::from_raw(0)).map_err(ioerr("setuid"))?;
    // The setuid from the unmapped worker uid cleared the dumpable
    // flag, which makes /proc/self inodes root-owned and would reject
    // the nested userns map writes below; the userns still confines
    // ptrace, so restore it.
    nix::sys::prctl::set_dumpable(true).map_err(ioerr("set dumpable"))?;
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

    // The build became in-ns root when joining the namespace;
    // single-uid builds must not run the builder with sandbox root's
    // capabilities, so remap to Nix's uid 1000 via a nested userns
    // (any binfmt registration above already ran as root). uid-range
    // builds keep in-ns root: container payloads need it.
    if p.uid_count == 1 {
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
    tmpfs_root(p)?;

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
    // Every bind is read-only: request-derived ones because the request
    // must not expose writable host files, device binds because the
    // sandbox must not chmod/chown the host nodes (writing *to* a char
    // device works regardless of MS_RDONLY).
    let nosuid_nodev = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
    for (src, dst) in p.binds {
        bind_one(src, dst, true, nosuid_nodev)?;
    }
    for (src, dst) in p.binds_dev {
        bind_one(src, dst, true, MsFlags::MS_NOSUID)?;
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
    // PER_LINUX32 is a base persona, not a flag bit; nix's Persona
    // bitflags truncate it, so do the read/modify/write via raw libc.
    let base: libc::c_ulong = if matches!(
        system,
        "i686-linux" | "armv7l-linux" | "armv6l-linux" | "armv5tel-linux"
    ) {
        0x0008 // PER_LINUX32
    } else {
        unsafe { libc::personality(0xFFFF_FFFF) as libc::c_ulong }
    };
    unsafe {
        libc::personality(base | 0x0004_0000 /* ADDR_NO_RANDOMIZE */)
    };
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

pub fn cleanup(_outputs: &[String], _dir: &Path) {
    // Mounts lived in the child's namespace and died with it; the
    // build dir itself is removed by the caller.
}
