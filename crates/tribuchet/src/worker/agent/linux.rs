//! Linux side of the agent: systemd socket activation, the
//! /proc-based uid sweep, the agent's pre-mapped user namespace and
//! the per-build cgroups.
//!
//! At startup the agent creates a user namespace mapping in-ns
//! 0..65536 to its uid block. Writing another namespace's uid_map
//! needs CAP_SETUID in the parent namespace, so the agent unit runs
//! with AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_CHOWN; the
//! setuid/setgid caps are dropped right after the write, CAP_CHOWN
//! stays for handing each build cgroup to its mapped root uid.
//! Sandboxed builds join that namespace via the worker's setup
//! stage, spawned here.

use std::fs;
use std::io::{self, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{self, Stdio};
use std::process::{Child, Command};
use std::sync::Arc;
use std::{env, slice, thread};

use rustix::io::{FdFlags, fcntl_setfd};
use rustix::net::sockopt::socket_peercred;
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendFlags, SocketFlags,
    SocketType, recvmsg, send, socketpair,
};
use rustix::process::getuid;
use rustix::process::{Gid, Pid, PidfdFlags, Uid, pidfd_open};
use rustix::thread::{
    LinkNameSpaceType, move_into_link_name_space, set_thread_gid, set_thread_uid,
};
use sandbox_proto::agent::StartRequest;

use super::{Build, Options, cgroup, make_readable, msg, spawn_plain, stage_scratch};
use crate::errors::{Error, Result, chain, err_ctx};
use crate::fsutil::io_ctx;
use crate::netpolicy::NetPolicy;
use crate::sd;
use crate::worker::sandbox::{self, SandboxSpec};
use crate::worker::userns::{self, UsernsHolder};

/// Argv[1] marker of the re-exec'd userns filesystem helper.
pub const FS_HELPER_ARG: &str = "__agent_fs";

/// Uids mapped into the agent's user namespace: enough for uid-range
/// (nspawn) builds, single-uid builds nest a 1-uid map inside it.
const UID_COUNT: u32 = 65536;

/// Per-agent confinement state: the pre-mapped user namespace backing
/// every build this agent runs, and the delegated cgroup subtree the
/// per-build cgroups live in. Both are None for development runs
/// (no `--uid-base`, no delegated unit).
pub(super) struct Confinement {
    userns: Option<Userns>,
    cgroup_base: Option<PathBuf>,
}

struct Userns {
    /// Pausing child that keeps the namespace alive.
    holder: UsernsHolder,
    fd: OwnedFd,
    uid_base: u32,
}

impl Confinement {
    pub(super) fn init(opts: &Options) -> Result<Self> {
        // Vacate the unit cgroup before forking the userns holder;
        // with the holder still in it the leaf cannot be enabled.
        let cgroup_base = cgroup::init();
        Ok(Self {
            userns: opts.uid_base.map(Userns::create).transpose()?,
            cgroup_base,
        })
    }

    /// The userns holder must survive the kill sweep.
    pub(super) fn exempt_pid(&self) -> Option<i32> {
        self.userns
            .as_ref()
            .and_then(|ns| i32::try_from(ns.holder.pid()).ok())
    }
}

/// Unpack the tmp dir. With a user namespace the unpack runs
/// through the userns helper as in-ns root, so the files belong to
/// the uid block and the builder can rewrite and unlink them; the
/// agent's own uid is not mapped in the build's namespace.
pub(super) fn stage_tmp_dir(
    confinement: &Confinement,
    scratch_root: &Path,
    build_dir: &Path,
    pack: OwnedFd,
) -> Result<()> {
    let Some(userns) = &confinement.userns else {
        return stage_scratch(fs::File::from(pack), build_dir);
    };
    // The scratch root is agent-owned and the agent's uid is unmapped
    // in the namespace, so in-ns root could not create the build dir
    // inside it otherwise. The sticky bit keeps the uid block from
    // deleting the agent's own files; the traverse-only state dir
    // hides the scratch root from other users.
    fs::set_permissions(scratch_root, fs::Permissions::from_mode(0o1777))
        .map_err(io_ctx("setting permissions on", scratch_root))?;
    let exe = env::current_exe()?;
    let (_ns_fd, ns_path) = userns::inherited_ns(&userns.fd)?;
    let status = Command::new(exe)
        .arg(FS_HELPER_ARG)
        .arg(ns_path)
        .arg("unpack")
        .arg(build_dir)
        .stdin(Stdio::from(fs::File::from(pack)))
        .status()?;
    if !status.success() {
        return Err(msg(format!("userns unpack helper exited with {status}")));
    }
    Ok(())
}

/// Spawn the build inside the pre-mapped user namespace. Only a
/// dev-mode agent (no --uid-base) may exec directly: on a confined
/// agent a spec-less Start would be an unsandboxed escape.
pub(super) fn spawn_builder(
    confinement: &Confinement,
    req: &StartRequest,
    scratch_root: &Path,
    build_dir: &Path,
    log: &fs::File,
) -> Result<(Child, Option<PathBuf>), Error> {
    let Some(sandbox_json) = &req.sandbox_json else {
        if confinement.userns.is_some() {
            return Err(msg("refusing an unsandboxed build on a confined agent"));
        }
        return Ok((spawn_plain(req, build_dir, log)?, None));
    };
    let userns = confinement
        .userns
        .as_ref()
        .ok_or_else(|| msg("sandboxed build requested but the agent has no --uid-base"))?;
    let mut spec: SandboxSpec =
        serde_json::from_str(sandbox_json).map_err(err_ctx("decoding the sandbox spec"))?;
    spec.root = scratch_root.join("root");
    spec.build_dir = build_dir.to_path_buf();
    let (_ns_fd, ns_path) = userns::inherited_ns(&userns.fd)?;
    spec.leased_userns = Some(ns_path);
    spec.leased_uid_count.get_or_insert(UID_COUNT);
    spec.cgroup = confinement
        .cgroup_base
        .as_deref()
        .map(|base| cgroup::create(base, &req.build_id, userns.uid_base))
        .transpose()?;
    if let (Some(cg), Some(bytes)) = (&spec.cgroup, req.memory_max_bytes) {
        cgroup::set_memory_max(cg, bytes)?;
    }
    sandbox::prepare_root(&mut spec).map_err(err_ctx("creating the sandbox root skeleton"))?;
    // Isolated network builds hand their tap fd back over this
    // socketpair to the forwarder thread spawned below.
    let net_fwd = if spec.net_isolation && spec.network {
        let (ours, theirs) = socketpair(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(err_ctx("creating the tap handoff socketpair"))?;
        // The setup stage inherits its end across the exec.
        fcntl_setfd(&theirs, FdFlags::empty()).map_err(err_ctx("clearing close-on-exec"))?;
        spec.net_fwd_fd = Some(theirs.as_raw_fd());
        Some((ours, theirs))
    } else {
        None
    };
    let (child, spec_w) = sandbox::spawn(&spec, log)?;
    if let Some((ours, theirs)) = net_fwd {
        drop(theirs);
        let policy = spec.net_policy.clone();
        let build_pid = child.id();
        thread::spawn(move || net_forward(&ours, policy, build_pid));
    }
    // The setup stage waits for the spec on stdin; move it into the
    // build cgroup first so its cgroup namespace is rooted there.
    if let Some(cg) = &spec.cgroup {
        cgroup::enter(cg, child.id().cast_signed(), userns.uid_base)?;
    }
    if let Some(w) = spec_w {
        sandbox::send_spec_to(&spec, w)?;
    }
    Ok((child, Some(spec.root)))
}

/// Per-build network forwarder: receive the tap fd the setup stage
/// created inside its netns, run the presto-pasta datapath on it and
/// stop it (letting the netns go away) once the build process dies.
fn net_forward(sock: &OwnedFd, policy: NetPolicy, build_pid: u32) {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut cmsg = RecvAncillaryBuffer::new(&mut space);
    let mut buf = [0u8; 8];
    let mut iov = [IoSliceMut::new(&mut buf)];
    if recvmsg(sock, &mut iov, &mut cmsg, RecvFlags::empty()).is_err() {
        return;
    }
    let Some(RecvAncillaryMessage::ScmRights(mut fds)) = cmsg.drain().next() else {
        // The build died before creating the tap; nothing to forward.
        return;
    };
    let Some(tap) = fds.next() else { return };
    let net = presto_pasta::Config {
        allow_flow: Some(Arc::new(move |d: &presto_pasta::FlowDst| {
            policy.allows(d.proto, d.ip, d.port)
        })),
        ..presto_pasta::Config::default()
    };
    let mut presto = presto_pasta::Presto::new(net, tap);
    // A pidfd stops the datapath (closing the tap fd and with it the
    // build netns) once the build process dies.
    if let Some(pid) = Pid::from_raw(build_pid.cast_signed())
        && let Ok(pidfd) = pidfd_open(pid, PidfdFlags::empty())
    {
        presto.stop_on(pidfd);
    }
    // Readiness ack: the setup stage waits for this before building.
    if send(sock, b"ok", SendFlags::empty()).is_err() {
        return;
    }
    if let Err(e) = presto.run() {
        tracing::warn!("presto-pasta datapath exited: {e}");
    }
}

/// Make outputs readable for the worker. Files of a namespace build
/// belong to the agent's uid block, so the chmod runs through the
/// userns helper; direct-exec outputs are agent-owned.
pub(super) fn finish(confinement: &Confinement, root: Option<&Path>, outputs: &[String]) {
    let Some(root) = root else {
        for out in outputs {
            make_readable(Path::new(out));
        }
        return;
    };
    let paths: Vec<PathBuf> = outputs
        .iter()
        .map(|o| root.join(o.trim_start_matches('/')))
        .collect();
    if let Err(e) = run_in_userns(confinement, "make-readable", &paths) {
        tracing::warn!("making outputs readable: {}", chain(&e));
    }
}

/// Remove a stale scratch tree before a new build. Uid-block files
/// need the userns helper, the agent-owned remainder a plain pass.
/// Agent-owned entries never nest under uid-block ones, so one pass
/// of each suffices.
pub(super) fn clean_scratch(confinement: &Confinement, scratch_root: &Path) -> Result<()> {
    match fs::remove_dir_all(scratch_root) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) if confinement.userns.is_some() => {
            run_in_userns(
                confinement,
                "remove",
                slice::from_ref(&scratch_root.to_path_buf()),
            )?;
        }
        Err(e) => return Err(e.into()),
    }
    match fs::remove_dir_all(scratch_root) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(msg(format!(
            "stale scratch tree {} could not be removed: {e}",
            scratch_root.display()
        ))),
    }
}

/// Remove a build's cgroup and scratch tree, plus stray outputs. A
/// namespace build's tree contains uid-block files only deletable
/// inside the userns; its outputs live under that tree.
pub(super) fn cleanup(confinement: &Confinement, build: &Build) {
    if build.sandbox_root.is_some() {
        if let Some(base) = &confinement.cgroup_base
            && let Err(e) = cgroup::destroy(&base.join(format!("build-{}", build.id)))
        {
            tracing::warn!("removing the build cgroup: {}", chain(&e));
        }
        if let Err(e) = run_in_userns(confinement, "remove", slice::from_ref(&build.scratch_root)) {
            tracing::warn!("removing the scratch tree: {}", chain(&e));
        }
        return;
    }
    let _ = fs::remove_dir_all(&build.scratch_root);
    for out in &build.outputs {
        // Direct-exec scratch outputs live at their real store paths
        // and are agent-owned; the sticky store dir lets the owner
        // delete them.
        let _ = fs::remove_dir_all(out);
        let _ = fs::remove_file(out);
    }
}

/// Re-exec this binary as the userns filesystem helper and wait it
/// out.
fn run_in_userns(confinement: &Confinement, op: &str, paths: &[PathBuf]) -> Result<()> {
    let userns = confinement
        .userns
        .as_ref()
        .ok_or_else(|| msg("no pre-mapped user namespace"))?;
    let exe = env::current_exe()?;
    let (_ns_fd, ns_path) = userns::inherited_ns(&userns.fd)?;
    let status = Command::new(exe)
        .arg(FS_HELPER_ARG)
        .arg(ns_path)
        .arg(op)
        .args(paths)
        .status()?;
    if !status.success() {
        return Err(msg(format!("userns fs helper exited with {status}")));
    }
    Ok(())
}

/// Entry point of the re-exec'd helper: joins the agent's user
/// namespace, whose owner gets full capabilities over the uid-block
/// files, and runs the filesystem operation the agent itself may not.
pub fn fs_helper_stage() -> ! {
    fn run() -> Result<()> {
        let mut args = env::args_os().skip(2);
        let ns_path = PathBuf::from(args.next().ok_or_else(|| msg("missing userns path"))?);
        let ns = fs::File::open(&ns_path).map_err(io_ctx("opening", &ns_path))?;
        let op = args.next().ok_or_else(|| msg("missing op"))?;
        move_into_link_name_space(ns.as_fd(), Some(LinkNameSpaceType::User))
            .map_err(err_ctx("joining the agent user namespace"))?;
        if op.to_str() == Some("unpack") {
            // Become in-ns root so the unpacked files belong to the
            // uid block instead of the agent's unmapped uid.
            set_thread_gid(Gid::from_raw(0)).map_err(err_ctx("setgid 0 in the ns"))?;
            set_thread_uid(Uid::from_raw(0)).map_err(err_ctx("setuid 0 in the ns"))?;
            let build_dir = PathBuf::from(args.next().ok_or_else(|| msg("missing build dir"))?);
            return stage_scratch(io::stdin(), &build_dir);
        }
        for path in args {
            let path = Path::new(&path);
            match op.to_str() {
                Some("make-readable") => make_readable(path),
                Some("remove") => {
                    let _ = fs::remove_dir_all(path);
                    let _ = fs::remove_file(path);
                }
                _ => return Err(msg(format!("unknown op {}", op.to_string_lossy()))),
            }
        }
        Ok(())
    }
    match run() {
        Ok(()) => process::exit(0),
        Err(e) => {
            eprintln!("agent fs helper: {}", chain(&e));
            process::exit(1);
        }
    }
}

/// Confinement hook of the direct-exec path (no sandbox spec):
/// seatbelt-profile requests have no Linux equivalent there.
pub(super) fn confine(_cmd: &mut Command, req: &StartRequest, _build_dir: &str) -> Result<()> {
    if !req.profile.is_empty() {
        return Err(msg("seatbelt profiles are only supported on macOS"));
    }
    Ok(())
}

impl Userns {
    /// Create the agent's user namespace, map `0 uid_base 65536` into
    /// it and drop the ambient/permitted capabilities that allowed
    /// the map write.
    fn create(uid_base: u32) -> Result<Self> {
        let (holder, fd) =
            UsernsHolder::new().map_err(err_ctx("creating the agent user namespace"))?;
        let map = format!("0 {uid_base} {UID_COUNT}");
        let pid = holder.pid();
        fs::write(format!("/proc/{pid}/uid_map"), &map).map_err(err_ctx(
            "writing the agent uid_map, which needs ambient CAP_SETUID",
        ))?;
        fs::write(format!("/proc/{pid}/gid_map"), &map).map_err(err_ctx(
            "writing the agent gid_map, which needs ambient CAP_SETGID",
        ))?;
        drop_caps()?;
        tracing::info!(
            uid_base,
            uid_count = UID_COUNT,
            "agent user namespace mapped"
        );
        Ok(Self {
            holder,
            fd,
            uid_base,
        })
    }
}

/// Drop the agent's capabilities down to CAP_CHOWN; only handing the
/// build cgroups to their mapped root uid still needs privilege after
/// the map write.
fn drop_caps() -> Result<()> {
    rustix::thread::clear_ambient_capability_set().map_err(err_ctx("clearing the ambient set"))?;
    rustix::thread::set_capabilities(
        None,
        rustix::thread::CapabilitySets {
            effective: rustix::thread::CapabilitySet::CHOWN,
            permitted: rustix::thread::CapabilitySet::CHOWN,
            inheritable: rustix::thread::CapabilitySet::empty(),
        },
    )
    .map_err(err_ctx("reducing the capability sets"))?;
    Ok(())
}

/// systemd-activated listener (the socket unit's fd), or None when not
/// socket-activated. The shared adoption helper serves the async hub
/// and marks the fd non-blocking; the agent's accept loop is
/// synchronous.
pub(super) fn activated_unix_listener() -> Result<Option<UnixListener>> {
    let listener = sd::activated_sockets()?.unix;
    if let Some(l) = &listener {
        l.set_nonblocking(false)?;
    }
    Ok(listener)
}

pub(super) fn peer_uid(conn: &UnixStream) -> Result<u32> {
    Ok(socket_peercred(conn).map_err(io::Error::from)?.uid.as_raw())
}

/// Whether the build cgroup's memory.max OOM-killed the build.
pub(super) fn oom_killed(confinement: &Confinement, build_id: &str) -> bool {
    let Some(base) = &confinement.cgroup_base else {
        return false;
    };
    fs::read_to_string(base.join(format!("build-{build_id}")).join("memory.events")).is_ok_and(
        |events| {
            events
                .lines()
                .any(|l| l.strip_prefix("oom_kill ").is_some_and(|n| n.trim() != "0"))
        },
    )
}

/// Pids whose real uid is this uid, from /proc.
pub(super) fn own_uid_pids() -> Vec<i32> {
    let uid = getuid().as_raw();
    let Ok(entries) = fs::read_dir("/proc") else {
        tracing::warn!("reading /proc failed, kill sweep degraded to the process group");
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let pid: i32 = e.file_name().to_str()?.parse().ok()?;
            let status = fs::read_to_string(e.path().join("status")).ok()?;
            let real_uid: u32 = status
                .lines()
                .find_map(|l| l.strip_prefix("Uid:"))?
                .split_whitespace()
                .next()?
                .parse()
                .ok()?;
            (real_uid == uid).then_some(pid)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confined_agent_refuses_an_unsandboxed_start() -> Result<()> {
        let Ok((holder, fd)) = UsernsHolder::new() else {
            eprintln!("skipping: cannot create a user namespace here");
            return Ok(());
        };
        let confinement = Confinement {
            userns: Some(Userns {
                holder,
                fd,
                uid_base: 65536,
            }),
            cgroup_base: None,
        };
        let dir = tempfile::tempdir()?;
        let log = fs::File::create(dir.path().join("log"))?;
        let req = StartRequest::default();
        let err = spawn_builder(&confinement, &req, dir.path(), dir.path(), &log).unwrap_err();
        assert!(err.to_string().contains("refusing an unsandboxed build"));
        Ok(())
    }
}
