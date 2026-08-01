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
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use anyhow::{Context, Result, bail, ensure};
use rustix::net::sockopt::socket_peercred;
use rustix::process::getuid;
use rustix::process::{Gid, Uid};
use rustix::thread::{
    LinkNameSpaceType, move_into_link_name_space, set_thread_gid, set_thread_uid,
};
use sandbox_proto::agent::StartRequest;

use super::{Build, Options, cgroup};
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
        return super::stage_scratch(fs::File::from(pack), build_dir);
    };
    // The scratch root is agent-owned and the agent's uid is unmapped
    // in the namespace, so in-ns root could not create the build dir
    // inside it otherwise. The sticky bit keeps the uid block from
    // deleting the agent's own files; the traverse-only state dir
    // hides the scratch root from other users.
    fs::set_permissions(scratch_root, fs::Permissions::from_mode(0o1777))?;
    let exe = std::env::current_exe()?;
    let (_ns_fd, ns_path) = userns::inherited_ns(&userns.fd)?;
    let status = Command::new(exe)
        .arg(FS_HELPER_ARG)
        .arg(ns_path)
        .arg("unpack")
        .arg(build_dir)
        .stdin(std::process::Stdio::from(fs::File::from(pack)))
        .status()?;
    ensure!(
        status.success(),
        "userns unpack helper exited with {status}"
    );
    Ok(())
}

/// Spawn the build. With a sandbox spec from the worker the setup
/// stage runs it inside the agent's pre-mapped user namespace; without
/// one (development, tests) the builder is exec'd directly.
pub(super) fn spawn_builder(
    confinement: &Confinement,
    req: &StartRequest,
    scratch_root: &Path,
    build_dir: &Path,
    log: &fs::File,
) -> Result<(Child, Option<PathBuf>)> {
    let Some(sandbox_json) = &req.sandbox_json else {
        return Ok((super::spawn_plain(req, build_dir, log)?, None));
    };
    let userns = confinement
        .userns
        .as_ref()
        .context("sandboxed build requested but the agent has no --uid-base")?;
    let mut spec: SandboxSpec =
        serde_json::from_str(sandbox_json).context("decoding the sandbox spec")?;
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
    sandbox::prepare_root(&mut spec).context("creating the sandbox root skeleton")?;
    let (child, spec_w) = sandbox::spawn(&spec, log)?;
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

/// Make outputs readable for the worker. Files of a namespace build
/// belong to the agent's uid block, so the chmod runs through the
/// userns helper; direct-exec outputs are agent-owned.
pub(super) fn finish(confinement: &Confinement, root: Option<&Path>, outputs: &[String]) {
    let Some(root) = root else {
        for out in outputs {
            super::make_readable(Path::new(out));
        }
        return;
    };
    let paths: Vec<PathBuf> = outputs
        .iter()
        .map(|o| root.join(o.trim_start_matches('/')))
        .collect();
    if let Err(e) = run_in_userns(confinement, "make-readable", &paths) {
        tracing::warn!("making outputs readable: {e:#}");
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
            tracing::warn!("removing the build cgroup: {e:#}");
        }
        if let Err(e) = run_in_userns(
            confinement,
            "remove",
            std::slice::from_ref(&build.scratch_root),
        ) {
            tracing::warn!("removing the scratch tree: {e:#}");
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
        .context("no pre-mapped user namespace")?;
    let exe = std::env::current_exe()?;
    let (_ns_fd, ns_path) = userns::inherited_ns(&userns.fd)?;
    let status = Command::new(exe)
        .arg(FS_HELPER_ARG)
        .arg(ns_path)
        .arg(op)
        .args(paths)
        .status()?;
    ensure!(status.success(), "userns fs helper exited with {status}");
    Ok(())
}

/// Entry point of the re-exec'd helper: joins the agent's user
/// namespace, whose owner gets full capabilities over the uid-block
/// files, and runs the filesystem operation the agent itself may not.
pub fn fs_helper_stage() -> ! {
    fn run() -> Result<()> {
        let mut args = std::env::args_os().skip(2);
        let ns = fs::File::open(args.next().context("missing userns path")?)?;
        let op = args.next().context("missing op")?;
        move_into_link_name_space(ns.as_fd(), Some(LinkNameSpaceType::User))
            .context("joining the agent user namespace")?;
        if op.to_str() == Some("unpack") {
            // Become in-ns root so the unpacked files belong to the
            // uid block instead of the agent's unmapped uid.
            set_thread_gid(Gid::from_raw(0)).context("setgid 0 in the ns")?;
            set_thread_uid(Uid::from_raw(0)).context("setuid 0 in the ns")?;
            let build_dir = PathBuf::from(args.next().context("missing build dir")?);
            return super::stage_scratch(std::io::stdin(), &build_dir);
        }
        for path in args {
            let path = Path::new(&path);
            match op.to_str() {
                Some("make-readable") => super::make_readable(path),
                Some("remove") => {
                    let _ = fs::remove_dir_all(path);
                    let _ = fs::remove_file(path);
                }
                _ => bail!("unknown op {}", op.to_string_lossy()),
            }
        }
        Ok(())
    }
    match run() {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("agent fs helper: {e:#}");
            std::process::exit(1);
        }
    }
}

/// Confinement hook of the direct-exec path (no sandbox spec):
/// seatbelt-profile requests have no Linux equivalent there.
pub(super) fn confine(_cmd: &mut Command, req: &StartRequest, _build_dir: &str) -> Result<()> {
    ensure!(
        req.profile.is_empty(),
        "seatbelt profiles are only supported on macOS"
    );
    Ok(())
}

impl Userns {
    /// Create the agent's user namespace, map `0 uid_base 65536` into
    /// it and drop the ambient/permitted capabilities that allowed
    /// the map write.
    fn create(uid_base: u32) -> Result<Self> {
        let (holder, fd) = UsernsHolder::new().context("creating the agent user namespace")?;
        let map = format!("0 {uid_base} {UID_COUNT}");
        let pid = holder.pid();
        fs::write(format!("/proc/{pid}/uid_map"), &map)
            .context("writing the agent uid_map, which needs ambient CAP_SETUID")?;
        fs::write(format!("/proc/{pid}/gid_map"), &map)
            .context("writing the agent gid_map, which needs ambient CAP_SETGID")?;
        drop_caps().context("dropping capabilities after the uid map write")?;
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
    rustix::thread::clear_ambient_capability_set().context("clearing the ambient set")?;
    rustix::thread::set_capabilities(
        None,
        rustix::thread::CapabilitySets {
            effective: rustix::thread::CapabilitySet::CHOWN,
            permitted: rustix::thread::CapabilitySet::CHOWN,
            inheritable: rustix::thread::CapabilitySet::empty(),
        },
    )
    .context("reducing the capability sets")?;
    Ok(())
}

/// systemd-activated listener (the socket unit's fd), or None when not
/// socket-activated. The shared adoption helper serves the async hub
/// and marks the fd non-blocking; the agent's accept loop is
/// synchronous.
pub(super) fn activated_unix_listener() -> Result<Option<UnixListener>> {
    let listener = crate::sd::activated_sockets()?.unix;
    if let Some(l) = &listener {
        l.set_nonblocking(false)?;
    }
    Ok(listener)
}

pub(super) fn peer_uid(conn: &UnixStream) -> Result<u32> {
    Ok(socket_peercred(conn)?.uid.as_raw())
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
