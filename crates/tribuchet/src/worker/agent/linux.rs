//! Linux side of the agent: systemd socket activation, the
//! /proc-based uid sweep and the agent's pre-mapped user namespace.
//!
//! At startup the agent creates a user namespace mapping in-ns
//! 0..65536 to its uid block. Writing another namespace's uid_map
//! needs CAP_SETUID in the parent namespace, so the agent unit runs
//! with AmbientCapabilities=CAP_SETUID CAP_SETGID and the caps are
//! dropped right after the write. Sandboxed builds join that
//! namespace via the worker's setup stage, spawned here.

use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use anyhow::{Context, Result, bail, ensure};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use sandbox_proto::agent::StartRequest;

use super::{Build, Options};
use crate::worker::sandbox::{self, SandboxSpec};
use crate::worker::userns::{self, UsernsHolder};

/// Argv[1] marker of the re-exec'd userns filesystem helper.
pub const FS_HELPER_ARG: &str = "__agent_fs";

/// Uids mapped into the agent's user namespace: enough for uid-range
/// (nspawn) builds, single-uid builds nest a 1-uid map inside it.
const UID_COUNT: u32 = 65536;

/// Per-agent confinement state: the pre-mapped user namespace backing
/// every build this agent runs. None without `--uid-base` (development
/// runs and containers without a uid block).
pub(super) struct Confinement {
    userns: Option<Userns>,
}

struct Userns {
    /// Pausing child that keeps the namespace alive.
    holder: UsernsHolder,
    fd: OwnedFd,
    uid_base: u32,
}

impl Confinement {
    pub(super) fn init(opts: &Options) -> Result<Self> {
        Ok(Self {
            userns: opts.uid_base.map(Userns::create).transpose()?,
        })
    }

    /// The userns holder must survive the kill sweep.
    pub(super) fn exempt_pid(&self) -> Option<i32> {
        self.userns.as_ref().map(|ns| ns.holder.pid().as_raw())
    }
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
    let Some(sandbox_json) = &req.sandbox else {
        return Ok((super::spawn_plain(req, build_dir, log)?, None));
    };
    let userns = confinement
        .userns
        .as_ref()
        .context("sandboxed build requested but the agent has no --uid-base")?;
    let mut spec: SandboxSpec =
        serde_json::from_value(sandbox_json.clone()).context("decoding the sandbox spec")?;
    spec.root = scratch_root.join("root");
    spec.build_dir = build_dir.to_path_buf();
    spec.leased_userns = Some(userns::ns_path(&userns.fd));
    spec.leased_uid_count = Some(UID_COUNT);
    spec.pool_base = Some(userns.uid_base);
    // No delegated per-build cgroup on the agent path.
    spec.cgroup = None;
    sandbox::prepare_root(&mut spec).context("creating the sandbox root skeleton")?;
    let (child, spec_w) = sandbox::spawn(&spec, log)?;
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

/// Remove a build's scratch tree and stray outputs. A namespace
/// build's tree contains uid-block files only deletable inside the
/// userns; its outputs live under that tree.
pub(super) fn cleanup(confinement: &Confinement, build: &Build) {
    if build.sandbox_root.is_some() {
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
    let status = Command::new(exe)
        .arg(FS_HELPER_ARG)
        .arg(userns::ns_path(&userns.fd))
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
        nix::sched::setns(ns, nix::sched::CloneFlags::CLONE_NEWUSER)
            .context("joining the agent user namespace")?;
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

/// Drop every capability of the agent process; nothing after the map
/// write needs privilege.
fn drop_caps() -> Result<()> {
    rustix::thread::clear_ambient_capability_set().context("clearing the ambient set")?;
    rustix::thread::set_capabilities(
        None,
        rustix::thread::CapabilitySets {
            effective: rustix::thread::CapabilitySet::empty(),
            permitted: rustix::thread::CapabilitySet::empty(),
            inheritable: rustix::thread::CapabilitySet::empty(),
        },
    )
    .context("clearing the capability sets")?;
    Ok(())
}

/// systemd-activated listener (the socket unit's fd), or None when not
/// socket-activated.
pub(super) fn activated_unix_listener() -> Result<Option<UnixListener>> {
    Ok(crate::sd::activated_sockets()?.unix)
}

pub(super) fn peer_uid(conn: &UnixStream) -> Result<u32> {
    Ok(getsockopt(conn, PeerCredentials)?.uid())
}

/// Pids whose real uid is this uid, from /proc.
pub(super) fn own_uid_pids() -> Vec<i32> {
    let uid = nix::unistd::getuid().as_raw();
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
