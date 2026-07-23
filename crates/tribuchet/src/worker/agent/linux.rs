//! Linux side of the agent: systemd socket activation, the
//! /proc-based uid sweep and the agent's pre-mapped user namespace.
//!
//! At startup the agent creates a user namespace mapping in-ns
//! 0..65536 to its uid block. Writing another namespace's uid_map
//! needs CAP_SETUID in the parent namespace, so the agent unit runs
//! with AmbientCapabilities=CAP_SETUID CAP_SETGID and the caps are
//! dropped right after the write. Builds do not yet run inside the
//! namespace; that sandbox setup still lives in the worker.

use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use sandbox_proto::agent::StartRequest;

use super::Options;
use crate::worker::userns::UsernsHolder;

/// Uids mapped into the agent's user namespace: enough for uid-range
/// (nspawn) builds, single-uid builds nest a 1-uid map inside it.
const UID_COUNT: u32 = 65536;

/// Per-agent confinement state: the pre-mapped user namespace backing
/// every build this agent runs. None without `--uid-base` (development
/// runs and containers without a uid block).
pub(super) struct Confinement {
    _userns: Option<Userns>,
}

struct Userns {
    /// Pausing child that keeps the namespace alive.
    holder: UsernsHolder,
    _fd: OwnedFd,
    _uid_base: u32,
}

impl Confinement {
    pub(super) fn init(opts: &Options) -> Result<Self> {
        Ok(Self {
            _userns: opts.uid_base.map(Userns::create).transpose()?,
        })
    }

    /// The userns holder must survive the kill sweep.
    pub(super) fn exempt_pid(&self) -> Option<i32> {
        self.userns.as_ref().map(|ns| ns.holder.pid().as_raw())
    }
}

/// Builder confinement hook; the namespace sandbox is not applied
/// yet, only seatbelt-profile requests are rejected.
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
            _fd: fd,
            _uid_base: uid_base,
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
