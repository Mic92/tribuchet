//! Linux side of the agent: systemd socket activation and the
//! /proc-based uid sweep. Builds are not yet confined here; the
//! namespace sandbox moves in from the worker's setup stage next.

use std::fs;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Command;

use anyhow::{Result, ensure};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use sandbox_proto::agent::StartRequest;

/// systemd-activated listener (the socket unit's fd), or None when not
/// socket-activated.
pub(super) fn activated_unix_listener() -> Result<Option<UnixListener>> {
    Ok(crate::sd::activated_sockets()?.unix)
}

pub(super) fn peer_uid(conn: &UnixStream) -> Result<u32> {
    Ok(getsockopt(conn, PeerCredentials)?.uid())
}

pub(super) fn confine(_cmd: &mut Command, req: &StartRequest, _build_dir: &str) -> Result<()> {
    ensure!(
        req.profile.is_empty(),
        "seatbelt profiles are only supported on macOS"
    );
    Ok(())
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
