//! systemd integration: socket activation and readiness/watchdog
//! notification. Every function degrades to a no-op outside systemd
//! (no NOTIFY_SOCKET / LISTEN_FDS), so plain CLI runs are unaffected.

use std::os::fd::{FromRawFd as _, RawFd};

use anyhow::{bail, Context, Result};

/// Listeners handed over by systemd socket activation, classified by
/// address family. Holding the listening sockets in systemd keeps them
/// accepting across hub restarts: clients queue instead of getting
/// ECONNREFUSED.
#[derive(Default)]
pub struct ActivatedSockets {
    pub tcp: Option<std::net::TcpListener>,
    pub unix: Option<std::os::unix::net::UnixListener>,
}

/// Claim activated sockets, at most one TCP and one unix listener.
pub fn activated_sockets() -> Result<ActivatedSockets> {
    let mut out = ActivatedSockets::default();
    let fds = sd_notify::listen_fds().context("inspecting LISTEN_FDS")?;
    for fd in fds {
        match socket_family(fd)? {
            libc::AF_INET | libc::AF_INET6 => {
                if out.tcp.is_some() {
                    bail!("more than one activated TCP socket");
                }
                // Safety: systemd passed this fd for us to own.
                let l = unsafe { std::net::TcpListener::from_raw_fd(fd) };
                l.set_nonblocking(true)?;
                out.tcp = Some(l);
            }
            libc::AF_UNIX => {
                if out.unix.is_some() {
                    bail!("more than one activated unix socket");
                }
                // Safety: systemd passed this fd for us to own.
                let l = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
                l.set_nonblocking(true)?;
                out.unix = Some(l);
            }
            family => bail!("activated socket fd {fd} has unsupported family {family}"),
        }
    }
    Ok(out)
}

fn socket_family(fd: RawFd) -> Result<libc::c_int> {
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let rc = unsafe { libc::getsockname(fd, &mut addr as *mut _ as *mut libc::sockaddr, &mut len) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("getsockname on activated fd {fd}"));
    }
    Ok(addr.ss_family as libc::c_int)
}

/// Tell systemd (Type=notify) that startup finished. Restarts become
/// reliable: systemd only considers the old instance replaced once the
/// new one is actually serving.
pub fn notify_ready() {
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
}

/// Keep the systemd watchdog fed (WatchdogSec=); a wedged runtime
/// stops the pings and gets the service killed and restarted.
pub fn spawn_watchdog() {
    let Some(timeout) = sd_notify::watchdog_enabled() else {
        return;
    };
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(timeout / 2);
        loop {
            tick.tick().await;
            let _ = sd_notify::notify(&[sd_notify::NotifyState::Watchdog]);
        }
    });
}
