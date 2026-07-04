//! Service-manager integration: socket activation (systemd LISTEN_FDS
//! and launchd's launch_activate_socket) and readiness/watchdog
//! notification. Every function degrades to a no-op outside the
//! respective service manager, so plain CLI runs are unaffected.

use std::net::TcpListener;
use std::os::fd::{FromRawFd as _, RawFd};

use anyhow::{Context, Result, bail};
use nix::sys::socket;

/// Listeners handed over by systemd socket activation, classified by
/// address family. Holding the listening sockets in systemd keeps them
/// accepting across hub restarts: clients queue instead of getting
/// ECONNREFUSED.
#[derive(Default)]
pub struct ActivatedSockets {
    pub tcp: Option<TcpListener>,
    pub unix: Option<std::os::unix::net::UnixListener>,
}

/// Claim activated sockets, at most one TCP and one unix listener.
pub fn activated_sockets() -> Result<ActivatedSockets> {
    let mut out = ActivatedSockets::default();
    for fd in sd_notify::listen_fds().context("inspecting LISTEN_FDS")? {
        out.adopt(fd)?;
    }
    #[cfg(target_os = "macos")]
    if out.tcp.is_none() && out.unix.is_none() {
        launchd_sockets(&mut out)?;
    }
    if out.tcp.is_some() || out.unix.is_some() {
        tracing::info!(
            tcp = out.tcp.is_some(),
            unix = out.unix.is_some(),
            "adopted activated sockets"
        );
    }
    Ok(out)
}

impl ActivatedSockets {
    /// Take ownership of one activated listener fd, classified by
    /// address family.
    fn adopt(&mut self, fd: RawFd) -> Result<()> {
        use socket::AddressFamily;
        match socket_family(fd)? {
            Some(AddressFamily::Inet | AddressFamily::Inet6) => {
                if self.tcp.is_some() {
                    bail!("more than one activated TCP socket");
                }
                // Safety: the service manager passed this fd for us to own.
                let l = unsafe { TcpListener::from_raw_fd(fd) };
                l.set_nonblocking(true)?;
                self.tcp = Some(l);
            }
            Some(AddressFamily::Unix) => {
                if self.unix.is_some() {
                    bail!("more than one activated unix socket");
                }
                // Safety: the service manager passed this fd for us to own.
                let l = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
                l.set_nonblocking(true)?;
                self.unix = Some(l);
            }
            family => bail!("activated socket fd {fd} has unsupported family {family:?}"),
        }
        Ok(())
    }
}

/// Adopt listeners launchd holds for this daemon (named "attach" and
/// "workers" in the plist's `Sockets` dictionary, the analogue of a
/// systemd .socket unit), so hub restarts keep the sockets accepting
/// and clients queue in launchd instead of seeing ECONNREFUSED.
/// No-op when not launched by launchd or the plist declares no
/// sockets.
#[cfg(target_os = "macos")]
fn launchd_sockets(out: &mut ActivatedSockets) -> Result<()> {
    unsafe extern "C" {
        fn launch_activate_socket(
            name: *const libc::c_char,
            fds: *mut *mut libc::c_int,
            cnt: *mut libc::size_t,
        ) -> libc::c_int;
    }
    for name in ["attach", "workers"] {
        let cname = std::ffi::CString::new(name).unwrap();
        let mut fds: *mut libc::c_int = std::ptr::null_mut();
        let mut cnt: libc::size_t = 0;
        let rc = unsafe { launch_activate_socket(cname.as_ptr(), &raw mut fds, &raw mut cnt) };
        match rc {
            0 => {}
            // Not running under launchd, or no socket of this name in
            // the plist: fall back to self-binding.
            libc::ESRCH | libc::ENOENT => continue,
            _ => {
                return Err(std::io::Error::from_raw_os_error(rc))
                    .with_context(|| format!("launch_activate_socket({name})"));
            }
        }
        if fds.is_null() || cnt == 0 {
            continue;
        }
        let adopted: Result<()> = (|| {
            for &fd in unsafe { std::slice::from_raw_parts(fds, cnt) } {
                out.adopt(fd)?;
            }
            Ok(())
        })();
        // launch_activate_socket allocates the fd array with malloc.
        unsafe { libc::free(fds.cast()) };
        adopted?;
    }
    Ok(())
}

fn socket_family(fd: RawFd) -> Result<Option<socket::AddressFamily>> {
    use socket::SockaddrLike;
    let addr: socket::SockaddrStorage =
        socket::getsockname(fd).with_context(|| format!("getsockname on activated fd {fd}"))?;
    Ok(addr.family())
}

/// Tell systemd (Type=notify) that startup finished. Restarts become
/// reliable: systemd only considers the old instance replaced once the
/// new one is actually serving.
pub fn notify_ready() {
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
}

/// Resolves on SIGTERM, after telling systemd shutdown started
/// ("deactivating" in systemctl status instead of an apparently hung
/// stop while builds drain). Never resolves if no handler can be
/// installed.
pub async fn stop_requested() {
    let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        return std::future::pending().await;
    };
    term.recv().await;
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Stopping]);
}

/// Keep the systemd watchdog fed (WatchdogSec=); a wedged runtime
/// stops the pings and gets the service killed and restarted.
pub fn spawn_watchdog() {
    // Not sd_notify::watchdog_enabled(): that insists WATCHDOG_PID ==
    // getpid(), but the worker is a fork below the main pid (the build
    // reaper). systemd accepts WATCHDOG=1 from any unit process under
    // NotifyAccess=all, so accept our parent's pid too.
    let Some(timeout) = std::env::var("WATCHDOG_USEC")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(std::time::Duration::from_micros)
        .filter(|_| {
            std::env::var("WATCHDOG_PID").map_or(true, |p| {
                p == std::process::id().to_string()
                    || p == nix::unistd::getppid().as_raw().to_string()
            })
        })
    else {
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
