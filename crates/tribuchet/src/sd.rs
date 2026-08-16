//! Service-manager integration: socket activation (systemd LISTEN_FDS
//! and launchd's launch_activate_socket) and readiness/watchdog
//! notification. Every function degrades to a no-op outside the
//! respective service manager, so plain CLI runs are unaffected.

#[cfg(target_os = "macos")]
use std::ffi::CString;
use std::io;
use std::net::TcpListener;
use std::os::fd::{BorrowedFd, FromRawFd as _, RawFd};
use std::os::unix::net::UnixListener;
use std::time::Duration;
use std::{env, future, process};
#[cfg(target_os = "macos")]
use std::{ptr, slice};

use rustix::net::{AddressFamily, getsockname};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("inspecting LISTEN_FDS")]
    ListenFds(#[source] io::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("more than one activated TCP socket")]
    MultipleTcp,
    #[error("more than one activated unix socket")]
    MultipleUnix,
    #[error("activated socket fd {fd} has unsupported family {family:?}")]
    UnsupportedFamily { fd: RawFd, family: AddressFamily },
    #[error("getsockname on activated fd {fd}")]
    Sockname {
        fd: RawFd,
        #[source]
        source: rustix::io::Errno,
    },
    #[cfg(target_os = "macos")]
    #[error("launch_activate_socket({0})")]
    LaunchActivate(String, #[source] io::Error),
    #[cfg(target_os = "macos")]
    #[error("launchd socket {0} is not a unix socket")]
    LaunchdNotUnix(String),
}

/// Listeners handed over by systemd socket activation, classified by
/// address family. Holding the listening sockets in systemd keeps them
/// accepting across hub restarts: clients queue instead of getting
/// ECONNREFUSED.
#[derive(Default)]
pub struct ActivatedSockets {
    pub tcp: Option<TcpListener>,
    pub unix: Option<UnixListener>,
}

/// Claim activated sockets, at most one TCP and one unix listener.
pub fn activated_sockets() -> Result<ActivatedSockets, Error> {
    let mut out = ActivatedSockets::default();
    for fd in sd_notify::listen_fds().map_err(Error::ListenFds)? {
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
    fn adopt(&mut self, fd: RawFd) -> Result<(), Error> {
        match socket_family(fd)? {
            AddressFamily::INET | AddressFamily::INET6 => {
                if self.tcp.is_some() {
                    return Err(Error::MultipleTcp);
                }
                // Safety: the service manager passed this fd for us to own.
                let l = unsafe { TcpListener::from_raw_fd(fd) };
                l.set_nonblocking(true)?;
                self.tcp = Some(l);
            }
            AddressFamily::UNIX => {
                if self.unix.is_some() {
                    return Err(Error::MultipleUnix);
                }
                // Safety: the service manager passed this fd for us to own.
                let l = unsafe { UnixListener::from_raw_fd(fd) };
                l.set_nonblocking(true)?;
                self.unix = Some(l);
            }
            family => return Err(Error::UnsupportedFamily { fd, family }),
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
fn launchd_sockets(out: &mut ActivatedSockets) -> Result<(), Error> {
    for name in ["attach", "workers"] {
        for fd in launchd_socket_fds(name)? {
            out.adopt(fd)?;
        }
    }
    Ok(())
}

/// The blocking unix listener launchd holds under `name` in the
/// plist's `Sockets` dictionary, or None when not launchd-activated.
#[cfg(target_os = "macos")]
pub fn launchd_unix_listener(name: &str) -> Result<Option<UnixListener>, Error> {
    let Some(fd) = launchd_socket_fds(name)?.into_iter().next() else {
        return Ok(None);
    };
    if socket_family(fd)? != AddressFamily::UNIX {
        return Err(Error::LaunchdNotUnix(name.to_owned()));
    }
    // Safety: launchd passed this fd for us to own.
    Ok(Some(unsafe { UnixListener::from_raw_fd(fd) }))
}

/// Fds launchd holds under `name`, empty when not running under
/// launchd or the plist declares no such socket.
#[cfg(target_os = "macos")]
fn launchd_socket_fds(name: &str) -> Result<Vec<RawFd>, Error> {
    unsafe extern "C" {
        fn launch_activate_socket(
            name: *const libc::c_char,
            fds: *mut *mut libc::c_int,
            cnt: *mut libc::size_t,
        ) -> libc::c_int;
    }
    let cname = CString::new(name).unwrap();
    let mut fds: *mut libc::c_int = ptr::null_mut();
    let mut cnt: libc::size_t = 0;
    let rc = unsafe { launch_activate_socket(cname.as_ptr(), &raw mut fds, &raw mut cnt) };
    match rc {
        0 => {}
        libc::ESRCH | libc::ENOENT => return Ok(Vec::new()),
        _ => {
            return Err(Error::LaunchActivate(
                name.to_owned(),
                io::Error::from_raw_os_error(rc),
            ));
        }
    }
    if fds.is_null() || cnt == 0 {
        return Ok(Vec::new());
    }
    let out = unsafe { slice::from_raw_parts(fds, cnt) }.to_vec();
    // launch_activate_socket allocates the fd array with malloc.
    unsafe { libc::free(fds.cast()) };
    Ok(out)
}

fn socket_family(fd: RawFd) -> Result<AddressFamily, Error> {
    // SAFETY: the service manager passed this fd; it stays open here.
    let sockfd = unsafe { BorrowedFd::borrow_raw(fd) };
    let addr = getsockname(sockfd).map_err(|source| Error::Sockname { fd, source })?;
    Ok(addr.address_family())
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
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("installing the SIGTERM handler failed, graceful stop disabled: {e}");
            return future::pending().await;
        }
    };
    term.recv().await;
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Stopping]);
}

/// Keep the systemd watchdog fed (WatchdogSec=); a wedged runtime
/// stops the pings and gets the service killed and restarted.
pub fn spawn_watchdog() {
    let Some(timeout) = env::var("WATCHDOG_USEC")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_micros)
        .filter(|_| {
            env::var("WATCHDOG_PID")
                .ok()
                .is_none_or(|p| p == process::id().to_string())
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
