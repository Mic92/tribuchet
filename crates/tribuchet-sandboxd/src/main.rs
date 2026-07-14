//! tribuchet-sandboxd: root daemon that leases per-build sandboxes to an
//! unprivileged tribuchet worker.
//!
//! Per lease it writes uid/gid maps into a worker-created user
//! namespace, hands back a delegated build cgroup, and tears both down
//! when the lease connection closes. See crates/sandbox-proto for the
//! wire protocol.

mod lease;
mod pool;

use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use nix::sys::socket::{UnixCredentials, getsockopt, sockopt::PeerCredentials};
use nix::unistd::{Gid, Pid, Uid, User};
use sandbox_proto::{AllocateReply, AllocateRequest, METHOD_ALLOCATE};

#[derive(Parser)]
struct Args {
    /// Unix socket to listen on (systemd socket activation wins if set).
    #[arg(long, default_value = sandbox_proto::SOCKET_PATH)]
    socket: PathBuf,
    /// User the worker runs as; only this uid may request leases.
    #[arg(long, default_value = "tribuchet")]
    worker_user: String,
    /// First uid of the pool handed to builds; the default starts
    /// right after nix-daemon's auto-allocate-uids range so the two
    /// never hand out the same uids on one host.
    #[arg(long, default_value_t = 1_325_400_064)]
    pool_start: u32,
    /// Number of 65536-uid blocks in the pool (max concurrent leases);
    /// the default matches nix-daemon's id-count.
    #[arg(long, default_value_t = 6912)]
    pool_blocks: u32,
}

struct Daemon {
    worker: User,
    pool: Mutex<pool::UidPool>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().init();
    let args = Args::parse();
    ensure!(
        nix::unistd::geteuid().is_root(),
        "sandboxd must run as root"
    );

    let worker = User::from_name(&args.worker_user)?
        .with_context(|| format!("no such user: {}", args.worker_user))?;
    let daemon = Arc::new(Daemon {
        worker,
        pool: Mutex::new(pool::UidPool::new(args.pool_start, args.pool_blocks)),
    });

    let listener = listener(&args.socket)?;
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
    tracing::info!(socket = %args.socket.display(), "listening");

    for conn in listener.incoming() {
        let conn = conn.context("accepting connection")?;
        let daemon = daemon.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle(&daemon, &conn) {
                tracing::warn!("lease failed: {e:#}");
                let _ = sandbox_proto::send_error(&conn, &format!("{e:#}"));
            }
        });
    }
    Ok(())
}

/// Socket-activated listener if systemd passed one, otherwise bind.
fn listener(path: &std::path::Path) -> Result<UnixListener> {
    if let Some(fd) = sd_notify::listen_fds()?.next() {
        return Ok(unsafe { UnixListener::from_raw_fd(fd) });
    }
    let _ = std::fs::remove_file(path);
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    // access control is the SO_PEERCRED check, not the socket mode
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

/// One lease: allocate on request, tear down when the build's cgroup
/// has drained (or the worker gave up before spawning into it).
fn handle(daemon: &Daemon, conn: &UnixStream) -> Result<()> {
    let peer: UnixCredentials = getsockopt(conn, PeerCredentials)?;
    ensure!(
        peer.uid() == daemon.worker.uid.as_raw(),
        "connection from uid {}, only the worker uid {} may lease",
        peer.uid(),
        daemon.worker.uid
    );

    let (method, request, fds): (_, AllocateRequest, _) = sandbox_proto::recv_call(conn)?;
    ensure!(method == METHOD_ALLOCATE, "unknown method {method}");
    ensure!(
        matches!(request.uid_count, 1 | 65536),
        "uid_count must be 1 or 65536"
    );
    let mut fds = fds.into_iter();
    let userns = fds.next().context("missing userns fd")?;
    let pidfd = fds.next().context("missing pidfd")?;
    let stage_fd = fds.next().context("missing setup-stage pidfd")?;
    let tmp_dir = fds.next().context("missing tmp dir fd")?;

    let holder = lease::pidfd_pid(pidfd.as_fd())?;
    lease::verify_userns(holder, userns.as_fd())?;

    let base = daemon
        .pool
        .lock()
        .unwrap()
        .allocate()
        .context("uid pool exhausted")?;

    let mut leaked = false;
    let result = (|| {
        lease::write_maps(holder, base, request.uid_count)?;
        lease::chown_tree(
            &tmp_dir,
            (Uid::from_raw(base), Gid::from_raw(base)),
            daemon.worker.uid,
        )
        .context("chowning the tmp dir")?;
        let cgroup = lease::create_cgroup(
            Pid::from_raw(peer.pid()),
            &request.build_id,
            base,
            daemon.worker.gid.as_raw(),
        )?;
        // From here the cgroup exists on disk; remove it on any early exit.
        let setup = (|| {
            lease::enter_cgroup(&cgroup, stage_fd.as_fd(), daemon.worker.uid)?;
            sandbox_proto::send_reply(
                conn,
                &AllocateReply { pool_base: base },
                &[cgroup.dir.as_raw_fd()],
            )
        })();
        if let Err(e) = setup {
            let _ = lease::destroy_cgroup(&cgroup);
            return Err(e);
        }
        tracing::info!(
            build = request.build_id,
            base,
            uid_count = request.uid_count,
            "leased"
        );

        // The build must survive worker restarts, so the connection
        // alone does not end the lease; the emptied cgroup does.
        let held = lease::wait_for_build_end(conn, &cgroup);

        // never reuse the block while build processes may still run
        if let Err(e) = lease::destroy_cgroup(&cgroup) {
            tracing::error!(build = request.build_id, "leaking uid block {base}: {e:#}");
            leaked = true;
        } else {
            tracing::info!(build = request.build_id, base, "released");
        }
        held
    })();
    if !leaked {
        daemon.pool.lock().unwrap().release(base);
    }
    result
}
