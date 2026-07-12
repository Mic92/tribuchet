//! Varlink client for systemd-nsresourced (io.systemd.NamespaceResource).
//!
//! Lets an unprivileged worker lease transient UID/GID ranges: the worker
//! creates an unmapped user namespace and nsresourced writes the uid/gid
//! maps for a range it allocates.

use std::io::{IoSlice, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{Context, Result, bail};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use serde_json::json;

pub const SOCKET_PATH: &str = "/run/systemd/io.systemd.NamespaceResource";

/// A user namespace with a UID/GID range delegated by nsresourced.
///
/// The fd pins the namespace and with it the leased range; dropping the
/// lease releases both (once no build process uses the namespace
/// anymore).
#[derive(Debug)]
pub struct UsernsLease {
    userns: OwnedFd,
    /// Name registered with nsresourced (shows up in NSS as `ns-<name>-…`).
    pub name: String,
}

impl UsernsLease {
    /// Path under which other processes of this user (the reaper-spawned
    /// sandbox setup stage) can open and setns() into the namespace.
    pub fn ns_path(&self) -> std::path::PathBuf {
        format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            self.userns.as_raw_fd()
        )
        .into()
    }
}

/// Whether nsresourced is running and willing to delegate ranges (it
/// refuses when its BPF-LSM support is missing).
pub fn available(socket: &Path) -> bool {
    if !socket.exists() {
        return false;
    }
    allocate_user_range(socket, "tribuchet-probe", 65536, 0).is_ok()
}

/// Allocate a `size`-uid range (1 or 65536) mapped at `target` inside a
/// fresh user namespace owned by this process.
pub fn allocate_user_range(
    socket: &Path,
    name: &str,
    size: u32,
    target: u32,
) -> Result<UsernsLease> {
    let userns = unmapped_userns().context("create unmapped user namespace")?;
    let reply = call(
        socket,
        "io.systemd.NamespaceResource.AllocateUserRange",
        &json!({
            "name": name,
            "mangleName": true,
            "size": size,
            "target": target,
            "userNamespaceFileDescriptor": 0,
        }),
        &[userns.as_raw_fd()],
    )?;
    let name = reply
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(name)
        .to_owned();
    Ok(UsernsLease { userns, name })
}

/// Hand ownership of the build's cgroup to the leased namespace's root
/// (replaces the chown a root worker does); nsresourced also removes
/// the cgroup when the namespace is released. Call only after entering
/// the cgroup: delegation takes cgroup.procs away from the worker uid.
pub fn add_cgroup_to_userns(socket: &Path, userns: &Path, cgroup: &Path) -> Result<()> {
    let ns =
        std::fs::File::open(userns).with_context(|| format!("open userns {}", userns.display()))?;
    let cg =
        std::fs::File::open(cgroup).with_context(|| format!("open cgroup {}", cgroup.display()))?;
    call(
        socket,
        "io.systemd.NamespaceResource.AddControlGroupToUserNamespace",
        &json!({
            "userNamespaceFileDescriptor": 0,
            "controlGroupFileDescriptor": 1,
        }),
        &[ns.as_raw_fd(), cg.as_raw_fd()],
    )?;
    Ok(())
}

/// One varlink method call: JSON + NUL over a unix socket, request fds
/// attached via SCM_RIGHTS (referenced by index in the parameters).
fn call(
    socket: &Path,
    method: &str,
    parameters: &serde_json::Value,
    fds: &[std::os::fd::RawFd],
) -> Result<serde_json::Value> {
    let mut conn =
        UnixStream::connect(socket).with_context(|| format!("connect to {}", socket.display()))?;

    let mut msg = serde_json::to_vec(&json!({ "method": method, "parameters": parameters }))?;
    msg.push(0);
    let sent = sendmsg::<()>(
        conn.as_raw_fd(),
        &[IoSlice::new(&msg)],
        &[ControlMessage::ScmRights(fds)],
        MsgFlags::empty(),
        None,
    )
    .context("send varlink request")?;
    if sent < msg.len() {
        conn.write_all(&msg[sent..])?;
    }

    let mut reply = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = conn.read(&mut buf)?;
        if n == 0 {
            bail!("varlink connection closed before reply");
        }
        reply.extend_from_slice(&buf[..n]);
        if let Some(end) = reply.iter().position(|&b| b == 0) {
            reply.truncate(end);
            break;
        }
    }
    let reply: serde_json::Value = serde_json::from_slice(&reply).context("parse varlink reply")?;
    if let Some(error) = reply.get("error").and_then(|e| e.as_str()) {
        bail!(
            "{method} failed: {error} {}",
            reply.get("parameters").unwrap_or(&json!({}))
        );
    }
    Ok(reply.get("parameters").cloned().unwrap_or(json!({})))
}

/// A user namespace with no UID assignments, owned by this process. Forks
/// because unshare(CLONE_NEWUSER) fails with EINVAL in a multithreaded
/// process; the child runs only async-signal-safe syscalls and is killed
/// once the parent has pinned the namespace with an fd. No pipe holds the
/// child open: a concurrently forked sibling would inherit the write end
/// and keep it (and us) waiting forever.
fn unmapped_userns() -> Result<OwnedFd> {
    use nix::unistd::{self, ForkResult};
    let (sync_r, sync_w) = unistd::pipe()?;
    match unsafe { unistd::fork() }? {
        ForkResult::Child => {
            if nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUSER).is_err() {
                unsafe { libc::_exit(1) }
            }
            let _ = unistd::write(&sync_w, b"u");
            loop {
                unsafe { libc::pause() };
            }
        }
        ForkResult::Parent { child } => {
            drop(sync_w);
            let unshared = unistd::read(&sync_r, &mut [0u8; 1]) == Ok(1);
            let userns = if unshared {
                std::fs::File::open(format!("/proc/{child}/ns/user"))
                    .map(OwnedFd::from)
                    .context("open child user namespace")
            } else {
                Err(anyhow::anyhow!("child failed to unshare a user namespace"))
            };
            let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(child, None);
            userns
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    /// Mock nsresourced: reads one request, asserts an fd arrived, replies.
    fn mock_server(
        listener: UnixListener,
        reply: &'static str,
    ) -> std::thread::JoinHandle<serde_json::Value> {
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut fds = [0i32; 1];
            let mut buf = vec![0u8; 4096];
            let mut iov = [std::io::IoSliceMut::new(&mut buf)];
            let mut cmsg = nix::cmsg_space!([std::os::fd::RawFd; 1]);
            let msg = nix::sys::socket::recvmsg::<()>(
                conn.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg),
                MsgFlags::empty(),
            )
            .unwrap();
            let n = msg.bytes;
            for c in msg.cmsgs().unwrap() {
                if let nix::sys::socket::ControlMessageOwned::ScmRights(r) = c {
                    fds[..r.len()].copy_from_slice(&r);
                }
            }
            let request: serde_json::Value = serde_json::from_slice(&buf[..n - 1]).unwrap();
            assert!(fds[0] > 0, "no userns fd passed");
            conn.write_all(reply.as_bytes()).unwrap();
            conn.write_all(&[0]).unwrap();
            request
        })
    }

    #[test]
    fn allocate_user_range_call() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let server = mock_server(listener, r#"{"parameters":{"name":"mangled"}}"#);

        let lease = allocate_user_range(&path, "test", 65536, 0).unwrap();
        assert_eq!(lease.name, "mangled");
        assert!(lease.userns.as_raw_fd() >= 0);

        let request = server.join().unwrap();
        assert_eq!(
            request["method"],
            "io.systemd.NamespaceResource.AllocateUserRange"
        );
        assert_eq!(request["parameters"]["size"], 65536);
        assert_eq!(request["parameters"]["userNamespaceFileDescriptor"], 0);
    }

    #[test]
    fn error_reply_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        mock_server(
            listener,
            r#"{"error":"io.systemd.NamespaceResource.DynamicRangeUnavailable"}"#,
        );

        let err = allocate_user_range(&path, "test", 65536, 0).unwrap_err();
        assert!(err.to_string().contains("DynamicRangeUnavailable"), "{err}");
    }

    #[test]
    fn missing_socket_is_unavailable() {
        assert!(!available(Path::new("/nonexistent/socket")));
    }
}
