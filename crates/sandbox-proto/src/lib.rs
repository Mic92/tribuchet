//! Wire protocol between the tribuchet worker and tribuchet-sandboxd.
//!
//! Varlink-style framing (one JSON object, NUL-terminated) over a unix
//! stream socket, with file descriptors attached via SCM_RIGHTS. gRPC
//! cannot carry fds, hence the separate protocol.

use std::io::{IoSlice, IoSliceMut, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result, bail};
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use serde::{Deserialize, Serialize};

/// Default daemon socket; its presence is how the worker detects sandboxd.
pub const SOCKET_PATH: &str = "/run/tribuchet-sandboxd.sock";

pub const METHOD_ALLOCATE: &str = "com.tribuchet.Sandbox.Allocate";

/// Lease a per-build sandbox. Attached fds: the worker-created user
/// namespace (0), a pidfd of the process holding it (1), and a pidfd of
/// the sandbox setup stage (2). sandboxd maps the namespace, creates
/// the build cgroup, and moves the setup stage into it -- as root, so
/// the worker needs no write on any ancestor `cgroup.procs` and thus no
/// delegated subtree.
///
/// The reply carries [`AllocateReply`] with the delegated build cgroup
/// directory as fd 0. The lease ends when the build cgroup drains after
/// having been populated -- so builds survive worker restarts -- or when
/// the connection closes before anything ran in it; the daemon then
/// removes the cgroup and returns the uid range.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllocateRequest {
    pub build_id: String,
    /// Uids mapped into the namespace starting at in-ns 0: 1 for
    /// single-uid builds, 65536 for uid-range builds.
    pub uid_count: u32,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllocateReply {
    /// First host uid of the leased block (backs in-ns uid 0).
    pub pool_base: u32,
}

/// Send one varlink message: `{"method": ..., "parameters": ...}` for
/// calls, `{"parameters": ...}` for replies, `{"error": ...}` for errors.
fn send_message(sock: &UnixStream, message: &serde_json::Value, fds: &[RawFd]) -> Result<()> {
    let mut buf = serde_json::to_vec(message)?;
    buf.push(0);
    let iov = [IoSlice::new(&buf)];
    let cmsg = [ControlMessage::ScmRights(fds)];
    let sent = sendmsg::<()>(sock.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
        .context("sending message")?;
    if sent < buf.len() {
        (&mut &*sock).write_all(&buf[sent..])?;
    }
    Ok(())
}

/// Receive one NUL-terminated varlink message and any attached fds.
fn recv_message(sock: &UnixStream) -> Result<(serde_json::Value, Vec<OwnedFd>)> {
    let mut buf = vec![0u8; 4096];
    let mut cmsg_buf = nix::cmsg_space!([RawFd; 8]);
    let (n, fds) = {
        let mut iov = [IoSliceMut::new(&mut buf)];
        let msg = recvmsg::<()>(
            sock.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buf),
            MsgFlags::empty(),
        )
        .context("receiving message")?;
        let mut fds = Vec::new();
        for c in msg.cmsgs()? {
            if let ControlMessageOwned::ScmRights(received) = c {
                fds.extend(
                    received
                        .into_iter()
                        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }),
                );
            }
        }
        (msg.bytes, fds)
    };
    let end = buf[..n]
        .iter()
        .position(|&b| b == 0)
        .context("connection closed or unterminated message")?;
    let value = serde_json::from_slice(&buf[..end]).context("parsing message")?;
    Ok((value, fds))
}

/// Send a method call.
///
/// # Errors
/// Serialization or socket errors.
pub fn send_call<T: Serialize>(
    sock: &UnixStream,
    method: &str,
    parameters: &T,
    fds: &[RawFd],
) -> Result<()> {
    send_message(
        sock,
        &serde_json::json!({ "method": method, "parameters": parameters }),
        fds,
    )
}

/// Send a successful reply.
///
/// # Errors
/// Serialization or socket errors.
pub fn send_reply<T: Serialize>(sock: &UnixStream, parameters: &T, fds: &[RawFd]) -> Result<()> {
    send_message(sock, &serde_json::json!({ "parameters": parameters }), fds)
}

/// Send an error reply.
///
/// # Errors
/// Socket errors.
pub fn send_error(sock: &UnixStream, error: &str) -> Result<()> {
    send_message(sock, &serde_json::json!({ "error": error }), &[])
}

/// Receive a method call and deserialize its parameters.
///
/// # Errors
/// Socket errors, a closed connection, or a malformed call.
pub fn recv_call<T: for<'de> Deserialize<'de>>(
    sock: &UnixStream,
) -> Result<(String, T, Vec<OwnedFd>)> {
    let (value, fds) = recv_message(sock)?;
    let method = value
        .get("method")
        .and_then(|m| m.as_str())
        .context("call without method")?
        .to_owned();
    let parameters = serde_json::from_value(
        value
            .get("parameters")
            .cloned()
            .unwrap_or(serde_json::json!({})),
    )
    .context("parsing call parameters")?;
    Ok((method, parameters, fds))
}

/// Receive a reply; a varlink error becomes an `Err`.
///
/// # Errors
/// Socket errors, a closed connection, a malformed reply, or an error
/// reply from the peer.
pub fn recv_reply<T: for<'de> Deserialize<'de>>(sock: &UnixStream) -> Result<(T, Vec<OwnedFd>)> {
    let (value, fds) = recv_message(sock)?;
    if let Some(error) = value.get("error").and_then(|e| e.as_str()) {
        bail!("sandboxd: {error}");
    }
    let parameters = serde_json::from_value(
        value
            .get("parameters")
            .cloned()
            .unwrap_or(serde_json::json!({})),
    )
    .context("parsing reply parameters")?;
    Ok((parameters, fds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_roundtrip_with_fds() {
        let (a, b) = UnixStream::pair().unwrap();
        let devnull = std::fs::File::open("/dev/null").unwrap();
        let request = AllocateRequest {
            build_id: "b1".into(),
            uid_count: 65536,
        };
        send_call(&a, METHOD_ALLOCATE, &request, &[devnull.as_raw_fd()]).unwrap();

        let (method, received, fds): (_, AllocateRequest, _) = recv_call(&b).unwrap();
        assert_eq!(method, METHOD_ALLOCATE);
        assert_eq!(received, request);
        assert_eq!(fds.len(), 1);
    }

    #[test]
    fn reply_roundtrip() {
        let (a, b) = UnixStream::pair().unwrap();
        send_reply(
            &a,
            &AllocateReply {
                pool_base: 3_000_000,
            },
            &[],
        )
        .unwrap();
        let (reply, fds): (AllocateReply, _) = recv_reply(&b).unwrap();
        assert_eq!(reply.pool_base, 3_000_000);
        assert!(fds.is_empty());
    }

    #[test]
    fn error_reply_is_err() {
        let (a, b) = UnixStream::pair().unwrap();
        send_error(&a, "com.tribuchet.Sandbox.PoolExhausted").unwrap();
        let err = recv_reply::<AllocateReply>(&b).unwrap_err();
        assert!(err.to_string().contains("PoolExhausted"), "{err}");
    }

    #[test]
    fn closed_connection_is_err() {
        let (a, b) = UnixStream::pair().unwrap();
        drop(a);
        assert!(recv_reply::<AllocateReply>(&b).is_err());
    }
}
