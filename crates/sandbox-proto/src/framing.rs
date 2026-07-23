//! Length-prefixed JSON messages (u32 little-endian, then the object)
//! over a unix stream socket, with file descriptors attached via
//! SCM_RIGHTS. gRPC cannot carry fds, hence the separate protocol.

use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result, bail, ensure};
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use serde::{Deserialize, Serialize};

/// Peers are worker and agent on the same host; anything bigger than
/// this is a corrupted length prefix, not a real message.
const MAX_MESSAGE: usize = 64 * 1024 * 1024;

/// Send one message: `{"method": ..., "parameters": ...}` for calls,
/// `{"parameters": ...}` for replies, `{"error": ...}` for errors.
fn send_message(sock: &UnixStream, message: &serde_json::Value, fds: &[RawFd]) -> Result<()> {
    let body = serde_json::to_vec(message)?;
    let mut buf = (u32::try_from(body.len())?).to_le_bytes().to_vec();
    buf.extend_from_slice(&body);
    let iov = [IoSlice::new(&buf)];
    let cmsg = [ControlMessage::ScmRights(fds)];
    let sent = sendmsg::<()>(sock.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
        .context("sending message")?;
    if sent < buf.len() {
        (&mut &*sock).write_all(&buf[sent..])?;
    }
    Ok(())
}

/// Receive one message and any attached fds. Only the length prefix
/// and the message body are read, so the peer's next message stays
/// queued.
fn recv_message(sock: &UnixStream) -> Result<(serde_json::Value, Vec<OwnedFd>)> {
    let mut len_buf = [0u8; 4];
    let mut cmsg_buf = nix::cmsg_space!([RawFd; 8]);
    // The first read also collects the attached fds.
    let (n, fds) = {
        let mut iov = [IoSliceMut::new(&mut len_buf)];
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
    if n == 0 {
        bail!("connection closed");
    }
    (&mut &*sock)
        .read_exact(&mut len_buf[n..])
        .context("receiving message")?;
    let len = u32::from_le_bytes(len_buf) as usize;
    ensure!(len <= MAX_MESSAGE, "message length {len} out of range");
    let mut data = vec![0u8; len];
    (&mut &*sock)
        .read_exact(&mut data)
        .context("receiving message")?;
    let value = serde_json::from_slice(&data).context("parsing message")?;
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

/// Receive a reply; an error reply becomes an `Err`.
///
/// # Errors
/// Socket errors, a closed connection, a malformed reply, or an error
/// reply from the peer.
pub fn recv_reply<T: for<'de> Deserialize<'de>>(sock: &UnixStream) -> Result<(T, Vec<OwnedFd>)> {
    let (value, fds) = recv_message(sock)?;
    if let Some(error) = value.get("error").and_then(|e| e.as_str()) {
        bail!("peer error: {error}");
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
    use crate::agent::{AdoptRequest, ERROR_BUSY, METHOD_ADOPT, StartReply};

    #[test]
    fn call_roundtrip_with_fds() {
        let (a, b) = UnixStream::pair().unwrap();
        let devnull = std::fs::File::open("/dev/null").unwrap();
        let request = AdoptRequest {
            build_id: "b1".into(),
        };
        send_call(&a, METHOD_ADOPT, &request, &[devnull.as_raw_fd()]).unwrap();

        let (method, received, fds): (_, AdoptRequest, _) = recv_call(&b).unwrap();
        assert_eq!(method, METHOD_ADOPT);
        assert_eq!(received, request);
        assert_eq!(fds.len(), 1);
    }

    /// A message larger than one read buffer must be reassembled, and
    /// reading it must not consume the already-queued next message.
    #[test]
    fn large_message_leaves_the_next_one_intact() {
        let (a, b) = UnixStream::pair().unwrap();
        let request = AdoptRequest {
            build_id: "x".repeat(64 * 1024),
        };
        send_call(&a, METHOD_ADOPT, &request, &[]).unwrap();
        send_reply(
            &a,
            &StartReply {
                pid: 7,
                scratch_dir: "/scratch/next".into(),
            },
            &[],
        )
        .unwrap();

        let (_, received, _): (_, AdoptRequest, _) = recv_call(&b).unwrap();
        assert_eq!(received, request);
        let (reply, _): (StartReply, _) = recv_reply(&b).unwrap();
        assert_eq!(reply.scratch_dir, "/scratch/next");
    }

    #[test]
    fn reply_roundtrip() {
        let (a, b) = UnixStream::pair().unwrap();
        send_reply(
            &a,
            &StartReply {
                pid: 42,
                scratch_dir: "/scratch/b1".into(),
            },
            &[],
        )
        .unwrap();
        let (reply, fds): (StartReply, _) = recv_reply(&b).unwrap();
        assert_eq!(reply.pid, 42);
        assert!(fds.is_empty());
    }

    #[test]
    fn error_reply_is_err() {
        let (a, b) = UnixStream::pair().unwrap();
        send_error(&a, ERROR_BUSY).unwrap();
        let err = recv_reply::<StartReply>(&b).unwrap_err();
        assert!(err.to_string().contains("Busy"), "{err}");
    }

    #[test]
    fn closed_connection_is_err() {
        let (a, b) = UnixStream::pair().unwrap();
        drop(a);
        assert!(recv_reply::<StartReply>(&b).is_err());
    }
}
