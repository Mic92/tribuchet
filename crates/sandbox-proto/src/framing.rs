//! Length-prefixed protobuf messages (u32 little-endian, then the
//! encoded [`agent::Call`]/[`agent::Reply`]) over a unix stream
//! socket, with file descriptors attached via SCM_RIGHTS. gRPC cannot
//! carry fds, hence the separate protocol.

use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result, bail, ensure};
use prost::Message;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};

use crate::agent::{self, call, reply};

/// Peers are worker and agent on the same host; anything bigger than
/// this is a corrupted length prefix, not a real message.
const MAX_MESSAGE: usize = 64 * 1024 * 1024;

fn send_message(sock: &UnixStream, body: &impl Message, fds: &[RawFd]) -> Result<()> {
    let body = body.encode_to_vec();
    let mut buf = (u32::try_from(body.len())?).to_le_bytes().to_vec();
    buf.extend_from_slice(&body);
    let iov = [IoSlice::new(&buf)];
    // SAFETY: the caller keeps the fds open for the duration of the call.
    let borrowed: Vec<BorrowedFd> = fds
        .iter()
        .map(|fd| unsafe { BorrowedFd::borrow_raw(*fd) })
        .collect();
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
    let mut cmsg = SendAncillaryBuffer::new(&mut space);
    if !borrowed.is_empty() {
        ensure!(
            cmsg.push(SendAncillaryMessage::ScmRights(&borrowed)),
            "too many fds for one message"
        );
    }
    let sent = sendmsg(sock, &iov, &mut cmsg, SendFlags::empty()).context("sending message")?;
    if sent < buf.len() {
        (&mut &*sock).write_all(&buf[sent..])?;
    }
    Ok(())
}

/// Receive one message and any attached fds. Only the length prefix
/// and the message body are read, so the peer's next message stays
/// queued.
fn recv_message<M: Message + Default>(sock: &UnixStream) -> Result<(M, Vec<OwnedFd>)> {
    let mut len_buf = [0u8; 4];
    let mut cmsg_buf = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
    // The first read also collects the attached fds.
    let (n, fds) = {
        let mut iov = [IoSliceMut::new(&mut len_buf)];
        let mut cmsg = RecvAncillaryBuffer::new(&mut cmsg_buf);
        let msg =
            recvmsg(sock, &mut iov, &mut cmsg, RecvFlags::empty()).context("receiving message")?;
        let mut fds = Vec::new();
        for c in cmsg.drain() {
            if let RecvAncillaryMessage::ScmRights(received) = c {
                fds.extend(received);
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
    let value = M::decode(data.as_slice()).context("decoding message")?;
    Ok((value, fds))
}

/// Send a method call.
///
/// # Errors
/// Socket errors.
pub fn send_call(sock: &UnixStream, call: call::Call, fds: &[RawFd]) -> Result<()> {
    send_message(sock, &agent::Call { call: Some(call) }, fds)
}

/// Send a successful reply.
///
/// # Errors
/// Socket errors.
pub fn send_reply(sock: &UnixStream, reply: reply::Reply, fds: &[RawFd]) -> Result<()> {
    send_message(sock, &agent::Reply { reply: Some(reply) }, fds)
}

/// Send an error reply.
///
/// # Errors
/// Socket errors.
pub fn send_error(sock: &UnixStream, error: &str) -> Result<()> {
    send_reply(sock, reply::Reply::Error(error.to_owned()), &[])
}

/// Receive a method call.
///
/// # Errors
/// Socket errors, a closed connection, or a malformed call.
pub fn recv_call(sock: &UnixStream) -> Result<(call::Call, Vec<OwnedFd>)> {
    let (msg, fds): (agent::Call, _) = recv_message(sock)?;
    Ok((msg.call.context("call without a payload")?, fds))
}

/// Receive a reply; an error reply becomes an `Err`.
///
/// # Errors
/// Socket errors, a closed connection, a malformed reply, or an error
/// reply from the peer.
pub fn recv_reply(sock: &UnixStream) -> Result<(reply::Reply, Vec<OwnedFd>)> {
    let (msg, fds): (agent::Reply, _) = recv_message(sock)?;
    match msg.reply.context("reply without a payload")? {
        reply::Reply::Error(e) => bail!("peer error: {e}"),
        r => Ok((r, fds)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{AdoptRequest, ERROR_BUSY, StartReply};
    use std::os::fd::AsRawFd;

    #[test]
    fn call_roundtrip_with_fds() {
        let (a, b) = UnixStream::pair().unwrap();
        let devnull = std::fs::File::open("/dev/null").unwrap();
        let request = AdoptRequest {
            build_id: "b1".into(),
        };
        send_call(
            &a,
            call::Call::Adopt(request.clone()),
            &[devnull.as_raw_fd()],
        )
        .unwrap();

        let (received, fds) = recv_call(&b).unwrap();
        assert_eq!(received, call::Call::Adopt(request));
        assert_eq!(fds.len(), 1);
    }

    /// A message larger than one read buffer must be reassembled, and
    /// reading it must not consume the already-queued next message.
    /// Sent from a thread: it exceeds macOS's socket buffer.
    #[test]
    fn large_message_leaves_the_next_one_intact() {
        let (a, b) = UnixStream::pair().unwrap();
        let build_id = "x".repeat(64 * 1024);
        let request = AdoptRequest {
            build_id: build_id.clone(),
        };
        let sender = {
            std::thread::spawn(move || {
                send_call(&a, call::Call::Adopt(request), &[]).unwrap();
                send_reply(
                    &a,
                    reply::Reply::Start(StartReply {
                        pid: 7,
                        scratch_dir: "/scratch/next".into(),
                    }),
                    &[],
                )
                .unwrap();
            })
        };

        let (received, _) = recv_call(&b).unwrap();
        let call::Call::Adopt(received) = received else {
            panic!("unexpected call {received:?}");
        };
        assert_eq!(received.build_id, build_id);
        let (reply, _) = recv_reply(&b).unwrap();
        let reply::Reply::Start(reply) = reply else {
            panic!("unexpected reply {reply:?}");
        };
        assert_eq!(reply.scratch_dir, "/scratch/next");
        sender.join().unwrap();
    }

    #[test]
    fn reply_roundtrip() {
        let (a, b) = UnixStream::pair().unwrap();
        send_reply(
            &a,
            reply::Reply::Start(StartReply {
                pid: 42,
                scratch_dir: "/scratch/b1".into(),
            }),
            &[],
        )
        .unwrap();
        let (reply, fds) = recv_reply(&b).unwrap();
        let reply::Reply::Start(reply) = reply else {
            panic!("unexpected reply {reply:?}");
        };
        assert_eq!(reply.pid, 42);
        assert!(fds.is_empty());
    }

    #[test]
    fn error_reply_is_err() {
        let (a, b) = UnixStream::pair().unwrap();
        send_error(&a, ERROR_BUSY).unwrap();
        let err = recv_reply(&b).unwrap_err();
        assert!(err.to_string().contains("Busy"), "{err}");
    }

    #[test]
    fn closed_connection_is_err() {
        let (a, b) = UnixStream::pair().unwrap();
        drop(a);
        assert!(recv_reply(&b).is_err());
    }
}
