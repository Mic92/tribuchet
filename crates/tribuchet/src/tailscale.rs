//! Tailscale LocalAPI client used when `auth = "tailscale"`.
//!
//! In that mode the worker listener runs without TLS and trusts the
//! WireGuard tunnel for confidentiality and integrity. Identity comes
//! from tailscaled: for each incoming TCP connection the hub asks
//! `GET /localapi/v0/whois?addr=<peer>` over the LocalAPI unix
//! socket, which returns the tailnet node name and tags. A peer
//! tailscaled does not know is rejected, so binding to the tailnet
//! interface is not required for correctness (only for attack
//! surface).

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
pub struct WhoIs {
    /// Short tailnet node name (first DNS label of `Node.Name`).
    pub node_name: String,
    /// ACL tags applied to the node, e.g. `tag:tribuchet-worker`.
    pub tags: Vec<String>,
}

#[derive(Deserialize)]
struct Resp {
    #[serde(rename = "Node")]
    node: Node,
}

#[derive(Deserialize)]
struct Node {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Tags", default)]
    tags: Vec<String>,
}

/// Resolve `addr` against the local tailscaled. The LocalAPI on Linux
/// is an HTTP/1.1 server on a unix socket; access control is the
/// socket's file mode, so no Authorization header is needed.
pub async fn whois(socket: &Path, addr: SocketAddr) -> Result<WhoIs> {
    let mut s = tokio::net::UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to tailscaled at {}", socket.display()))?;
    // Host header is a fixed sentinel the daemon expects; the path
    // takes the full ip:port so tailscaled can match the exact
    // 4-tuple it NATed. The Go client percent-encodes the addr; do
    // the same so an IPv6 `[::1]:p` is a valid query value.
    // HTTP/1.0 so tailscaled cannot reply with Transfer-Encoding:
    // chunked, which keeps the body parser below trivial.
    let req = format!(
        "GET /localapi/v0/whois?addr={} HTTP/1.0\r\n\
         Host: local-tailscaled.sock\r\n\r\n",
        encode_addr(addr),
    );
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await?;
    let body = http_body(&buf)?;
    let resp: Resp = serde_json::from_slice(body)
        .with_context(|| format!("parsing whois response for {addr}"))?;
    Ok(WhoIs {
        node_name: resp
            .node
            .name
            .split('.')
            .next()
            .unwrap_or(&resp.node.name)
            .to_owned(),
        tags: resp.node.tags,
    })
}

/// Minimal percent-encoding for the characters `SocketAddr` can emit
/// that are reserved in a URI query (`[` `]` `:`).
fn encode_addr(addr: SocketAddr) -> String {
    let mut out = String::new();
    for b in addr.to_string().bytes() {
        match b {
            b'[' => out.push_str("%5B"),
            b']' => out.push_str("%5D"),
            b':' => out.push_str("%3A"),
            _ => out.push(b as char),
        }
    }
    out
}

/// Split status line / headers from body and check for 200. The
/// request is HTTP/1.0, so the body is delimited by connection close
/// and never chunked.
fn http_body(buf: &[u8]) -> Result<&[u8]> {
    let sep = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed HTTP response from tailscaled")?;
    let head = std::str::from_utf8(&buf[..sep]).context("non-utf8 HTTP head")?;
    let status = head.lines().next().unwrap_or_default();
    if !status.contains(" 200 ") {
        bail!("tailscaled whois: {status}");
    }
    Ok(&buf[sep + 4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_whois_body() {
        let raw = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n\
            {\"Node\":{\"Name\":\"worker-1.tailnet.ts.net.\",\"Tags\":[\"tag:ci\"]},\
             \"UserProfile\":{}}";
        let body = http_body(raw).unwrap();
        let r: Resp = serde_json::from_slice(body).unwrap();
        assert_eq!(r.node.name, "worker-1.tailnet.ts.net.");
        assert_eq!(r.node.tags, vec!["tag:ci"]);
    }

    #[test]
    fn ipv6_addr_is_encoded() {
        let a: SocketAddr = "[fd7a:115c::1]:1234".parse().unwrap();
        assert_eq!(encode_addr(a), "%5Bfd7a%3A115c%3A%3A1%5D%3A1234");
    }

    #[test]
    fn non_200_is_error() {
        let raw = b"HTTP/1.1 404 Not Found\r\n\r\nno match";
        assert!(http_body(raw).is_err());
    }
}
