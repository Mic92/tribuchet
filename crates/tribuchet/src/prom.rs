//! Prometheus text exposition for the hub and the worker: a tiny
//! text/plain HTTP endpoint. Kept dependency-free (raw tokio TCP): a
//! scrape is a single short request/response and needs no routing.

use std::fmt::Write as _;
use std::future::Future;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::errors::{Result, err_ctx};

/// Content type of the Prometheus text format.
pub(crate) const TEXT: &str = "text/plain; version=0.0.4";

/// One unlabelled sample with its HELP and TYPE lines.
pub(crate) fn metric(out: &mut String, name: &str, kind: &str, help: &str, value: u64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
    let _ = writeln!(out, "{name} {value}");
}

/// Serve over plain HTTP/1.1 on `addr` (the `metrics-listen` setting)
/// until the process exits. `respond` gets the start of the request and
/// returns the content type and body. Each connection is handled inline
/// and then dropped.
pub(crate) async fn serve<F, Fut>(addr: &str, respond: F) -> Result<()>
where
    F: Fn(Vec<u8>) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = (&'static str, String)> + Send,
{
    let parsed: SocketAddr = addr
        .parse()
        .map_err(err_ctx("parsing metrics-listen address"))?;
    let listener = tokio::net::TcpListener::bind(parsed)
        .await
        .map_err(err_ctx(format!("binding metrics-listen address {addr}")))?;
    tracing::info!(%addr, "metrics endpoint listening");
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!("metrics accept failed: {e}");
                continue;
            }
        };
        let respond = respond.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let (kind, body) = respond(buf[..n].to_vec()).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
    }
}
