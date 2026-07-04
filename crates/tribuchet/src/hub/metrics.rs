//! Prometheus metrics for the hub, exposed as a tiny text/plain HTTP
//! endpoint. Kept dependency-free (raw tokio TCP) since the hub already
//! pulls in plenty and a scrape endpoint needs no routing.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::state::HubState;

/// Monotonic build lifecycle counters. Gauges (queue depth, connected
/// workers) are read straight from the live state at scrape time.
#[derive(Default)]
pub(super) struct Metrics {
    pub(super) submitted: AtomicU64,
    pub(super) dispatched: AtomicU64,
    pub(super) declined: AtomicU64,
    pub(super) requeued: AtomicU64,
    pub(super) failed: AtomicU64,
    pub(super) succeeded: AtomicU64,
}

impl Metrics {
    pub(super) fn inc(field: &AtomicU64) {
        field.fetch_add(1, Ordering::Relaxed);
    }
}

/// Escape a label value per the Prometheus text format; worker names
/// are peer-supplied, so a stray quote or newline must not break a line.
fn label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn metric(out: &mut String, name: &str, kind: &str, help: &str, value: u64) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
    let _ = writeln!(out, "{name} {value}");
}

/// Render the current metrics in Prometheus text exposition format.
async fn render(state: &HubState) -> String {
    let m = &state.metrics;
    let mut out = String::new();
    let counters = [
        (
            "tribuchet_builds_submitted_total",
            "Builds accepted for scheduling.",
            &m.submitted,
        ),
        (
            "tribuchet_builds_dispatched_total",
            "Builds handed to a worker.",
            &m.dispatched,
        ),
        (
            "tribuchet_builds_declined_total",
            "Builds declined because no capable worker registered in time.",
            &m.declined,
        ),
        (
            "tribuchet_builds_requeued_total",
            "Builds requeued after a worker session was lost.",
            &m.requeued,
        ),
        (
            "tribuchet_builds_failed_total",
            "Builds that ended in failure.",
            &m.failed,
        ),
        (
            "tribuchet_builds_succeeded_total",
            "Builds that completed successfully.",
            &m.succeeded,
        ),
    ];
    for (name, help, value) in counters {
        metric(
            &mut out,
            name,
            "counter",
            help,
            value.load(Ordering::Relaxed),
        );
    }

    let queue_depth = state.queue.lock().await.len() as u64;
    metric(
        &mut out,
        "tribuchet_queue_depth",
        "gauge",
        "Builds waiting for a worker.",
        queue_depth,
    );

    render_workers(&mut out, state);
    out
}

/// Connected builders: a `tribuchet_builder_up` gauge per (worker,
/// system) plus the connected and per-system totals.
fn render_workers(out: &mut String, state: &HubState) {
    use std::fmt::Write;
    let mut per_system: BTreeMap<String, u64> = BTreeMap::new();
    let mut builders: Vec<(String, Vec<String>)> = Vec::new();
    let caps = state.worker_caps.lock().unwrap();
    for c in caps.values() {
        let mut systems: Vec<String> = c.systems.keys().cloned().collect();
        systems.sort();
        for system in &systems {
            *per_system.entry(system.clone()).or_default() += 1;
        }
        builders.push((c.name.clone(), systems));
    }
    let connected = caps.len() as u64;
    drop(caps);
    builders.sort();

    metric(
        out,
        "tribuchet_workers_connected",
        "gauge",
        "Workers with an open session.",
        connected,
    );
    let _ = writeln!(
        out,
        "# HELP tribuchet_builder_up Connected builder, labelled by hostname and system."
    );
    let _ = writeln!(out, "# TYPE tribuchet_builder_up gauge");
    for (worker, systems) in &builders {
        for system in systems {
            let _ = writeln!(
                out,
                "tribuchet_builder_up{{worker=\"{}\",system=\"{}\"}} 1",
                label(worker),
                label(system)
            );
        }
    }
    let _ = writeln!(
        out,
        "# HELP tribuchet_workers_for_system Connected workers advertising a system."
    );
    let _ = writeln!(out, "# TYPE tribuchet_workers_for_system gauge");
    for (system, count) in &per_system {
        let _ = writeln!(
            out,
            "tribuchet_workers_for_system{{system=\"{system}\"}} {count}"
        );
    }
}

/// Serve `/metrics` over plain HTTP/1.1 on `addr` until the process
/// exits. A scrape is a single short request/response, so each
/// connection is handled inline and then dropped.
pub(super) async fn serve(state: Arc<HubState>, addr: String) -> Result<()> {
    let parsed: std::net::SocketAddr = addr.parse().context("parsing metrics-listen address")?;
    let listener = tokio::net::TcpListener::bind(parsed)
        .await
        .with_context(|| format!("binding metrics-listen address {addr}"))?;
    tracing::info!(%addr, "metrics endpoint listening");
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!("metrics accept failed: {e}");
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            // Drain the request head; any path scrapes the same metrics.
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let body = render(&state).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
    }
}
