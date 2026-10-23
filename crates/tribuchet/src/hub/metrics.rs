//! Prometheus metrics for the hub, exposed as a tiny text/plain HTTP
//! endpoint. Kept dependency-free (raw tokio TCP) since the hub already
//! pulls in plenty and a scrape endpoint needs no routing.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::state::HubState;
use crate::errors::{Result, err_ctx};
use crate::proto::BuildUsage;

mod histogram;
mod workers;
use histogram::{BYTES, SECONDS, Series, bytes_f64, observe, render_histogram};
use workers::{render_workers_json, wants_workers};

/// Monotonic build lifecycle counters. Gauges (queue depth, connected
/// workers) are read straight from the live state at scrape time.
#[derive(Default)]
pub(super) struct Metrics {
    pub(super) submitted: AtomicU64,
    pub(super) declined: AtomicU64,
    pub(super) requeued: AtomicU64,
    pub(super) failed: AtomicU64,
    pub(super) succeeded: AtomicU64,
    /// Worker-to-hub messages by variant, indexed like [`MSG_KINDS`].
    msgs: [AtomicU64; MSG_KINDS.len()],
    /// Encoded bytes of those messages, same index.
    msg_bytes: [AtomicU64; MSG_KINDS.len()],
    /// Per-system histograms, keyed by system.
    queue_seconds: Series,
    build_seconds: Series,
    build_cpu_seconds: Series,
    build_peak_memory_bytes: Series,
    /// Builds currently on a worker, by system.
    running: Arc<Counts>,
}

type Counts = Mutex<BTreeMap<String, u64>>;

pub(super) struct Running {
    counts: Arc<Counts>,
    system: String,
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(n) = self.counts.lock().unwrap().get_mut(&self.system) {
            *n = n.saturating_sub(1);
        }
    }
}

/// Names returned by `relay::msg_name`.
const MSG_KINDS: [&str; 8] = [
    "Register",
    "Heartbeat",
    "Log",
    "Need",
    "Result",
    "ChunkFrame",
    "RequestJob",
    "Resumed",
];

impl Metrics {
    pub(super) fn inc(field: &AtomicU64) {
        field.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one worker message and its encoded size, which shows what
    /// the hub spends its time on.
    pub(super) fn count_msg(&self, name: &str, bytes: usize) {
        if let Some(i) = MSG_KINDS.iter().position(|k| *k == name) {
            Self::inc(&self.msgs[i]);
            self.msg_bytes[i].fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }

    /// Count a build as running until the guard drops, on every exit path.
    pub(super) fn running(&self, system: &str) -> Running {
        *self
            .running
            .lock()
            .unwrap()
            .entry(system.to_owned())
            .or_default() += 1;
        Running {
            counts: self.running.clone(),
            system: system.to_owned(),
        }
    }

    /// A build left the queue for a worker.
    pub(super) fn observe_queue(&self, system: &str, waited: Duration) {
        observe(&self.queue_seconds, SECONDS, system, waited.as_secs_f64());
    }

    /// What a finished build used on its worker. CPU and memory are 0
    /// where the worker could not tell, which is not a measurement.
    pub(super) fn observe_usage(&self, system: &str, u: &BuildUsage) {
        let secs = |d: Duration| d.as_secs_f64();
        observe(
            &self.build_seconds,
            SECONDS,
            system,
            secs(Duration::from_millis(u.wall_ms)),
        );
        if u.cpu_usec > 0 {
            observe(
                &self.build_cpu_seconds,
                SECONDS,
                system,
                secs(Duration::from_micros(u.cpu_usec)),
            );
        }
        if u.peak_memory_bytes > 0 {
            observe(
                &self.build_peak_memory_bytes,
                BYTES,
                system,
                bytes_f64(u.peak_memory_bytes),
            );
        }
    }
}

/// Escape a label value per the Prometheus text format; worker names
/// and systems are peer-supplied, so a stray quote or newline must not
/// break a line, and an oversized value must not bloat every scrape.
fn label(value: &str) -> String {
    const MAX: usize = 128;
    let mut end = value.len().min(MAX);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end]
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn metric(out: &mut String, name: &str, kind: &str, help: &str, value: u64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
    let _ = writeln!(out, "{name} {value}");
}

fn render_histograms(out: &mut String, m: &Metrics) {
    render_histogram(
        out,
        "tribuchet_queue_seconds",
        "Time a build waited in the queue for a worker, by system.",
        SECONDS,
        &m.queue_seconds,
    );
    render_histogram(
        out,
        "tribuchet_build_seconds",
        "Wall time of a build on its worker, by system.",
        SECONDS,
        &m.build_seconds,
    );
    render_histogram(
        out,
        "tribuchet_build_cpu_seconds",
        "CPU time a build used, by system. Without a cgroup only the builder and the processes it waited for.",
        SECONDS,
        &m.build_cpu_seconds,
    );
    render_histogram(
        out,
        "tribuchet_build_peak_memory_bytes",
        "Peak memory of a build, by system. A lower bound without a cgroup.",
        BYTES,
        &m.build_peak_memory_bytes,
    );
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

    for (name, help, counts) in [
        (
            "tribuchet_worker_messages_total",
            "Messages received from workers, by type.",
            &m.msgs,
        ),
        (
            "tribuchet_worker_message_bytes_total",
            "Encoded bytes of messages received from workers, by type.",
            &m.msg_bytes,
        ),
    ] {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} counter");
        for (kind, n) in MSG_KINDS.iter().zip(counts) {
            let _ = writeln!(
                out,
                "{name}{{type=\"{kind}\"}} {}",
                n.load(Ordering::Relaxed)
            );
        }
    }
    render_histograms(&mut out, m);

    let mut queued: BTreeMap<String, u64> = BTreeMap::new();
    for j in state.queue.lock().await.iter() {
        *queued.entry(j.req.system.clone()).or_default() += 1;
    }

    render_workers(&mut out, state);
    render_systems(&mut out, state, &queued);
    out
}

/// Queue, running builds and capacity per system, for autoscaling. A worker
/// serving several systems counts its slots in each. Free slots are
/// `slots - running`.
fn render_systems(out: &mut String, state: &HubState, queued: &BTreeMap<String, u64>) {
    let mut slots: BTreeMap<String, u64> = BTreeMap::new();
    for c in state.worker_caps.lock().unwrap().values() {
        for system in c.systems.keys() {
            *slots.entry(system.clone()).or_default() += u64::from(c.max_jobs);
        }
    }
    let running = state.metrics.running.lock().unwrap().clone();
    let _ = writeln!(
        out,
        "# HELP tribuchet_system_builds Builds queued or running, by system."
    );
    let _ = writeln!(out, "# TYPE tribuchet_system_builds gauge");
    for (kind, counts) in [("queued", queued), ("running", &running)] {
        for (system, n) in counts {
            let _ = writeln!(
                out,
                "tribuchet_system_builds{{system=\"{}\",state=\"{kind}\"}} {n}",
                label(system)
            );
        }
    }
    let _ = writeln!(
        out,
        "# HELP tribuchet_system_slots Build slots of connected workers, by system."
    );
    let _ = writeln!(out, "# TYPE tribuchet_system_slots gauge");
    for (system, n) in &slots {
        let _ = writeln!(
            out,
            "tribuchet_system_slots{{system=\"{}\"}} {n}",
            label(system)
        );
    }
}

/// Connected workers, in total and per system. Per-worker detail is on
/// `/workers`, which keeps the series count independent of worker churn.
fn render_workers(out: &mut String, state: &HubState) {
    let mut per_system: BTreeMap<String, u64> = BTreeMap::new();
    let caps = state.worker_caps.lock().unwrap();
    for c in caps.values() {
        for system in c.systems.keys() {
            *per_system.entry(system.clone()).or_default() += 1;
        }
    }
    let connected = caps.len() as u64;
    drop(caps);

    metric(
        out,
        "tribuchet_workers_connected",
        "gauge",
        "Workers with an open session.",
        connected,
    );
    let _ = writeln!(
        out,
        "# HELP tribuchet_workers_for_system Connected workers advertising a system."
    );
    let _ = writeln!(out, "# TYPE tribuchet_workers_for_system gauge");
    for (system, count) in &per_system {
        let _ = writeln!(
            out,
            "tribuchet_workers_for_system{{system=\"{}\"}} {count}",
            label(system)
        );
    }
}

/// Serve `/metrics` over plain HTTP/1.1 on `addr` until the process
/// exits. A scrape is a single short request/response, so each
/// connection is handled inline and then dropped.
pub(super) async fn serve(state: Arc<HubState>, addr: String) -> Result<()> {
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
        let state = state.clone();
        tokio::spawn(async move {
            // Only /workers is special. Any other path scrapes the metrics.
            let mut buf = [0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let (kind, body) = if wants_workers(&buf[..n]) {
                ("application/json", render_workers_json(&state))
            } else {
                ("text/plain; version=0.0.4", render(&state).await)
            };
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::time::Instant;

    use super::*;
    use crate::hub::state::{Job, Replay, WorkerCaps};
    use crate::proto::BuildRequest;

    #[test]
    fn worker_messages_are_counted_by_variant() {
        let m = Metrics::default();
        m.count_msg("Result", 10);
        m.count_msg("Result", 20);
        m.count_msg("Log", 5);
        // unknown names are ignored instead of panicking
        m.count_msg("Nope", 1);
        let get = |k: &str| {
            let i = MSG_KINDS.iter().position(|n| *n == k).unwrap();
            (
                m.msgs[i].load(Ordering::Relaxed),
                m.msg_bytes[i].load(Ordering::Relaxed),
            )
        };
        assert_eq!(
            (get("Result"), get("Log"), get("Need")),
            ((2, 30), (1, 5), (0, 0))
        );
    }

    #[test]
    fn histograms_are_cumulative_per_system() {
        let m = Metrics::default();
        let wait = |s, secs| m.observe_queue(s, Duration::from_secs_f64(secs));
        wait("x86_64-linux", 0.1);
        wait("x86_64-linux", 3.0);
        wait("x86_64-linux", 7200.0);
        wait("aarch64-linux", 0.01);
        let mut out = String::new();
        render_histogram(&mut out, "q", "h", SECONDS, &m.queue_seconds);
        let has = |l: &str| out.lines().any(|x| x == l);
        assert!(
            has("q_bucket{system=\"x86_64-linux\",le=\"0.05\"} 0"),
            "{out}"
        );
        assert!(
            has("q_bucket{system=\"x86_64-linux\",le=\"0.25\"} 1"),
            "{out}"
        );
        assert!(has("q_bucket{system=\"x86_64-linux\",le=\"5\"} 2"), "{out}");
        assert!(
            has("q_bucket{system=\"x86_64-linux\",le=\"3600\"} 2"),
            "{out}"
        );
        assert!(
            has("q_bucket{system=\"x86_64-linux\",le=\"+Inf\"} 3"),
            "{out}"
        );
        assert!(has("q_count{system=\"x86_64-linux\"} 3"), "{out}");
        assert!(
            has("q_bucket{system=\"aarch64-linux\",le=\"0.05\"} 1"),
            "{out}"
        );
    }

    #[test]
    fn running_counts_until_the_guard_drops() {
        let m = Metrics::default();
        let a = m.running("x86_64-linux");
        let b = m.running("x86_64-linux");
        let get = || m.running.lock().unwrap().get("x86_64-linux").copied();
        assert_eq!(get(), Some(2));
        drop(a);
        assert_eq!(get(), Some(1));
        drop(b);
        assert_eq!(get(), Some(0));
    }

    #[tokio::test]
    async fn system_gauges_show_queued_running_and_slots() {
        let state = HubState::for_test(Duration::ZERO);
        let job = |system: &str| Job {
            id: "j".into(),
            key: "k".into(),
            req: BuildRequest {
                system: system.into(),
                ..Default::default()
            },
            tmp_dir_pack: Arc::new(Vec::new()),
            features: vec![],
            replay: Arc::new(Replay::default()),
            listing: Mutex::default(),
            attempts: 0,
            queued_at: Instant::now(),
            reserved: None,
        };
        state.queue.lock().await.push_back(job("x86_64-linux"));
        state.queue.lock().await.push_back(job("x86_64-linux"));
        state.queue.lock().await.push_back(job("aarch64-linux"));
        let _r = state.metrics.running("x86_64-linux");
        for (id, max_jobs) in [(1, 4), (2, 8)] {
            state.worker_caps.lock().unwrap().insert(
                id,
                WorkerCaps {
                    name: format!("w{id}"),
                    connected_at: Instant::now(),
                    systems: [("x86_64-linux".to_owned(), HashSet::default())].into(),
                    max_jobs,
                },
            );
        }
        let out = render(&state).await;
        let has = |l: &str| out.lines().any(|x| x == l);
        assert!(
            has("tribuchet_system_builds{system=\"x86_64-linux\",state=\"queued\"} 2"),
            "{out}"
        );
        assert!(
            has("tribuchet_system_builds{system=\"aarch64-linux\",state=\"queued\"} 1"),
            "{out}"
        );
        assert!(
            has("tribuchet_system_builds{system=\"x86_64-linux\",state=\"running\"} 1"),
            "{out}"
        );
        assert!(
            has("tribuchet_system_slots{system=\"x86_64-linux\"} 12"),
            "{out}"
        );
    }

    #[test]
    fn unknown_cpu_and_memory_are_not_observed() {
        let m = Metrics::default();
        m.observe_usage(
            "x86_64-linux",
            &BuildUsage {
                wall_ms: 1500,
                ..Default::default()
            },
        );
        assert_eq!(m.build_seconds.lock().unwrap().len(), 1);
        assert!(m.build_cpu_seconds.lock().unwrap().is_empty());
        assert!(m.build_peak_memory_bytes.lock().unwrap().is_empty());
    }

    #[test]
    fn label_escapes_and_truncates() {
        assert_eq!(label("x86_64-linux"), "x86_64-linux");
        assert_eq!(label("a\"\n\\b"), "a\\\"\\n\\\\b");
        // Peer-supplied values are capped so one worker cannot bloat
        // every scrape; truncation stays on a char boundary.
        assert_eq!(label(&"x".repeat(300)).len(), 128);
        let long = "é".repeat(300);
        let out = label(&long);
        assert!(out.len() <= 128);
        assert!(long.starts_with(&out));
    }
}
