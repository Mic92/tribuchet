//! The worker's own builds as Prometheus gauges, for whatever runs next
//! to it: an autoscaler's idle check must not power off a machine while
//! a build stages, runs or still hands its outputs to the hub.

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::WorkerCtx;
use crate::errors::{Result, chain};
use crate::prom::{self, metric};

/// Builds per state. Only `building` holds a slot: a staging build may
/// wait for one (the lookahead), and a delivering build gave its slot
/// back when the builder exited.
#[derive(Debug, Default, PartialEq, Eq)]
struct Builds {
    /// Assigned, inputs still arriving; ends with this hub session.
    staging: usize,
    /// The builder runs, including builds adopted after a restart.
    building: usize,
    /// Finished; the result waits for the hub's acknowledgement.
    delivering: usize,
}

fn builds(ctx: &WorkerCtx) -> Builds {
    let mut b = Builds {
        staging: ctx.staging.load(Ordering::Relaxed),
        ..Builds::default()
    };
    for e in ctx.resumable.lock().unwrap().values() {
        if e.finished.is_some() {
            b.delivering += 1;
        } else {
            b.building += 1;
        }
    }
    b
}

fn render(b: &Builds, max_jobs: u32) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# HELP tribuchet_worker_builds Builds on this worker, by state. All zero means idle."
    );
    let _ = writeln!(out, "# TYPE tribuchet_worker_builds gauge");
    for (state, n) in [
        ("staging", b.staging),
        ("building", b.building),
        ("delivering", b.delivering),
    ] {
        let _ = writeln!(out, "tribuchet_worker_builds{{state=\"{state}\"}} {n}");
    }
    metric(
        &mut out,
        "tribuchet_worker_slots",
        "gauge",
        "Concurrent build slots (max-jobs).",
        u64::from(max_jobs),
    );
    out
}

/// Serve the gauges on `addr`, if set, until the process exits; errors
/// are logged.
pub(super) fn spawn(ctx: &Arc<WorkerCtx>, addr: Option<String>, max_jobs: u32) {
    let Some(addr) = addr else { return };
    let ctx = ctx.clone();
    tokio::spawn(async move {
        let res: Result<()> = prom::serve(&addr, move |_req| {
            let body = render(&builds(&ctx), max_jobs);
            async move { (prom::TEXT, body) }
        })
        .await;
        if let Err(e) = res {
            let e = chain(&e);
            tracing::error!("metrics endpoint stopped: {e}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_every_state_and_the_slots() {
        let out = render(
            &Builds {
                staging: 1,
                building: 6,
                delivering: 2,
            },
            6,
        );
        let has = |l: &str| out.lines().any(|x| x == l);
        assert!(has("tribuchet_worker_builds{state=\"staging\"} 1"), "{out}");
        assert!(
            has("tribuchet_worker_builds{state=\"building\"} 6"),
            "{out}"
        );
        assert!(
            has("tribuchet_worker_builds{state=\"delivering\"} 2"),
            "{out}"
        );
        assert!(has("tribuchet_worker_slots 6"), "{out}");
    }

    #[test]
    fn an_idle_worker_reports_zeros_not_nothing() {
        // an absent series would read as "no data", not as idle
        let out = render(&Builds::default(), 4);
        for state in ["staging", "building", "delivering"] {
            let line = format!("tribuchet_worker_builds{{state=\"{state}\"}} 0");
            assert!(out.lines().any(|x| x == line), "{out}");
        }
    }
}
