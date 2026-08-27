//! Per-job protocol with a worker: input staging, output relay and verification.

mod extras;
mod outputs;
mod serve;
mod staging;
use outputs::{deliver_outputs, parse_extras, verify_set};
pub(super) use staging::WorkerSession;
use staging::{Staging, stream_tmp_dir};

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tonic::Status;

use super::metrics::Metrics;
use super::state::{HubState, Job, Replay};
use crate::errors::{Result, err_msg};
use crate::proto::{
    BuildAssignment, BuildResult, CancelBuild, HubMessage, ResultAck, attach_event, hub_message,
    worker_message,
};

/// How long a dispatched build may run with no attach client listening
/// before the hub cancels it on the worker.
const CANCEL_GRACE: Duration = Duration::from_secs(10);

pub(super) async fn send(
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    msg: hub_message::Msg,
) -> Result<()> {
    out_tx
        .send(Ok(HubMessage { msg: Some(msg) }))
        .await
        .map_err(|_| err_msg("worker connection lost"))
}

/// Drive one dispatched build to its verdict. A failed build is not an `Err`.
pub(super) async fn run_job(
    state: &HubState,
    job: &Job,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    mut in_rx: mpsc::Receiver<worker_message::Msg>,
    sess: Arc<WorkerSession>,
    credit_free: bool,
    dispatched: &mut bool,
) -> Result<()> {
    let req = &job.req;
    let mut staging = Staging::new(state, job, &sess);
    let inputs = staging.assignment_inputs().await?;
    *dispatched = true;
    send(
        out_tx,
        hub_message::Msg::Assignment(BuildAssignment {
            build_id: job.id.clone(),
            system: req.system.clone(),
            builder: req.builder.clone(),
            args: req.args.clone(),
            env: req.env.clone(),
            outputs: req.outputs.clone(),
            tmp_dir_in_sandbox: req.tmp_dir_in_sandbox.clone(),
            store_dir: req.store_dir.clone(),
            fixed_output: req.fixed_output,
            dedupe_key: job.key.clone(),
            inputs,
            credit_free,
            required_features: job.features.clone(),
        }),
    )
    .await?;

    stream_tmp_dir(&job.id, &job.tmp_dir_pack, out_tx).await?;

    let mut abandoned_since: Option<Instant> = None;
    let mut cancel_sent = false;
    // An interval, not a per-iteration sleep: a build that logs
    // continuously must not starve the abandonment check.
    let mut abandon_check = tokio::time::interval(Duration::from_secs(2));
    abandon_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let m = tokio::select! {
            r = staging.progress(out_tx), if staging.busy() => {
                r?;
                continue;
            }
            _ = abandon_check.tick(), if !cancel_sent => {
                if job.replay.has_subscribers().await {
                    abandoned_since = None;
                } else if abandoned_since.get_or_insert_with(Instant::now).elapsed()
                    > CANCEL_GRACE
                {
                    tracing::info!(id = job.id, "no attach client left; cancelling build");
                    state.unlist(job).await;
                    send(
                        out_tx,
                        hub_message::Msg::Cancel(CancelBuild {
                            build_id: job.id.clone(),
                            dedupe_key: job.key.clone(),
                        }),
                    )
                    .await?;
                    cancel_sent = true;
                }
                continue;
            }
            m = recv(&mut in_rx) => m?,
        };
        match m {
            // The worker already holds this build (it survived a hub
            // restart). Its result arrives like any other.
            worker_message::Msg::Resumed(_) => {
                tracing::info!(id = job.id, "worker resumed an in-flight build");
            }
            worker_message::Msg::Log(l) => {
                job.replay.publish(attach_event::Event::Log(l.data)).await;
            }
            worker_message::Msg::Need(n) => staging.handle_need(n, out_tx).await?,
            worker_message::Msg::Result(res) => {
                if res.exit_code != 0 {
                    return publish_worker_failure(state, out_tx, job, &res).await;
                }
                let outputs = verify_set(res.outputs, &job.req.outputs)?;
                let extras = parse_extras(res.extras)?;
                deliver_outputs(state, job, out_tx, &mut in_rx, outputs, extras).await?;
                finish_relay(state, out_tx, &job.replay, job).await;
                return Ok(());
            }
            other => {
                return Err(err_msg(format!(
                    "unexpected worker message: {}",
                    msg_name(&other)
                )));
            }
        }
    }
}

/// Log/error-safe name of a worker message variant. The messages embed
/// peer-controlled bytes (NAR chunks, log data); Debug-formatting them
/// into error strings would balloon logs and replay buffers.
pub(super) fn msg_name(msg: &worker_message::Msg) -> &'static str {
    match msg {
        worker_message::Msg::Register(_) => "Register",
        worker_message::Msg::Heartbeat(_) => "Heartbeat",
        worker_message::Msg::Log(_) => "Log",
        worker_message::Msg::Need(_) => "Need",
        worker_message::Msg::Result(_) => "Result",
        worker_message::Msg::Chunk(_) => "ChunkFrame",
        worker_message::Msg::RequestJob(_) => "RequestJob",
        worker_message::Msg::Resumed(_) => "Resumed",
    }
}

/// The channel carries only this build's messages (route_loop filters);
/// it closes when the worker disconnects or goes silent.
pub(super) async fn recv(
    in_rx: &mut mpsc::Receiver<worker_message::Msg>,
) -> Result<worker_message::Msg> {
    in_rx
        .recv()
        .await
        .ok_or_else(|| err_msg("worker disconnected or went silent"))
}

async fn finish_relay(
    state: &HubState,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    replay: &Replay,
    job: &Job,
) {
    Metrics::inc(&state.metrics.succeeded);
    replay.publish(attach_event::Event::ExitCode(0)).await;
    ack_result(out_tx, job).await;
}

/// Report a worker-side build failure to attached clients: forward
/// the error text and exit code, count the failure, and ack so the
/// worker can drop the build.
async fn publish_worker_failure(
    state: &HubState,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    job: &Job,
    res: &BuildResult,
) -> Result<()> {
    // Unix exposes only the low 8 bits to the parent; a nonzero
    // multiple of 256 would look like success.
    if !(1..=255).contains(&res.exit_code) {
        return Err(err_msg(format!(
            "worker sent invalid exit code {}",
            res.exit_code
        )));
    }
    if !res.error.is_empty() {
        job.replay
            .publish(attach_event::Event::Log(
                format!("tribuchet worker error: {}\n", res.error).into_bytes(),
            ))
            .await;
    }
    Metrics::inc(&state.metrics.failed);
    job.replay
        .publish(attach_event::Event::ExitCode(res.exit_code))
        .await;
    ack_result(out_tx, job).await;
    Ok(())
}

/// Tell the worker its result (and all output NARs) arrived intact,
/// so it can stop keeping the build for redelivery. Best effort: a
/// lost ack only means the worker holds the build dir until its TTL.
async fn ack_result(out_tx: &mpsc::Sender<Result<HubMessage, Status>>, job: &Job) {
    let _ = send(
        out_tx,
        hub_message::Msg::ResultAck(ResultAck {
            build_id: job.id.clone(),
            dedupe_key: job.key.clone(),
        }),
    )
    .await;
}
