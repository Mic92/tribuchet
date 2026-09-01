//! Hub session: connect, register, and drive the per-build message loop.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

use super::build::{ActiveBuild, StagingStatus, Wake, validate_assignment};
use super::caps::system_caps;
use super::resume::{
    ResumableBuild, ack_delivery, execute_to_finished, record_finished, serve_chunks, try_deliver,
};
use super::{WorkerCtx, hostname, loadavg1, msg};
use crate::chunkio;
use crate::config::{Auth, WorkerConfig};
use crate::errors::{Error, Result, chain, err_ctx, err_msg};
use crate::proto::{
    BuildAssignment, BuildResult, CancelBuild, Heartbeat, HubMessage, MAX_MSG_SIZE, Need, Register,
    RequestJob, Resumed, WorkerMessage, hub_message, worker_hub_client::WorkerHubClient,
    worker_message,
};
use crate::sd;

/// nix/flakelet-worker.nix greps the unit's StatusText for this.
pub const CONNECTED_STATUS: &str = "connected to hub";

pub(super) async fn session(opts: &WorkerConfig, ctx: &Arc<WorkerCtx>) -> Result<()> {
    let mut endpoint = Endpoint::from_shared(opts.hub.clone())?;
    if matches!(opts.auth, Auth::Mtls) {
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(
                fs::read(&opts.ca_cert).map_err(err_ctx("reading CA cert"))?,
            ))
            .identity(Identity::from_pem(
                fs::read(&opts.cert).map_err(err_ctx("reading worker cert"))?,
                fs::read(&opts.key).map_err(err_ctx("reading worker key"))?,
            ));
        endpoint = endpoint.tls_config(tls)?;
    }
    let channel = endpoint
        // Detect a silently dead hub connection instead of waiting on a
        // half-open TCP session forever.
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(20))
        .keep_alive_while_idle(true)
        .initial_stream_window_size(Some(chunkio::H2_STREAM_WINDOW))
        .initial_connection_window_size(Some(chunkio::H2_CONNECTION_WINDOW))
        .connect()
        .await
        .map_err(err_ctx("connecting to hub"))?;
    let mut client = WorkerHubClient::new(channel)
        .max_decoding_message_size(MAX_MSG_SIZE)
        .max_encoding_message_size(MAX_MSG_SIZE);

    let (out_tx, out_rx) = mpsc::channel::<WorkerMessage>(64);
    // Register must be the first message the hub reads; it fits in the
    // channel buffer, so queue it before the stream is consumed.
    out_tx
        .send(msg(worker_message::Msg::Register(Register {
            worker_name: hostname(),
            caps: system_caps(opts, ctx),
            resumable_keys: ctx.resumable_keys(),
            max_jobs: opts.max_jobs.max(1),
        })))
        .await?;

    let mut inbound = client
        .session(ReceiverStream::new(out_rx))
        .await?
        .into_inner();
    tracing::info!(hub = opts.hub, systems = ?opts.systems, "connected to hub");
    sd::notify_status(CONNECTED_STATUS);

    let mut active: HashMap<String, ActiveBuild> = HashMap::new();
    let result = session_loop(
        &mut inbound,
        &mut active,
        &out_tx,
        ctx,
        Duration::from_secs(opts.build_timeout_secs),
        opts.max_jobs.max(1),
    )
    .await;
    // Builds still staging when the session dies must not keep their
    // unpackers writing; executing builds finish on their own threads.
    for (_, build) in active.drain() {
        build.abort().await;
    }
    result
}

async fn session_loop(
    inbound: &mut tonic::Streaming<HubMessage>,
    active: &mut HashMap<String, ActiveBuild>,
    out_tx: &mpsc::Sender<WorkerMessage>,
    ctx: &Arc<WorkerCtx>,
    build_timeout: Duration,
    max_jobs: u32,
) -> Result<()> {
    let env = LaunchEnv {
        ctx,
        out_tx,
        build_timeout,
    };
    // Builds staged to completion but waiting for a free slot.
    let mut ready: VecDeque<String> = VecDeque::new();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
    let (wake_tx, mut wake_rx) = mpsc::unbounded_channel::<Wake>();
    declare_capacity(active, &ready, &env).await?;
    loop {
        let m = tokio::select! {
            () = ctx.slot_freed.notified() => {
                grant_slots(active, &mut ready, &env);
                declare_capacity(active, &ready, &env).await?;
                continue;
            }
            _ = heartbeat.tick() => {
                let staging = active.values().filter(|b| b.slot.is_some()).count();
                let running = (max_jobs as usize)
                    .saturating_sub(ctx.slots.available_permits() + staging);
                out_tx.send(msg(worker_message::Msg::Heartbeat(Heartbeat {
                    running_jobs: u32::try_from(running).unwrap_or(u32::MAX),
                    load1: loadavg1(),
                    resumable_keys: ctx.resumable_keys(),
                }))).await?;
                declare_capacity(active, &ready, &env).await?;
                continue;
            }
            Some(w) = wake_rx.recv() => {
                if let Some(build) = active.get_mut(&w.build_id) {
                    let res = build.woken(&w.path);
                    advance_staging(active, &mut ready, &w.build_id, res, &env).await?;
                }
                continue;
            }
            m = inbound.message() => {
                m?.ok_or_else(|| err_msg("hub closed the session"))?
            }
        };
        let Some(m) = m.msg else { continue };
        match m {
            hub_message::Msg::Assignment(a) => {
                if let Some(id) = handle_assignment(a, active, &wake_tx, out_tx, ctx).await? {
                    let res = active.get_mut(&id).unwrap().negotiate().await;
                    advance_staging(active, &mut ready, &id, res, &env).await?;
                }
                declare_capacity(active, &ready, &env).await?;
            }
            hub_message::Msg::TmpDir(t) => {
                let id = t.build_id.clone();
                if let Some(build) = active.get_mut(&id) {
                    let res = build.feed_tmp_dir(t).await.map(|s| (None, s));
                    advance_staging(active, &mut ready, &id, res, &env).await?;
                }
            }
            hub_message::Msg::Manifest(m) => {
                let id = m.build_id.clone();
                if let Some(build) = active.get_mut(&id) {
                    let res = build.feed_manifest(&m);
                    advance_staging(active, &mut ready, &id, res, &env).await?;
                }
            }
            hub_message::Msg::Chunk(c) => {
                let id = c.build_id.clone();
                if let Some(build) = active.get_mut(&id) {
                    let res = build.feed_chunk(&c);
                    advance_staging(active, &mut ready, &id, res, &env).await?;
                }
            }
            hub_message::Msg::Cancel(c) => {
                handle_cancel(c, active, out_tx, ctx).await?;
                declare_capacity(active, &ready, &env).await?;
            }
            hub_message::Msg::Need(n) => {
                serve_chunks(ctx, n.build_id, &n.hashes, out_tx.clone());
            }
            hub_message::Msg::ResultAck(a) => {
                ack_delivery(ctx, &a.dedupe_key, &a.build_id);
            }
        }
    }
}

/// Free slots, plus one lookahead build staged while every slot is
/// busy so a finishing build hands over without a round trip.
async fn declare_capacity(
    active: &HashMap<String, ActiveBuild>,
    ready: &VecDeque<String>,
    env: &LaunchEnv<'_>,
) -> Result<()> {
    let lookahead = ready.is_empty() && active.values().all(|b| b.slot.is_some());
    let capacity = env.ctx.slots.available_permits() + usize::from(lookahead);
    env.out_tx
        .send(msg(worker_message::Msg::RequestJob(RequestJob {
            capacity: u32::try_from(capacity).unwrap_or(u32::MAX),
        })))
        .await?;
    Ok(())
}

/// Act on a staging step: forward a Need, launch, or abort.
async fn advance_staging(
    active: &mut HashMap<String, ActiveBuild>,
    ready: &mut VecDeque<String>,
    id: &str,
    res: Result<(Option<Need>, StagingStatus)>,
    env: &LaunchEnv<'_>,
) -> Result<()> {
    let status = match res {
        Err(e) => {
            abort_active(active, id, env.out_tx, &e).await?;
            return declare_capacity(active, ready, env).await;
        }
        Ok((need, status)) => {
            if let Some(n) = need {
                env.out_tx.send(msg(worker_message::Msg::Need(n))).await?;
            }
            status
        }
    };
    match status {
        StagingStatus::InProgress => {}
        StagingStatus::Ready => {
            let build = active.get_mut(id).unwrap();
            if build.slot.is_none() {
                build.slot = env.ctx.try_slot();
            }
            if build.slot.is_none() {
                ready.push_back(id.to_string());
                return Ok(());
            }
            let build = active.remove(id).unwrap();
            launch_build(env.ctx, build, env.out_tx, env.build_timeout);
            declare_capacity(active, ready, env).await?;
        }
    }
    Ok(())
}

/// Cancel a build. Still staging: tear it down right here. Already
/// executing: flag its dedupe key for the supervising loop. The key
/// is the stable identity, the build_id the hub knows may predate a
/// concurrent resume.
async fn handle_cancel(
    c: CancelBuild,
    active: &mut HashMap<String, ActiveBuild>,
    out_tx: &mpsc::Sender<WorkerMessage>,
    ctx: &Arc<WorkerCtx>,
) -> Result<()> {
    tracing::info!(id = c.build_id, "hub cancelled the build");
    if let Some(build) = active.remove(&c.build_id) {
        build.abort().await;
        fail_build(out_tx, &c.build_id, &err_msg("build cancelled")).await?;
    } else {
        // Only flag builds that are still running: a key flagged for
        // an already-finished build would never be consumed and would
        // kill the next build sharing that dedupe key. The flag is
        // set while holding the registry lock so a build finishing
        // concurrently in record_finished cannot slip between the
        // check and the insert.
        let map = ctx.resumable.lock().unwrap();
        if map.get(&c.dedupe_key).is_some_and(|e| e.finished.is_none()) {
            ctx.cancelled.lock().unwrap().insert(c.dedupe_key);
        }
    }
    Ok(())
}

/// Everything needed to launch a staged build.
struct LaunchEnv<'a> {
    ctx: &'a Arc<WorkerCtx>,
    out_tx: &'a mpsc::Sender<WorkerMessage>,
    build_timeout: Duration,
}

/// Hand freed slots to staged builds waiting for one.
fn grant_slots(
    active: &mut HashMap<String, ActiveBuild>,
    ready: &mut VecDeque<String>,
    env: &LaunchEnv<'_>,
) {
    while let Some(id) = ready.front() {
        // cancel may have removed it from active
        let Some(build) = active.get_mut(id) else {
            ready.pop_front();
            continue;
        };
        let Some(slot) = env.ctx.try_slot() else {
            break;
        };
        build.slot = Some(slot);
        let build = active.remove(&ready.pop_front().unwrap()).unwrap();
        launch_build(env.ctx, build, env.out_tx, env.build_timeout);
    }
}

/// Adopt a re-dispatched build or register a fresh one for staging.
async fn handle_assignment(
    a: BuildAssignment,
    active: &mut HashMap<String, ActiveBuild>,
    wake: &mpsc::UnboundedSender<Wake>,
    out_tx: &mpsc::Sender<WorkerMessage>,
    ctx: &Arc<WorkerCtx>,
) -> Result<Option<String>> {
    // A key we already hold means a hub (likely freshly restarted)
    // re-dispatched a build we are running or have finished: adopt
    // the new build_id and deliver the result when there is one,
    // instead of building again.
    if ctx.adopt_assignment(&a, out_tx) {
        tracing::info!(id = a.build_id, key = a.dedupe_key, "build resumed");
        out_tx
            .send(msg(worker_message::Msg::Resumed(Resumed {
                build_id: a.build_id.clone(),
            })))
            .await?;
        let ctx = ctx.clone();
        tokio::task::spawn_blocking(move || try_deliver(&ctx, &a.dedupe_key));
        return Ok(None);
    }
    tracing::info!(id = a.build_id, "build assigned");
    // build ids are never reused; a duplicate is a confused hub
    if let Some(old) = active.remove(&a.build_id) {
        tracing::warn!(id = old.assignment.build_id, "discarding duplicate build");
        old.abort().await;
    }
    let build_id = a.build_id.clone();
    match validate_assignment(&a).and_then(|()| ActiveBuild::new(a, ctx.clone(), wake.clone())) {
        Ok(mut b) => {
            b.slot = ctx.try_slot();
            active.insert(build_id.clone(), b);
            Ok(Some(build_id))
        }
        Err(e) => {
            fail_build(out_tx, &build_id, &e).await?;
            Ok(None)
        }
    }
}

/// Register a fully-staged build as resumable and run it on a blocking
/// thread; the result is delivered via the resumable registry, so the
/// build outlives this session.
fn launch_build(
    ctx: &Arc<WorkerCtx>,
    build: ActiveBuild,
    out_tx: &mpsc::Sender<WorkerMessage>,
    build_timeout: Duration,
) {
    let ctx = ctx.clone();
    let out_tx = out_tx.clone();
    let key = build.assignment.dedupe_key.clone();
    ctx.resumable.lock().unwrap().insert(
        key.clone(),
        ResumableBuild {
            build_id: build.assignment.build_id.clone(),
            out_tx: Some(out_tx.clone()),
            finished: None,
            delivering: false,
            dir: build.dir.clone(),
            // execute() streams the log live itself
            log_tail: None,
        },
    );
    tokio::task::spawn_blocking(move || {
        let fin = execute_to_finished(&build, &out_tx, build_timeout);
        drop(build);
        record_finished(&ctx, &key, fin);
    });
}

/// Tear down a still-staging build and report the error to the hub.
async fn abort_active(
    active: &mut HashMap<String, ActiveBuild>,
    id: &str,
    out_tx: &mpsc::Sender<WorkerMessage>,
    e: &Error,
) -> Result<()> {
    if let Some(build) = active.remove(id) {
        build.abort().await;
    }
    fail_build(out_tx, id, e).await
}

/// Report a per-build failure to the hub without tearing the session down.
async fn fail_build(
    out_tx: &mpsc::Sender<WorkerMessage>,
    build_id: &str,
    err: &Error,
) -> Result<()> {
    let err = chain(err);
    tracing::error!(id = build_id, "build setup failed: {err}");
    out_tx
        .send(msg(worker_message::Msg::Result(BuildResult {
            build_id: build_id.into(),
            exit_code: 1,
            outputs: vec![],
            extras: vec![],
            error: err,
        })))
        .await?;
    Ok(())
}
