//! Hub session: connect, register, and drive the per-build message loop.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::sync::Arc;
use std::time::Duration;

use harmonia_utils_signature::SecretKey;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

use super::build::{ActiveBuild, StagingStatus, validate_assignment};
use super::caps::system_caps;
use super::resume::{
    ResumableBuild, ack_delivery, execute_to_finished, record_finished, try_deliver,
};
use super::{WorkerCtx, hostname, loadavg1, msg, request_job};
use crate::chunkio;
use crate::config::{Auth, WorkerConfig};
use crate::errors::{Error, Result, chain, err_ctx, err_msg};
use crate::proto::{
    BuildAssignment, BuildResult, CancelBuild, Heartbeat, HubMessage, MAX_MSG_SIZE, MissingPaths,
    NeedChunks, PathRecipe, Register, Resumed, WorkerMessage, hub_message,
    worker_hub_client::WorkerHubClient, worker_message,
};

pub(super) async fn session(
    opts: &WorkerConfig,
    signing_key: &Arc<SecretKey>,
    ctx: &Arc<WorkerCtx>,
) -> Result<()> {
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
            signing_public_key: signing_key.to_public_key().to_string(),
            resumable_keys: ctx.resumable_keys(),
            max_jobs: opts.max_jobs.max(1),
            chunk_support: ctx.chunks.is_some(),
        })))
        .await?;

    let mut inbound = client
        .session(ReceiverStream::new(out_rx))
        .await?
        .into_inner();
    tracing::info!(hub = opts.hub, systems = ?opts.systems, "connected to hub");

    let mut active: HashMap<String, ActiveBuild> = HashMap::new();
    let result = session_loop(
        &mut inbound,
        &mut active,
        &out_tx,
        signing_key,
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
    signing_key: &Arc<SecretKey>,
    ctx: &Arc<WorkerCtx>,
    build_timeout: Duration,
    max_jobs: u32,
) -> Result<()> {
    let env = LaunchEnv {
        ctx,
        out_tx,
        signing_key,
        build_timeout,
    };
    // Permits already funded to the hub but not yet assigned back.
    let mut pending = Vec::new();
    // Builds staged to completion but waiting for a free slot.
    let mut ready: VecDeque<String> = VecDeque::new();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
    // One unfunded request beyond the free slots: the hub assigns and
    // stages the next build while every slot is busy, so a finishing
    // build hands its slot to a build that starts immediately instead
    // of waiting a round trip plus staging.
    out_tx.send(request_job()).await?;
    loop {
        let m = tokio::select! {
            permit = ctx.slots.clone().acquire_owned() => {
                let permit = permit.expect("slots never closed");
                grant_slot(permit, active, &mut ready, &mut pending, &env);
                out_tx.send(request_job()).await?;
                continue;
            }
            _ = heartbeat.tick() => {
                let occupied = max_jobs as usize - ctx.slots.available_permits();
                let running = occupied.saturating_sub(pending.len() + active.len());
                out_tx.send(msg(worker_message::Msg::Heartbeat(Heartbeat {
                    running_jobs: u32::try_from(running).unwrap_or(u32::MAX),
                    load1: loadavg1(),
                }))).await?;
                continue;
            }
            m = inbound.message() => {
                m?.ok_or_else(|| err_msg("hub closed the session"))?
            }
        };
        let Some(m) = m.msg else { continue };
        match m {
            hub_message::Msg::Assignment(a) => {
                handle_assignment(a, active, &mut pending, out_tx, ctx).await?;
            }
            hub_message::Msg::PathOffer(offer) => {
                let Some(build) = active.get_mut(&offer.build_id) else {
                    continue;
                };
                match build.negotiate(&offer.store_paths).await {
                    Ok(missing) => {
                        out_tx
                            .send(msg(worker_message::Msg::MissingPaths(MissingPaths {
                                build_id: offer.build_id,
                                store_paths: missing,
                            })))
                            .await?;
                    }
                    Err(e) => abort_active(active, &offer.build_id, out_tx, &e).await?,
                }
            }
            hub_message::Msg::Nar(n) => {
                let id = n.build_id.clone();
                if let Some(build) = active.get_mut(&id) {
                    // A bad transfer fails this build, not the session.
                    // A NAR eof can complete staging: the hub streams
                    // optimistically, so the tmp dir may already be done.
                    let res = build.feed_nar(n).await;
                    advance_staging(active, &mut ready, &id, res, &env).await?;
                }
            }
            hub_message::Msg::TmpDir(t) => {
                let id = t.build_id.clone();
                if let Some(build) = active.get_mut(&id) {
                    let res = build.feed_tmp_dir(t).await;
                    advance_staging(active, &mut ready, &id, res, &env).await?;
                }
            }
            hub_message::Msg::StagingComplete(s) => {
                if let Some(build) = active.get_mut(&s.build_id) {
                    let res = build.complete_staging().await;
                    advance_staging(active, &mut ready, &s.build_id, res, &env).await?;
                }
            }
            hub_message::Msg::PathInfo(pi) => {
                let id = pi.build_id.clone();
                if let Some(build) = active.get_mut(&id)
                    && let Err(e) = build.feed_path_info(&pi)
                {
                    abort_active(active, &id, out_tx, &e).await?;
                }
            }
            hub_message::Msg::Recipe(r) => {
                handle_recipe(r, active, &mut ready, out_tx, &env).await?;
            }
            hub_message::Msg::ChunkRun(c) => {
                let id = c.build_id.clone();
                if let Some(build) = active.get_mut(&id) {
                    let res = build.feed_chunk_run(c).await;
                    advance_staging(active, &mut ready, &id, res, &env).await?;
                }
            }
            hub_message::Msg::Cancel(c) => handle_cancel(c, active, out_tx, ctx).await?,
            hub_message::Msg::ResultAck(a) => {
                ack_delivery(ctx, &a.dedupe_key, &a.build_id);
            }
        }
    }
}

/// Act on a staging step: launch, request an input resend, or abort.
async fn advance_staging(
    active: &mut HashMap<String, ActiveBuild>,
    ready: &mut VecDeque<String>,
    id: &str,
    res: Result<StagingStatus>,
    env: &LaunchEnv<'_>,
) -> Result<()> {
    match res {
        Err(e) => abort_active(active, id, env.out_tx, &e).await?,
        Ok(StagingStatus::InProgress) => {}
        Ok(StagingStatus::Ready) => {
            // The lookahead assignment carries no permit. Grab a free
            // slot (funding its advertisement ourselves) or queue
            // until one frees.
            let build = active.get_mut(id).unwrap();
            if build.permit.is_none() {
                let Ok(p) = env.ctx.slots.clone().try_acquire_owned() else {
                    ready.push_back(id.to_string());
                    return Ok(());
                };
                build.permit = Some(p);
                env.out_tx.send(request_job()).await?;
            }
            let build = active.remove(id).unwrap();
            launch_build(
                env.ctx,
                build,
                env.out_tx,
                env.signing_key,
                env.build_timeout,
            );
        }
        Ok(StagingStatus::NeedResend(paths)) => {
            tracing::info!(
                id,
                count = paths.len(),
                "re-requesting inputs another build failed to import"
            );
            env.out_tx
                .send(msg(worker_message::Msg::MissingPaths(MissingPaths {
                    build_id: id.to_string(),
                    store_paths: paths,
                })))
                .await?;
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

/// A recipe may end the recipe set (`last`), in which case the union
/// of chunks the store lacks goes back as one NeedChunks.
async fn handle_recipe(
    r: PathRecipe,
    active: &mut HashMap<String, ActiveBuild>,
    ready: &mut VecDeque<String>,
    out_tx: &mpsc::Sender<WorkerMessage>,
    env: &LaunchEnv<'_>,
) -> Result<()> {
    let id = r.build_id.clone();
    let Some(build) = active.get_mut(&id) else {
        return Ok(());
    };
    match build.feed_recipe(r).await {
        Ok((needed, status)) => {
            if let Some(hashes) = needed {
                out_tx
                    .send(msg(worker_message::Msg::NeedChunks(NeedChunks {
                        build_id: id.clone(),
                        hashes,
                    })))
                    .await?;
            }
            advance_staging(active, ready, &id, Ok(status), env).await?;
        }
        Err(e) => abort_active(active, &id, out_tx, &e).await?,
    }
    Ok(())
}

/// Everything needed to launch a staged build.
struct LaunchEnv<'a> {
    ctx: &'a Arc<WorkerCtx>,
    out_tx: &'a mpsc::Sender<WorkerMessage>,
    signing_key: &'a Arc<SecretKey>,
    build_timeout: Duration,
}

/// Hand a freed slot to a staged build waiting for one, or advertise
/// it to the hub as pending.
fn grant_slot(
    permit: tokio::sync::OwnedSemaphorePermit,
    active: &mut HashMap<String, ActiveBuild>,
    ready: &mut VecDeque<String>,
    pending: &mut Vec<tokio::sync::OwnedSemaphorePermit>,
    env: &LaunchEnv<'_>,
) {
    let mut permit = Some(permit);
    while let Some(id) = ready.pop_front() {
        // cancel may have removed it from active
        if let Some(mut build) = active.remove(&id) {
            build.permit = permit.take();
            launch_build(
                env.ctx,
                build,
                env.out_tx,
                env.signing_key,
                env.build_timeout,
            );
            break;
        }
    }
    if let Some(p) = permit {
        pending.push(p);
    }
}

/// Adopt a re-dispatched build or stage a fresh assignment.
async fn handle_assignment(
    a: BuildAssignment,
    active: &mut HashMap<String, ActiveBuild>,
    pending: &mut Vec<tokio::sync::OwnedSemaphorePermit>,
    out_tx: &mpsc::Sender<WorkerMessage>,
    ctx: &Arc<WorkerCtx>,
) -> Result<()> {
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
        return Ok(());
    }
    // Resumed assignments are credit-free on the hub, so never funded
    // a permit into `pending`.
    let permit = pending.pop();
    tracing::info!(id = a.build_id, "build assigned");
    // build ids are never reused; a duplicate is a confused hub
    if let Some(old) = active.remove(&a.build_id) {
        tracing::warn!(id = old.assignment.build_id, "discarding duplicate build");
        old.abort().await;
    }
    let build_id = a.build_id.clone();
    match validate_assignment(&a).and_then(|()| ActiveBuild::new(a, ctx.clone())) {
        Ok(mut b) => {
            b.permit = permit;
            active.insert(build_id, b);
        }
        Err(e) => fail_build(out_tx, &build_id, &e).await?,
    }
    Ok(())
}

/// Register a fully-staged build as resumable and run it on a blocking
/// thread; the result is delivered via the resumable registry, so the
/// build outlives this session.
fn launch_build(
    ctx: &Arc<WorkerCtx>,
    build: ActiveBuild,
    out_tx: &mpsc::Sender<WorkerMessage>,
    signing_key: &Arc<SecretKey>,
    build_timeout: Duration,
) {
    let ctx = ctx.clone();
    let out_tx = out_tx.clone();
    let signing_key = signing_key.clone();
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
        let fin = execute_to_finished(&build, &out_tx, &signing_key, build_timeout);
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
