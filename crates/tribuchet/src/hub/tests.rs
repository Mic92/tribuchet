use super::*;

use state::Replay;

use crate::proto::BuildRequest;

fn caps(name: &str) -> WorkerCaps {
    WorkerCaps {
        name: name.into(),
        connected_at: Instant::now(),
        systems: [("x86_64-linux".to_owned(), HashSet::new())].into(),
        max_jobs: 1,
    }
}

/// A worker session as worker_loop registers it.
fn register(state: &Arc<HubState>, name: &str, held: &[&str]) -> CapsGuard {
    let guard = CapsGuard::new(state.clone(), caps(name));
    let keys = held.iter().map(|k| (*k).to_owned()).collect();
    state.held.lock().unwrap().insert(guard.id, keys);
    guard
}

fn job(n: usize, replay: Arc<Replay>) -> Job {
    Job {
        id: format!("{n:032x}"),
        key: format!("k{n}"),
        req: BuildRequest {
            system: "x86_64-linux".into(),
            ..Default::default()
        },
        tmp_dir_pack: Arc::new(Vec::new()),
        features: vec![],
        replay,
        listing: Mutex::default(),
        attempts: 0,
        queued_at: Instant::now(),
        loss: None,
    }
}

/// Dispatch `job` to `worker`, whose session then dies while the build
/// runs, as when the worker unit restarts.
async fn lose_session(state: &Arc<HubState>, job: Job, worker: CapsGuard) {
    let session = (worker.id, worker.caps.name.clone());
    drop(worker);
    requeue_lost(state, job, session).await;
}

/// Supervise `job` on `session`, whose channels are closed: the build is
/// requeued as one whose session died.
async fn requeue_lost(state: &Arc<HubState>, job: Job, session: (u64, String)) {
    let router = Router::default();
    let in_rx = router.register(&job.id);
    let (out_tx, _out_rx) = mpsc::channel(64);
    router.close_all();
    let sess = Arc::new(WorkerSession::new());
    supervise_job(state.clone(), job, router, out_tx, in_rx, sess, session).await;
}

#[tokio::test]
async fn restarted_worker_gets_its_build_back() {
    let state = Arc::new(HubState::for_test(Duration::from_secs(30)));
    let other = register(&state, "w2", &[]);
    let replay = Arc::new(Replay::default());
    let _client = replay.subscribe().await;
    lose_session(&state, job(1, replay), register(&state, "w1", &[])).await;
    assert!(
        state.take_job(&caps("w2"), other.id).await.is_none(),
        "build handed to another worker while its own reconnects"
    );
    let back = register(&state, "w1", &["k1"]);
    assert!(state.take_job(&caps("w2"), other.id).await.is_none());
    let resumed = state.take_job_by_key(back.id).await;
    assert_eq!(resumed.map(|j| j.attempts), Some(1));
}

#[tokio::test]
async fn build_goes_elsewhere_once_the_grace_ends() {
    let state = Arc::new(HubState::for_test(Duration::from_secs(1)));
    let other = register(&state, "w2", &[]);
    let replay = Arc::new(Replay::default());
    let _client = replay.subscribe().await;
    lose_session(&state, job(1, replay), register(&state, "w1", &[])).await;
    assert!(state.take_job(&caps("w2"), other.id).await.is_none());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(state.take_job(&caps("w2"), other.id).await.is_some());
}

/// The worker came back without the build (it was still staging):
/// no reason to keep it from the others any longer.
#[tokio::test]
async fn build_is_released_when_its_worker_returns_without_it() {
    let state = Arc::new(HubState::for_test(Duration::from_secs(30)));
    let other = register(&state, "w2", &[]);
    let replay = Arc::new(Replay::default());
    let _client = replay.subscribe().await;
    lose_session(&state, job(1, replay), register(&state, "w1", &[])).await;
    let _back = register(&state, "w1", &[]);
    assert!(state.take_job(&caps("w2"), other.id).await.is_some());
}

/// worker_loop drops a dead session's registration only after its
/// builds' channels close, so the requeue can see that session still
/// registered under the worker's name. It is not the worker back.
#[tokio::test]
async fn a_dead_session_still_registered_is_not_its_worker_back() {
    let state = Arc::new(HubState::for_test(Duration::from_secs(30)));
    let other = register(&state, "w2", &[]);
    let replay = Arc::new(Replay::default());
    let _client = replay.subscribe().await;
    let dead = register(&state, "w1", &[]);
    let session = (dead.id, dead.caps.name.clone());
    requeue_lost(&state, job(1, replay), session).await;
    assert!(
        state.take_job(&caps("w2"), other.id).await.is_none(),
        "the dead session counted as its worker back"
    );
    drop(dead);
    assert!(state.take_job(&caps("w2"), other.id).await.is_none());
}

/// A build whose assignment was never sent (the hub's daemon did not
/// answer while it prepared the inputs) is no loss of that worker's:
/// it is not kept for it, though its session died.
#[tokio::test]
async fn an_assignment_never_sent_is_kept_for_no_worker() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = HubState::for_test(Duration::from_secs(30));
    state.daemon_pool = harmonia_store_remote::ConnectionPool::new(
        dir.path().join("no-daemon.sock"),
        harmonia_store_remote::PoolConfig::default(),
    );
    let state = Arc::new(state);
    let input = "/nix/store/00000000000000000000000000000000-input".to_owned();
    state
        .chunks
        .store_recipe(input.clone(), vec![], Arc::default());
    let other = register(&state, "w2", &[]);
    let replay = Arc::new(Replay::default());
    let _client = replay.subscribe().await;
    let mut j = job(1, replay);
    j.req.input_paths = vec![input];
    lose_session(&state, j, register(&state, "w1", &[])).await;
    assert!(
        state.take_job(&caps("w2"), other.id).await.is_some(),
        "kept for a worker that never got the assignment"
    );
}

/// The session is gone when the assignment is sent: the send fails, so
/// the worker never got the build, and it is kept for no worker.
#[tokio::test]
async fn an_assignment_whose_send_fails_is_kept_for_no_worker() {
    let state = Arc::new(HubState::for_test(Duration::from_secs(30)));
    let other = register(&state, "w2", &[]);
    let replay = Arc::new(Replay::default());
    let _client = replay.subscribe().await;
    let w1 = register(&state, "w1", &[]);
    let session = (w1.id, w1.caps.name.clone());
    drop(w1);
    let job = job(1, replay);
    let router = Router::default();
    let in_rx = router.register(&job.id);
    let (out_tx, out_rx) = mpsc::channel(64);
    drop(out_rx);
    router.close_all();
    let sess = Arc::new(WorkerSession::new());
    supervise_job(state.clone(), job, router, out_tx, in_rx, sess, session).await;
    assert!(
        state.take_job(&caps("w2"), other.id).await.is_some(),
        "kept for a worker whose assignment was never sent"
    );
}
