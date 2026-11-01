use super::*;
use std::fs;

use crate::config::NixConfig;
use crate::proto::Heartbeat;

fn heartbeat(max_jobs: Option<u32>) -> WorkerMessage {
    WorkerMessage {
        msg: Some(worker_message::Msg::Heartbeat(Heartbeat {
            max_jobs,
            ..Default::default()
        })),
    }
}

/// A heartbeat carries the worker's current capacity, e.g. after
/// an agent joined or went down, and the nix.conf fragment follows
/// it. One from a worker predating the field keeps the value.
#[tokio::test]
async fn heartbeat_updates_the_advertised_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nix.conf");
    let mut state = HubState::for_test(Duration::ZERO);
    state.nix_config = Some(NixConfig {
        path: path.clone(),
        attach_program: "/attach".into(),
        oversubscribe_percent: 100,
        max_jobs_cap: 256,
    });
    let state = Arc::new(state);
    let caps = WorkerCaps {
        name: "w".into(),
        connected_at: Instant::now(),
        systems: HashMap::new(),
        max_jobs: 2,
    };
    let guard = CapsGuard::new(state.clone(), caps);
    let id = guard.id;
    let (tx, rx) = mpsc::channel(4);
    tx.send(heartbeat(Some(3))).await.unwrap();
    tx.send(heartbeat(None)).await.unwrap();
    drop(tx);
    let capacity = Arc::new(AtomicU32::new(0));
    route_loop(rx, Router::default(), capacity, state.clone(), id).await;
    let jobs = state.worker_caps.lock().unwrap()[&id].max_jobs;
    assert_eq!(jobs, 3);
    let conf = fs::read_to_string(&path).unwrap();
    assert!(conf.contains("max-jobs = 3\n"), "{conf}");
}
