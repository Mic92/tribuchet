//! Registry of input paths some build is importing. Later builds wait
//! on the claim instead of fetching twice. Modelled in spec/staging.qnt.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::worker) enum ClaimState {
    Running,
    Done,
    /// owner gave up
    Failed,
}

#[derive(Default)]
pub(in crate::worker) struct Claims(Mutex<HashMap<String, watch::Sender<ClaimState>>>);

/// Sent to the session loop when a waited-on claim settles.
pub(in crate::worker) struct Wake {
    pub build_id: String,
    pub path: String,
}

pub(super) struct Wait {
    pub(super) rx: watch::Receiver<ClaimState>,
    watcher: JoinHandle<()>,
}

impl Drop for Wait {
    fn drop(&mut self) {
        self.watcher.abort();
    }
}

pub(super) enum Claimed {
    Mine,
    Theirs(Wait),
}

impl Claims {
    /// Check and insert under one lock, so exactly one build claims.
    pub(super) fn claim_or_wait(
        &self,
        path: &str,
        build_id: &str,
        wake: &mpsc::UnboundedSender<Wake>,
    ) -> Claimed {
        let mut map = self.0.lock().unwrap();
        if let Some(tx) = map.get(path) {
            let rx = tx.subscribe();
            let wake = wake.clone();
            let msg = Wake {
                build_id: build_id.to_string(),
                path: path.to_string(),
            };
            let mut w = rx.clone();
            let watcher = tokio::spawn(async move {
                let _ = w.wait_for(|s| *s != ClaimState::Running).await;
                let _ = wake.send(msg);
            });
            return Claimed::Theirs(Wait { rx, watcher });
        }
        map.insert(path.to_string(), watch::channel(ClaimState::Running).0);
        Claimed::Mine
    }

    pub(super) fn settle(&self, path: &str, state: ClaimState) {
        if let Some(tx) = self.0.lock().unwrap().remove(path) {
            tx.send_replace(state);
        }
    }
}

impl Wait {
    /// `None` while still running. A dropped sender counts as Failed.
    pub(super) fn settled(&self) -> Option<ClaimState> {
        match *self.rx.borrow() {
            ClaimState::Running if self.rx.has_changed().is_ok() => None,
            ClaimState::Running | ClaimState::Failed => Some(ClaimState::Failed),
            ClaimState::Done => Some(ClaimState::Done),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn second_build_waits_and_is_woken() {
        let claims = Claims::default();
        let (tx, mut rx) = mpsc::unbounded_channel();
        assert!(matches!(claims.claim_or_wait("p", "a", &tx), Claimed::Mine));
        let Claimed::Theirs(wait) = claims.claim_or_wait("p", "b", &tx) else {
            panic!("second claim must wait");
        };
        assert_eq!(wait.settled(), None);
        claims.settle("p", ClaimState::Done);
        let w = rx.recv().await.unwrap();
        assert_eq!((w.build_id.as_str(), w.path.as_str()), ("b", "p"));
        assert_eq!(wait.settled(), Some(ClaimState::Done));
        // released: the next build claims it afresh
        assert!(matches!(claims.claim_or_wait("p", "c", &tx), Claimed::Mine));
    }

    #[tokio::test]
    async fn abandoned_claim_reads_as_failed() {
        let claims = Claims::default();
        let (tx, mut rx) = mpsc::unbounded_channel();
        claims.claim_or_wait("p", "a", &tx);
        let Claimed::Theirs(wait) = claims.claim_or_wait("p", "b", &tx) else {
            panic!();
        };
        claims.settle("p", ClaimState::Failed);
        rx.recv().await.unwrap();
        assert_eq!(wait.settled(), Some(ClaimState::Failed));
    }
}
