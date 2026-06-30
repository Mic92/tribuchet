//! Per-session dedup of input-NAR imports across concurrent builds.
//!
//! Builds sharing a session have overlapping input closures. Two builds
//! importing the same missing path concurrently both take the
//! nix-daemon's per-path lock; since the session feeds NAR chunks
//! serially, the lock-holder can stall behind the lock-waiter and
//! deadlock. `SessionImports` gives each missing path one owner that
//! imports it; other builds await the owner instead. One import per
//! path: no lock contention, no redundant transfer.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::watch;

/// Outcome of claiming a path: `Some(true)` imported successfully,
/// `Some(false)` the owner failed (or dropped without finishing).
type Outcome = Option<bool>;

/// Session-scoped registry of in-flight/finished input imports. Dropped
/// when the hub session ends; a fresh session re-checks path validity
/// against the daemon, so already-imported paths are simply no longer
/// missing.
#[derive(Default)]
pub(super) struct SessionImports {
    map: Mutex<HashMap<String, watch::Receiver<Outcome>>>,
}

/// The caller's role for one path.
pub(super) enum Claim {
    /// This build must fetch and import the path; complete the guard
    /// when the import settles.
    Owner(ImportGuard),
    /// Another build is already importing the path; await its result.
    Awaiter(ImportWait),
}

/// Held by the owning build until its import settles. Completing it (or
/// dropping it) wakes every awaiter; a drop without `complete` reports
/// failure so awaiters do not hang on an abandoned import.
pub(super) struct ImportGuard {
    tx: watch::Sender<Outcome>,
    settled: bool,
}

/// An awaiter's handle to the owner's eventual result.
pub(super) struct ImportWait {
    rx: watch::Receiver<Outcome>,
}

impl SessionImports {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Claim responsibility for `path`. The first caller owns the
    /// import; later callers (this session) await that owner.
    pub(super) fn claim(&self, path: &str) -> Claim {
        let mut map = self.map.lock().unwrap();
        if let Some(rx) = map.get(path) {
            return Claim::Awaiter(ImportWait { rx: rx.clone() });
        }
        let (tx, rx) = watch::channel(None);
        map.insert(path.to_owned(), rx);
        Claim::Owner(ImportGuard { tx, settled: false })
    }
}

impl ImportGuard {
    /// Record the import result and wake awaiters.
    pub(super) fn complete(mut self, ok: bool) {
        self.settled = true;
        let _ = self.tx.send(Some(ok));
    }
}

impl Drop for ImportGuard {
    fn drop(&mut self) {
        // Owner went away without finishing (build aborted, panic):
        // report failure so awaiters do not wait forever.
        if !self.settled {
            let _ = self.tx.send(Some(false));
        }
    }
}

impl ImportWait {
    /// Block until the owner settles; the bool is its success.
    pub(super) async fn wait(mut self) -> bool {
        // wait_for returns immediately if the value already satisfies
        // the predicate, covering an owner that settled before we
        // started waiting. A send error (owner dropped its sender
        // after sending) still leaves the last value observable.
        match self.rx.wait_for(Option::is_some).await {
            Ok(v) => v.unwrap_or(false),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn second_claim_awaits_owner_success() {
        let imports = SessionImports::new();
        let Claim::Owner(guard) = imports.claim("/nix/store/x") else {
            panic!("first claim should own");
        };
        let Claim::Awaiter(wait) = imports.claim("/nix/store/x") else {
            panic!("second claim of the same path should await");
        };
        let waiter = tokio::spawn(wait.wait());
        guard.complete(true);
        assert!(waiter.await.unwrap());
    }

    #[tokio::test]
    async fn awaiter_sees_owner_failure() {
        let imports = SessionImports::new();
        let Claim::Owner(guard) = imports.claim("/nix/store/x") else {
            unreachable!()
        };
        let Claim::Awaiter(wait) = imports.claim("/nix/store/x") else {
            unreachable!()
        };
        guard.complete(false);
        assert!(!wait.wait().await);
    }

    #[tokio::test]
    async fn dropped_owner_fails_awaiters() {
        let imports = SessionImports::new();
        let Claim::Owner(guard) = imports.claim("/nix/store/x") else {
            unreachable!()
        };
        let Claim::Awaiter(wait) = imports.claim("/nix/store/x") else {
            unreachable!()
        };
        drop(guard); // build aborted before importing
        assert!(!wait.wait().await);
    }
}
