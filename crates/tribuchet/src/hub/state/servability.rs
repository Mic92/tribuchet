//! Whether a platform can be built now, once an expected worker is
//! back, or never: what decides between dispatching a submission,
//! queueing it and declining it.
use std::time::Instant;

use super::{HubState, WorkerCaps};

pub(in crate::hub) enum Servability {
    Now,
    ExpectedBy(Instant),
    /// Awaited with no deadline: `require-worker` is set.
    Awaited,
    Never,
}

impl HubState {
    /// Remember a departed worker's capabilities so a build for the
    /// platform it served waits for it to reconnect rather than
    /// declining at once.
    pub(in crate::hub) fn record_departed(&self, caps: WorkerCaps) {
        let now = Instant::now();
        let mut departed = self.departed.lock().unwrap();
        // Prune here: expected_deadline() only runs for unservable
        // submissions, so a healthy fleet would otherwise accumulate
        // an entry per worker reconnect indefinitely.
        departed.retain(|(_, at)| now < *at + self.worker_grace);
        departed.push((caps, now));
    }

    /// Whether a platform can be built now, once an expected worker is
    /// back, or never.
    pub(in crate::hub) fn servability(&self, system: &str, features: &[String]) -> Servability {
        // Only the hub's own Nix has these: waiting, even for a worker
        // that `require-worker` insists on, would wait forever.
        if features.iter().any(|f| self.local_features.contains(f)) {
            return Servability::Never;
        }
        if self
            .worker_caps
            .lock()
            .unwrap()
            .values()
            .any(|c| c.serves(system, features))
        {
            return Servability::Now;
        }
        if self.require_worker {
            return Servability::Awaited;
        }
        self.expected_deadline(system, features)
            .map_or(Servability::Never, Servability::ExpectedBy)
    }

    fn expected_deadline(&self, system: &str, features: &[String]) -> Option<Instant> {
        let now = Instant::now();
        // During the startup window no worker has re-registered yet, so
        // every platform is awaited; afterwards only one a worker served
        // until it dropped within the reconnect window (reload/crash).
        let startup = self.started_at + self.worker_grace;
        if now < startup {
            return Some(startup);
        }
        let mut departed = self.departed.lock().unwrap();
        departed.retain(|(_, at)| now < *at + self.worker_grace);
        departed
            .iter()
            .filter(|(c, _)| c.serves(system, features))
            .map(|(_, at)| *at + self.worker_grace)
            .max()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::tests::caps;
    use super::*;

    #[test]
    fn startup_window_awaits_then_unseen_platform_declines() {
        // Within the startup window any platform is awaited (workers
        // have not re-registered yet); once it lapses a never-seen
        // platform with no departed worker declines at once.
        let within = HubState::for_test(Duration::from_secs(30));
        assert!(within.expected_deadline("aarch64-linux", &[]).is_some());
        let lapsed = HubState::for_test(Duration::ZERO);
        assert!(lapsed.expected_deadline("aarch64-linux", &[]).is_none());
    }
    #[test]
    fn require_worker_waits_instead_of_declining() {
        // A hub that is not a build machine: past the startup window,
        // with no worker ever seen, every platform would decline and
        // Nix would build it here. require-worker keeps them queued.
        let mut state = HubState::for_test(Duration::ZERO);
        assert!(matches!(
            state.servability("x86_64-linux", &[]),
            Servability::Never
        ));
        state.require_worker = true;
        for system in ["x86_64-linux", "aarch64-linux", "aarch64-darwin"] {
            assert!(matches!(
                state.servability(system, &[]),
                Servability::Awaited
            ));
        }
    }

    #[test]
    fn local_features_decline_even_with_require_worker() {
        // A dynamic derivation's producer needs the hub's own daemon
        // (builder-rpc-v0): no worker will ever serve it, so it must not
        // wait for one, and no worker that claims it gets it either.
        let mut state = HubState::for_test(Duration::ZERO);
        state.require_worker = true;
        state.local_features = vec!["builder-rpc-v0".to_owned()];
        state
            .worker_caps
            .lock()
            .unwrap()
            .insert(1, caps("x86_64-linux", &["builder-rpc-v0"]));
        let rpc = vec!["builder-rpc-v0".to_owned()];
        assert!(matches!(
            state.servability("x86_64-linux", &rpc),
            Servability::Never
        ));
        // Everything else still waits for a worker.
        let kvm = vec!["kvm".to_owned()];
        assert!(matches!(
            state.servability("x86_64-linux", &kvm),
            Servability::Awaited
        ));
        assert!(matches!(
            state.servability("x86_64-linux", &[]),
            Servability::Now
        ));
    }

    #[test]
    fn departed_worker_keeps_its_platform_expected() {
        // Past the startup window but inside the reconnect window.
        let mut state = HubState::for_test(Duration::from_secs(30));
        state.started_at = Instant::now().checked_sub(Duration::from_mins(1)).unwrap();
        state.record_departed(caps("x86_64-linux", &["kvm"]));
        let kvm = vec!["kvm".to_owned()];
        let kvm_bp = vec!["kvm".to_owned(), "big-parallel".to_owned()];
        // The exact platform it served is still awaited.
        assert!(state.expected_deadline("x86_64-linux", &kvm).is_some());
        // A feature it never offered, or another system, is not.
        assert!(state.expected_deadline("x86_64-linux", &kvm_bp).is_none());
        assert!(state.expected_deadline("aarch64-linux", &[]).is_none());
    }
}
