//! Build submission: request validation, dedupe keys, the AttachHub service.

use std::collections::HashSet;
use std::path::{Component, Path};
use std::sync::Arc;
use std::time::Instant;

use nix::fcntl;
use sha2::{Digest, Sha256};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use super::state::{HubState, Job, Replay};
use crate::proto::{AttachEvent, BuildRequest, attach_event, attach_hub_server};
use crate::store::{STORE_DIR, valid_store_path};

fn validate_request(req: &BuildRequest) -> Result<(), Status> {
    let bad = |what: &str, p: &str| {
        Status::invalid_argument(format!("{what} is not a valid store path: {p}"))
    };
    // A client-chosen store_dir would turn the root hub into an
    // arbitrary-file-read (and the worker sandbox into worse).
    if req.store_dir != STORE_DIR {
        return Err(Status::invalid_argument("invalid store dir"));
    }
    let mut seen_inputs = HashSet::new();
    for p in &req.input_paths {
        if !valid_store_path(&req.store_dir, p) {
            return Err(bad("input path", p));
        }
        if !seen_inputs.insert(p) {
            return Err(Status::invalid_argument(format!(
                "duplicate input path {p}"
            )));
        }
    }
    let mut seen_outputs = HashSet::new();
    for p in req.outputs.values() {
        if !valid_store_path(&req.store_dir, p) {
            return Err(bad("output path", p));
        }
        if !seen_outputs.insert(p) {
            return Err(Status::invalid_argument(format!(
                "duplicate output path {p}"
            )));
        }
        if seen_inputs.contains(p) {
            return Err(Status::invalid_argument(format!(
                "output path {p} is also an input"
            )));
        }
    }
    // Nix builders are absolute store paths; anything else would also be
    // option-injectable into sandbox-exec on Darwin workers.
    if !req.builder.starts_with('/') {
        return Err(Status::invalid_argument("builder must be an absolute path"));
    }
    // Where the worker mounts/symlinks the shipped build dir: "/build"
    // from Linux clients, the real per-build topTmpDir from Darwin.
    let tmp_in_sandbox = Path::new(&req.tmp_dir_in_sandbox);
    if !tmp_in_sandbox.is_absolute()
        || tmp_in_sandbox
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || req.tmp_dir_in_sandbox.starts_with(STORE_DIR)
    {
        return Err(Status::invalid_argument("invalid tmpDirInSandbox"));
    }
    let tmp = Path::new(&req.top_tmp_dir);
    if !tmp.is_absolute() || tmp.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(Status::invalid_argument("invalid topTmpDir"));
    }
    Ok(())
}

/// The root hub tars `top_tmp_dir` off local disk; require it to be a
/// real directory owned by the connecting peer so a client cannot have
/// the hub ship `/root` or another user's build dir. Returns the opened
/// directory: tarring later goes through this fd, so swapping the path
/// for a symlink after validation cannot redirect what gets shipped.
pub(super) fn validate_top_tmp_dir(
    top_tmp_dir: &str,
    peer_uid: u32,
) -> Result<std::fs::File, Status> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((fcntl::OFlag::O_DIRECTORY | fcntl::OFlag::O_NOFOLLOW).bits())
        .open(top_tmp_dir)
        .map_err(|e| Status::invalid_argument(format!("topTmpDir {top_tmp_dir}: {e}")))?;
    // O_DIRECTORY already guarantees a directory; only ownership is
    // left to check, via fstat on the handle just opened.
    let meta = dir
        .metadata()
        .map_err(|e| Status::invalid_argument(format!("topTmpDir {top_tmp_dir}: {e}")))?;
    if meta.uid() != peer_uid {
        return Err(Status::permission_denied(
            "topTmpDir is not owned by the requesting user",
        ));
    }
    Ok(dir)
}

/// Dedupe key: hash of the full canonicalized request, so only truly
/// identical submissions share a build. A key built from output paths
/// alone would let a colliding (or crafted) request attach to another
/// client's build.
pub(super) fn dedupe_key(req: &BuildRequest) -> String {
    fn feed(h: &mut Sha256, s: &str) {
        h.update((s.len() as u64).to_le_bytes());
        h.update(s.as_bytes());
    }
    // Each variable-length section is preceded by its element count;
    // without it, an args tail and an env entry (for example) would
    // feed identical bytes and two different requests could collide.
    fn count(h: &mut Sha256, n: usize) {
        h.update((n as u64).to_le_bytes());
    }
    let mut h = Sha256::new();
    feed(&mut h, &req.system);
    feed(&mut h, &req.builder);
    count(&mut h, req.args.len());
    for a in &req.args {
        feed(&mut h, a);
    }
    let mut env: Vec<_> = req.env.iter().collect();
    env.sort();
    count(&mut h, env.len());
    for (k, v) in env {
        feed(&mut h, k);
        feed(&mut h, v);
    }
    let mut outs: Vec<_> = req.outputs.iter().collect();
    outs.sort();
    count(&mut h, outs.len());
    for (k, v) in outs {
        feed(&mut h, k);
        feed(&mut h, v);
    }
    let mut inputs: Vec<_> = req.input_paths.iter().collect();
    inputs.sort();
    count(&mut h, inputs.len());
    for p in inputs {
        feed(&mut h, p);
    }
    feed(&mut h, &req.store_dir);
    feed(&mut h, &req.tmp_dir_in_sandbox);
    h.update([u8::from(req.fixed_output)]);
    hex::encode(h.finalize())
}

fn new_id() -> String {
    let mut buf = [0u8; 16];
    rand::RngExt::fill(&mut rand::rng(), &mut buf);
    hex::encode(buf)
}

pub(super) struct AttachSvc {
    pub(super) state: Arc<HubState>,
}

type BuildStream = ReceiverStream<Result<AttachEvent, Status>>;

impl AttachSvc {
    /// Block until a worker can serve `system`+`features`, or return a
    /// decline stream (single exit-code event, so a patched Nix falls
    /// back to a local build). `None` means a worker is now available.
    /// Platforms we never expect to see decline without any wait.
    async fn await_capable_worker(
        &self,
        system: &str,
        features: &[String],
    ) -> Option<Response<BuildStream>> {
        let servable = || {
            let caps = self.state.worker_caps.lock().unwrap();
            caps.values().any(|c| c.serves(system, features))
        };
        let decline = || {
            tracing::info!(system, "no capable worker; declining");
            super::metrics::Metrics::inc(&self.state.metrics.declined);
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            let _ = tx.try_send(Ok(AttachEvent {
                event: Some(attach_event::Event::ExitCode(
                    crate::proto::DECLINE_EXIT_CODE,
                )),
            }));
            Response::new(ReceiverStream::new(rx))
        };
        if servable() {
            return None;
        }
        // A platform no worker is expected to (re)serve declines at once.
        let Some(deadline) = self.state.expected_deadline(system, features) else {
            return Some(decline());
        };
        tracing::info!(system, "no capable worker yet; waiting");
        loop {
            // Arm the wakeup before re-checking, else a worker
            // registering in the gap would be missed.
            let notified = self.state.caps_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if servable() {
                return None;
            }
            let now = Instant::now();
            if now >= deadline {
                return Some(decline());
            }
            tokio::select! {
                () = &mut notified => {}
                () = tokio::time::sleep(deadline - now) => {}
            }
        }
    }
}

#[tonic::async_trait]
impl attach_hub_server::AttachHub for AttachSvc {
    type BuildStream = ReceiverStream<Result<AttachEvent, Status>>;

    async fn build(
        &self,
        request: Request<BuildRequest>,
    ) -> Result<Response<Self::BuildStream>, Status> {
        let peer_uid = request
            .extensions()
            .get::<tonic::transport::server::UdsConnectInfo>()
            .and_then(|info| info.peer_cred)
            .map(|cred| cred.uid())
            .ok_or_else(|| Status::internal("missing unix peer credentials"))?;
        let req = request.into_inner();
        if req.outputs.is_empty() {
            return Err(Status::invalid_argument("build request without outputs"));
        }
        validate_request(&req)?;
        let tmp_dir = Arc::new(validate_top_tmp_dir(&req.top_tmp_dir, peer_uid)?);
        let key = dedupe_key(&req);

        let features = crate::build_json::required_system_features(&req.env);
        if let Some(declined) = self.await_capable_worker(&req.system, &features).await {
            return Ok(declined);
        }

        let mut inflight = self.state.inflight.lock().await;
        let replay = if let Some(replay) = inflight.by_key.get(&key) {
            tracing::info!(key, "deduplicating build submission");
            replay.clone()
        } else {
            // A different request claiming an in-flight scratch path
            // would race the other client's unpack at the same dest.
            for p in req.outputs.values() {
                if inflight.by_path.contains_key(p) {
                    return Err(Status::failed_precondition(format!(
                        "output path {p} is part of a different in-flight build"
                    )));
                }
            }
            let replay = Arc::new(Replay::default());
            inflight.by_key.insert(key.clone(), replay.clone());
            for p in req.outputs.values() {
                inflight.by_path.insert(p.clone(), key.clone());
            }
            let job = Job {
                id: new_id(),
                key,
                req,
                tmp_dir,
                features,
                replay: replay.clone(),
                attempts: 0,
                requeued_at: None,
            };
            tracing::info!(id = job.id, system = job.req.system, "queueing build");
            super::metrics::Metrics::inc(&self.state.metrics.submitted);
            self.state.queue.lock().await.push_back(job);
            self.state.notify.notify_waiters();
            replay
        };
        // Subscribe outside the global inflight lock: the snapshot clone
        // of a large backlog must not stall every other submission.
        drop(inflight);
        // Close the check-then-queue race: the last capable worker may
        // have disconnected (and swept the queue) between the capability
        // check above and the push.
        self.state.fail_unservable().await;
        let rx = replay.subscribe().await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// 32-char base32 hash part for synthetic store paths.
    const H: &str = "00000000000000000000000000000000";

    fn base_request() -> BuildRequest {
        BuildRequest {
            system: "x86_64-linux".into(),
            builder: format!("/nix/store/{H}-bash/bin/bash"),
            args: vec!["-c".into(), "true".into()],
            env: HashMap::default(),
            outputs: [("out".to_string(), format!("/nix/store/{H}-out"))].into(),
            input_paths: vec![format!("/nix/store/{H}-dep")],
            top_tmp_dir: "/tmp/nix-build-x".into(),
            tmp_dir_in_sandbox: "/build".into(),
            store_dir: "/nix/store".into(),
            fixed_output: false,
        }
    }

    #[test]
    fn request_validation() {
        assert!(validate_request(&base_request()).is_ok());

        let mut req = base_request();
        req.store_dir = "/etc".into();
        req.input_paths = vec!["/etc/shadow".into()];
        req.outputs = [("out".to_string(), "/etc/out".to_string())].into();
        assert!(validate_request(&req).is_err());

        let mut req = base_request();
        req.builder = "-p".into();
        assert!(validate_request(&req).is_err());

        let mut req = base_request();
        req.tmp_dir_in_sandbox = "relative".into();
        assert!(validate_request(&req).is_err());

        // Darwin clients send the real per-build tmp dir path.
        let mut req = base_request();
        req.tmp_dir_in_sandbox = "/private/tmp/nix-build-foo.drv-0".into();
        assert!(validate_request(&req).is_ok());

        let mut req = base_request();
        req.tmp_dir_in_sandbox = "/build/../etc".into();
        assert!(validate_request(&req).is_err());

        let mut req = base_request();
        req.tmp_dir_in_sandbox = format!("/nix/store/{H}-x");
        assert!(validate_request(&req).is_err());

        let mut req = base_request();
        req.input_paths = vec![format!("/nix/store/{H}-dep"), format!("/nix/store/{H}-dep")];
        assert!(validate_request(&req).is_err());

        let mut req = base_request();
        req.outputs
            .insert("doc".into(), format!("/nix/store/{H}-out"));
        assert!(validate_request(&req).is_err());

        let mut req = base_request();
        req.outputs = [("out".to_string(), format!("/nix/store/{H}-dep"))].into();
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn top_tmp_dir_validation_rejects_symlinks_and_foreign_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let me = nix::unistd::getuid().as_raw();
        let dir = tmp.path().join("build");
        std::fs::create_dir(&dir).unwrap();
        assert!(validate_top_tmp_dir(dir.to_str().unwrap(), me).is_ok());
        assert!(validate_top_tmp_dir(dir.to_str().unwrap(), me + 1).is_err());
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(validate_top_tmp_dir(link.to_str().unwrap(), me).is_err());
    }

    #[test]
    fn dedupe_key_binds_full_request() {
        let a = dedupe_key(&base_request());
        assert_eq!(a, dedupe_key(&base_request()));
        let mut req = base_request();
        req.args = vec!["-c".into(), "false".into()];
        assert_ne!(a, dedupe_key(&req));
        let mut req = base_request();
        req.env.insert("X".into(), "1".into());
        assert_ne!(a, dedupe_key(&req));
    }

    /// Two submissions of the same derivation differ only in the
    /// per-attempt `topTmpDir`; the key ignores it so they dedupe.
    #[test]
    fn dedupe_key_ignores_per_attempt_top_tmp_dir() {
        let a = base_request();
        let mut b = base_request();
        b.top_tmp_dir = "/nix/var/nix/builds/nix-1909052-1544484239".into();
        assert_ne!(a.top_tmp_dir, b.top_tmp_dir);
        assert_eq!(dedupe_key(&a), dedupe_key(&b));
    }

    /// Strings shifted between adjacent sections must not collide:
    /// args `["-c", "K", "V"]` with no env and args `["-c"]` with
    /// env `{K: V}` would feed identical bytes without section counts.
    #[test]
    fn dedupe_key_separates_sections() {
        let mut a = base_request();
        a.args = vec!["-c".into(), "K".into(), "V".into()];
        a.env.clear();
        let mut b = base_request();
        b.args = vec!["-c".into()];
        b.env = [("K".to_string(), "V".to_string())].into();
        assert_ne!(dedupe_key(&a), dedupe_key(&b));
    }
}
