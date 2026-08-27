//! Build submission: request validation, dedupe keys, the AttachHub service.

use std::collections::HashSet;
use std::path::{Component, Path};
use std::sync::{Arc, Mutex};

use prost::Message;
use sha2::{Digest, Sha256};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use super::metrics::Metrics;
use super::state::{HubState, Inflight, Job, Replay, Servability};
use crate::proto::{
    AttachEvent, BuildMessage, BuildRequest, DECLINE_EXIT_CODE, attach_event, attach_hub_server,
    build_message,
};
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
    Ok(())
}

/// Cap on the client-shipped tmp dir archive: it is buffered in hub
/// memory for the lifetime of the job (redispatch resends it).
const MAX_TMP_DIR_BYTES: usize = 64 * 1024 * 1024;

/// Read the client submission stream: the request first, then the
/// zstd-packed build tmp dir up to its eof chunk.
async fn read_submission(
    stream: &mut Streaming<BuildMessage>,
) -> Result<(BuildRequest, Vec<u8>), Status> {
    let bad = |what: &str| Status::invalid_argument(format!("malformed submission stream: {what}"));
    let Some(build_message::Msg::Request(req)) = stream.message().await?.and_then(|m| m.msg) else {
        return Err(bad("expected the build request first"));
    };
    let mut pack = Vec::new();
    loop {
        let Some(build_message::Msg::TmpDir(chunk)) = stream.message().await?.and_then(|m| m.msg)
        else {
            return Err(bad("expected tmp dir archive chunks"));
        };
        if pack.len() + chunk.zstd_chunk.len() > MAX_TMP_DIR_BYTES {
            return Err(Status::resource_exhausted("tmp dir archive too large"));
        }
        pack.extend(chunk.zstd_chunk);
        if chunk.eof {
            return Ok((req, pack));
        }
    }
}

/// Hash of the whole request plus the tmp dir pack. prost maps are
/// BTreeMaps, so the encoding is deterministic.
pub(super) fn dedupe_key(req: &BuildRequest, tmp_dir_pack: &[u8]) -> String {
    let mut h = Sha256::new();
    let buf = req.encode_to_vec();
    h.update((buf.len() as u64).to_le_bytes());
    h.update(&buf);
    h.update(tmp_dir_pack);
    hex::encode(h.finalize())
}

fn new_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("read system randomness");
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
        let decline = || {
            tracing::info!(system, "no capable worker; declining");
            Metrics::inc(&self.state.metrics.declined);
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            let _ = tx.try_send(Ok(AttachEvent {
                event: Some(attach_event::Event::ExitCode(DECLINE_EXIT_CODE)),
            }));
            Response::new(ReceiverStream::new(rx))
        };
        loop {
            // Arm the wakeup before checking, else a worker registering
            // in the gap would be missed.
            let notified = self.state.caps_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let deadline = match self.state.servability(system, features) {
                Servability::Now => return None,
                Servability::Never => return Some(decline()),
                Servability::ExpectedBy(at) => at,
            };
            tracing::info!(system, "no capable worker yet; waiting");
            tokio::select! {
                () = &mut notified => {}
                () = tokio::time::sleep_until(deadline.into()) => {}
            }
        }
    }
}

#[tonic::async_trait]
impl attach_hub_server::AttachHub for AttachSvc {
    type BuildStream = ReceiverStream<Result<AttachEvent, Status>>;

    async fn build(
        &self,
        request: Request<Streaming<BuildMessage>>,
    ) -> Result<Response<Self::BuildStream>, Status> {
        let (req, tmp_dir_pack) = read_submission(&mut request.into_inner()).await?;
        if req.outputs.is_empty() {
            return Err(Status::invalid_argument("build request without outputs"));
        }
        validate_request(&req)?;
        let tmp_dir_pack = Arc::new(tmp_dir_pack);
        let key = dedupe_key(&req, &tmp_dir_pack);

        let features = req.required_features.clone();
        if let Some(declined) = self.await_capable_worker(&req.system, &features).await {
            return Ok(declined);
        }

        let existing = self
            .state
            .inflight
            .lock()
            .unwrap()
            .by_key
            .get(&key)
            .cloned();
        let rx = if let Some(replay) = existing {
            tracing::info!(key, "deduplicating build submission");
            replay.subscribe().await
        } else {
            let replay = Arc::new(Replay::default());
            let rx = replay.subscribe().await;
            let paths = req.outputs.values().cloned().collect();
            // A different request claiming an in-flight scratch path
            // would race the other client's unpack at the same dest.
            let listing =
                Inflight::list(&self.state.inflight, &key, paths, &replay).ok_or_else(|| {
                    Status::failed_precondition(
                        "an output path is part of a different in-flight build",
                    )
                })?;
            let job = Job {
                id: new_id(),
                key,
                req,
                tmp_dir_pack,
                features,
                replay,
                listing: Mutex::new(Some(listing)),
                attempts: 0,
            };
            tracing::info!(id = job.id, system = job.req.system, "queueing build");
            Metrics::inc(&self.state.metrics.submitted);
            self.state.queue.lock().await.push_back(job);
            self.state.notify.notify_waiters();
            rx
        };
        // Close the check-then-queue race: the last capable worker may
        // have disconnected (and swept the queue) between the capability
        // check above and the push.
        self.state.fail_unservable().await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// 32-char base32 hash part for synthetic store paths.
    const H: &str = "00000000000000000000000000000000";

    fn base_request() -> BuildRequest {
        BuildRequest {
            system: "x86_64-linux".into(),
            builder: format!("/nix/store/{H}-bash/bin/bash"),
            args: vec!["-c".into(), "true".into()],
            env: BTreeMap::default(),
            outputs: [("out".to_string(), format!("/nix/store/{H}-out"))].into(),
            input_paths: vec![format!("/nix/store/{H}-dep")],
            tmp_dir_in_sandbox: "/build".into(),
            store_dir: "/nix/store".into(),
            fixed_output: false,
            required_features: vec![],
            local_networking: false,
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
    fn dedupe_key_binds_full_request() {
        let a = dedupe_key(&base_request(), b"");
        assert_eq!(a, dedupe_key(&base_request(), b""));
        let mut req = base_request();
        req.args = vec!["-c".into(), "false".into()];
        assert_ne!(a, dedupe_key(&req, b""));
        let mut req = base_request();
        req.env.insert("X".into(), "1".into());
        assert_ne!(a, dedupe_key(&req, b""));
        assert_ne!(a, dedupe_key(&base_request(), b"other .attrs.sh"));
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
        assert_ne!(dedupe_key(&a, b""), dedupe_key(&b, b""));
    }
}
