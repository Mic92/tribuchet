//! `tribuchet attach`: shim executed by Nix (external-builders).
//!
//! Parses build.json, submits the build to the local hub over a unix
//! socket, streams logs to stderr, and unpacks returned output NARs at
//! the scratch output paths (identical on client and worker; Nix
//! performs self-reference rewriting and registration afterwards).
//! Exits with the builder's exit code.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use hyper_util::rt::TokioIo;
use tokio::sync::mpsc;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

use crate::build_json::BuildJson;
use crate::nar;
use crate::proto::{attach_event, attach_hub_client::AttachHubClient, BuildRequest};

pub fn run(build_json: &Path, socket: &Path) -> Result<()> {
    let build = BuildJson::load(build_json)?;
    let rt = tokio::runtime::Runtime::new()?;
    let code = rt.block_on(run_async(build, socket.to_owned()))?;
    // Unix exposes only the low 8 bits of the exit status; never let a
    // nonzero code collapse to an observed 0.
    std::process::exit(if code != 0 && code & 0xff == 0 {
        1
    } else {
        code
    });
}

/// Reconnect budget across the whole build: a restarting hub is back
/// within seconds, and the worker holds finished results for resume
/// far longer than this.
const RECONNECT_ATTEMPTS: u32 = 30;
const RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

async fn run_async(build: BuildJson, socket: PathBuf) -> Result<i32> {
    let fixed_output = build.is_fixed_output();
    let req = BuildRequest {
        system: build.system,
        builder: build.builder,
        args: build.args,
        env: build.env.into_iter().collect(),
        outputs: build.outputs.into_iter().collect(),
        input_paths: build.input_paths,
        top_tmp_dir: build.top_tmp_dir.to_string_lossy().into_owned(),
        tmp_dir_in_sandbox: build.tmp_dir_in_sandbox.to_string_lossy().into_owned(),
        store_dir: build.store_dir,
        fixed_output,
    };
    let expected_outputs: Vec<String> = req.outputs.values().cloned().collect();

    // The hub holds no durable state: when it restarts mid-build we
    // reconnect and resubmit the identical request. Its dedupe key
    // matches the build still running on the worker, which resumes
    // instead of building twice.
    let mut attempts = 0u32;
    loop {
        match attempt_build(&req, &socket, &expected_outputs).await? {
            Outcome::Done(code) => return Ok(code),
            Outcome::Retry(e) => {
                attempts += 1;
                if attempts > RECONNECT_ATTEMPTS {
                    return Err(e.context("giving up reconnecting to the hub"));
                }
                eprintln!("tribuchet: hub connection lost ({e:#}); reconnecting");
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        }
    }
}

enum Outcome {
    Done(i32),
    /// Transport-level failure: hub restarting or briefly unreachable.
    /// Build failures never take this path.
    Retry(anyhow::Error),
}

async fn attempt_build(
    req: &BuildRequest,
    socket: &Path,
    expected_outputs: &[String],
) -> Result<Outcome> {
    // The URI is ignored; the connector always dials the unix socket.
    let socket_owned = socket.to_owned();
    let channel = match Endpoint::try_from("http://hub.invalid")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let socket = socket_owned.clone();
            async move {
                Ok::<_, std::io::Error>(TokioIo::new(
                    tokio::net::UnixStream::connect(socket).await?,
                ))
            }
        }))
        .await
    {
        Ok(c) => c,
        Err(e) => {
            return Ok(Outcome::Retry(
                anyhow::Error::new(e).context("connecting to hub socket"),
            ))
        }
    };
    let mut client = AttachHubClient::new(channel)
        .max_decoding_message_size(crate::hub::MAX_MSG_SIZE)
        .max_encoding_message_size(crate::hub::MAX_MSG_SIZE);

    // Ready marker for Nix; emitted only after a hub connection
    // exists so persistent connect failures surface as setup errors,
    // not build failures.
    ready_marker()?;

    let mut stream = match client.build(req.clone()).await {
        Ok(s) => s.into_inner(),
        Err(e) if retryable(&e) => {
            return Ok(Outcome::Retry(
                anyhow::Error::new(e).context("submitting build"),
            ))
        }
        Err(e) => return Err(e).context("submitting build"),
    };

    let mut unpackers: std::collections::HashMap<String, Unpacker> = Default::default();

    loop {
        let ev = match stream.message().await {
            Ok(Some(ev)) => ev,
            // Stream ended or broke without a result: the hub went
            // away; clean up partial output trees and resubmit.
            Ok(None) => {
                cleanup_unpackers(&mut unpackers).await;
                return Ok(Outcome::Retry(anyhow::anyhow!(
                    "hub closed event stream without a result"
                )));
            }
            Err(e) if retryable(&e) => {
                cleanup_unpackers(&mut unpackers).await;
                return Ok(Outcome::Retry(
                    anyhow::Error::new(e).context("event stream"),
                ));
            }
            Err(e) => {
                cleanup_unpackers(&mut unpackers).await;
                return Err(e).context("build event stream");
            }
        };
        match ev.event {
            Some(attach_event::Event::Log(data)) => {
                std::io::stderr().write_all(&data)?;
            }
            Some(attach_event::Event::Output(out)) => {
                if !expected_outputs.contains(&out.store_path) {
                    bail!("hub sent unexpected output {}", out.store_path);
                }
                let (tx, _) = unpackers.entry(out.store_path.clone()).or_insert_with(|| {
                    let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
                    // Unpack to a temp sibling, renamed into place at
                    // eof: the scratch path never holds a partial or
                    // unverified tree.
                    let tmp = unpack_temp_path(&out.store_path);
                    let task = tokio::spawn(async move { nar::unpack_zstd_chunks(rx, &tmp).await });
                    (tx, task)
                });
                if !out.zstd_nar_chunk.is_empty() {
                    tx.send(out.zstd_nar_chunk)
                        .await
                        .map_err(|_| anyhow::anyhow!("output unpacker died"))?;
                }
                if out.eof {
                    let (tx, task) = unpackers.remove(&out.store_path).unwrap();
                    drop(tx);
                    let tmp = unpack_temp_path(&out.store_path);
                    if let Err(e) = task.await? {
                        remove_tree(&tmp);
                        return Err(e);
                    }
                    // A pre-reconnect attempt may have placed this
                    // output already; the re-delivered NAR replaces it.
                    remove_tree(Path::new(&out.store_path));
                    std::fs::rename(&tmp, &out.store_path).with_context(|| {
                        format!("moving output into place at {}", out.store_path)
                    })?;
                    tracing::info!(path = out.store_path, "output unpacked");
                }
            }
            Some(attach_event::Event::ExitCode(code)) => {
                if !unpackers.is_empty() {
                    bail!("hub closed build with unfinished output transfers");
                }
                return Ok(Outcome::Done(code));
            }
            Some(attach_event::Event::Error(e)) => {
                cleanup_unpackers(&mut unpackers).await;
                bail!("remote build failed: {e}");
            }
            None => {}
        }
    }
}

/// Deliberate hub rejections (no capable worker, bad request, output
/// path conflict) are final; everything else is the transport dying
/// around a hub restart and worth resubmitting.
fn retryable(status: &tonic::Status) -> bool {
    use tonic::Code;
    !matches!(
        status.code(),
        Code::FailedPrecondition
            | Code::InvalidArgument
            | Code::PermissionDenied
            | Code::NotFound
            | Code::AlreadyExists
            | Code::ResourceExhausted
            | Code::Unimplemented
    )
}

/// Print Nix's \x02 ready marker exactly once, however many
/// reconnect attempts the build takes.
fn ready_marker() -> Result<()> {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    let mut res = Ok(());
    ONCE.call_once(|| {
        res = std::io::stderr().write_all(b"\x02\n").map_err(Into::into);
    });
    res
}

/// (chunk sender, unpack task) for one in-flight output transfer.
type Unpacker = (mpsc::Sender<Vec<u8>>, tokio::task::JoinHandle<Result<()>>);

fn unpack_temp_path(store_path: &str) -> PathBuf {
    let path = Path::new(store_path);
    let base = path.file_name().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!(".tribuchet-tmp-{base}"))
}

fn remove_tree(path: &Path) {
    let _ = std::fs::remove_dir_all(path);
    let _ = std::fs::remove_file(path);
}

/// Stop in-flight unpackers and drop their partial temp trees.
async fn cleanup_unpackers(unpackers: &mut std::collections::HashMap<String, Unpacker>) {
    for (store_path, (tx, task)) in unpackers.drain() {
        drop(tx);
        task.abort();
        let _ = task.await;
        remove_tree(&unpack_temp_path(&store_path));
    }
}
