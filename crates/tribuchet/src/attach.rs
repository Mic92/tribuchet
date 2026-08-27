//! `tribuchet attach`: shim executed by Nix (external-builders).
//!
//! Parses build.json, submits the build to the local hub over a unix
//! socket, streams logs to stderr, and unpacks returned output NARs at
//! the scratch output paths (identical on client and worker; Nix
//! performs self-reference rewriting and registration afterwards).
//! Exits with the builder's exit code.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Once;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::sync::mpsc;
use tonic::Code;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

use crate::build_json::{BuildJson, flag, required_system_features};
use crate::chunkio;
use crate::errors::{Error, Result, chain, err_ctx, err_msg};
use crate::nar;
use crate::proto::{
    BuildMessage, BuildRequest, DECLINE_EXIT_CODE, MAX_MSG_SIZE, OutputNar, TmpDirChunk,
    attach_event, attach_hub_client::AttachHubClient, build_message,
};
use crate::rt;
use crate::tmpdir;

pub fn run(build_json: &Path, socket: &Path) -> Result<()> {
    let build = BuildJson::load(build_json)?;
    let rt = rt::runtime("trib-attach").map_err(err_ctx("creating the tokio runtime"))?;
    let code = rt.block_on(run_async(build, socket.to_owned(), build_json.to_owned()))?;
    // Unix exposes only the low 8 bits of the exit status; never let a
    // nonzero code collapse to an observed 0.
    process::exit(if code != 0 && code.trailing_zeros() >= 8 {
        1
    } else {
        code
    });
}

/// Reconnect budget across the whole build: a restarting hub is back
/// within seconds, and the worker holds finished results for resume
/// far longer than this.
const RECONNECT_ATTEMPTS: u32 = 30;
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

async fn run_async(build: BuildJson, socket: PathBuf, build_json_path: PathBuf) -> Result<i32> {
    if build
        .real_store_dir
        .as_deref()
        .is_some_and(|r| r != build.store_dir)
    {
        tracing::info!("diverted store; declining so Nix builds locally");
        return Ok(DECLINE_EXIT_CODE);
    }
    let attrs = build.attrs();
    let fixed_output = build.network_allowed(attrs.as_ref());
    let required_features = required_system_features(&build.env, attrs.as_ref());
    let local_networking = flag(&build.env, attrs.as_ref(), "__darwinAllowLocalNetworking");
    tracing::info!(fixed_output, system = %build.system, "submitting build");
    let req = BuildRequest {
        system: build.system,
        builder: build.builder,
        args: build.args,
        env: build.env.into_iter().collect(),
        outputs: build.outputs.into_iter().collect(),
        input_paths: build.input_paths,
        tmp_dir_in_sandbox: build.tmp_dir_in_sandbox.to_string_lossy().into_owned(),
        store_dir: build.store_dir,
        fixed_output,
        required_features,
        local_networking,
    };
    // Packed once and resent verbatim on every reconnect attempt.
    // Nix places everything the builder consumes in topTmpDir/build.
    let tmp_dir_pack = tokio::task::spawn_blocking({
        let dir = build.top_tmp_dir.join("build");
        move || tmpdir::pack_zstd_dir(&dir)
    })
    .await??;
    let expected_outputs: Vec<String> = req.outputs.values().cloned().collect();
    let top_tmp_dir = build_json_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_owned);

    // The hub holds no durable state: when it restarts mid-build we
    // reconnect and resubmit the identical request. Its dedupe key
    // matches the build still running on the worker, which resumes
    // instead of building twice.
    let mut attempts = 0u32;
    loop {
        match attempt_build(
            &req,
            &tmp_dir_pack,
            &socket,
            &expected_outputs,
            &top_tmp_dir,
        )
        .await?
        {
            Outcome::Done(code) => return Ok(code),
            Outcome::Retry(e) => {
                attempts += 1;
                if attempts > RECONNECT_ATTEMPTS {
                    return Err(err_ctx("giving up reconnecting to the hub")(e));
                }
                eprintln!(
                    "tribuchet: hub connection lost ({}); reconnecting",
                    chain(&e)
                );
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        }
    }
}

enum Outcome {
    Done(i32),
    /// Transport-level failure: hub restarting or briefly unreachable.
    /// Build failures never take this path.
    Retry(Error),
}

/// gRPC channel over the hub's local unix socket; tonic only knows
/// HTTP URIs, so the connector ignores the URI and dials the path.
async fn connect(socket: &Path) -> Result<tonic::transport::Channel> {
    let socket = socket.to_owned();
    Endpoint::try_from("http://hub.invalid")?
        .initial_stream_window_size(Some(chunkio::H2_STREAM_WINDOW))
        .initial_connection_window_size(Some(chunkio::H2_CONNECTION_WINDOW))
        .connect_with_connector(service_fn(move |_: Uri| {
            let socket = socket.clone();
            async move {
                Ok::<_, io::Error>(TokioIo::new(tokio::net::UnixStream::connect(socket).await?))
            }
        }))
        .await
        .map_err(err_ctx("connecting to hub socket"))
}

/// The submission stream: the request, then the tmp dir entries with
/// its eof marker.
fn submission(req: &BuildRequest, tmp_dir_pack: &[u8]) -> Vec<BuildMessage> {
    let tmp_dir = |zstd_chunk: Vec<u8>, eof| BuildMessage {
        msg: Some(build_message::Msg::TmpDir(TmpDirChunk { zstd_chunk, eof })),
    };
    let mut msgs = vec![BuildMessage {
        msg: Some(build_message::Msg::Request(req.clone())),
    }];
    msgs.extend(
        tmp_dir_pack
            .chunks(chunkio::CHUNK_SIZE)
            .map(|c| tmp_dir(c.to_vec(), false)),
    );
    msgs.push(tmp_dir(Vec::new(), true));
    msgs
}

async fn attempt_build(
    req: &BuildRequest,
    tmp_dir_pack: &[u8],
    socket: &Path,
    expected_outputs: &[String],
    top_tmp_dir: &Path,
) -> Result<Outcome> {
    let channel = match connect(socket).await {
        Ok(c) => c,
        Err(e) => return Ok(Outcome::Retry(e)),
    };
    let mut client = AttachHubClient::new(channel)
        .max_decoding_message_size(MAX_MSG_SIZE)
        .max_encoding_message_size(MAX_MSG_SIZE);

    // Ready marker for Nix; emitted only after a hub connection
    // exists so persistent connect failures surface as setup errors,
    // not build failures.
    ready_marker()?;

    let mut stream = match client
        .build(tokio_stream::iter(submission(req, tmp_dir_pack)))
        .await
    {
        Ok(s) => s.into_inner(),
        Err(e) if retryable(&e) => {
            return Ok(Outcome::Retry(err_ctx("submitting build")(e)));
        }
        Err(e) => return Err(err_ctx("submitting build")(e)),
    };

    let mut unpackers: HashMap<String, Unpacker> = HashMap::default();
    // BTreeSet dedupes events replayed across reconnects and gives
    // result.json a stable order.
    let mut added_paths: BTreeSet<String> = BTreeSet::new();

    loop {
        let ev = match stream.message().await {
            Ok(Some(ev)) => ev,
            // Stream ended or broke without a result: the hub went
            // away; clean up partial output trees and resubmit.
            Ok(None) => {
                cleanup_unpackers(&mut unpackers).await;
                return Ok(Outcome::Retry(err_msg(
                    "hub closed event stream without a result",
                )));
            }
            Err(e) if retryable(&e) => {
                cleanup_unpackers(&mut unpackers).await;
                return Ok(Outcome::Retry(err_ctx("event stream")(e)));
            }
            Err(e) => {
                cleanup_unpackers(&mut unpackers).await;
                return Err(err_ctx("build event stream")(e));
            }
        };
        match ev.event {
            Some(attach_event::Event::Log(data)) => {
                io::stderr().write_all(&data)?;
            }
            Some(attach_event::Event::Output(out)) => {
                handle_output_chunk(&mut unpackers, expected_outputs, out).await?;
            }
            Some(attach_event::Event::AddedPath(path)) => {
                added_paths.insert(path);
            }
            Some(attach_event::Event::Dispatched(worker)) => {
                eprintln!("tribuchet: building on {worker}");
            }
            Some(attach_event::Event::OutputRestart(path)) => {
                // The previous worker attempt died mid-NAR; the next
                // attempt streams this output again from the start.
                if let Some((tx, task)) = unpackers.remove(&path) {
                    drop(tx);
                    let _ = task.await;
                }
            }
            Some(attach_event::Event::ExitCode(code)) => {
                if !unpackers.is_empty() {
                    return Err(err_msg("hub closed build with unfinished output transfers"));
                }
                if code == 0 && !added_paths.is_empty() {
                    write_result_json(top_tmp_dir, &added_paths)?;
                }
                return Ok(Outcome::Done(code));
            }
            Some(attach_event::Event::Error(e)) => {
                cleanup_unpackers(&mut unpackers).await;
                return Err(err_msg(format!("remote build failed: {e}")));
            }
            None => {}
        }
    }
}

/// Deliberate hub rejections (no capable worker, bad request, output
/// path conflict) are final; everything else is the transport dying
/// around a hub restart and worth resubmitting.
fn retryable(status: &tonic::Status) -> bool {
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
    static ONCE: Once = Once::new();
    let mut res = Ok(());
    ONCE.call_once(|| {
        res = io::stderr().write_all(b"\x02\n").map_err(Into::into);
    });
    res
}

/// (chunk sender, unpack task) for one in-flight output transfer.
type Unpacker = (mpsc::Sender<Vec<u8>>, tokio::task::JoinHandle<Result<()>>);

fn remove_tree(path: &Path) {
    let _ = fs::remove_dir_all(path);
    let _ = fs::remove_file(path);
}

/// Unpack directly into the output path. Nix holds the path lock and
/// deletes invalid leftovers before the next builder run; a killed
/// attach leaves nothing behind that Nix does not already clean up.
async fn handle_output_chunk(
    unpackers: &mut HashMap<String, Unpacker>,
    expected: &[String],
    out: OutputNar,
) -> Result<()> {
    if !expected.contains(&out.store_path) {
        return Err(err_msg(format!(
            "hub sent unexpected output {}",
            out.store_path
        )));
    }
    let (tx, _) = unpackers.entry(out.store_path.clone()).or_insert_with(|| {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
        let dest = PathBuf::from(&out.store_path);
        // An earlier attempt in this process may have left a partial
        // tree here; the re-delivered NAR replaces it.
        remove_tree(&dest);
        let task =
            tokio::spawn(
                async move { nar::unpack_zstd_chunks(rx, &dest).await.map_err(Into::into) },
            );
        (tx, task)
    });
    if !out.zstd_nar_chunk.is_empty() && tx.send(out.zstd_nar_chunk).await.is_err() {
        // The unpacker only stops early on error; report that error.
        let (_, task) = unpackers.remove(&out.store_path).unwrap();
        let err = task
            .await?
            .err()
            .unwrap_or_else(|| err_msg("unpacker exited before eof"));
        return Err(err_ctx(format!("unpacking output {}", out.store_path))(err));
    }
    if out.eof {
        let (tx, task) = unpackers.remove(&out.store_path).unwrap();
        drop(tx);
        task.await??;
        tracing::debug!(path = out.store_path, "output unpacked");
    }
    Ok(())
}

/// Sidecar the patched external-derivation-builder reads to extend
/// addedPaths before the output reference scan.
fn write_result_json(top_tmp_dir: &Path, added: &BTreeSet<String>) -> Result<()> {
    let path = top_tmp_dir.join("result.json");
    let body = serde_json::json!({ "addedPaths": added });
    fs::write(&path, serde_json::to_vec(&body)?)
        .map_err(err_ctx(format!("writing {}", path.display())))
}

/// Stop in-flight unpackers; partial trees stay at the output paths
/// and are removed before the next unpack of the same path.
async fn cleanup_unpackers(unpackers: &mut HashMap<String, Unpacker>) {
    for (_, (tx, task)) in unpackers.drain() {
        drop(tx);
        let _ = task.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// zstd-compressed NAR of a single regular file, as the hub streams it.
    fn zstd_nar_of_file(dir: &Path, body: &[u8]) -> Vec<u8> {
        let src = dir.join("src");
        fs::write(&src, body).unwrap();
        let nar = nar::pack::to_vec(&src).unwrap();
        zstd::encode_all(&nar[..], 3).unwrap()
    }

    async fn deliver(
        unpackers: &mut HashMap<String, Unpacker>,
        out: &str,
        chunk: Vec<u8>,
    ) -> Result<()> {
        let expected = vec![out.to_owned()];
        handle_output_chunk(
            unpackers,
            &expected,
            OutputNar {
                store_path: out.to_owned(),
                zstd_nar_chunk: chunk,
                eof: false,
            },
        )
        .await?;
        handle_output_chunk(
            unpackers,
            &expected,
            OutputNar {
                store_path: out.to_owned(),
                zstd_nar_chunk: Vec::new(),
                eof: true,
            },
        )
        .await
    }

    /// Regression: a leftover tree at the output path (earlier attempt in
    /// this process) must be replaced, not fail with EEXIST.
    #[tokio::test]
    async fn replaces_existing_output_path() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let out_str = out.to_string_lossy().into_owned();
        fs::create_dir(&out).unwrap();
        fs::write(out.join("stale"), b"junk").unwrap();

        let chunk = zstd_nar_of_file(dir.path(), b"fresh");
        let mut unpackers = HashMap::default();
        deliver(&mut unpackers, &out_str, chunk).await.unwrap();

        assert!(unpackers.is_empty());
        assert_eq!(fs::read(&out).unwrap(), b"fresh");
    }
}
