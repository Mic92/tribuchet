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
use std::sync::atomic::{AtomicU64, Ordering};
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
                if let Err(err) = handle_output_chunk(&mut unpackers, expected_outputs, out).await {
                    cleanup_unpackers(&mut unpackers).await;
                    return Err(err);
                }
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
                if let Some((tx, task, scratch)) = unpackers.remove(&path) {
                    drop(tx);
                    let _ = task.await;
                    remove_tree(&scratch);
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

/// (chunk sender, unpack task, scratch directory) for one in-flight
/// output transfer.
type Unpacker = (
    mpsc::Sender<Vec<u8>>,
    tokio::task::JoinHandle<Result<()>>,
    PathBuf,
);

/// Serial for scratch directory names, unique within this process.
static SCRATCH_SERIAL: AtomicU64 = AtomicU64::new(0);

fn remove_tree(path: &Path) {
    let _ = fs::remove_dir_all(path);
    let _ = fs::remove_file(path);
}

/// Scratch directory for one unpack, beside the output so the rename
/// stays on the same filesystem. The pid separates attach processes and
/// the counter separates transfers within one.
fn scratch_path(store_path: &str, serial: u64) -> PathBuf {
    // A sibling, not a suffix: a long output name plus the suffix could
    // exceed NAME_MAX. Only the store hash part of the name is kept.
    let path = Path::new(store_path);
    let hash: String = path
        .file_name()
        .map(|n| n.to_string_lossy().chars().take(32).collect())
        .unwrap_or_default();
    path.parent()
        .unwrap_or_else(|| Path::new(""))
        .join(format!(".tribuchet-{hash}-{}-{serial}", process::id()))
}

/// Move a finished unpack onto the output path. Nix holds the path
/// lock and clears an invalid leftover before it runs the builder, so
/// anything already there is another client that won the race with the
/// same content: losing is not an error.
fn commit_output(scratch: &Path, dest: &Path) -> Result<()> {
    match fs::rename(scratch, dest) {
        Ok(()) => Ok(()),
        Err(_) if dest.exists() => {
            remove_tree(scratch);
            Ok(())
        }
        Err(err) => {
            remove_tree(scratch);
            Err(err_ctx(format!("moving output into {}", dest.display()))(
                err,
            ))
        }
    }
}

/// Unpack beside the output path and rename it into place. Deduped
/// requests (`Inflight::by_key`) replay the same NARs to both clients,
/// which restore into the same directory when they share a store; one
/// would fail with `File exists`. A private scratch directory plus a
/// rename keeps that race harmless: first renamer wins, the loser
/// discards an identical tree.
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
    let (tx, _, _) = unpackers.entry(out.store_path.clone()).or_insert_with(|| {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
        let scratch = scratch_path(
            &out.store_path,
            SCRATCH_SERIAL.fetch_add(1, Ordering::Relaxed),
        );
        // An earlier attempt in this process may have left a partial
        // tree here; the re-delivered NAR replaces it.
        remove_tree(&scratch);
        let unpack_into = scratch.clone();
        let task = tokio::spawn(async move {
            nar::unpack_zstd_chunks(rx, &unpack_into).await?;
            Ok(())
        });
        (tx, task, scratch)
    });
    if !out.zstd_nar_chunk.is_empty() && tx.send(out.zstd_nar_chunk).await.is_err() {
        // The unpacker only stops early on error; report that error.
        let (_, task, scratch) = unpackers.remove(&out.store_path).unwrap();
        let joined = task.await;
        remove_tree(&scratch);
        let err = joined?
            .err()
            .unwrap_or_else(|| err_msg("unpacker exited before eof"));
        return Err(err_ctx(format!("unpacking output {}", out.store_path))(err));
    }
    if out.eof {
        let (tx, task, scratch) = unpackers.remove(&out.store_path).unwrap();
        drop(tx);
        let unpacked = match task.await {
            Ok(res) => res,
            Err(err) => Err(err.into()),
        };
        if let Err(err) = unpacked {
            remove_tree(&scratch);
            return Err(err);
        }
        commit_output(&scratch, &PathBuf::from(&out.store_path))?;
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

/// Stop in-flight unpackers and drop their scratch directories; a
/// partial tree never reaches the output path.
async fn cleanup_unpackers(unpackers: &mut HashMap<String, Unpacker>) {
    for (_, (tx, task, scratch)) in unpackers.drain() {
        drop(tx);
        let _ = task.await;
        remove_tree(&scratch);
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

    fn scratch_leftovers(dir: &Path) -> Vec<PathBuf> {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.to_string_lossy().contains(".tribuchet-"))
            .collect()
    }

    /// The scratch directory is a sibling with a bounded name, however
    /// long the output's name is.
    #[test]
    fn scratch_path_is_a_bounded_sibling() {
        let hash = "0123456789abcdfghijklmnpqrsvwxyz";
        let out = format!("/nix/store/{hash}-{}", "n".repeat(211));
        let scratch = scratch_path(&out, u64::MAX);
        assert_eq!(scratch.parent(), Path::new(&out).parent());
        let name = scratch.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with(&format!(".tribuchet-{hash}-")), "{name}");
        assert!(name.len() <= 80, "{name}");
    }

    /// A NAR that ends early fails at eof with the unpack error, and the
    /// partial tree is removed.
    #[tokio::test]
    async fn failed_unpack_leaves_no_scratch() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("tree");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a"), b"first").unwrap();
        fs::write(src.join("b"), vec![7u8; 64 * 1024]).unwrap();
        let nar = nar::pack::to_vec(&src).unwrap();
        let chunk = zstd::encode_all(&nar[..nar.len() / 2], 3).unwrap();

        let out = dir.path().join("out");
        let out_str = out.to_string_lossy().into_owned();
        let mut unpackers = HashMap::default();
        assert!(deliver(&mut unpackers, &out_str, chunk).await.is_err());

        assert!(unpackers.is_empty());
        assert!(!out.exists());
        assert_eq!(scratch_leftovers(dir.path()), Vec::<PathBuf>::new());
    }

    /// The output lands at its path and the scratch directory is gone.
    #[tokio::test]
    async fn unpacks_output_and_leaves_no_scratch() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let out_str = out.to_string_lossy().into_owned();

        let chunk = zstd_nar_of_file(dir.path(), b"fresh");
        let mut unpackers = HashMap::default();
        deliver(&mut unpackers, &out_str, chunk).await.unwrap();

        assert!(unpackers.is_empty());
        assert_eq!(fs::read(&out).unwrap(), b"fresh");
        assert_eq!(scratch_leftovers(dir.path()), Vec::<PathBuf>::new());
    }

    /// Regression: a directory output already in place belongs to a
    /// client that won the race. Renaming onto it fails with EEXIST,
    /// which must not fail the build; the scratch is dropped instead.
    #[tokio::test]
    async fn keeps_a_directory_output_another_client_committed() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("tree");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("file"), b"fresh").unwrap();
        let nar = nar::pack::to_vec(&src).unwrap();
        let chunk = zstd::encode_all(&nar[..], 3).unwrap();

        let out = dir.path().join("out");
        let out_str = out.to_string_lossy().into_owned();
        fs::create_dir(&out).unwrap();
        fs::write(out.join("file"), b"winner").unwrap();

        let mut unpackers = HashMap::default();
        deliver(&mut unpackers, &out_str, chunk).await.unwrap();

        assert_eq!(fs::read(out.join("file")).unwrap(), b"winner");
        assert_eq!(scratch_leftovers(dir.path()), Vec::<PathBuf>::new());
    }

    /// Regression: a request that dedupes onto an in-flight one is
    /// replayed, so two clients sharing a store receive the same output
    /// and unpack it at the same time. Neither may fail with EEXIST.
    #[tokio::test]
    async fn concurrent_clients_unpack_the_same_output() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let out_str = out.to_string_lossy().into_owned();
        let chunk = zstd_nar_of_file(dir.path(), b"fresh");

        let mut first = HashMap::default();
        let mut second = HashMap::default();
        let (a, b) = tokio::join!(
            deliver(&mut first, &out_str, chunk.clone()),
            deliver(&mut second, &out_str, chunk),
        );
        a.unwrap();
        b.unwrap();

        assert_eq!(fs::read(&out).unwrap(), b"fresh");
    }
}
