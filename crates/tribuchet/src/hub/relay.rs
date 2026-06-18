//! Per-job protocol with a worker: input staging, output relay and verification.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use harmonia_utils_signature::{PublicKey, Signature};
use nix::{dir, fcntl};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tonic::Status;

use super::state::{HubState, Job};
use crate::chunkio::ChunkWriter;
use crate::proto::{
    attach_event, hub_message, nar_transfer, worker_message, BuildAssignment, CancelBuild,
    ExtraPath, HubMessage, NarTransfer, OutputNar, OutputSignature, PathInfoMsg, PathOffer,
    ResultAck, TmpDirArchive,
};

/// How long a dispatched build may run with no attach client listening
/// before the hub cancels it on the worker.
const CANCEL_GRACE: Duration = Duration::from_secs(10);

pub(super) async fn send(
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    msg: hub_message::Msg,
) -> Result<()> {
    out_tx
        .send(Ok(HubMessage { msg: Some(msg) }))
        .await
        .map_err(|_| anyhow::anyhow!("worker connection lost"))
}

pub(super) async fn run_job(
    state: &HubState,
    job: &Job,
    vkey: &PublicKey,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    mut in_rx: mpsc::Receiver<worker_message::Msg>,
) -> Result<()> {
    let req = &job.req;
    send(
        out_tx,
        hub_message::Msg::Assignment(BuildAssignment {
            build_id: job.id.clone(),
            system: req.system.clone(),
            builder: req.builder.clone(),
            args: req.args.clone(),
            env: req.env.clone(),
            outputs: req.outputs.clone(),
            tmp_dir_in_sandbox: req.tmp_dir_in_sandbox.clone(),
            store_dir: req.store_dir.clone(),
            fixed_output: req.fixed_output,
            dedupe_key: job.key.clone(),
        }),
    )
    .await?;
    send(
        out_tx,
        hub_message::Msg::PathOffer(PathOffer {
            build_id: job.id.clone(),
            store_paths: req.input_paths.clone(),
        }),
    )
    .await?;

    let missing = loop {
        match recv(&mut in_rx).await? {
            // The worker already holds this build (it survived a hub
            // restart); skip staging, its result arrives like any other.
            worker_message::Msg::Resumed(_) => {
                tracing::info!(id = job.id, "worker resumed an in-flight build");
                return relay_build(state, job, vkey, out_tx, &mut in_rx).await;
            }
            // A resumed build's log tail can race ahead of its Resumed
            // reply (separate task, same stream); pass the chunk on.
            worker_message::Msg::Log(l) => {
                job.replay.publish(attach_event::Event::Log(l.data)).await;
            }
            worker_message::Msg::MissingPaths(m) => {
                // Only ever pack paths we offered: anything else would let
                // a compromised worker read arbitrary host files. Dedupe,
                // so a repeated entry cannot amplify pack work either.
                let offered: HashSet<&String> = req.input_paths.iter().collect();
                let mut missing = Vec::new();
                let mut seen = HashSet::new();
                for p in m.store_paths {
                    if !offered.contains(&p) {
                        bail!("worker requested unoffered path {p}");
                    }
                    if seen.insert(p.clone()) {
                        missing.push(p);
                    }
                }
                break missing;
            }
            // Staging failed worker-side (assignment validation, its
            // nix-daemon unreachable, ...): the worker reports it as a
            // Result before ever sending MissingPaths. Pass the error
            // on to the client instead of calling it unexpected.
            worker_message::Msg::Result(res) if res.exit_code != 0 => {
                if !(1..=255).contains(&res.exit_code) {
                    bail!("worker sent invalid exit code {}", res.exit_code);
                }
                if !res.error.is_empty() {
                    job.replay
                        .publish(attach_event::Event::Log(
                            format!("tribuchet worker error: {}\n", res.error).into_bytes(),
                        ))
                        .await;
                }
                job.replay
                    .publish(attach_event::Event::ExitCode(res.exit_code))
                    .await;
                ack_result(out_tx, job).await;
                return Ok(());
            }
            other => bail!(
                "unexpected worker message while negotiating paths: {}",
                msg_name(&other)
            ),
        }
    };
    tracing::info!(
        id = job.id,
        total = req.input_paths.len(),
        missing = missing.len(),
        "input path negotiation done"
    );

    // The worker imports missing inputs through its Nix daemon, which
    // needs the full ValidPathInfo; ask the local nix-daemon for it.
    // AddToStoreNar also needs a path's references valid first, and
    // Nix's order is not topological, so reorder references before
    // referrers.
    let infos = order_by_references(query_path_infos(&state.daemon_pool, &missing).await?);
    for mut info in infos {
        let path = info.store_path.clone();
        info.build_id = job.id.clone();
        send(out_tx, hub_message::Msg::PathInfo(info)).await?;
        stream_store_path(&job.id, &path, out_tx).await?;
    }
    stream_tmp_dir(&job.id, job.tmp_dir.clone(), out_tx).await?;

    relay_build(state, job, vkey, out_tx, &mut in_rx).await
}

/// Log/error-safe name of a worker message variant. The messages embed
/// peer-controlled bytes (NAR chunks, log data); Debug-formatting them
/// into error strings would balloon logs and replay buffers.
fn msg_name(msg: &worker_message::Msg) -> &'static str {
    match msg {
        worker_message::Msg::Register(_) => "Register",
        worker_message::Msg::Heartbeat(_) => "Heartbeat",
        worker_message::Msg::MissingPaths(_) => "MissingPaths",
        worker_message::Msg::Log(_) => "Log",
        worker_message::Msg::Result(_) => "Result",
        worker_message::Msg::Nar(_) => "Nar",
        worker_message::Msg::RequestJob(_) => "RequestJob",
        worker_message::Msg::Resumed(_) => "Resumed",
    }
}

/// The channel carries only this build's messages (route_loop filters);
/// it closes when the worker disconnects or goes silent.
pub(super) async fn recv(
    in_rx: &mut mpsc::Receiver<worker_message::Msg>,
) -> Result<worker_message::Msg> {
    in_rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("worker disconnected or went silent"))
}

/// Nix db metadata for input paths, in wire form, queried over the
/// daemon protocol rather than db.sqlite: harmonia-store-db opens the
/// db with sqlite's immutable=1, which skips locking and WAL replay,
/// so rows still in the WAL -- freshly registered inputs, the common
/// case for build requests -- would be invisible and concurrent
/// checkpoints could yield torn reads. The daemon answers from its
/// own consistent view.
/// Topologically order path infos (references before referrers) via DFS
/// post-order. Tolerates self-references and cycles.
fn order_by_references(infos: Vec<PathInfoMsg>) -> Vec<PathInfoMsg> {
    use std::collections::HashMap;
    let roots: Vec<String> = infos.iter().map(|i| i.store_path.clone()).collect();
    let mut nodes: HashMap<String, PathInfoMsg> =
        infos.into_iter().map(|i| (i.store_path.clone(), i)).collect();
    let mut order = Vec::with_capacity(roots.len());
    let mut visited: HashSet<String> = HashSet::new();
    for root in &roots {
        let mut stack = vec![(root.clone(), false)];
        while let Some((path, emit)) = stack.pop() {
            if emit {
                order.push(path);
                continue;
            }
            if !visited.insert(path.clone()) {
                continue;
            }
            stack.push((path.clone(), true));
            if let Some(info) = nodes.get(&path) {
                for r in &info.references {
                    if !visited.contains(r) && nodes.contains_key(r) {
                        stack.push((r.clone(), false));
                    }
                }
            }
        }
    }
    order.into_iter().map(|p| nodes.remove(&p).unwrap()).collect()
}

async fn query_path_infos(
    pool: &harmonia_store_remote::ConnectionPool,
    paths: &[String],
) -> Result<Vec<PathInfoMsg>> {
    use harmonia_store_path::{StoreDir, StorePath};
    use harmonia_store_remote::DaemonStore as _;
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let store_dir = StoreDir::default();
    let mut guard = pool
        .acquire()
        .await
        .context("connecting to the local nix-daemon")?;
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        let sp: StorePath = store_dir.parse(p)?;
        let info = guard
            .client()
            .query_path_info(&sp)
            .await
            .with_context(|| format!("querying path info for {p}"))?
            .with_context(|| format!("{p} is not a valid path in the local store"))?;
        out.push(PathInfoMsg {
            build_id: String::new(), // filled in by the caller
            store_path: p.clone(),
            nar_sha256: info.nar_hash.digest_bytes().to_vec(),
            nar_size: info.nar_size,
            references: info
                .references
                .iter()
                .map(|r| store_dir.display(r).to_string())
                .collect(),
            signatures: info.signatures.iter().map(ToString::to_string).collect(),
            deriver: info
                .deriver
                .map(|d| store_dir.display(&d).to_string())
                .unwrap_or_default(),
            ca: info.ca.map(|c| c.to_string()).unwrap_or_default(),
        });
    }
    Ok(out)
}

/// NAR-pack a local store path, zstd-compress, and stream it to the
/// worker. Filesystem reads run on harmonia's blocking pool; the zstd
/// level-3 encode here is cheap relative to the per-chunk awaits.
async fn stream_store_path(
    build_id: &str,
    store_path: &str,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
) -> Result<()> {
    use tokio::io::AsyncReadExt as _;
    let nar = harmonia_file_nar::archive::NarByteStream::new(PathBuf::from(store_path));
    let mut enc = async_compression::tokio::bufread::ZstdEncoder::with_quality(
        tokio_util::io::StreamReader::new(nar),
        async_compression::Level::Precise(3),
    );
    let mut buf = vec![0u8; crate::chunkio::CHUNK_SIZE];
    loop {
        let n = enc
            .read(&mut buf)
            .await
            .with_context(|| format!("packing {store_path}"))?;
        if n == 0 {
            break;
        }
        send(
            out_tx,
            hub_message::Msg::Nar(NarTransfer {
                build_id: build_id.into(),
                store_path: store_path.into(),
                payload: Some(nar_transfer::Payload::ZstdNarChunk(buf[..n].to_vec())),
                eof: false,
            }),
        )
        .await?;
    }
    send(
        out_tx,
        hub_message::Msg::Nar(NarTransfer {
            build_id: build_id.into(),
            store_path: store_path.into(),
            payload: None,
            eof: true,
        }),
    )
    .await
}

/// Tar+zstd the topTmpDir (structured attrs, passAsFile files) to the
/// worker. Always sent last: its EOF tells the worker to start the build.
async fn stream_tmp_dir(
    build_id: &str,
    top_tmp_dir: Arc<fs::File>,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8);
    let task = tokio::task::spawn_blocking(move || -> Result<()> {
        let enc = zstd::stream::write::Encoder::new(ChunkWriter::new(tx), 3)?;
        let mut tar = tar::Builder::new(enc);
        // Walk the directory through the fd validated at submission
        // time, not by re-resolving the client-controlled path.
        append_dir_fd(&mut tar, &top_tmp_dir, Path::new(""))?;
        tar.into_inner()?.finish()?.flush()?;
        Ok(())
    });
    while let Some(chunk) = rx.recv().await {
        send(
            out_tx,
            hub_message::Msg::TmpDir(TmpDirArchive {
                build_id: build_id.into(),
                zstd_tar_chunk: chunk,
                eof: false,
            }),
        )
        .await?;
    }
    task.await??;
    send(
        out_tx,
        hub_message::Msg::TmpDir(TmpDirArchive {
            build_id: build_id.into(),
            zstd_tar_chunk: Vec::new(),
            eof: true,
        }),
    )
    .await
}

/// Recursively archive a client-owned directory through fds relative to
/// the held handle. The client can rewrite the tree while the root hub
/// walks it, so every descent uses openat with O_NOFOLLOW and headers
/// are taken from the opened fd: an entry swapped for a symlink between
/// listing and opening is archived as whatever it now is, never
/// followed into a foreign root-readable file.
fn append_dir_fd<W: io::Write>(
    tar: &mut tar::Builder<W>,
    dir: &fs::File,
    prefix: &Path,
) -> Result<()> {
    use std::os::fd::AsFd;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::MetadataExt;
    // List through fdopendir on a dup of the validated handle instead
    // of re-resolving the client-controlled path (and instead of
    // /proc/self/fd, which is Linux-only and unreliable on macOS).
    let mut listing = dir::Dir::from_fd(std::os::fd::OwnedFd::from(dir.try_clone()?))?;
    // Collect names and types up front: dir::Entry borrows the
    // iterator, and we recurse below.
    let mut entries = Vec::new();
    for res in listing.iter() {
        let entry = res?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        entries.push((
            std::ffi::OsString::from_vec(bytes.to_vec()),
            entry.file_type(),
        ));
    }
    for (name, ftype) in entries {
        let in_tar = prefix.join(&name);
        // Tar carries only files, dirs and symlinks; openat would
        // ENXIO on the .nix-socket recursive-nix leaves in topTmpDir.
        // An unknown type is resolved by the O_NOFOLLOW open below.
        if !matches!(
            ftype,
            None | Some(dir::Type::Directory | dir::Type::File | dir::Type::Symlink)
        ) {
            continue;
        }
        if ftype == Some(dir::Type::Symlink) {
            let target = fcntl::readlinkat(dir.as_fd(), name.as_os_str())?;
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            h.set_mode(0o777);
            tar.append_link(&mut h, &in_tar, target)?;
            continue;
        }
        // O_NOFOLLOW: an entry swapped for a symlink since the listing
        // fails the open instead of being followed. O_NONBLOCK: a fifo
        // swapped in cannot stall the hub; the fstat below skips it.
        let fd: fs::File = fcntl::openat(
            dir.as_fd(),
            name.as_os_str(),
            fcntl::OFlag::O_RDONLY
                | fcntl::OFlag::O_NOFOLLOW
                | fcntl::OFlag::O_CLOEXEC
                | fcntl::OFlag::O_NONBLOCK,
            nix::sys::stat::Mode::empty(),
        )?
        .into();
        let meta = fd.metadata()?;
        let mut h = tar::Header::new_gnu();
        h.set_mode(meta.mode() & 0o7777);
        h.set_mtime(u64::try_from(meta.mtime()).unwrap_or(0));
        if meta.is_dir() {
            h.set_entry_type(tar::EntryType::Directory);
            h.set_size(0);
            tar.append_data(&mut h, &in_tar, io::empty())?;
            append_dir_fd(tar, &fd, &in_tar)?;
        } else if meta.is_file() {
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(meta.len());
            tar.append_data(&mut h, &in_tar, &fd)?;
        }
        // anything else (fifo, socket, device) is not build-dir content
    }
    Ok(())
}

/// Hashes the decompressed NAR while the compressed chunks are relayed
/// untouched, so signature verification adds no extra buffering or
/// recompression.
struct OutputVerify {
    decoder: zstd::stream::write::Decoder<'static, HashWriter>,
    signature: Signature,
}

struct HashWriter {
    hasher: Sha256,
    /// Decompressed byte budget: zstd RLE amplifies ~30,000:1, so a
    /// sub-4MiB message could otherwise expand without bound on the hub
    /// (and later fill the client's disk).
    remaining: u64,
}

impl Default for HashWriter {
    fn default() -> Self {
        Self {
            hasher: Sha256::new(),
            remaining: MAX_OUTPUT_NAR_BYTES,
        }
    }
}

/// Decompressed size cap per output NAR, matching the worker's pack cap.
const MAX_OUTPUT_NAR_BYTES: u64 = 64 * 1024 * 1024 * 1024;

impl Write for HashWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() as u64 > self.remaining {
            return Err(io::Error::other(format!(
                "output NAR exceeds the {MAX_OUTPUT_NAR_BYTES} byte limit"
            )));
        }
        self.remaining -= buf.len() as u64;
        self.hasher.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Verifier for each output the worker reports, checked to be exactly
/// the requested set: a missing output is a build failure, and an extra
/// one would let a worker plant arbitrary store paths on the client.
fn verify_set(
    reported: Vec<OutputSignature>,
    requested: &HashMap<String, String>,
) -> Result<HashMap<String, OutputVerify>> {
    let mut pending = HashMap::new();
    for out in reported {
        let signature: Signature = out
            .signature
            .parse()
            .context("malformed output signature")?;
        pending.insert(
            out.store_path,
            OutputVerify {
                decoder: zstd::stream::write::Decoder::new(HashWriter::default())?,
                signature,
            },
        );
    }
    for scratch in requested.values() {
        if !pending.contains_key(scratch) {
            bail!("worker result is missing output {scratch}");
        }
    }
    if pending.len() != requested.len() {
        let extra: Vec<&String> = pending
            .keys()
            .filter(|p| !requested.values().any(|o| o == *p))
            .collect();
        bail!("worker result contains unrequested outputs: {extra:?}");
    }
    Ok(pending)
}

/// In-flight AddToStoreNar of one recursive-nix extra. Chunks stream
/// through `tx` into a daemon-pool connection held by `task`.
struct ExtraImport {
    tx: mpsc::Sender<bytes::Bytes>,
    task: tokio::task::JoinHandle<Result<()>>,
}

/// Verify each extra's worker signature over `path:nar_sha256_hex`
/// (the same envelope as outputs) and spawn the daemon import. The
/// daemon then verifies on its end that the NAR matches the signed
/// hash.
fn start_extras(
    state: &HubState,
    vkey: &PublicKey,
    reported: Vec<ExtraPath>,
) -> Result<HashMap<String, ExtraImport>> {
    let mut out = HashMap::with_capacity(reported.len());
    for extra in reported {
        let info = extra
            .info
            .ok_or_else(|| anyhow::anyhow!("extra without PathInfo"))?;
        let path = info.store_path.clone();
        let sig: Signature = extra
            .signature
            .parse()
            .context("malformed extra signature")?;
        let envelope = format!("{}:{}", path, hex::encode(&info.nar_sha256));
        if !vkey.verify(envelope.as_bytes(), &sig) {
            bail!("signature verification failed for extra {path}");
        }
        let parsed = crate::store::parse_path_info(&info).context("parsing extra PathInfo")?;
        let (tx, rx) = mpsc::channel::<bytes::Bytes>(8);
        let pool = state.daemon_pool.clone();
        let task = tokio::spawn(async move { import_extra(&pool, parsed, rx).await });
        out.insert(path, ExtraImport { tx, task });
    }
    Ok(out)
}

async fn import_extra(
    pool: &harmonia_store_remote::ConnectionPool,
    info: harmonia_store_path_info::ValidPathInfo,
    rx: mpsc::Receiver<bytes::Bytes>,
) -> Result<()> {
    use futures_util::StreamExt as _;
    use harmonia_store_remote::DaemonStore as _;
    use tokio::io::AsyncReadExt as _;
    let mut guard = pool
        .acquire()
        .await
        .context("connecting to the local nix-daemon")?;
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(Ok::<_, io::Error>);
    let reader = tokio_util::io::StreamReader::new(stream);
    let dec =
        async_compression::tokio::bufread::ZstdDecoder::new(tokio::io::BufReader::new(reader));
    let limited = tokio::io::BufReader::new(dec.take(info.info.nar_size));
    guard
        .client()
        .add_to_store_nar(&info, limited, false, true)
        .await
        .map_err(|e| anyhow::anyhow!("registering extra {} via daemon: {e}", info.path))
}

async fn relay_output_chunk(
    vkey: &PublicKey,
    pending: &mut HashMap<String, OutputVerify>,
    replay: &super::state::Replay,
    n: &NarTransfer,
) -> Result<()> {
    let verify = pending.get_mut(&n.store_path).unwrap();
    if let Some(nar_transfer::Payload::ZstdNarChunk(chunk)) = &n.payload {
        tokio::task::block_in_place(|| verify.decoder.write_all(chunk))?;
        replay
            .publish(attach_event::Event::Output(OutputNar {
                store_path: n.store_path.clone(),
                zstd_nar_chunk: chunk.clone(),
                eof: false,
            }))
            .await;
    }
    if n.eof {
        let mut verify = pending.remove(&n.store_path).unwrap();
        verify.decoder.flush()?;
        let hash = verify.decoder.into_inner().hasher.finalize();
        let msg = format!("{}:{}", n.store_path, hex::encode(hash));
        if !vkey.verify(msg.as_bytes(), &verify.signature) {
            bail!("signature verification failed for {}", n.store_path);
        }
        replay
            .publish(attach_event::Event::Output(OutputNar {
                store_path: n.store_path.clone(),
                zstd_nar_chunk: Vec::new(),
                eof: true,
            }))
            .await;
    }
    Ok(())
}

async fn relay_extra_chunk(
    extras: &mut HashMap<String, ExtraImport>,
    replay: &super::state::Replay,
    n: NarTransfer,
) -> Result<()> {
    let extra = extras.get_mut(&n.store_path).unwrap();
    if let Some(nar_transfer::Payload::ZstdNarChunk(chunk)) = n.payload {
        if extra.tx.send(chunk.into()).await.is_err() {
            let extra = extras.remove(&n.store_path).unwrap();
            return Err(extra.task.await?.unwrap_err());
        }
    }
    if n.eof {
        let extra = extras.remove(&n.store_path).unwrap();
        drop(extra.tx);
        extra.task.await??;
        replay
            .publish(attach_event::Event::AddedPath(n.store_path))
            .await;
    }
    Ok(())
}

async fn finish_relay(
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    replay: &super::state::Replay,
    job: &Job,
) {
    replay.publish(attach_event::Event::ExitCode(0)).await;
    ack_result(out_tx, job).await;
}

/// Tell the worker its result (and all output NARs) arrived intact,
/// so it can stop keeping the build for redelivery. Best effort: a
/// lost ack only means the worker holds the build dir until its TTL.
async fn ack_result(out_tx: &mpsc::Sender<Result<HubMessage, Status>>, job: &Job) {
    let _ = send(
        out_tx,
        hub_message::Msg::ResultAck(ResultAck {
            build_id: job.id.clone(),
            dedupe_key: job.key.clone(),
        }),
    )
    .await;
}

async fn relay_build(
    state: &HubState,
    job: &Job,
    vkey: &PublicKey,
    out_tx: &mpsc::Sender<Result<HubMessage, Status>>,
    in_rx: &mut mpsc::Receiver<worker_message::Msg>,
) -> Result<()> {
    let mut pending: HashMap<String, OutputVerify> = HashMap::new();
    let mut extras: HashMap<String, ExtraImport> = HashMap::new();
    let mut awaiting_outputs = false;
    let mut abandoned_since: Option<Instant> = None;
    let mut cancel_sent = false;
    // An interval, not a per-iteration sleep: a build that logs
    // continuously must not starve the abandonment check.
    let mut abandon_check = tokio::time::interval(Duration::from_secs(2));
    abandon_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // Periodically watch for the last attach client going away;
        // after a grace period the worker is told to kill the build.
        // Its "cancelled" result then flows back through the arms
        // below like any other failure.
        let m = tokio::select! {
            m = recv(in_rx) => m?,
            _ = abandon_check.tick(), if !cancel_sent => {
                if job.replay.has_subscribers().await {
                    abandoned_since = None;
                } else if abandoned_since.get_or_insert_with(Instant::now).elapsed()
                    > CANCEL_GRACE
                {
                    tracing::info!(id = job.id, "no attach client left; cancelling build");
                    send(
                        out_tx,
                        hub_message::Msg::Cancel(CancelBuild {
                            build_id: job.id.clone(),
                            dedupe_key: job.key.clone(),
                        }),
                    )
                    .await?;
                    cancel_sent = true;
                }
                continue;
            }
        };
        match m {
            worker_message::Msg::Log(l) => {
                job.replay.publish(attach_event::Event::Log(l.data)).await;
            }
            worker_message::Msg::Result(res) => {
                if awaiting_outputs {
                    bail!("worker sent a duplicate build result");
                }
                if res.exit_code != 0 {
                    // Unix exposes only the low 8 bits to the parent; a
                    // nonzero multiple of 256 would look like success.
                    if !(1..=255).contains(&res.exit_code) {
                        bail!("worker sent invalid exit code {}", res.exit_code);
                    }
                    if !res.error.is_empty() {
                        job.replay
                            .publish(attach_event::Event::Log(
                                format!("tribuchet worker error: {}\n", res.error).into_bytes(),
                            ))
                            .await;
                    }
                    job.replay
                        .publish(attach_event::Event::ExitCode(res.exit_code))
                        .await;
                    ack_result(out_tx, job).await;
                    return Ok(());
                }
                pending = verify_set(res.outputs, &job.req.outputs)?;
                extras = start_extras(state, vkey, res.extras)?;
                awaiting_outputs = true;
                if pending.is_empty() && extras.is_empty() {
                    finish_relay(out_tx, &job.replay, job).await;
                    return Ok(());
                }
            }
            worker_message::Msg::Nar(n) if awaiting_outputs => {
                if pending.contains_key(&n.store_path) {
                    relay_output_chunk(vkey, &mut pending, &job.replay, &n).await?;
                } else if extras.contains_key(&n.store_path) {
                    relay_extra_chunk(&mut extras, &job.replay, n).await?;
                } else {
                    bail!("worker sent unexpected store path {}", n.store_path);
                }
                if pending.is_empty() && extras.is_empty() {
                    finish_relay(out_tx, &job.replay, job).await;
                    return Ok(());
                }
            }
            other => bail!("unexpected worker message: {}", msg_name(&other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::submit::validate_top_tmp_dir;
    use super::*;

    fn info(path: &str, refs: &[&str]) -> PathInfoMsg {
        PathInfoMsg {
            build_id: String::new(),
            store_path: path.into(),
            nar_sha256: Vec::new(),
            nar_size: 0,
            references: refs.iter().map(ToString::to_string).collect(),
            signatures: Vec::new(),
            deriver: String::new(),
            ca: String::new(),
        }
    }

    #[test]
    fn references_are_streamed_before_referrers() {
        // keyring references more-itertools; offered in referrer-first
        // order, as Nix's inputPaths can be.
        let dep = "/nix/store/aaa-more-itertools";
        let lib = "/nix/store/bbb-keyring";
        let ordered = order_by_references(vec![info(lib, &[dep, lib]), info(dep, &[])]);
        let seq: Vec<&str> = ordered.iter().map(|i| i.store_path.as_str()).collect();
        assert_eq!(seq, vec![dep, lib]);
    }

    #[test]
    fn reference_cycles_do_not_loop() {
        let a = "/nix/store/aaa";
        let b = "/nix/store/bbb";
        let ordered = order_by_references(vec![info(a, &[b]), info(b, &[a])]);
        assert_eq!(ordered.len(), 2);
    }

    /// Run stream_tmp_dir over an already-validated handle and return
    /// the decompressed tar bytes.
    async fn tmp_dir_tar(handle: fs::File) -> Vec<u8> {
        let (tx, mut rx) = mpsc::channel(64);
        stream_tmp_dir("b1", Arc::new(handle), &tx).await.unwrap();
        drop(tx);
        let mut compressed = Vec::new();
        while let Some(Ok(msg)) = rx.recv().await {
            if let Some(hub_message::Msg::TmpDir(c)) = msg.msg {
                compressed.extend(c.zstd_tar_chunk);
            }
        }
        zstd::decode_all(&compressed[..]).unwrap()
    }

    /// Swapping the submitted path for a symlink after validation must
    /// not redirect what the hub tars: the archive is built from the
    /// directory handle opened at validation time.
    #[tokio::test]
    async fn tmp_dir_archive_comes_from_the_validated_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("build");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("attrs"), "validated").unwrap();
        let me = nix::unistd::getuid().as_raw();
        let handle = validate_top_tmp_dir(dir.to_str().unwrap(), me).unwrap();

        // attacker swaps the path for a symlink to a foreign directory
        let foreign = tmp.path().join("foreign");
        fs::create_dir(&foreign).unwrap();
        fs::write(foreign.join("secret"), "foreign").unwrap();
        fs::rename(&dir, tmp.path().join("moved-aside")).unwrap();
        std::os::unix::fs::symlink(&foreign, &dir).unwrap();

        let tar_bytes = tmp_dir_tar(handle).await;
        let mut names = Vec::new();
        let mut ar = tar::Archive::new(&tar_bytes[..]);
        for entry in ar.entries().unwrap() {
            names.push(entry.unwrap().path().unwrap().into_owned());
        }
        assert!(names.iter().any(|p| p.ends_with("attrs")), "{names:?}");
        assert!(!names.iter().any(|p| p.ends_with("secret")), "{names:?}");
    }

    /// Symlinks inside the build dir are archived as symlinks; their
    /// targets (potentially root-only files) are never read or shipped.
    #[tokio::test]
    async fn tmp_dir_archive_does_not_follow_symlink_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("build");
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("sub/file"), "payload").unwrap();
        let secret = tmp.path().join("secret");
        fs::write(&secret, "foreign-content").unwrap();
        std::os::unix::fs::symlink(&secret, dir.join("link")).unwrap();
        let me = nix::unistd::getuid().as_raw();
        let handle = validate_top_tmp_dir(dir.to_str().unwrap(), me).unwrap();

        let tar_bytes = tmp_dir_tar(handle).await;
        assert!(!tar_bytes.windows(15).any(|w| w == b"foreign-content"));
        let mut found = HashMap::new();
        let mut ar = tar::Archive::new(&tar_bytes[..]);
        for entry in ar.entries().unwrap() {
            let entry = entry.unwrap();
            found.insert(
                entry.path().unwrap().into_owned(),
                entry.header().entry_type(),
            );
        }
        assert_eq!(
            found.get(Path::new("link")),
            Some(&tar::EntryType::Symlink),
            "{found:?}"
        );
        assert_eq!(
            found.get(Path::new("sub/file")),
            Some(&tar::EntryType::Regular),
            "{found:?}"
        );
    }

    /// Wrong-key signatures must fail before any daemon contact, so a
    /// compromised worker cannot plant store paths on the client.
    #[tokio::test]
    async fn extras_with_wrong_signature_are_rejected() {
        use harmonia_utils_signature::SecretKey;
        let hub_sk = SecretKey::generate("hub-trusted-key-1".into()).unwrap();
        let attacker_sk = SecretKey::generate("attacker-1".into()).unwrap();
        let vkey = hub_sk.to_public_key();

        let path = format!("/nix/store/{}-extra", "0".repeat(32));
        let nar_sha256 = vec![0u8; 32];
        let envelope = format!("{path}:{}", hex::encode(&nar_sha256));
        let bad = ExtraPath {
            info: Some(PathInfoMsg {
                build_id: String::new(),
                store_path: path.clone(),
                nar_sha256: nar_sha256.clone(),
                nar_size: 1024,
                references: vec![],
                signatures: vec![],
                deriver: String::new(),
                ca: String::new(),
            }),
            signature: attacker_sk.sign(envelope.as_bytes()).to_string(),
        };
        let state = HubState::default();
        let err = start_extras(&state, &vkey, vec![bad])
            .err()
            .expect("expected signature rejection");
        assert!(
            err.to_string().contains("signature verification failed"),
            "{err}"
        );
    }
}
