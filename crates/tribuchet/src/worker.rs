//! `tribuchet worker`: dials the hub over mTLS, caches input paths,
//! executes builds in a local sandbox, signs and returns output NARs.
//!
//! Input sources, in order of preference:
//! 1. the host's own /nix/store (read-only seed; no transfer needed)
//! 2. the worker cache (`state_dir/store`), filled from hub NAR streams
//!
//! One build at a time (max_jobs = 1) for the MVP.

pub mod sandbox;

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

use crate::chunkio::{ChannelReader, CHUNK_SIZE};
use crate::nar;
use crate::proto::{
    hub_message, nar_transfer, worker_hub_client::WorkerHubClient, worker_message, BuildAssignment,
    BuildResult, Heartbeat, LogChunk, MissingPaths, NarTransfer, OutputSignature, Register,
    WorkerMessage,
};

pub struct WorkerOpts {
    pub hub: String,
    pub state_dir: PathBuf,
    pub systems: Vec<String>,
    pub ca_cert: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

pub fn host_system() -> String {
    let arch = std::env::consts::ARCH;
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        os => os,
    };
    format!("{arch}-{os}")
}

fn load_signing_key(state_dir: &Path) -> Result<SigningKey> {
    use std::os::unix::fs::PermissionsExt;
    let path = state_dir.join("signing.key");
    if path.exists() {
        let bytes: [u8; 32] = std::fs::read(&path)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing.key must be 32 bytes"))?;
        Ok(SigningKey::from_bytes(&bytes))
    } else {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        std::fs::write(&path, key.to_bytes())?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(key)
    }
}

fn msg(m: worker_message::Msg) -> WorkerMessage {
    WorkerMessage { msg: Some(m) }
}

pub fn run(opts: WorkerOpts) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(opts))
}

async fn run_async(opts: WorkerOpts) -> Result<()> {
    std::fs::create_dir_all(opts.state_dir.join("store"))?;
    std::fs::create_dir_all(opts.state_dir.join("builds"))?;
    let signing_key = load_signing_key(&opts.state_dir)?;

    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(
            std::fs::read(&opts.ca_cert).context("reading CA cert")?,
        ))
        .identity(Identity::from_pem(
            std::fs::read(&opts.cert).context("reading worker cert")?,
            std::fs::read(&opts.key).context("reading worker key")?,
        ));
    let channel = Endpoint::from_shared(opts.hub.clone())?
        .tls_config(tls)?
        .connect()
        .await
        .context("connecting to hub")?;
    let mut client = WorkerHubClient::new(channel);

    let (out_tx, out_rx) = mpsc::channel::<WorkerMessage>(64);
    out_tx
        .send(msg(worker_message::Msg::Register(Register {
            worker_name: std::env::var("HOSTNAME").unwrap_or_else(|_| "worker".into()),
            systems: opts.systems.clone(),
            features: vec![],
            max_jobs: 1,
            signing_public_key: signing_key.verifying_key().to_bytes().to_vec(),
        })))
        .await?;

    let heartbeat_tx = out_tx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            if heartbeat_tx
                .send(msg(worker_message::Msg::Heartbeat(Heartbeat {
                    running_jobs: 0,
                    load1: 0.0,
                })))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let mut inbound = client
        .session(ReceiverStream::new(out_rx))
        .await?
        .into_inner();
    tracing::info!(hub = opts.hub, systems = ?opts.systems, "connected to hub");

    let mut active: Option<ActiveBuild> = None;
    while let Some(m) = inbound.message().await? {
        let Some(m) = m.msg else { continue };
        match m {
            hub_message::Msg::Assignment(a) => {
                tracing::info!(id = a.build_id, "build assigned");
                active = Some(ActiveBuild::new(a, &opts.state_dir)?);
            }
            hub_message::Msg::PathOffer(offer) => {
                let Some(build) = active.as_mut() else {
                    continue;
                };
                let missing = build.negotiate(&offer.store_paths, &opts.state_dir);
                out_tx
                    .send(msg(worker_message::Msg::MissingPaths(MissingPaths {
                        build_id: offer.build_id,
                        store_paths: missing,
                    })))
                    .await?;
            }
            hub_message::Msg::Nar(n) => {
                if let Some(build) = active.as_mut() {
                    build.feed_nar(n, &opts.state_dir).await?;
                }
            }
            hub_message::Msg::TmpDir(t) => {
                if let Some(build) = active.as_mut() {
                    if build.feed_tmp_dir(t).await? {
                        // All inputs and the tmp dir are in place: build.
                        let build = active.take().unwrap();
                        let out_tx = out_tx.clone();
                        let signing_key = signing_key.clone();
                        tokio::task::spawn_blocking(move || {
                            if let Err(e) = build.execute(&out_tx, &signing_key) {
                                tracing::error!("build execution failed: {e:#}");
                                let _ = out_tx.blocking_send(msg(worker_message::Msg::Result(
                                    BuildResult {
                                        build_id: build.assignment.build_id.clone(),
                                        exit_code: 1,
                                        outputs: vec![],
                                        error: format!("{e:#}"),
                                    },
                                )));
                            }
                            build.cleanup();
                        });
                    }
                }
            }
            hub_message::Msg::Cancel(_) => {
                tracing::warn!("build cancellation not implemented yet");
            }
        }
    }
    bail!("hub closed the session");
}

type Unpacker = (mpsc::Sender<Vec<u8>>, tokio::task::JoinHandle<Result<()>>);

struct ActiveBuild {
    assignment: BuildAssignment,
    dir: PathBuf, // state_dir/builds/<id>
    /// Input store path -> host filesystem source.
    sources: HashMap<String, PathBuf>,
    pending: HashSet<String>,
    nar_unpackers: HashMap<String, Unpacker>,
    tmp_unpacker: Option<Unpacker>,
}

fn store_base(store_path: &str) -> &str {
    store_path.rsplit('/').next().unwrap_or(store_path)
}

impl ActiveBuild {
    fn new(assignment: BuildAssignment, state_dir: &Path) -> Result<Self> {
        let dir = state_dir.join("builds").join(&assignment.build_id);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        std::fs::create_dir_all(dir.join("top"))?;
        Ok(Self {
            assignment,
            dir,
            sources: HashMap::new(),
            pending: HashSet::new(),
            nar_unpackers: HashMap::new(),
            tmp_unpacker: None,
        })
    }

    fn negotiate(&mut self, offered: &[String], state_dir: &Path) -> Vec<String> {
        let mut missing = Vec::new();
        for p in offered {
            let host = PathBuf::from(p);
            let cached = state_dir.join("store").join(store_base(p));
            if host.exists() {
                self.sources.insert(p.clone(), host);
            } else if cached.exists() {
                self.sources.insert(p.clone(), cached);
            } else {
                self.pending.insert(p.clone());
                missing.push(p.clone());
            }
        }
        missing
    }

    async fn feed_nar(&mut self, n: NarTransfer, state_dir: &Path) -> Result<()> {
        if !self.pending.contains(&n.store_path) && !self.nar_unpackers.contains_key(&n.store_path)
        {
            bail!("hub sent NAR for unrequested path {}", n.store_path);
        }
        let partial = state_dir
            .join("store")
            .join(format!("{}.partial", store_base(&n.store_path)));
        let (tx, _) = self
            .nar_unpackers
            .entry(n.store_path.clone())
            .or_insert_with(|| {
                let dest = partial.clone();
                let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
                let task = tokio::task::spawn_blocking(move || -> Result<()> {
                    if dest.exists() {
                        // stale leftover from a crashed transfer
                        let _ = std::fs::remove_dir_all(&dest);
                        let _ = std::fs::remove_file(&dest);
                    }
                    let mut dec = zstd::stream::read::Decoder::new(ChannelReader::new(rx))?;
                    nar::unpack(&mut dec, &dest)
                        .with_context(|| format!("unpacking {}", dest.display()))
                });
                (tx, task)
            });
        if let Some(nar_transfer::Payload::ZstdNarChunk(chunk)) = n.payload {
            tx.send(chunk)
                .await
                .map_err(|_| anyhow::anyhow!("input unpacker died"))?;
        }
        if n.eof {
            let (tx, task) = self.nar_unpackers.remove(&n.store_path).unwrap();
            drop(tx);
            task.await??;
            let cached = state_dir.join("store").join(store_base(&n.store_path));
            std::fs::rename(&partial, &cached)?;
            self.pending.remove(&n.store_path);
            self.sources.insert(n.store_path, cached);
        }
        Ok(())
    }

    /// Returns true when the tmp dir transfer completed, which is the
    /// signal to start the build.
    async fn feed_tmp_dir(&mut self, t: crate::proto::TmpDirArchive) -> Result<bool> {
        let (tx, _) = self.tmp_unpacker.get_or_insert_with(|| {
            let dest = self.dir.join("top");
            let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
            let task = tokio::task::spawn_blocking(move || -> Result<()> {
                let dec = zstd::stream::read::Decoder::new(ChannelReader::new(rx))?;
                let mut tar = tar::Archive::new(dec);
                tar.set_preserve_permissions(true);
                tar.unpack(&dest).context("unpacking tmp dir archive")
            });
            (tx, task)
        });
        if !t.zstd_tar_chunk.is_empty() {
            tx.send(t.zstd_tar_chunk)
                .await
                .map_err(|_| anyhow::anyhow!("tmp dir unpacker died"))?;
        }
        if t.eof {
            let (tx, task) = self.tmp_unpacker.take().unwrap();
            drop(tx);
            task.await??;
            if !self.pending.is_empty() {
                bail!("tmp dir transfer finished before all input paths arrived");
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Runs on a blocking thread: sandboxed build, live log streaming,
    /// output packing/signing/upload.
    fn execute(
        &self,
        out_tx: &mpsc::Sender<WorkerMessage>,
        signing_key: &SigningKey,
    ) -> Result<()> {
        let a = &self.assignment;
        let spec = sandbox::prepare(a, &self.dir, &self.sources)?;
        let mut child = sandbox::spawn(&spec)?;

        let mut log_threads = Vec::new();
        for pipe in [
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let tx = out_tx.clone();
            let build_id = a.build_id.clone();
            log_threads.push(std::thread::spawn(move || {
                let mut pipe = pipe;
                let mut buf = [0u8; 8192];
                loop {
                    match pipe.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx
                                .blocking_send(msg(worker_message::Msg::Log(LogChunk {
                                    build_id: build_id.clone(),
                                    data: buf[..n].to_vec(),
                                })))
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
            }));
        }
        let status = child.wait()?;
        for t in log_threads {
            let _ = t.join();
        }
        let exit_code = status.code().unwrap_or(128);
        tracing::info!(id = a.build_id, exit_code, "builder finished");

        if exit_code != 0 {
            out_tx.blocking_send(msg(worker_message::Msg::Result(BuildResult {
                build_id: a.build_id.clone(),
                exit_code,
                outputs: vec![],
                error: String::new(),
            })))?;
            return Ok(());
        }

        // Pack, hash and sign every output before announcing the result,
        // because signatures travel in BuildResult ahead of the NAR data.
        let mut packed = Vec::new();
        for scratch in a.outputs.values() {
            let host_path = sandbox::output_host_path(&spec, scratch);
            if !host_path.exists() {
                bail!("builder did not produce output {scratch}");
            }
            let nar_file = self.dir.join(format!("{}.nar.zst", store_base(scratch)));
            let mut hasher = Sha256::new();
            {
                let f = std::fs::File::create(&nar_file)?;
                let mut enc = zstd::stream::write::Encoder::new(f, 3)?;
                let mut tee = TeeWriter(&mut enc, &mut hasher);
                nar::pack(&host_path, &mut tee)?;
                enc.finish()?.flush()?;
            }
            let hash = hasher.finalize();
            let sig = signing_key.sign(format!("{}:{}", scratch, hex::encode(hash)).as_bytes());
            packed.push((
                scratch.clone(),
                nar_file,
                hash.to_vec(),
                sig.to_bytes().to_vec(),
            ));
        }

        out_tx.blocking_send(msg(worker_message::Msg::Result(BuildResult {
            build_id: a.build_id.clone(),
            exit_code: 0,
            outputs: packed
                .iter()
                .map(|(path, _, hash, sig)| OutputSignature {
                    store_path: path.clone(),
                    nar_sha256: hash.clone(),
                    signature: sig.clone(),
                })
                .collect(),
            error: String::new(),
        })))?;

        for (path, nar_file, _, _) in &packed {
            let mut f = std::fs::File::open(nar_file)?;
            let mut buf = vec![0u8; CHUNK_SIZE];
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                out_tx.blocking_send(msg(worker_message::Msg::Nar(NarTransfer {
                    build_id: a.build_id.clone(),
                    store_path: path.clone(),
                    payload: Some(nar_transfer::Payload::ZstdNarChunk(buf[..n].to_vec())),
                    eof: false,
                })))?;
            }
            out_tx.blocking_send(msg(worker_message::Msg::Nar(NarTransfer {
                build_id: a.build_id.clone(),
                store_path: path.clone(),
                payload: None,
                eof: true,
            })))?;
        }
        Ok(())
    }

    fn cleanup(&self) {
        sandbox::cleanup(&self.assignment, &self.dir);
        if let Err(e) = std::fs::remove_dir_all(&self.dir) {
            tracing::warn!("cleaning up {}: {e}", self.dir.display());
        }
    }
}

struct TeeWriter<'a, A: Write, B: Write>(&'a mut A, &'a mut B);

impl<A: Write, B: Write> Write for TeeWriter<'_, A, B> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write_all(buf)?;
        self.1.write_all(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
