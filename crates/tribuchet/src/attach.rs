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
use crate::chunkio::ChannelReader;
use crate::nar;
use crate::proto::{attach_event, attach_hub_client::AttachHubClient, BuildRequest};

pub fn run(build_json: &Path, socket: &Path) -> Result<()> {
    // Tell Nix the build environment is ready (everything before this
    // byte is treated as sandbox setup chatter, not build log).
    std::io::stderr().write_all(b"\x02\n")?;
    let build = BuildJson::load(build_json)?;
    let rt = tokio::runtime::Runtime::new()?;
    let code = rt.block_on(run_async(build, socket.to_owned()))?;
    std::process::exit(code);
}

async fn run_async(build: BuildJson, socket: PathBuf) -> Result<i32> {
    // The URI is ignored; the connector always dials the unix socket.
    let channel = Endpoint::try_from("http://hub.invalid")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let socket = socket.clone();
            async move {
                Ok::<_, std::io::Error>(TokioIo::new(
                    tokio::net::UnixStream::connect(socket).await?,
                ))
            }
        }))
        .await
        .context("connecting to hub socket")?;
    let mut client = AttachHubClient::new(channel);

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
    let mut stream = client.build(req).await?.into_inner();

    // store path -> (chunk sender, unpack task)
    type Unpacker = (mpsc::Sender<Vec<u8>>, tokio::task::JoinHandle<Result<()>>);
    let mut unpackers: std::collections::HashMap<String, Unpacker> = Default::default();

    while let Some(ev) = stream.message().await? {
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
                    let dest = PathBuf::from(&out.store_path);
                    let task = tokio::task::spawn_blocking(move || -> Result<()> {
                        let mut dec = zstd::stream::read::Decoder::new(ChannelReader::new(rx))?;
                        nar::unpack(&mut dec, &dest)
                            .with_context(|| format!("unpacking {}", dest.display()))
                    });
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
                    task.await??;
                    tracing::info!(path = out.store_path, "output unpacked");
                }
            }
            Some(attach_event::Event::ExitCode(code)) => {
                if !unpackers.is_empty() {
                    bail!("hub closed build with unfinished output transfers");
                }
                return Ok(code);
            }
            Some(attach_event::Event::Error(e)) => bail!("remote build failed: {e}"),
            None => {}
        }
    }
    bail!("hub closed event stream without a result");
}
