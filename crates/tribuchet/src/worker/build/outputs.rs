//! Output packing: chunked NARs for outputs and runtime-closure extras.

use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;

use harmonia_store_path::{StoreDir, StorePath};
use harmonia_store_path_info::UnkeyedValidPathInfo;
use harmonia_store_ref_scan::RefScanSink;
use harmonia_store_remote::{DaemonClient, DaemonStore};

use std::os::fd::{AsRawFd, OwnedFd};

use super::super::resume::{OutChunk, PackedExtra, PackedOutput};
use super::super::sandbox;
use super::store_base;
use crate::chunker::{Chunk, chunk_store_path};
use crate::errors::{Result, err_ctx, err_msg};
use crate::fsutil::io_ctx;
use crate::proto::MAX_NAR_BYTES;
use crate::store::topo_order;

/// Pack the outputs, then (under recursive-nix) the closure-delta
/// extras.
pub(in crate::worker) async fn pack_outputs_and_extras(
    dir: &Path,
    spec: &sandbox::SandboxSpec,
    pack_root: Option<&OwnedFd>,
    deadline: Instant,
) -> Result<(Vec<PackedOutput>, Vec<PackedExtra>)> {
    let extra_candidates = if spec.recursive_nix {
        query_all_valid_paths()
            .await
            .map_err(err_ctx("queryAllValidPaths"))?
    } else {
        BTreeSet::new()
    };
    let packed = pack_outputs(dir, spec, pack_root, &extra_candidates, deadline)?;
    let extras = if spec.recursive_nix {
        pack_extras(dir, &packed, &spec.store_inputs, &spec.outputs, deadline)
            .await
            .map_err(err_ctx("packing recursive-nix extras"))?
    } else {
        Vec::new()
    };
    Ok((packed, extras))
}

/// Snapshot of every valid store path on the worker, used to widen
/// the ref-scan candidate set when recursive-nix is on.
async fn query_all_valid_paths() -> Result<BTreeSet<harmonia_store_path::StorePath>> {
    let mut daemon = DaemonClient::builder()
        .connect_daemon()
        .await
        .map_err(err_ctx("connecting to the local nix-daemon"))?;
    let set = daemon
        .query_all_valid_paths()
        .await
        .map_err(err_ctx("queryAllValidPaths"))?;
    Ok(set.into_iter().collect())
}

fn pack_outputs(
    dir: &Path,
    spec: &sandbox::SandboxSpec,
    pack_root: Option<&OwnedFd>,
    extra_candidates: &BTreeSet<harmonia_store_path::StorePath>,
    deadline: Instant,
) -> Result<Vec<PackedOutput>> {
    let mut candidates = scan_candidates(&spec.store_inputs, &spec.outputs);
    candidates.extend(extra_candidates.iter().cloned());
    let mut packed = Vec::new();
    for scratch in &spec.outputs {
        let host_path = match pack_root {
            // The mount clones spec.root, so the same relative path
            // reaches the output with the worker as apparent owner.
            Some(fd) => PathBuf::from(format!(
                "/proc/self/fd/{}/{}",
                fd.as_raw_fd(),
                scratch.trim_start_matches('/')
            )),
            None => sandbox::output_host_path(spec, scratch),
        };
        // lstat: a symlink output whose target only resolves inside
        // the sandbox is still a valid output.
        if host_path.symlink_metadata().is_err() {
            return Err(err_msg(format!("builder did not produce output {scratch}")));
        }
        let frames_file = dir.join(format!("{}.frames", store_base(scratch)));
        let self_path = harmonia_store_path::StorePath::from_base_path(store_base(scratch)).ok();
        let scan = spec
            .recursive_nix
            .then_some((&candidates, self_path.as_ref()));
        let res = pack_one_nar(&host_path, &frames_file, scan, deadline)
            .map_err(err_ctx(format!("packing output {scratch}")))?;
        packed.push(PackedOutput {
            scratch: scratch.clone(),
            frames_file,
            chunks: res.chunks,
            references: res.references,
        });
    }
    Ok(packed)
}

/// Pack the closure-delta extras: paths an output references that
/// are neither inputs nor sibling outputs.
async fn pack_extras(
    dir: &Path,
    outputs: &[PackedOutput],
    store_inputs: &[String],
    spec_outputs: &[String],
    deadline: Instant,
) -> Result<Vec<PackedExtra>> {
    let known: BTreeSet<&str> = store_inputs
        .iter()
        .map(String::as_str)
        .chain(spec_outputs.iter().map(String::as_str))
        .collect();
    let queue: Vec<String> = outputs
        .iter()
        .flat_map(|o| o.references.iter())
        .filter(|r| !known.contains(r.as_str()))
        .cloned()
        .collect();
    if queue.is_empty() {
        return Ok(Vec::new());
    }
    let store_dir = StoreDir::default();
    let mut infos = extra_closure(queue, &known, &store_dir).await?;
    // Referenced-before-referrer, matching hub-side sequential import.
    let ordered = topo_order(infos.keys().cloned(), |p| {
        infos[p]
            .references
            .iter()
            .map(|r| {
                r.to_absolute_path(&store_dir)
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|r| infos.contains_key(r))
            .collect()
    });
    let mut out = Vec::with_capacity(infos.len());
    for path in ordered {
        let info = infos.remove(&path).unwrap();
        let sp = StorePath::from_base_path(store_base(&path))?;
        let mut candidates: BTreeSet<StorePath> = info.references.iter().cloned().collect();
        candidates.insert(sp.clone());
        let frames_file = dir.join(format!("extra-{}.frames", store_base(&path)));
        let res = pack_one_nar(
            Path::new(&path),
            &frames_file,
            Some((&candidates, Some(&sp))),
            deadline,
        )
        .map_err(err_ctx(format!("packing extra {path}")))?;
        out.push(PackedExtra {
            path,
            frames_file,
            chunks: res.chunks,
            nar_sha256: info.nar_hash.digest_bytes().to_vec(),
            nar_size: info.nar_size,
            references: info
                .references
                .iter()
                .map(|p| {
                    p.to_absolute_path(&store_dir)
                        .to_string_lossy()
                        .into_owned()
                })
                .collect(),
            sigs: info.signatures.iter().map(ToString::to_string).collect(),
            deriver: info
                .deriver
                .as_ref()
                .map(|p| {
                    p.to_absolute_path(&store_dir)
                        .to_string_lossy()
                        .into_owned()
                })
                .unwrap_or_default(),
            ca: info
                .ca
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
        });
    }
    Ok(out)
}

/// Walk `queue` into a transitive closure of path infos, temp-rooting
/// each path so the daemon does not GC it while we read it. The hub
/// daemon rejects an import whose references are not already valid.
async fn extra_closure(
    mut queue: Vec<String>,
    known: &BTreeSet<&str>,
    store_dir: &StoreDir,
) -> Result<HashMap<String, UnkeyedValidPathInfo>> {
    let mut daemon = DaemonClient::builder()
        .connect_daemon()
        .await
        .map_err(err_ctx("connecting to the local nix-daemon"))?;
    let mut infos: HashMap<String, UnkeyedValidPathInfo> = HashMap::new();
    while let Some(path) = queue.pop() {
        if infos.contains_key(&path) {
            continue;
        }
        let sp = StorePath::from_base_path(store_base(&path))
            .map_err(err_ctx(format!("parsing extra path {path}")))?;
        daemon
            .add_temp_root(&sp)
            .await
            .map_err(err_ctx(format!("temp-rooting {path}")))?;
        let info = daemon
            .query_path_info(&sp)
            .await
            .map_err(err_ctx(format!("queryPathInfo {path}")))?
            .ok_or_else(|| err_msg(format!("extra {path} vanished from store")))?;
        for r in &info.references {
            let r = r.to_absolute_path(store_dir).to_string_lossy().into_owned();
            if !known.contains(r.as_str()) {
                queue.push(r);
            }
        }
        infos.insert(path, info);
    }
    Ok(infos)
}

struct NarPackResult {
    references: Vec<String>,
    chunks: Vec<OutChunk>,
}

type ScanArgs<'a> = (
    &'a BTreeSet<harmonia_store_path::StorePath>,
    Option<&'a harmonia_store_path::StorePath>,
);

/// Chunks compressed per parallel batch.
const BATCH: usize = 64;

/// Chunk `host_path`'s NAR into a file of zstd frames, reference-
/// scanning the plaintext when `scan` is set. Blocking.
fn pack_one_nar(
    host_path: &Path,
    frames_path: &Path,
    scan: Option<ScanArgs>,
    deadline: Instant,
) -> Result<NarPackResult> {
    let mut sink = scan.map(|(c, s)| RefScanSink::new(c, s));
    let mut frames = FrameWriter {
        file: BufWriter::new(File::create(frames_path).map_err(io_ctx("creating", frames_path))?),
        chunks: Vec::new(),
        off: 0,
    };
    let mut batch: Vec<Chunk> = Vec::with_capacity(BATCH);
    let mut total = 0u64;
    chunk_store_path(host_path, |c| {
        // A builder can exit instantly leaving a multi-TB sparse output.
        if Instant::now() >= deadline {
            return Err(err_msg("build timed out"));
        }
        total += c.data.len() as u64;
        if total > MAX_NAR_BYTES {
            return Err(err_msg(format!("NAR exceeds {MAX_NAR_BYTES} bytes")));
        }
        if let Some(s) = &mut sink {
            s.feed(&c.data);
        }
        batch.push(c);
        if batch.len() == BATCH {
            frames.write(&mut batch)?;
        }
        Ok(true)
    })?;
    frames.write(&mut batch)?;
    frames
        .file
        .flush()
        .map_err(io_ctx("writing", frames_path))?;
    let store_dir = StoreDir::default();
    let self_path = scan.and_then(|(_, s)| s);
    let references = sink
        .map(|s| s.found_paths())
        .unwrap_or_default()
        .into_iter()
        .filter(|p| self_path != Some(p))
        .map(|p| {
            p.to_absolute_path(&store_dir)
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    Ok(NarPackResult {
        references,
        chunks: frames.chunks,
    })
}

struct FrameWriter {
    file: BufWriter<File>,
    chunks: Vec<OutChunk>,
    off: u64,
}

impl FrameWriter {
    /// zstd-3 does ~330 MB/s per core, so compress a batch in parallel.
    fn write(&mut self, batch: &mut Vec<Chunk>) -> Result<()> {
        let threads = thread::available_parallelism()
            .map_or(1, NonZero::get)
            .min(4);
        let per = batch.len().div_ceil(threads).max(1);
        let parts: Vec<io::Result<Vec<Vec<u8>>>> = thread::scope(|s| {
            let handles: Vec<_> = batch
                .chunks(per)
                .map(|part| {
                    s.spawn(move || {
                        part.iter()
                            .map(|c| zstd::bulk::compress(&c.data, 3))
                            .collect()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let mut frames = Vec::with_capacity(batch.len());
        for p in parts {
            frames.append(&mut p.map_err(err_ctx("compressing chunk"))?);
        }
        for (c, frame) in batch.drain(..).zip(frames) {
            self.file.write_all(&frame)?;
            self.chunks.push(OutChunk {
                hash: c.hash,
                size: u32::try_from(c.data.len()).expect("chunk size bounded"),
                off: self.off,
                len: u32::try_from(frame.len()).expect("frame size bounded"),
            });
            self.off += frame.len() as u64;
        }
        Ok(())
    }
}

fn scan_candidates(
    inputs: &[String],
    outputs: &[String],
) -> BTreeSet<harmonia_store_path::StorePath> {
    inputs
        .iter()
        .chain(outputs.iter())
        .filter_map(|p| harmonia_store_path::StorePath::from_base_path(store_base(p)).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use super::*;

    /// pack_one_nar finds references while chunking and drops self-paths.
    #[test]
    fn pack_one_nar_finds_references_and_excludes_self() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let host = dir.path().join("out");
        fs::create_dir(&host)?;
        let input = "/nix/store/00000000000000000000000000000001-input";
        let self_path = "/nix/store/00000000000000000000000000000002-self";
        let unrelated = "/nix/store/00000000000000000000000000000003-unrelated";
        fs::write(host.join("data"), format!("refs: {input} {self_path}\n"))?;
        let candidates = scan_candidates(&[input.into(), unrelated.into()], &[self_path.into()]);
        let self_sp = harmonia_store_path::StorePath::from_base_path(store_base(self_path)).ok();
        let res = pack_one_nar(
            &host,
            &dir.path().join("out.frames"),
            Some((&candidates, self_sp.as_ref())),
            Instant::now() + Duration::from_secs(30),
        )?;
        assert_eq!(res.references, vec![input.to_string()]);
        assert_eq!(res.chunks.len(), 1);
        Ok(())
    }
}
