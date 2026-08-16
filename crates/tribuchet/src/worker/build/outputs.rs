//! Output packing: NARs for outputs and runtime-closure extras.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use harmonia_store_path::{StoreDir, StorePath};
use harmonia_store_path_info::UnkeyedValidPathInfo;
use harmonia_store_remote::{DaemonClient, DaemonStore};
use harmonia_utils_signature::SecretKey;
use sha2::{Digest, Sha256};

use std::os::fd::{AsRawFd, OwnedFd};

use super::super::resume::{PackedExtra, PackedOutput};
use super::super::sandbox;
use super::store_base;
use crate::capwrite::CappedWriter;
use crate::errors::chain;
use crate::errors::{Result, err_ctx, err_msg};
use crate::nar;
use crate::store::topo_order;

/// Pack the outputs, then (under recursive-nix) the closure-delta
/// extras.
pub(in crate::worker) async fn pack_outputs_and_extras(
    dir: &Path,
    spec: &sandbox::SandboxSpec,
    pack_root: Option<&OwnedFd>,
    deadline: Instant,
    signing_key: &SecretKey,
    build_id: &str,
) -> Result<(Vec<PackedOutput>, Vec<PackedExtra>)> {
    let extra_candidates = if spec.recursive_nix {
        query_all_valid_paths().await.unwrap_or_else(|e| {
            tracing::warn!(id = build_id, "queryAllValidPaths failed: {}", chain(&e));
            BTreeSet::new()
        })
    } else {
        BTreeSet::new()
    };
    let packed = pack_outputs(
        dir,
        spec,
        pack_root,
        &extra_candidates,
        deadline,
        signing_key,
    )
    .await?;
    let extras = if spec.recursive_nix {
        pack_extras(
            dir,
            &packed,
            &spec.store_inputs,
            &spec.outputs,
            deadline,
            signing_key,
        )
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(id = build_id, "packing extras failed: {}", chain(&e));
            Vec::new()
        })
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

/// Pack, hash and sign every output before announcing the result,
/// because signatures travel in BuildResult ahead of the NAR data.
async fn pack_outputs(
    dir: &Path,
    spec: &sandbox::SandboxSpec,
    pack_root: Option<&OwnedFd>,
    extra_candidates: &BTreeSet<harmonia_store_path::StorePath>,
    deadline: Instant,
    signing_key: &SecretKey,
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
        let nar_file = dir.join(format!("{}.nar.zst", store_base(scratch)));
        let self_path = harmonia_store_path::StorePath::from_base_path(store_base(scratch)).ok();
        let res = pack_one_nar(
            &host_path,
            &nar_file,
            &candidates,
            self_path.as_ref(),
            deadline,
        )
        .await
        .map_err(err_ctx(format!("packing output {scratch}")))?;
        let sig =
            signing_key.sign(format!("{scratch}:{}", hex::encode(&res.nar_sha256)).as_bytes());
        packed.push(PackedOutput {
            scratch: scratch.clone(),
            nar_file,
            nar_sha256: res.nar_sha256,
            signature: sig.to_string(),
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
    signing_key: &SecretKey,
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
        let nar_file = dir.join(format!("extra-{}.nar.zst", store_base(&path)));
        let res = pack_one_nar(
            Path::new(&path),
            &nar_file,
            &candidates,
            Some(&sp),
            deadline,
        )
        .await
        .map_err(err_ctx(format!("packing extra {path}")))?;
        // Daemon NAR layout is deterministic, so its recorded
        // nar_size matches the bytes we just hashed.
        let nar_size = info.nar_size;
        let sig = signing_key.sign(format!("{path}:{}", hex::encode(&res.nar_sha256)).as_bytes());
        out.push(PackedExtra {
            path,
            nar_file,
            nar_sha256: res.nar_sha256,
            nar_size,
            signature: sig.to_string(),
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
    nar_sha256: Vec<u8>,
    references: Vec<String>,
}

/// Pack `host_path` as a zstd-compressed NAR into `nar_path`, hashing
/// and reference-scanning the plaintext NAR in the same pass.
async fn pack_one_nar(
    host_path: &Path,
    nar_path: &Path,
    candidates: &BTreeSet<harmonia_store_path::StorePath>,
    self_path: Option<&harmonia_store_path::StorePath>,
    deadline: Instant,
) -> Result<NarPackResult> {
    let mut hasher = Sha256::new();
    let mut sink = harmonia_store_ref_scan::RefScanSink::new(candidates, self_path);
    {
        let f = fs::File::create(nar_path)?;
        let mut enc = zstd::stream::write::Encoder::new(f, 3)?;
        let mut tee = TeeScanner {
            zstd: &mut enc,
            hasher: &mut hasher,
            scan: &mut sink,
        };
        // Deadline bounds packing too: a builder can exit instantly
        // leaving a multi-TB sparse output.
        let mut limited = CappedWriter::with_deadline(&mut tee, deadline);
        nar::pack(host_path, &mut limited).await?;
        enc.finish()?.flush()?;
    }
    let store_dir = harmonia_store_path::StoreDir::default();
    let references = sink
        .found_paths()
        .into_iter()
        .filter(|p| self_path != Some(p))
        .map(|p| {
            p.to_absolute_path(&store_dir)
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    Ok(NarPackResult {
        nar_sha256: hasher.finalize().to_vec(),
        references,
    })
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

/// One-pass tee of plaintext NAR bytes into zstd, sha256, and the
/// reference scanner.
struct TeeScanner<'a, W: Write> {
    zstd: &'a mut W,
    hasher: &'a mut Sha256,
    scan: &'a mut harmonia_store_ref_scan::RefScanSink,
}

impl<W: Write> Write for TeeScanner<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.zstd.write_all(buf)?;
        self.hasher.update(buf);
        self.scan.feed(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.zstd.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// pack_one_nar finds references in the same pass as the NAR
    /// hash; self-paths are dropped.
    #[tokio::test]
    async fn pack_one_nar_finds_references_and_excludes_self() -> Result<()> {
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
            &dir.path().join("out.nar.zst"),
            &candidates,
            self_sp.as_ref(),
            Instant::now() + Duration::from_secs(30),
        )
        .await?;
        assert_eq!(res.references, vec![input.to_string()]);
        assert_eq!(res.nar_sha256.len(), 32);
        Ok(())
    }
}
