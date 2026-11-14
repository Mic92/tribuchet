//! Output delivery: each output NAR is unpacked into a private scratch
//! directory beside the output path and renamed into place at EOF.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;

use crate::errors::{Result, err_ctx, err_msg};
use crate::nar;
use crate::proto::OutputNar;

/// (chunk sender, unpack task, scratch directory) for one in-flight
/// output transfer.
pub(super) type Unpacker = (
    mpsc::Sender<Vec<u8>>,
    tokio::task::JoinHandle<Result<()>>,
    PathBuf,
);

/// Serial for scratch directory names, unique within this process.
static SCRATCH_SERIAL: AtomicU64 = AtomicU64::new(0);

pub(super) fn remove_tree(path: &Path) {
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
/// same content: losing is not an error. True when ours is in place.
fn commit_output(scratch: &Path, dest: &Path) -> Result<bool> {
    match fs::rename(scratch, dest) {
        Ok(()) => Ok(true),
        Err(_) if dest.exists() => {
            remove_tree(scratch);
            Ok(false)
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
pub(super) async fn handle_output_chunk(
    unpackers: &mut HashMap<String, Unpacker>,
    committed: &mut HashSet<String>,
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
        let dest = PathBuf::from(&out.store_path);
        // Delivered again after this run committed it (the hub requeued
        // the build, or we resubmitted): the new attempt's tree replaces
        // ours, so all outputs come from one run. Another client's tree
        // is never ours to remove.
        if committed.contains(&out.store_path) {
            remove_tree(&dest);
        }
        if commit_output(&scratch, &dest)? {
            committed.insert(out.store_path.clone());
        }
        tracing::debug!(path = out.store_path, "output unpacked");
    }
    Ok(())
}

/// Stop in-flight unpackers and drop their scratch directories; a
/// partial tree never reaches the output path.
pub(super) async fn cleanup_unpackers(unpackers: &mut HashMap<String, Unpacker>) {
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
        deliver_with(unpackers, &mut HashSet::new(), out, chunk).await
    }

    /// `deliver` within one attach run that remembers its commits.
    async fn deliver_with(
        unpackers: &mut HashMap<String, Unpacker>,
        committed: &mut HashSet<String>,
        out: &str,
        chunk: Vec<u8>,
    ) -> Result<()> {
        let expected = vec![out.to_owned()];
        handle_output_chunk(
            unpackers,
            committed,
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
            committed,
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

    /// A requeued or resubmitted build delivers an output this run
    /// already committed: the replacement attempt's tree wins, so the
    /// outputs all come from the same run.
    #[tokio::test]
    async fn a_redelivered_output_replaces_our_earlier_commit() {
        let dir = tempfile::tempdir().unwrap();
        let nar_of_tree = |body: &[u8]| {
            let src = dir.path().join("tree");
            let _ = fs::remove_dir_all(&src);
            fs::create_dir(&src).unwrap();
            fs::write(src.join("file"), body).unwrap();
            zstd::encode_all(&nar::pack::to_vec(&src).unwrap()[..], 3).unwrap()
        };
        let out = dir.path().join("out");
        let out_str = out.to_string_lossy().into_owned();
        let mut unpackers = HashMap::default();
        let mut committed = HashSet::new();

        deliver_with(
            &mut unpackers,
            &mut committed,
            &out_str,
            nar_of_tree(b"first"),
        )
        .await
        .unwrap();
        deliver_with(
            &mut unpackers,
            &mut committed,
            &out_str,
            nar_of_tree(b"second"),
        )
        .await
        .unwrap();

        assert_eq!(fs::read(out.join("file")).unwrap(), b"second");
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
