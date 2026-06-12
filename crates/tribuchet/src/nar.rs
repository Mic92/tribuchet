//! Nix ARchive (NAR) pack/unpack, built on harmonia-file-nar.
//!
//! NAR is the canonical serialization for store paths: deterministic,
//! preserves only executable bits and symlinks, and its hash matches
//! Nix's narHash, keeping us interoperable with caches and signatures.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use futures_util::StreamExt as _;
use tokio::sync::mpsc;

/// Serialize the filesystem object at `path` as a NAR into `w`.
///
/// Synchronous wrapper for blocking call sites (worker output packing
/// runs on a blocking thread, interleaved with deadline checks); the
/// async byte stream is driven by a local `block_on`.
pub fn pack(path: &Path, w: &mut impl Write) -> Result<()> {
    let fut = async {
        let mut stream = harmonia_file_nar::archive::NarByteStream::new(path.to_path_buf());
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.with_context(|| format!("packing {}", path.display()))?;
            w.write_all(&chunk)?;
        }
        Ok(())
    };
    // Callers are on spawn_blocking threads (or plain threads in
    // tests), never inside an async context, so block_on cannot
    // deadlock the runtime.
    match tokio::runtime::Handle::try_current() {
        Ok(h) => h.block_on(fut),
        Err(_) => tokio::runtime::Runtime::new()
            .expect("building a runtime for NAR I/O")
            .block_on(fut),
    }
}

/// Restore a zstd-compressed NAR arriving as byte chunks on `rx` at
/// `dest` (must not exist). Ends when the sender closes the channel.
pub async fn unpack_zstd_chunks(rx: mpsc::Receiver<Vec<u8>>, dest: &Path) -> Result<()> {
    use harmonia_file_nar::archive::NarWriteError;
    let chunks = tokio_stream::wrappers::ReceiverStream::new(rx)
        .map(|c| Ok::<_, std::io::Error>(bytes::Bytes::from(c)));
    let dec = async_compression::tokio::bufread::ZstdDecoder::new(
        tokio_util::io::StreamReader::new(chunks),
    );
    // restore() takes NarWriteError items; fold parse errors in (there
    // is no dedicated "reading the NAR" variant).
    let parse_err_path = dest.to_path_buf();
    let events = harmonia_file_nar::archive::parse_nar(dec).map(move |e| {
        e.map_err(|err| NarWriteError::create_file_error(parse_err_path.clone(), err))
    });
    harmonia_file_nar::archive::restore(events, dest)
        .await
        .with_context(|| format!("unpacking into {}", dest.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    async fn round_trip_via_zstd(src: &Path, dest: &Path) -> Result<()> {
        let mut nar = Vec::new();
        pack_blocking(src, &mut nar)?;
        let zstd = zstd::stream::encode_all(nar.as_slice(), 3)?;
        // capacity for every chunk: sender runs before the consumer
        let (tx, rx) = mpsc::channel(zstd.len() / 7 + 2);
        for chunk in zstd.chunks(7) {
            tx.send(chunk.to_vec()).await?;
        }
        drop(tx);
        unpack_zstd_chunks(rx, dest).await
    }

    /// pack() must not run inside an async context; tests drive it on
    /// a plain thread like the worker's blocking call site does.
    fn pack_blocking(path: &Path, w: &mut Vec<u8>) -> Result<()> {
        let path = path.to_path_buf();
        let mut buf = Vec::new();
        std::thread::scope(|s| s.spawn(|| pack(&path, &mut buf)).join().unwrap())?;
        w.extend_from_slice(&buf);
        Ok(())
    }

    /// Round-trip a tree with the cases NAR distinguishes: regular
    /// files, executables, symlinks (valid and dangling), nested dirs.
    #[tokio::test]
    async fn round_trip() -> Result<()> {
        let src = tempfile::tempdir()?;
        std::fs::write(src.path().join("file"), b"hello")?;
        std::fs::create_dir(src.path().join("dir"))?;
        std::fs::write(src.path().join("dir/exe"), b"#!/bin/sh\n")?;
        std::fs::set_permissions(
            src.path().join("dir/exe"),
            std::fs::Permissions::from_mode(0o755),
        )?;
        std::os::unix::fs::symlink("file", src.path().join("link"))?;
        std::os::unix::fs::symlink("/nowhere", src.path().join("dangling"))?;

        let out = tempfile::tempdir()?;
        let dest = out.path().join("restored");
        round_trip_via_zstd(src.path(), &dest).await?;

        assert_eq!(std::fs::read(dest.join("file"))?, b"hello");
        let mode = std::fs::metadata(dest.join("dir/exe"))?
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0, "executable bit preserved");
        assert_eq!(
            std::fs::read_link(dest.join("link"))?.to_str(),
            Some("file")
        );
        assert_eq!(
            std::fs::read_link(dest.join("dangling"))?.to_str(),
            Some("/nowhere")
        );

        // packing the restored tree yields identical bytes (determinism)
        let mut a = Vec::new();
        pack_blocking(src.path(), &mut a)?;
        let mut b = Vec::new();
        pack_blocking(&dest, &mut b)?;
        assert_eq!(a, b);
        Ok(())
    }

    /// The NAR matches nix-store --dump byte for byte when nix exists.
    #[test]
    fn matches_nix_store_dump() -> Result<()> {
        let src = tempfile::tempdir()?;
        std::fs::write(src.path().join("a"), b"x")?;
        std::os::unix::fs::symlink("a", src.path().join("b"))?;
        let mut ours = Vec::new();
        pack(src.path(), &mut ours)?;
        let theirs = match std::process::Command::new("nix-store")
            .arg("--dump")
            .arg(src.path())
            .output()
        {
            Ok(out) if out.status.success() => out.stdout,
            _ => {
                eprintln!("nix-store not usable; skipping");
                return Ok(());
            }
        };
        assert_eq!(ours, theirs);
        Ok(())
    }
}
