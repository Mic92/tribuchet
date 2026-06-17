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
pub async fn pack(path: &Path, w: &mut impl Write) -> Result<()> {
    let mut stream = harmonia_file_nar::archive::NarByteStream::new(path.to_path_buf());
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("packing {}", path.display()))?;
        w.write_all(&chunk)?;
    }
    Ok(())
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
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    async fn round_trip_via_zstd(src: &Path, dest: &Path) -> Result<()> {
        let mut nar = Vec::new();
        pack(src, &mut nar).await?;
        let zstd = zstd::stream::encode_all(nar.as_slice(), 3)?;
        // capacity for every chunk: sender runs before the consumer
        let (tx, rx) = mpsc::channel(zstd.len() / 7 + 2);
        for chunk in zstd.chunks(7) {
            tx.send(chunk.to_vec()).await?;
        }
        drop(tx);
        unpack_zstd_chunks(rx, dest).await
    }

    /// Round-trip a tree with the cases NAR distinguishes: regular
    /// files, executables, symlinks (valid and dangling), nested dirs.
    #[tokio::test]
    async fn round_trip() -> Result<()> {
        let src = tempfile::tempdir()?;
        fs::write(src.path().join("file"), b"hello")?;
        fs::create_dir(src.path().join("dir"))?;
        fs::write(src.path().join("dir/exe"), b"#!/bin/sh\n")?;
        fs::set_permissions(
            src.path().join("dir/exe"),
            fs::Permissions::from_mode(0o755),
        )?;
        std::os::unix::fs::symlink("file", src.path().join("link"))?;
        std::os::unix::fs::symlink("/nowhere", src.path().join("dangling"))?;

        let out = tempfile::tempdir()?;
        let dest = out.path().join("restored");
        round_trip_via_zstd(src.path(), &dest).await?;

        assert_eq!(fs::read(dest.join("file"))?, b"hello");
        let mode = fs::metadata(dest.join("dir/exe"))?.permissions().mode();
        assert_ne!(mode & 0o111, 0, "executable bit preserved");
        assert_eq!(fs::read_link(dest.join("link"))?.to_str(), Some("file"));
        assert_eq!(
            fs::read_link(dest.join("dangling"))?.to_str(),
            Some("/nowhere")
        );

        // packing the restored tree yields identical bytes (determinism)
        let mut a = Vec::new();
        pack(src.path(), &mut a).await?;
        let mut b = Vec::new();
        pack(&dest, &mut b).await?;
        assert_eq!(a, b);
        Ok(())
    }

    /// The NAR matches nix-store --dump byte for byte when nix exists.
    #[tokio::test]
    async fn matches_nix_store_dump() -> Result<()> {
        let src = tempfile::tempdir()?;
        fs::write(src.path().join("a"), b"x")?;
        std::os::unix::fs::symlink("a", src.path().join("b"))?;
        let mut ours = Vec::new();
        pack(src.path(), &mut ours).await?;
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
