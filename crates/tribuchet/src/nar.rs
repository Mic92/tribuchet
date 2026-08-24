//! Nix ARchive (NAR) serialization (`pack`) and restore (harmonia).
//!
//! NAR is the canonical serialization for store paths: deterministic,
//! preserves only executable bits and symlinks, and its hash matches
//! Nix's narHash, keeping us interoperable with caches and signatures.

use std::io;

pub mod pack;
use std::path::{Path, PathBuf};

use futures_util::StreamExt as _;
use harmonia_file_nar::archive::NarWriteError;
use tokio::sync::mpsc;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unpacking into {path}")]
    Unpack {
        path: PathBuf,
        #[source]
        source: NarWriteError,
    },
}

/// Restore a zstd-compressed NAR arriving as byte chunks on `rx` at
/// `dest` (must not exist). Ends when the sender closes the channel.
pub async fn unpack_zstd_chunks(rx: mpsc::Receiver<Vec<u8>>, dest: &Path) -> Result<(), Error> {
    let chunks = tokio_stream::wrappers::ReceiverStream::new(rx)
        .map(|c| Ok::<_, io::Error>(bytes::Bytes::from(c)));
    let mut dec = async_compression::tokio::bufread::ZstdDecoder::new(
        tokio_util::io::StreamReader::new(chunks),
    );
    // Outputs arrive as one zstd frame per chunk.
    dec.multiple_members(true);
    // restore() takes NarWriteError items; fold parse errors in (there
    // is no dedicated "reading the NAR" variant).
    let parse_err_path = dest.to_path_buf();
    let events = harmonia_file_nar::archive::parse_nar(dec).map(move |e| {
        e.map_err(|err| NarWriteError::create_file_error(parse_err_path.clone(), err))
    });
    harmonia_file_nar::archive::restore(events, dest)
        .await
        .map_err(|source| Error::Unpack {
            path: dest.to_path_buf(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{error, result};
    type Result<T> = result::Result<T, Box<dyn error::Error>>;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;

    async fn round_trip_via_zstd(src: &Path, dest: &Path) -> Result<()> {
        let nar = pack::to_vec(src)?;
        let zstd = zstd::stream::encode_all(nar.as_slice(), 3)?;
        // capacity for every chunk: sender runs before the consumer
        let (tx, rx) = mpsc::channel(zstd.len() / 7 + 2);
        for chunk in zstd.chunks(7) {
            tx.send(chunk.to_vec()).await?;
        }
        drop(tx);
        Ok(unpack_zstd_chunks(rx, dest).await?)
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
        symlink("file", src.path().join("link"))?;
        symlink("/nowhere", src.path().join("dangling"))?;

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
        assert_eq!(pack::to_vec(src.path())?, pack::to_vec(&dest)?);
        Ok(())
    }

    /// A store object that is itself a symlink round-trips as a symlink.
    #[tokio::test]
    async fn root_symlink_round_trip() -> Result<()> {
        let src = tempfile::tempdir()?;
        fs::write(src.path().join("target"), b"hello")?;
        let link = src.path().join("link");
        symlink(src.path().join("target"), &link)?;

        let out = tempfile::tempdir()?;
        let dest = out.path().join("restored");
        round_trip_via_zstd(&link, &dest).await?;

        let meta = fs::symlink_metadata(&dest)?;
        assert!(meta.file_type().is_symlink(), "root symlink dereferenced");
        assert_eq!(fs::read_link(&dest)?, src.path().join("target"));

        Ok(())
    }
}
