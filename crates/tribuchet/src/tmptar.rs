//! Archives the client's topTmpDir (structured attrs, passAsFile
//! files): `tribuchet attach` tars its own build directory, so the
//! hub never reads client paths off disk.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use nix::{dir, fcntl};

/// zstd tar of `path`: only files, directories and unfollowed
/// symlinks, mirroring what the worker's unpack accepts.
pub fn tar_zstd_dir(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = fs::OpenOptions::new()
        .read(true)
        .custom_flags((fcntl::OFlag::O_DIRECTORY | fcntl::OFlag::O_NOFOLLOW).bits())
        .open(path)
        .with_context(|| format!("opening build dir {}", path.display()))?;
    let enc = zstd::stream::write::Encoder::new(Vec::new(), 3)?;
    let mut tar = tar::Builder::new(enc);
    append_dir_fd(&mut tar, &dir, Path::new(""), 0)?;
    let mut out = tar.into_inner()?.finish()?;
    out.flush()?;
    Ok(out)
}

/// Recursively archive a directory through fds relative to the held
/// handle: openat + O_NOFOLLOW with headers taken from the opened fd,
/// so an entry swapped for a symlink between listing and opening is
/// archived as whatever it now is, never followed.
fn append_dir_fd<W: io::Write>(
    tar: &mut tar::Builder<W>,
    dir: &fs::File,
    prefix: &Path,
    depth: u32,
) -> Result<()> {
    use std::os::fd::AsFd;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::MetadataExt;
    // Bound recursion so a deep tree cannot overflow the stack.
    ensure!(depth < 128, "topTmpDir nesting too deep");
    // List through fdopendir on a dup of the handle instead of
    // re-resolving the path (and instead of /proc/self/fd, which is
    // Linux-only and unreliable on macOS).
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
        // Tar carries only files, dirs and symlinks. openat would
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
        // swapped in cannot stall attach, the fstat below skips it.
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
            append_dir_fd(tar, &fd, &in_tar, depth + 1)?;
        } else if meta.is_file() {
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(meta.len());
            tar.append_data(&mut h, &in_tar, &fd)?;
        }
        // anything else (fifo, socket, device) is not build-dir content
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn entries(archive: &[u8]) -> HashMap<std::path::PathBuf, tar::EntryType> {
        let tar_bytes = zstd::decode_all(archive).unwrap();
        let mut found = HashMap::new();
        let mut ar = tar::Archive::new(&tar_bytes[..]);
        for entry in ar.entries().unwrap() {
            let entry = entry.unwrap();
            found.insert(
                entry.path().unwrap().into_owned(),
                entry.header().entry_type(),
            );
        }
        found
    }

    #[test]
    fn archives_files_dirs_and_symlink_entries_without_following_them() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("build");
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("sub/file"), "payload").unwrap();
        let secret = tmp.path().join("secret");
        fs::write(&secret, "foreign-content").unwrap();
        std::os::unix::fs::symlink(&secret, dir.join("link")).unwrap();

        let archive = tar_zstd_dir(&dir).unwrap();
        // symlink targets are never read or shipped
        let tar_bytes = zstd::decode_all(&archive[..]).unwrap();
        assert!(!tar_bytes.windows(15).any(|w| w == b"foreign-content"));
        let found = entries(&archive);
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
        assert_eq!(
            found.get(Path::new("sub")),
            Some(&tar::EntryType::Directory),
            "{found:?}"
        );
    }

    #[test]
    fn refuses_a_symlinked_build_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("build");
        fs::create_dir(&dir).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(tar_zstd_dir(&link).is_err());
        assert!(tar_zstd_dir(&dir).is_ok());
    }
}
