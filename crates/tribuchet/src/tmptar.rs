//! Ships the client's topTmpDir (structured attrs, passAsFile files):
//! `tribuchet attach` tars its own build directory, so the hub never
//! reads client paths off disk, and the executing side unpacks it with
//! matching restrictions.

use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path};

use anyhow::{Context, Result, bail, ensure};
use nix::sys::stat;
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

/// Unpack the client-supplied tmp-dir tar, refusing anything but plain
/// files, directories, and symlinks, and applying only the 0777 mode
/// bits: a root worker must not materialize client-chosen setuid bits.
///
/// Every path is created relative to the destination directory's fd via
/// openat with O_NOFOLLOW, so no entry name -- absolute, dot-dotted, or
/// aimed at a symlink planted by an earlier entry -- can place or chmod
/// anything outside the destination.
pub(crate) fn unpack_tmp_dir_archive(reader: impl Read, dest: &Path) -> Result<()> {
    use fcntl::OFlag;
    use std::os::fd::{AsFd, OwnedFd};

    fn open_dir_at(at: &impl AsFd, name: &OsStr) -> Result<OwnedFd> {
        Ok(fcntl::openat(
            at.as_fd(),
            name,
            OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_RDONLY | OFlag::O_CLOEXEC,
            stat::Mode::empty(),
        )?)
    }

    fn mkdir_at(at: &impl AsFd, name: &OsStr, mode: stat::Mode) -> Result<()> {
        match stat::mkdirat(at.as_fd(), name, mode) {
            Ok(()) | Err(nix::errno::Errno::EEXIST) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    let dest = fs::File::open(dest).context("opening tmp dir destination")?;
    let mut tar = tar::Archive::new(reader);
    for entry in tar.entries()? {
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        match kind {
            tar::EntryType::Regular | tar::EntryType::Directory | tar::EntryType::Symlink => {}
            other => bail!("unsupported tar entry type {other:?} in tmp dir archive"),
        }
        // Mirror unpack_in's name handling: drop root/cur-dir
        // components (absolute names land under dest), refuse `..`.
        let path = entry.path()?.into_owned();
        let mut comps = Vec::new();
        for c in path.components() {
            match c {
                Component::Normal(p) => comps.push(p.to_owned()),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
                Component::ParentDir => {
                    bail!("tar entry escapes the tmp dir: {}", path.display())
                }
            }
        }
        let Some(leaf) = comps.pop() else { continue };
        // Descend to the parent, creating intermediate directories.
        let mut parent: OwnedFd = dest.as_fd().try_clone_to_owned()?;
        for c in &comps {
            mkdir_at(&parent, c.as_os_str(), stat::Mode::S_IRWXU)?;
            parent = open_dir_at(&parent, c)?;
        }
        let mode = stat::Mode::from_bits_truncate(
            // mode_t is u16 on macOS but u32 on Linux
            (entry.header().mode()? & 0o777) as nix::libc::mode_t,
        );
        match kind {
            tar::EntryType::Directory => {
                mkdir_at(&parent, leaf.as_os_str(), mode)?;
                let dir = open_dir_at(&parent, &leaf)?;
                stat::fchmod(dir.as_fd(), mode)?;
            }
            tar::EntryType::Symlink => {
                let target = entry
                    .link_name()?
                    .ok_or_else(|| anyhow::anyhow!("symlink entry without target"))?
                    .into_owned();
                nix::unistd::symlinkat(target.as_os_str(), parent.as_fd(), leaf.as_os_str())?;
            }
            _ => {
                let file: fs::File = fcntl::openat(
                    parent.as_fd(),
                    leaf.as_os_str(),
                    OFlag::O_WRONLY
                        | OFlag::O_CREAT
                        | OFlag::O_TRUNC
                        | OFlag::O_NOFOLLOW
                        | OFlag::O_CLOEXEC,
                    mode,
                )?
                .into();
                io::copy(&mut entry, &mut &file)?;
                // the umask at create time may have masked bits off
                stat::fchmod(file.as_fd(), mode)?;
            }
        }
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

    #[test]
    fn unpack_strips_setuid_and_rejects_hardlinks() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        // setuid bit in the archive must not materialize on disk
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path("evil")?;
        header.set_size(2);
        header.set_mode(0o4755);
        header.set_cksum();
        builder.append(&header, &b"hi"[..])?;
        let data = builder.into_inner()?;
        let dest = tempfile::tempdir()?;
        unpack_tmp_dir_archive(data.as_slice(), dest.path())?;
        let mode = fs::metadata(dest.path().join("evil"))?.permissions().mode();
        assert_eq!(mode & 0o7777, 0o755, "mode {mode:o}");

        // hard links could alias files outside the build dir
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path("link")?;
        header.set_entry_type(tar::EntryType::Link);
        header.set_link_name("/etc/passwd")?;
        header.set_size(0);
        header.set_cksum();
        builder.append(&header, &b""[..])?;
        let data = builder.into_inner()?;
        let dest = tempfile::tempdir()?;
        assert!(unpack_tmp_dir_archive(data.as_slice(), dest.path()).is_err());
        Ok(())
    }

    /// A symlink planted by an earlier entry must not redirect later
    /// entries outside the destination: descent uses O_NOFOLLOW.
    #[test]
    fn unpack_does_not_follow_planted_symlinks() -> Result<()> {
        let outside = tempfile::tempdir()?;
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path("exit")?;
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name(outside.path())?;
        header.set_size(0);
        header.set_cksum();
        builder.append(&header, &b""[..])?;
        let mut header = tar::Header::new_gnu();
        header.set_path("exit/pwn")?;
        header.set_size(1);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, &b"x"[..])?;
        let data = builder.into_inner()?;
        let dest = tempfile::tempdir()?;
        assert!(unpack_tmp_dir_archive(data.as_slice(), dest.path()).is_err());
        assert!(!outside.path().join("pwn").exists());
        Ok(())
    }

    /// An absolute entry name unpacks under dest (unpack_in skips the
    /// root component); the chmod must follow it there instead of
    /// touching the literal host path.
    #[test]
    fn unpack_chmod_stays_inside_dest() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let outside = tempfile::tempdir()?;
        let victim = outside.path().join("victim");
        fs::write(&victim, "x")?;
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644))?;
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        // set_path refuses absolute names, so write the name bytes the
        // way a hostile archive would carry them
        let name = victim.to_str().unwrap().as_bytes();
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        header.set_size(1);
        header.set_mode(0o600);
        header.set_cksum();
        builder.append(&header, &b"y"[..])?;
        let data = builder.into_inner()?;
        let dest = tempfile::tempdir()?;
        unpack_tmp_dir_archive(data.as_slice(), dest.path())?;
        let mode = fs::metadata(&victim)?.permissions().mode();
        assert_eq!(mode & 0o777, 0o644, "outside file was chmodded: {mode:o}");
        let unpacked = dest
            .path()
            .join(victim.strip_prefix("/").unwrap_or(&victim));
        assert_eq!(fs::metadata(&unpacked)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }
}
