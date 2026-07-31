//! Ships the client's build tmp dir (structured attrs, passAsFile
//! files) as a zstd stream of length-prefixed [`TmpDirFile`] messages.
//! `tribuchet attach` packs its own build directory, so the hub never
//! reads client paths off disk. The executing side unpacks it with
//! matching restrictions.

use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use nix::fcntl::OFlag;
use nix::sys::stat;
use nix::{dir, fcntl};
use prost::Message;

use crate::proto::TmpDirFile;

/// Upper bound on the whole unpacked stream.
const MAX_UNPACKED: u64 = 1024 * 1024 * 1024;

fn write_file(w: &mut impl Write, file: &TmpDirFile) -> Result<()> {
    let body = file.encode_to_vec();
    w.write_all(&u32::try_from(body.len())?.to_le_bytes())?;
    w.write_all(&body)?;
    Ok(())
}

/// The next file, or `None` at a clean end of the stream.
fn read_file(r: &mut impl Read) -> Result<Option<TmpDirFile>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u64::from(u32::from_le_bytes(len));
    // Grow as data arrives: a lying prefix cannot force a huge allocation.
    let mut body = Vec::new();
    r.take(len).read_to_end(&mut body)?;
    ensure!(body.len() as u64 == len, "truncated tmp dir file");
    Ok(Some(TmpDirFile::decode(body.as_slice())?))
}

/// zstd stream of the regular files directly inside `path`. Anything
/// else (subdirectories, symlinks, the recursive-nix socket) is
/// skipped.
pub fn pack_zstd_dir(path: &Path) -> Result<Vec<u8>> {
    let dir = fs::OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW).bits())
        .open(path)
        .with_context(|| format!("opening build dir {}", path.display()))?;
    let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 3)?;
    // List through fdopendir on a dup of the handle instead of
    // re-resolving the path (and instead of /proc/self/fd, which is
    // Linux-only and unreliable on macOS).
    let mut listing = dir::Dir::from_fd(OwnedFd::from(dir.try_clone()?))?;
    // Collect names up front: dir::Entry borrows the iterator.
    let mut names = Vec::new();
    for res in listing.iter() {
        let entry = res?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." || entry.file_type() != Some(dir::Type::File) {
            continue;
        }
        let Ok(name) = std::str::from_utf8(bytes) else {
            bail!("non-UTF-8 name in the build tmp dir");
        };
        names.push(name.to_owned());
    }
    for name in names {
        // O_NOFOLLOW: a listing entry swapped for a symlink fails the open.
        // O_NONBLOCK: a swapped-in fifo cannot stall attach.
        let mut fd: fs::File = fcntl::openat(
            dir.as_fd(),
            name.as_str(),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            stat::Mode::empty(),
        )?
        .into();
        if !fd.metadata()?.is_file() {
            continue;
        }
        let mut data = Vec::new();
        fd.read_to_end(&mut data)?;
        write_file(&mut enc, &TmpDirFile { name, data })?;
    }
    Ok(enc.finish()?)
}

/// Unpack a client-supplied tmp-dir file stream into `dest`. Each file
/// is created with mode 0644 via openat + O_NOFOLLOW on the
/// destination's fd, and names must be plain basenames, so nothing can
/// land outside the destination.
pub(crate) fn unpack_tmp_dir(reader: impl Read, dest: &Path) -> Result<()> {
    let dest = fs::File::open(dest).context("opening tmp dir destination")?;
    let mode = stat::Mode::from_bits_truncate(0o644);
    // Bounds a decompression bomb. Real tmp dir contents are tiny.
    let mut reader = reader.take(MAX_UNPACKED);
    while let Some(f) = read_file(&mut reader)? {
        if f.name.is_empty() || f.name == "." || f.name == ".." || f.name.contains('/') {
            bail!("invalid tmp dir file name {:?}", f.name);
        }
        let file: fs::File = fcntl::openat(
            dest.as_fd(),
            f.name.as_str(),
            OFlag::O_WRONLY
                | OFlag::O_CREAT
                | OFlag::O_TRUNC
                | OFlag::O_NOFOLLOW
                | OFlag::O_CLOEXEC,
            mode,
        )?
        .into();
        (&file).write_all(&f.data)?;
        // the umask at create time may have masked bits off
        stat::fchmod(file.as_fd(), mode)?;
    }
    ensure!(
        reader.limit() > 0,
        "tmp dir stream exceeds {MAX_UNPACKED} bytes"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn unpack_zstd(archive: &[u8], dest: &Path) -> Result<()> {
        unpack_tmp_dir(zstd::stream::read::Decoder::new(archive)?, dest)
    }

    fn entries(archive: &[u8]) -> HashMap<String, Vec<u8>> {
        let data = zstd::decode_all(archive).unwrap();
        let mut r = data.as_slice();
        let mut found = HashMap::new();
        while let Some(e) = read_file(&mut r).unwrap() {
            found.insert(e.name, e.data);
        }
        found
    }

    fn pack(files: &[TmpDirFile]) -> Vec<u8> {
        let mut out = Vec::new();
        for f in files {
            write_file(&mut out, f).unwrap();
        }
        out
    }

    #[test]
    fn packs_files_and_skips_symlinks_and_subdirs() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("build");
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("sub/nested"), "nested").unwrap();
        fs::write(dir.join(".attrs.json"), "{}").unwrap();
        let secret = tmp.path().join("secret");
        fs::write(&secret, "foreign-content").unwrap();
        std::os::unix::fs::symlink(&secret, dir.join("link")).unwrap();

        let archive = pack_zstd_dir(&dir).unwrap();
        // symlinks are neither followed nor shipped
        let raw = zstd::decode_all(&archive[..]).unwrap();
        assert!(!raw.windows(15).any(|w| w == b"foreign-content"));
        let found = entries(&archive);
        assert_eq!(
            found,
            HashMap::from([(".attrs.json".to_owned(), b"{}".to_vec())])
        );

        // and a round trip restores the files
        let dest = tempfile::tempdir().unwrap();
        unpack_zstd(&archive, dest.path()).unwrap();
        assert_eq!(fs::read(dest.path().join(".attrs.json")).unwrap(), b"{}");
    }

    #[test]
    fn refuses_a_symlinked_build_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("build");
        fs::create_dir(&dir).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(pack_zstd_dir(&link).is_err());
        assert!(pack_zstd_dir(&dir).is_ok());
    }

    #[test]
    fn large_files_round_trip() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("build");
        fs::create_dir(&dir)?;
        let payload = vec![7u8; 3 * 1024 * 1024];
        fs::write(dir.join("big"), &payload)?;
        let archive = pack_zstd_dir(&dir)?;
        let dest = tempfile::tempdir()?;
        unpack_zstd(&archive, dest.path())?;
        assert_eq!(fs::read(dest.path().join("big"))?, payload);
        Ok(())
    }

    #[test]
    fn unpack_fixes_modes_and_refuses_non_basenames() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let data = pack(&[TmpDirFile {
            name: "file".into(),
            data: b"hi".to_vec(),
        }]);
        let dest = tempfile::tempdir()?;
        unpack_tmp_dir(data.as_slice(), dest.path())?;
        let mode = fs::metadata(dest.path().join("file"))?.permissions().mode();
        assert_eq!(mode & 0o7777, 0o644, "mode {mode:o}");

        // anything with a slash could land outside the destination
        for name in ["../pwn", "/etc/pwn", "sub/pwn", "", "."] {
            let data = pack(&[TmpDirFile {
                name: name.into(),
                data: Vec::new(),
            }]);
            let dest = tempfile::tempdir()?;
            assert!(
                unpack_tmp_dir(data.as_slice(), dest.path()).is_err(),
                "{name:?} was accepted"
            );
        }
        Ok(())
    }

    /// A symlink already present in the destination must not be
    /// followed when a file of the same name arrives.
    #[test]
    fn unpack_does_not_follow_existing_symlinks() -> Result<()> {
        let outside = tempfile::tempdir()?;
        let victim = outside.path().join("victim");
        fs::write(&victim, "x")?;
        let dest = tempfile::tempdir()?;
        std::os::unix::fs::symlink(&victim, dest.path().join("evil"))?;
        let data = pack(&[TmpDirFile {
            name: "evil".into(),
            data: b"y".to_vec(),
        }]);
        assert!(unpack_tmp_dir(data.as_slice(), dest.path()).is_err());
        assert_eq!(fs::read(&victim)?, b"x");
        Ok(())
    }
}
