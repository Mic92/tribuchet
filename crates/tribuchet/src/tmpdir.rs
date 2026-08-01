//! Ships the client's build tmp dir (structured attrs, passAsFile
//! files) as a zstd stream of length-prefixed [`TmpDirFile`] messages.
//! `tribuchet attach` packs its own build directory, so the hub never
//! reads client paths off disk. The executing side unpacks it with
//! matching restrictions.

use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::path::Path;

use prost::Message;
use rustix::fs::{Dir, FileType, Mode, OFlags, fchmod, open, openat};

use crate::proto::TmpDirFile;

/// Upper bound on the whole unpacked stream.
const MAX_UNPACKED: u64 = 1024 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("opening build dir {path}")]
    OpenDir {
        path: std::path::PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("opening tmp dir destination")]
    OpenDest(#[source] io::Error),
    #[error("tmp dir file too large")]
    FileTooLarge,
    #[error("truncated tmp dir file")]
    Truncated,
    #[error("decoding tmp dir file")]
    Decode(#[from] prost::DecodeError),
    #[error("non-UTF-8 name in the build tmp dir")]
    NonUtf8Name,
    #[error("invalid tmp dir file name {0:?}")]
    InvalidName(String),
    #[error("tmp dir stream exceeds {MAX_UNPACKED} bytes")]
    StreamTooLarge,
}

fn write_file(w: &mut impl Write, file: &TmpDirFile) -> Result<(), Error> {
    let body = file.encode_to_vec();
    let len = u32::try_from(body.len()).map_err(|_| Error::FileTooLarge)?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&body)?;
    Ok(())
}

/// The next file, or `None` at a clean end of the stream.
fn read_file(r: &mut impl Read) -> Result<Option<TmpDirFile>, Error> {
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
    if body.len() as u64 != len {
        return Err(Error::Truncated);
    }
    Ok(Some(TmpDirFile::decode(body.as_slice())?))
}

/// zstd stream of the regular files directly inside `path`. Anything
/// else (subdirectories, symlinks, the recursive-nix socket) is
/// skipped.
pub fn pack_zstd_dir(path: &Path) -> Result<Vec<u8>, Error> {
    let dir = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| Error::OpenDir {
        path: path.to_path_buf(),
        source: e.into(),
    })?;
    let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 3)?;
    // List through fdopendir on a dup of the handle instead of
    // re-resolving the path (and instead of /proc/self/fd, which is
    // Linux-only and unreliable on macOS).
    let listing = Dir::read_from(&dir).map_err(io::Error::from)?;
    // Collect names up front so the directory handle is free for openat.
    let mut names = Vec::new();
    for res in listing {
        let entry = res.map_err(io::Error::from)?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." || entry.file_type() != FileType::RegularFile {
            continue;
        }
        let Ok(name) = std::str::from_utf8(bytes) else {
            return Err(Error::NonUtf8Name);
        };
        names.push(name.to_owned());
    }
    for name in names {
        // O_NOFOLLOW: a listing entry swapped for a symlink fails the open.
        // O_NONBLOCK: a swapped-in fifo cannot stall attach.
        let mut fd: fs::File = openat(
            &dir,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(io::Error::from)?
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
pub(crate) fn unpack_tmp_dir(reader: impl Read, dest: &Path) -> Result<(), Error> {
    let dest = fs::File::open(dest).map_err(Error::OpenDest)?;
    let mode = Mode::from_bits_truncate(0o644);
    // Bounds a decompression bomb. Real tmp dir contents are tiny.
    let mut reader = reader.take(MAX_UNPACKED);
    while let Some(f) = read_file(&mut reader)? {
        if f.name.is_empty() || f.name == "." || f.name == ".." || f.name.contains('/') {
            return Err(Error::InvalidName(f.name));
        }
        let file: fs::File = openat(
            dest.as_fd(),
            f.name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            mode,
        )
        .map_err(io::Error::from)?
        .into();
        (&file).write_all(&f.data)?;
        // the umask at create time may have masked bits off
        fchmod(&file, mode).map_err(io::Error::from)?;
    }
    if reader.limit() == 0 {
        return Err(Error::StreamTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
    use std::collections::HashMap;

    fn unpack_zstd(archive: &[u8], dest: &Path) -> Result<()> {
        Ok(unpack_tmp_dir(
            zstd::stream::read::Decoder::new(archive)?,
            dest,
        )?)
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
