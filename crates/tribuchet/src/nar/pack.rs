//! NAR serializer that hands out typed pieces, so the chunker can
//! tell file bodies from framing without parsing the stream.

use std::fs;
use std::io::{self, Read};
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const EMIT_CHUNK: usize = 256 * 1024;

/// What the callback receives. Concatenating all `data` in order
/// yields the NAR. File bodies of at least `BODY_MIN` bytes arrive
/// as `Body`, possibly in several parts.
#[derive(Clone, Copy)]
pub enum Piece<'a> {
    Framing(&'a [u8]),
    Body { data: &'a [u8], last: bool },
}

pub const BODY_MIN: usize = 16 * 1024;

/// Nix appends this on case-insensitive filesystems; the dumper
/// strips it again.
#[cfg(target_os = "macos")]
const CASE_HACK_SUFFIX: &[u8] = b"~nix~case~hack~";

fn nar_name(name: &[u8]) -> Vec<u8> {
    #[cfg(target_os = "macos")]
    if let Some(pos) = name
        .windows(CASE_HACK_SUFFIX.len())
        .rposition(|w| w == CASE_HACK_SUFFIX)
    {
        return name[..pos].to_vec();
    }
    name.to_vec()
}

/// Pack `root` as a NAR, handing pieces to `emit`. Stops early when
/// `emit` returns false.
pub fn pack(root: &Path, mut emit: impl FnMut(Piece) -> io::Result<bool>) -> io::Result<()> {
    let mut out = Emitter {
        buf: Vec::with_capacity(2 * EMIT_CHUNK),
        body: Vec::new(),
        emit: &mut emit,
        stopped: false,
        err: None,
    };
    out.str(b"nix-archive-1");
    node(&mut out, root, &fs::symlink_metadata(root)?)?;
    out.finish()
}

#[cfg(test)]
pub fn to_vec(root: &Path) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    pack(root, |p| {
        let (Piece::Framing(b) | Piece::Body { data: b, .. }) = p;
        out.extend_from_slice(b);
        Ok(true)
    })?;
    Ok(out)
}

fn node(out: &mut Emitter, path: &Path, meta: &fs::Metadata) -> io::Result<()> {
    let ft = meta.file_type();
    out.str(b"(");
    out.str(b"type");
    if ft.is_dir() {
        out.str(b"directory");
        // Disk name as tie-break: stripped names may collide.
        let mut entries = fs::read_dir(path)?
            .map(|e| e.map(|e| (nar_name(e.file_name().as_bytes()), e)))
            .collect::<io::Result<Vec<_>>>()?;
        entries.sort_unstable_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.file_name().cmp(&b.1.file_name()))
        });
        for (name, e) in entries {
            if out.stopped {
                return Ok(());
            }
            out.str(b"entry");
            out.str(b"(");
            out.str(b"name");
            out.str(&name);
            out.str(b"node");
            node(out, &e.path(), &e.metadata()?)?;
            out.str(b")");
        }
    } else if ft.is_symlink() {
        out.str(b"symlink");
        out.str(b"target");
        out.str(fs::read_link(path)?.as_os_str().as_bytes());
    } else {
        out.str(b"regular");
        if meta.permissions().mode() & 0o100 != 0 {
            out.str(b"executable");
            out.str(b"");
        }
        out.str(b"contents");
        file(out, path, meta.len())?;
    }
    out.str(b")");
    Ok(())
}

fn file(out: &mut Emitter, path: &Path, size: u64) -> io::Result<()> {
    out.len(size);
    let mut f = fs::File::open(path)?;
    if size < BODY_MIN as u64 {
        let start = out.buf.len();
        // Bounded by `size`: a file that grew meanwhile must not
        // corrupt the framing.
        let n = f.take(size).read_to_end(&mut out.buf)? as u64;
        if n != size {
            out.buf.truncate(start);
            return Err(truncated(path));
        }
        out.pad(size);
        if out.buf.len() >= EMIT_CHUNK {
            out.flush();
        }
        return Ok(());
    }
    out.flush();
    let mut buf = mem::take(&mut out.body);
    buf.resize(1 << 20, 0);
    let mut left = size;
    while left > 0 && !out.stopped {
        let want = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
        let n = f.read(&mut buf[..want])?;
        if n == 0 {
            out.body = buf;
            return Err(truncated(path));
        }
        left -= n as u64;
        out.hand_out(Piece::Body {
            data: &buf[..n],
            last: left == 0,
        });
    }
    out.body = buf;
    out.pad(size);
    Ok(())
}

fn truncated(path: &Path) -> io::Error {
    io::Error::other(format!("{} changed while packing", path.display()))
}

/// Buffers framing and small files into ~EMIT_CHUNK pieces.
struct Emitter<'a> {
    buf: Vec<u8>,
    /// Reused read buffer for streamed bodies.
    body: Vec<u8>,
    emit: &'a mut dyn FnMut(Piece) -> io::Result<bool>,
    stopped: bool,
    err: Option<io::Error>,
}

impl Emitter<'_> {
    fn str(&mut self, s: &[u8]) {
        self.len(s.len() as u64);
        self.buf.extend_from_slice(s);
        self.pad(s.len() as u64);
        if self.buf.len() >= EMIT_CHUNK {
            self.flush();
        }
    }

    fn len(&mut self, n: u64) {
        self.buf.extend_from_slice(&n.to_le_bytes());
    }

    fn pad(&mut self, n: u64) {
        let r = (n % 8) as usize;
        if r != 0 {
            self.buf.extend_from_slice(&[0u8; 8][..8 - r]);
        }
    }

    fn flush(&mut self) {
        if self.stopped || self.buf.is_empty() {
            return;
        }
        let buf = mem::take(&mut self.buf);
        self.hand_out(Piece::Framing(&buf));
        self.buf = buf;
        self.buf.clear();
    }

    fn hand_out(&mut self, piece: Piece) {
        match (self.emit)(piece) {
            Ok(true) => {}
            Ok(false) => self.stopped = true,
            Err(e) => {
                self.stopped = true;
                self.err = Some(e);
            }
        }
    }

    fn finish(&mut self) -> io::Result<()> {
        self.flush();
        self.err.take().map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::process::Command;

    use futures_util::StreamExt as _;

    fn harmonia_bytes(root: &Path) -> Vec<u8> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut s = harmonia_file_nar::archive::NarByteStream::new(root.to_path_buf());
            let mut buf = Vec::new();
            while let Some(b) = s.next().await {
                buf.extend_from_slice(&b.unwrap());
            }
            buf
        })
    }

    fn tricky_tree() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        let p = t.path();
        // "a" dir vs "a.c" sibling: '.' < '/' trips naive path sorts.
        fs::create_dir(p.join("a")).unwrap();
        fs::write(p.join("a/b"), b"inner").unwrap();
        fs::write(p.join("a.c"), b"sibling").unwrap();
        fs::create_dir(p.join("empty")).unwrap();
        fs::create_dir_all(p.join("deep/er/most")).unwrap();
        fs::write(p.join("deep/er/most/leaf"), vec![7u8; 3000]).unwrap();
        fs::write(p.join("exe"), b"#!/bin/sh\n").unwrap();
        fs::set_permissions(p.join("exe"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink("a/b", p.join("link")).unwrap();
        symlink("/nowhere", p.join("dangling")).unwrap();
        fs::write(p.join("big"), vec![42u8; (1 << 20) + 4096]).unwrap();
        t
    }

    #[test]
    fn matches_harmonia() {
        let t = tricky_tree();
        assert_eq!(to_vec(t.path()).unwrap(), harmonia_bytes(t.path()));
    }

    #[test]
    fn matches_nix_store_dump() {
        let t = tricky_tree();
        let out = match Command::new("nix-store")
            .arg("--dump")
            .arg(t.path())
            .output()
        {
            Ok(o) if o.status.success() => o.stdout,
            _ => return,
        };
        assert_eq!(to_vec(t.path()).unwrap(), out);
    }

    #[test]
    fn root_file_and_symlink() {
        let t = tempfile::tempdir().unwrap();
        fs::write(t.path().join("f"), b"solo").unwrap();
        symlink("f", t.path().join("l")).unwrap();
        for name in ["f", "l"] {
            let p = t.path().join(name);
            assert_eq!(to_vec(&p).unwrap(), harmonia_bytes(&p));
        }
    }

    #[test]
    fn early_stop_terminates() {
        let t = tricky_tree();
        let mut calls = 0;
        pack(t.path(), |_| {
            calls += 1;
            Ok(false)
        })
        .unwrap();
        assert_eq!(calls, 1);
    }
}
