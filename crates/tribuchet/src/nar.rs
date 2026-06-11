//! Nix ARchive (NAR) encoder/decoder.
//!
//! NAR is the canonical serialization for store paths: deterministic,
//! preserves only executable bits and symlinks, and its hash matches
//! Nix's narHash, keeping us interoperable with caches and signatures.

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};

const MAGIC: &str = "nix-archive-1";

/// Maximum directory nesting; deeper trees would risk overflowing the
/// (2 MiB) blocking-thread stack via per-level recursion.
const MAX_DEPTH: u32 = 256;

fn write_str(w: &mut impl Write, s: &[u8]) -> io::Result<()> {
    w.write_all(&(s.len() as u64).to_le_bytes())?;
    w.write_all(s)?;
    let pad = (8 - s.len() % 8) % 8;
    w.write_all(&[0u8; 8][..pad])
}

fn read_padding(r: &mut impl Read, len: u64) -> Result<()> {
    let pad = ((8 - len % 8) % 8) as usize;
    if pad > 0 {
        let mut buf = [0u8; 8];
        r.read_exact(&mut buf[..pad])?;
        if buf[..pad].iter().any(|&b| b != 0) {
            bail!("non-zero NAR padding");
        }
    }
    Ok(())
}

fn read_len(r: &mut impl Read) -> Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Read a length-prefixed byte token (not file contents; bounded).
/// Entry names and symlink targets are byte strings, like in Nix.
fn read_bytes(r: &mut impl Read) -> Result<Vec<u8>> {
    let len = read_len(r)?;
    if len > 4096 {
        bail!("NAR token too long: {len}");
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    read_padding(r, len)?;
    Ok(buf)
}

/// Read a length-prefixed token that must be a UTF-8 keyword.
fn read_str(r: &mut impl Read) -> Result<String> {
    String::from_utf8(read_bytes(r)?).context("NAR token not UTF-8")
}

fn expect(r: &mut impl Read, tok: &str) -> Result<()> {
    let got = read_str(r)?;
    if got != tok {
        bail!("expected NAR token {tok:?}, got {got:?}");
    }
    Ok(())
}

/// Serialize the filesystem object at `path` as a NAR into `w`.
pub fn pack(path: &Path, w: &mut impl Write) -> Result<()> {
    write_str(w, MAGIC.as_bytes())?;
    pack_node(path, w, 0)
}

fn pack_node(path: &Path, w: &mut impl Write, depth: u32) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("NAR nesting deeper than {MAX_DEPTH} levels");
    }
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    write_str(w, b"(")?;
    write_str(w, b"type")?;
    if meta.file_type().is_symlink() {
        write_str(w, b"symlink")?;
        write_str(w, b"target")?;
        let target = fs::read_link(path)?;
        write_str(w, target.as_os_str().as_encoded_bytes())?;
    } else if meta.is_file() {
        write_str(w, b"regular")?;
        if meta.permissions().mode() & 0o100 != 0 {
            write_str(w, b"executable")?;
            write_str(w, b"")?;
        }
        write_str(w, b"contents")?;
        w.write_all(&meta.len().to_le_bytes())?;
        let mut f = fs::File::open(path)?;
        // Bound the copy: a file growing mid-pack must not push extra
        // bytes into the stream (framing corruption on the wire).
        let copied = io::copy(&mut (&mut f).take(meta.len()), w)?;
        if copied != meta.len() {
            bail!("file {} changed size during pack", path.display());
        }
        let pad = (8 - meta.len() % 8) % 8;
        w.write_all(&[0u8; 8][..pad as usize])?;
    } else if meta.is_dir() {
        write_str(w, b"directory")?;
        let mut entries: Vec<_> = fs::read_dir(path)?.collect::<io::Result<_>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            write_str(w, b"entry")?;
            write_str(w, b"(")?;
            write_str(w, b"name")?;
            write_str(w, entry.file_name().as_encoded_bytes())?;
            write_str(w, b"node")?;
            pack_node(&entry.path(), w, depth + 1)?;
            write_str(w, b")")?;
        }
    } else {
        bail!("unsupported file type: {}", path.display());
    }
    write_str(w, b")")?;
    Ok(())
}

/// Deserialize a NAR from `r`, creating the filesystem object at `dest`.
/// `dest` must not exist yet.
pub fn unpack(r: &mut impl Read, dest: &Path) -> Result<()> {
    expect(r, MAGIC)?;
    unpack_node(r, dest, 0)?;
    // The verified hash covers the whole stream; refuse trailing bytes
    // it would otherwise silently attest to.
    let mut buf = [0u8; 1];
    if r.read(&mut buf)? != 0 {
        bail!("trailing data after NAR");
    }
    Ok(())
}

fn unpack_node(r: &mut impl Read, dest: &Path, depth: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if depth > MAX_DEPTH {
        bail!("NAR nesting deeper than {MAX_DEPTH} levels");
    }
    expect(r, "(")?;
    expect(r, "type")?;
    match read_str(r)?.as_str() {
        "regular" => {
            let mut executable = false;
            let mut tok = read_str(r)?;
            if tok == "executable" {
                expect(r, "")?;
                executable = true;
                tok = read_str(r)?;
            }
            if tok != "contents" {
                bail!("expected NAR token \"contents\", got {tok:?}");
            }
            let len = read_len(r)?;
            // create_new: never truncate an existing file or follow a
            // pre-planted symlink at dest.
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dest)?;
            let copied = io::copy(&mut r.take(len), &mut f)?;
            if copied != len {
                bail!("truncated NAR file contents");
            }
            read_padding(r, len)?;
            f.set_permissions(fs::Permissions::from_mode(if executable {
                0o755
            } else {
                0o644
            }))?;
            expect(r, ")")?;
        }
        "symlink" => {
            expect(r, "target")?;
            let target = read_bytes(r)?;
            let target = std::os::unix::ffi::OsStrExt::from_bytes(target.as_slice());
            std::os::unix::fs::symlink::<&std::ffi::OsStr, _>(target, dest)?;
            expect(r, ")")?;
        }
        "directory" => {
            fs::create_dir(dest)?;
            // Strictly increasing names (as the NAR spec requires) rule
            // out duplicate entries; a duplicate name could otherwise
            // first create a symlink and then write through it, escaping
            // the unpack root.
            let mut last_name: Vec<u8> = Vec::new();
            let mut seen_folded = std::collections::HashSet::new();
            loop {
                match read_str(r)?.as_str() {
                    ")" => break,
                    "entry" => {
                        expect(r, "(")?;
                        expect(r, "name")?;
                        let name = read_bytes(r)?;
                        if name.is_empty()
                            || name == b"."
                            || name == b".."
                            || name.contains(&b'/')
                            || name.contains(&0)
                        {
                            bail!("invalid NAR entry name {name:?}");
                        }
                        if name <= last_name {
                            bail!("NAR entry {name:?} not in strictly increasing order");
                        }
                        last_name = name.clone();
                        // On the case-insensitive default filesystem a
                        // case-colliding entry would overwrite its sibling
                        // (Nix uses a case hack here; we reject).
                        if cfg!(target_os = "macos")
                            && !seen_folded.insert(String::from_utf8_lossy(&name).to_lowercase())
                        {
                            bail!("case-colliding NAR entry {name:?}");
                        }
                        expect(r, "node")?;
                        let name: &std::ffi::OsStr =
                            std::os::unix::ffi::OsStrExt::from_bytes(name.as_slice());
                        unpack_node(r, &dest.join(name), depth + 1)?;
                        expect(r, ")")?;
                    }
                    other => bail!("unexpected NAR token {other:?} in directory"),
                }
            }
        }
        other => bail!("unknown NAR node type {other:?}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn roundtrip() -> Result<()> {
        let src = tempfile::tempdir()?;
        fs::create_dir(src.path().join("sub"))?;
        fs::write(
            src.path().join("sub/file"),
            b"hello world, more than 8 bytes",
        )?;
        fs::write(src.path().join("script"), b"#!/bin/sh\n")?;
        fs::set_permissions(src.path().join("script"), fs::Permissions::from_mode(0o755))?;
        std::os::unix::fs::symlink("sub/file", src.path().join("link"))?;

        let mut nar = Vec::new();
        pack(src.path(), &mut nar)?;

        let dst = tempfile::tempdir()?;
        let out = dst.path().join("out");
        unpack(&mut nar.as_slice(), &out)?;

        assert_eq!(
            fs::read(out.join("sub/file"))?,
            b"hello world, more than 8 bytes"
        );
        assert!(fs::metadata(out.join("script"))?.permissions().mode() & 0o100 != 0);
        assert_eq!(fs::read_link(out.join("link"))?.to_str(), Some("sub/file"));

        // Determinism: repack must produce identical bytes.
        let mut nar2 = Vec::new();
        pack(&out, &mut nar2)?;
        assert_eq!(nar, nar2);
        Ok(())
    }

    /// Names and symlink targets are byte strings on Unix; the decoder
    /// must accept what the encoder produces.
    #[test]
    fn roundtrip_non_utf8_names() -> Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let src = tempfile::tempdir()?;
        let name = std::ffi::OsStr::from_bytes(b"f\xff\xfe");
        fs::write(src.path().join(name), b"x")?;
        std::os::unix::fs::symlink(
            std::ffi::OsStr::from_bytes(b"t\xffarget"),
            src.path().join("link"),
        )?;

        let mut nar = Vec::new();
        pack(src.path(), &mut nar)?;
        let dst = tempfile::tempdir()?;
        let out = dst.path().join("out");
        unpack(&mut nar.as_slice(), &out)?;
        assert_eq!(fs::read(out.join(name))?, b"x");
        assert_eq!(
            fs::read_link(out.join("link"))?.as_os_str().as_bytes(),
            b"t\xffarget"
        );
        Ok(())
    }

    /// The verified stream hash must cover exactly what is materialized.
    #[test]
    fn rejects_trailing_data() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("f"), b"x").unwrap();
        let mut nar = Vec::new();
        pack(src.path(), &mut nar).unwrap();
        nar.extend_from_slice(b"garbage");
        let dst = tempfile::tempdir().unwrap();
        let err = unpack(&mut nar.as_slice(), &dst.path().join("out")).unwrap_err();
        assert!(err.to_string().contains("trailing data"), "{err}");
    }

    /// A pre-existing file (or pre-planted symlink) at dest must not be
    /// truncated or written through.
    #[test]
    fn refuses_existing_dest() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("f"), b"x").unwrap();
        let mut nar = Vec::new();
        pack(&src.path().join("f"), &mut nar).unwrap();
        let dst = tempfile::tempdir().unwrap();
        let out = dst.path().join("out");
        fs::write(&out, b"old").unwrap();
        assert!(unpack(&mut nar.as_slice(), &out).is_err());
        assert_eq!(fs::read(&out).unwrap(), b"old");
    }

    fn tok(buf: &mut Vec<u8>, s: &[u8]) {
        write_str(buf, s).unwrap();
    }

    /// A NAR with a duplicate entry name (symlink, then regular file)
    /// would write through the symlink and escape the unpack root.
    #[test]
    fn rejects_duplicate_entries() {
        let escape = tempfile::tempdir().unwrap();
        let mut nar = Vec::new();
        tok(&mut nar, b"nix-archive-1");
        tok(&mut nar, b"(");
        tok(&mut nar, b"type");
        tok(&mut nar, b"directory");
        for _ in 0..2 {
            tok(&mut nar, b"entry");
            tok(&mut nar, b"(");
            tok(&mut nar, b"name");
            tok(&mut nar, b"x");
            tok(&mut nar, b"node");
            tok(&mut nar, b"(");
            tok(&mut nar, b"type");
            tok(&mut nar, b"symlink");
            tok(&mut nar, b"target");
            tok(&mut nar, escape.path().as_os_str().as_encoded_bytes());
            tok(&mut nar, b")");
            tok(&mut nar, b")");
        }
        tok(&mut nar, b")");

        let dst = tempfile::tempdir().unwrap();
        let err = unpack(&mut nar.as_slice(), &dst.path().join("out")).unwrap_err();
        assert!(err.to_string().contains("strictly increasing"), "{err}");
    }
}
