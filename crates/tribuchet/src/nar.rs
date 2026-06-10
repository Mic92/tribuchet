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

/// Read a length-prefixed token (not file contents; bounded).
fn read_str(r: &mut impl Read) -> Result<String> {
    let len = read_len(r)?;
    if len > 4096 {
        bail!("NAR token too long: {len}");
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    read_padding(r, len)?;
    String::from_utf8(buf).context("NAR token not UTF-8")
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
    pack_node(path, w)
}

fn pack_node(path: &Path, w: &mut impl Write) -> Result<()> {
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
        let copied = io::copy(&mut f, w)?;
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
            pack_node(&entry.path(), w)?;
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
    unpack_node(r, dest)
}

fn unpack_node(r: &mut impl Read, dest: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
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
            let mut f = fs::File::create(dest)?;
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
            let target = read_str(r)?;
            std::os::unix::fs::symlink(target, dest)?;
            expect(r, ")")?;
        }
        "directory" => {
            fs::create_dir(dest)?;
            // Strictly increasing names (as the NAR spec requires) rule
            // out duplicate entries; a duplicate name could otherwise
            // first create a symlink and then write through it, escaping
            // the unpack root.
            let mut last_name = String::new();
            let mut seen_folded = std::collections::HashSet::new();
            loop {
                match read_str(r)?.as_str() {
                    ")" => break,
                    "entry" => {
                        expect(r, "(")?;
                        expect(r, "name")?;
                        let name = read_str(r)?;
                        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
                            bail!("invalid NAR entry name {name:?}");
                        }
                        if name <= last_name {
                            bail!("NAR entry {name:?} not in strictly increasing order");
                        }
                        last_name = name.clone();
                        // On the case-insensitive default filesystem a
                        // case-colliding entry would overwrite its sibling
                        // (Nix uses a case hack here; we reject).
                        if cfg!(target_os = "macos") && !seen_folded.insert(name.to_lowercase()) {
                            bail!("case-colliding NAR entry {name:?}");
                        }
                        expect(r, "node")?;
                        unpack_node(r, &dest.join(name))?;
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
