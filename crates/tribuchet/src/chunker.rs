//! Chunk a store path so identical files dedup regardless of path:
//! FastCDC over each file body, NAR framing and small files
//! coalesced into literal chunks in between. The chunk list is flat:
//! concatenation yields the NAR, no parsing on reassembly.

use std::mem;
use std::path::Path;

use fastcdc::v2020::FastCDC;
use zstd::bulk::decompress;

use crate::chunkstore::Hash;
use crate::errors::{Result, err_ctx, err_msg};
use crate::nar::pack::{BODY_MIN, Piece, pack};
use crate::proto::MAX_NAR_BYTES;
use crate::rt;

const CDC_MIN: usize = BODY_MIN;
const CDC_AVG: usize = 64 * 1024;
const CDC_MAX: usize = 256 * 1024;

/// Upper bound of one chunk's plaintext on the wire. `Chunker::emit`
/// enforces it for everything produced, `Recipe::parse` for everything
/// accepted, so receivers can size buffers from the announced length.
pub const MAX_CHUNK_BYTES: usize = 1024 * 1024;
const _: () = assert!(CDC_MAX <= MAX_CHUNK_BYTES);

pub struct Chunk {
    pub hash: Hash,
    pub data: Vec<u8>,
}

/// Ordered (hash, plaintext size) list that concatenates to a NAR.
pub type Recipe = Vec<(Hash, usize)>;

/// Validate a peer-announced recipe.
pub fn parse_recipe(path: &str, hashes: &[u8], sizes: &[u64]) -> Result<Recipe> {
    if !hashes.len().is_multiple_of(32) || hashes.len() / 32 != sizes.len() {
        return Err(err_msg(format!("malformed recipe for {path}")));
    }
    let mut total = 0u64;
    hashes
        .chunks_exact(32)
        .zip(sizes)
        .map(|(h, s)| {
            total += s;
            if *s > MAX_CHUNK_BYTES as u64 || total > MAX_NAR_BYTES {
                return Err(err_msg(format!("oversized recipe for {path}")));
            }
            Ok((h.try_into().unwrap(), usize::try_from(*s).unwrap()))
        })
        .collect()
}

pub fn parse_hashes(hashes: &[u8]) -> Result<Vec<Hash>> {
    if !hashes.len().is_multiple_of(32) {
        return Err(err_msg("misaligned chunk hashes"));
    }
    Ok(hashes
        .chunks_exact(32)
        .map(|h| h.try_into().unwrap())
        .collect())
}

/// Decompress a chunk's zstd frame and check it against its recipe entry.
pub fn decode_chunk(frame: &[u8], hash: &Hash, size: usize) -> Result<Vec<u8>> {
    let raw = decompress(frame, size).map_err(err_ctx("decompressing chunk"))?;
    if raw.len() != size || blake3::hash(&raw).as_bytes() != hash {
        return Err(err_msg("chunk does not match its recipe"));
    }
    Ok(raw)
}

struct Chunker<F> {
    /// Framing and small files awaiting coalesced emission.
    lit: Vec<u8>,
    /// Carry-over of a file body streamed in parts.
    body: Vec<u8>,
    sink: F,
}

impl<F: FnMut(Chunk) -> Result<bool>> Chunker<F> {
    /// The only constructor of `Chunk`, so the bound holds for all.
    fn emit(&mut self, data: Vec<u8>) -> Result<bool> {
        if data.len() > MAX_CHUNK_BYTES {
            for part in data.chunks(MAX_CHUNK_BYTES) {
                if !self.emit(part.to_vec())? {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        let hash = *blake3::hash(&data).as_bytes();
        (self.sink)(Chunk { hash, data })
    }

    fn flush_lit(&mut self) -> Result<bool> {
        if self.lit.is_empty() {
            return Ok(true);
        }
        let lit = mem::take(&mut self.lit);
        self.emit(lit)
    }

    fn push(&mut self, piece: Piece) -> Result<bool> {
        match piece {
            Piece::Framing(b) => {
                self.lit.extend_from_slice(b);
                if self.lit.len() >= CDC_MAX {
                    return self.flush_lit();
                }
                Ok(true)
            }
            Piece::Body { data, last } => {
                // A body starts a chunk of its own, so the framing
                // before it ends one.
                if !self.flush_lit()? {
                    return Ok(false);
                }
                if self.body.is_empty() && last {
                    return self.split(data);
                }
                self.body.extend_from_slice(data);
                // The first cut of a window at least CDC_MAX long
                // is final. One drain at the end: draining per cut
                // would memmove the tail quadratically.
                let mut start = 0;
                while self.body.len() - start >= CDC_MAX {
                    let cut = start + first_cut(&self.body[start..]);
                    if !self.emit(self.body[start..cut].to_vec())? {
                        return Ok(false);
                    }
                    start = cut;
                }
                if last {
                    let body = mem::take(&mut self.body);
                    self.split(&body[start..])
                } else {
                    self.body.drain(..start);
                    Ok(true)
                }
            }
        }
    }

    fn split(&mut self, data: &[u8]) -> Result<bool> {
        for piece in cdc_split(data) {
            if !self.emit(piece.to_vec())? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Serialize a store path to NAR, chunk it, and feed each chunk to
/// `sink`. Stops early when `sink` returns false. Blocking.
pub fn chunk_store_path(store_path: &Path, sink: impl FnMut(Chunk) -> Result<bool>) -> Result<()> {
    rt::name_current_thread("trib-pack");
    let mut chunker = Chunker {
        lit: Vec::new(),
        body: Vec::new(),
        sink,
    };
    let mut more = Ok(true);
    pack(store_path, |p| {
        more = chunker.push(p);
        Ok(matches!(more, Ok(true)))
    })
    .map_err(err_ctx(format!(
        "serializing {} to NAR",
        store_path.display()
    )))?;
    if more? {
        chunker.flush_lit()?;
    }
    Ok(())
}

fn first_cut(data: &[u8]) -> usize {
    FastCDC::new(data, CDC_MIN, CDC_AVG, CDC_MAX)
        .next()
        .map_or(data.len(), |c| c.length)
}

fn cdc_split(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    FastCDC::new(data, CDC_MIN, CDC_AVG, CDC_MAX).map(|c| &data[c.offset..c.offset + c.length])
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::nar;

    #[test]
    fn concatenation_is_the_nar() {
        let dir = tempfile::tempdir().unwrap();
        // > INLINE_LIMIT streams in parts, the middle one is inline.
        fs::write(dir.path().join("huge"), vec![7u8; 9 << 20]).unwrap();
        fs::write(dir.path().join("mid"), vec![3u8; 300 << 10]).unwrap();
        // ~1.7 MiB of framing: coalesced, still bounded per chunk
        for i in 0..140 {
            fs::write(dir.path().join(format!("small{i}")), vec![1u8; 12 << 10]).unwrap();
        }
        let mut cat = Vec::new();
        let mut n = 0;
        chunk_store_path(dir.path(), |c| {
            assert_eq!(c.hash, *blake3::hash(&c.data).as_bytes());
            assert!(c.data.len() <= MAX_CHUNK_BYTES);
            cat.extend_from_slice(&c.data);
            n += 1;
            Ok(true)
        })
        .unwrap();
        assert_eq!(cat, nar::pack::to_vec(dir.path()).unwrap());
        // Small files coalesced rather than one chunk each.
        assert!(n < 100, "{n} chunks");
    }
}
