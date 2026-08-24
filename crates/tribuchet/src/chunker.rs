//! Chunk a store path so identical files dedup regardless of path:
//! FastCDC over each file body, NAR framing and small files
//! coalesced into literal chunks in between. The chunk list is flat:
//! concatenation yields the NAR, no parsing on reassembly.

use std::mem;
use std::path::Path;

use fastcdc::v2020::FastCDC;

use crate::chunkstore::Hash;
use crate::errors::{Result, err_ctx};
use crate::nar::pack::{BODY_MIN, Piece, pack};
use crate::rt;

const CDC_MIN: u32 = BODY_MIN;
const CDC_AVG: u32 = 64 * 1024;
const CDC_MAX: u32 = 256 * 1024;
pub const MAX_SIZE: usize = CDC_MAX as usize;

pub struct Chunk {
    pub hash: Hash,
    pub data: Vec<u8>,
}

struct Chunker<F> {
    /// Framing and small files awaiting coalesced emission.
    lit: Vec<u8>,
    /// Carry-over of a file body streamed in parts.
    body: Vec<u8>,
    sink: F,
}

impl<F: FnMut(Chunk) -> Result<bool>> Chunker<F> {
    fn emit(&mut self, data: Vec<u8>) -> Result<bool> {
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
                if self.lit.len() >= MAX_SIZE {
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
                // The first cut of a window at least MAX_SIZE long
                // is final. One drain at the end: draining per cut
                // would memmove the tail quadratically.
                let mut start = 0;
                while self.body.len() - start >= MAX_SIZE {
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
        for i in 0..50 {
            fs::write(dir.path().join(format!("small{i}")), format!("s{i}")).unwrap();
        }
        let mut cat = Vec::new();
        let mut n = 0;
        chunk_store_path(dir.path(), |c| {
            assert_eq!(c.hash, *blake3::hash(&c.data).as_bytes());
            assert!(c.data.len() <= MAX_SIZE);
            cat.extend_from_slice(&c.data);
            n += 1;
            Ok(true)
        })
        .unwrap();
        assert_eq!(cat, nar::pack::to_vec(dir.path()).unwrap());
        // Small files coalesced rather than one chunk each.
        assert!(n < 60, "{n} chunks");
    }
}
