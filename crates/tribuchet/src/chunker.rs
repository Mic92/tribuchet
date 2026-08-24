//! Chunk a store path so identical files dedup regardless of path:
//! FastCDC over each file body, NAR framing and small files
//! coalesced into literal chunks in between. The chunk list is flat:
//! concatenation yields the NAR, no parsing on reassembly.

use std::mem;
use std::path::Path;

use fastcdc::v2020::FastCDC;
use tokio::runtime;

use crate::chunkstore::Hash;
use crate::errors::{Result, err_ctx};
use crate::nar::pack::{BODY_MIN, Piece, pack};
use crate::rt;

const CDC_MIN: u32 = BODY_MIN;
const CDC_AVG: u32 = 64 * 1024;
const CDC_MAX: u32 = 256 * 1024;
const MAX_SIZE: usize = CDC_MAX as usize;

pub struct Chunk {
    pub hash: Hash,
    pub data: Vec<u8>,
}

fn emit(data: Vec<u8>, out: &mut Vec<Chunk>) {
    let hash = *blake3::hash(&data).as_bytes();
    out.push(Chunk { hash, data });
}

#[derive(Default)]
struct Chunker {
    /// Framing and small files awaiting coalesced emission.
    lit: Vec<u8>,
    /// Carry-over of a file body streamed in parts.
    body: Vec<u8>,
}

impl Chunker {
    fn push(&mut self, piece: Piece, out: &mut Vec<Chunk>) {
        match piece {
            Piece::Framing(b) => {
                self.lit.extend_from_slice(b);
                if self.lit.len() >= MAX_SIZE {
                    emit(mem::take(&mut self.lit), out);
                }
            }
            Piece::Body { data, last } => {
                // A body starts a chunk of its own, so the framing
                // before it ends one.
                if !self.lit.is_empty() {
                    emit(mem::take(&mut self.lit), out);
                }
                if self.body.is_empty() && last {
                    for piece in cdc_split(data) {
                        emit(piece.to_vec(), out);
                    }
                    return;
                }
                self.body.extend_from_slice(data);
                // The first cut of a window at least MAX_SIZE long
                // is final. One drain at the end: draining per cut
                // would memmove the tail quadratically.
                let mut start = 0;
                while self.body.len() - start >= MAX_SIZE {
                    let cut = start + first_cut(&self.body[start..]);
                    emit(self.body[start..cut].to_vec(), out);
                    start = cut;
                }
                if last {
                    for piece in cdc_split(&self.body[start..]) {
                        emit(piece.to_vec(), out);
                    }
                    self.body.clear();
                } else {
                    self.body.drain(..start);
                }
            }
        }
    }

    fn finish(&mut self, out: &mut Vec<Chunk>) {
        if !self.lit.is_empty() {
            emit(mem::take(&mut self.lit), out);
        }
    }
}

/// Serialize a store path to NAR, chunk it, and feed each chunk to
/// `f`, which may
/// await channel sends. Stops early when `f` returns false. Runs its
/// own current-thread runtime, so call from spawn_blocking.
pub fn chunk_store_path(
    store_path: &str,
    mut f: impl AsyncFnMut(Chunk) -> Result<bool>,
) -> Result<()> {
    rt::name_current_thread("trib-pack");
    let rt = runtime::Builder::new_current_thread()
        .build()
        .map_err(err_ctx("building NAR pack runtime"))?;
    let mut chunker = Chunker::default();
    let mut chunks = Vec::new();
    let mut feed = |chunks: &mut Vec<Chunk>| -> Result<bool> {
        for c in chunks.drain(..) {
            if !rt.block_on(f(c))? {
                return Ok(false);
            }
        }
        Ok(true)
    };
    let mut more = Ok(true);
    pack(Path::new(store_path), |p| {
        chunker.push(p, &mut chunks);
        more = feed(&mut chunks);
        Ok(matches!(more, Ok(true)))
    })
    .map_err(err_ctx(format!("serializing {store_path} to NAR")))?;
    if more? {
        chunker.finish(&mut chunks);
        feed(&mut chunks)?;
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
        chunk_store_path(dir.path().to_str().unwrap(), async |c| {
            assert_eq!(c.hash, *blake3::hash(&c.data).as_bytes());
            assert!(c.data.len() <= MAX_SIZE);
            cat.extend_from_slice(&c.data);
            n += 1;
            Ok(true)
        })
        .unwrap();
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        let mut want = Vec::new();
        rt.block_on(nar::pack(dir.path(), &mut want)).unwrap();
        assert_eq!(cat, want);
        // Small files coalesced rather than one chunk each.
        assert!(n < 60, "{n} chunks");
    }
}
