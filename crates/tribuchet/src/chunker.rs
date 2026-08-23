//! FastCDC over a NAR stream with boundaries forced on file
//! contents, so identical files dedup regardless of path. Framing
//! and small files coalesce into literal chunks. The chunk list is
//! flat: concatenation yields the NAR, no parsing on reassembly.
//!
//! A NAR is a flat sequence of length-prefixed padded strings. File
//! contents are the single string after a "contents" token, which is
//! all the structure the alignment needs.

use std::mem;
use std::path::PathBuf;

use fastcdc::v2020::FastCDC;
use futures_util::StreamExt as _;
use harmonia_file_nar::archive::NarByteStream;
use tokio::runtime;

use crate::chunkstore::Hash;
use crate::errors::{Result, err_ctx};
use crate::rt;

const CDC_MIN: u32 = 16 * 1024;
const CDC_AVG: u32 = 64 * 1024;
const CDC_MAX: u32 = 256 * 1024;
pub const MIN_SIZE: usize = CDC_MIN as usize;
pub const MAX_SIZE: usize = CDC_MAX as usize;

pub struct Chunk {
    pub hash: Hash,
    pub data: Vec<u8>,
}

fn emit(data: Vec<u8>, out: &mut Vec<Chunk>) {
    let hash = *blake3::hash(&data).as_bytes();
    out.push(Chunk { hash, data });
}

enum State {
    /// Collecting the 8-byte length prefix.
    Len { got: usize, buf: [u8; 8] },
    /// Inside a string's payload plus its padding to 8.
    Str { remaining: u64, cdc: bool },
}

pub struct NarChunker {
    state: State,
    /// Framing, small strings and padding awaiting coalesced emission.
    lit: Vec<u8>,
    /// Contents of the file currently being CDC-chunked.
    content: Vec<u8>,
    /// The previous string was the "contents" token.
    contents_token: bool,
    /// Payload capture of an 8-byte string, the "contents" length.
    token_buf: Option<Vec<u8>>,
}

impl Default for NarChunker {
    fn default() -> Self {
        Self {
            state: State::Len {
                got: 0,
                buf: [0; 8],
            },
            lit: Vec::new(),
            content: Vec::new(),
            contents_token: false,
            token_buf: None,
        }
    }
}

impl NarChunker {
    pub fn push(&mut self, mut bytes: &[u8], out: &mut Vec<Chunk>) {
        while !bytes.is_empty() {
            match &mut self.state {
                State::Len { got, buf } => {
                    let take = bytes.len().min(8 - *got);
                    buf[*got..*got + take].copy_from_slice(&bytes[..take]);
                    *got += take;
                    let lit_bytes = &bytes[..take];
                    self.lit.extend_from_slice(lit_bytes);
                    bytes = &bytes[take..];
                    if *got == 8 {
                        let len = u64::from_le_bytes(*buf);
                        let cdc = self.contents_token && len >= MIN_SIZE as u64;
                        if cdc {
                            // The boundary before the contents: flush
                            // the accumulated framing as a literal.
                            emit(mem::take(&mut self.lit), out);
                        }
                        self.contents_token = false;
                        // "contents" is 8 bytes. A file *named*
                        // contents is harmless: a name value is
                        // always followed by the short "node" token.
                        self.token_buf = (len == 8).then(Vec::new);
                        self.state = State::Str {
                            remaining: len + pad(len),
                            cdc,
                        };
                    }
                }
                State::Str { remaining, cdc } => {
                    let take = usize::try_from(*remaining)
                        .unwrap_or(usize::MAX)
                        .min(bytes.len());
                    let (chunk, rest) = bytes.split_at(take);
                    *remaining -= take as u64;
                    bytes = rest;
                    if *cdc {
                        self.content.extend_from_slice(chunk);
                        // The first cut of a window at least MAX_SIZE
                        // long is final, so drain incrementally.
                        while self.content.len() >= MAX_SIZE {
                            let cut = first_cut(&self.content);
                            let rest = self.content.split_off(cut);
                            emit(mem::replace(&mut self.content, rest), out);
                        }
                        if *remaining == 0 {
                            for piece in cdc_split(&self.content) {
                                emit(piece.to_vec(), out);
                            }
                            self.content.clear();
                            self.state = State::Len {
                                got: 0,
                                buf: [0; 8],
                            };
                        }
                    } else {
                        self.lit.extend_from_slice(chunk);
                        if let Some(tb) = &mut self.token_buf {
                            tb.extend_from_slice(chunk);
                        }
                        if self.lit.len() >= MAX_SIZE {
                            emit(mem::take(&mut self.lit), out);
                        }
                        if *remaining == 0 {
                            self.contents_token =
                                self.token_buf.take().is_some_and(|tb| tb == b"contents");
                            self.state = State::Len {
                                got: 0,
                                buf: [0; 8],
                            };
                        }
                    }
                }
            }
        }
    }

    pub fn finish(&mut self, out: &mut Vec<Chunk>) {
        // Ship partial state from a truncated NAR: the daemon's
        // hash check judges it, not the chunker.
        self.lit.extend_from_slice(&self.content);
        self.content.clear();
        if !self.lit.is_empty() {
            emit(mem::take(&mut self.lit), out);
        }
    }
}

/// Pack a store path as a NAR and feed each chunk to `f`, which may
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
    rt.block_on(async {
        let mut nar = NarByteStream::new(PathBuf::from(store_path));
        let mut chunker = NarChunker::default();
        let mut chunks = Vec::new();
        loop {
            let eof = if let Some(b) = nar.next().await {
                let b = b.map_err(err_ctx(format!("packing {store_path}")))?;
                chunker.push(&b, &mut chunks);
                false
            } else {
                chunker.finish(&mut chunks);
                true
            };
            for c in chunks.drain(..) {
                if !f(c).await? {
                    return Ok(());
                }
            }
            if eof {
                return Ok(());
            }
        }
    })
}

fn pad(len: u64) -> u64 {
    (8 - len % 8) % 8
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
    use std::collections::HashSet;
    use std::fs;
    use std::path::Path;

    use super::*;
    use crate::nar;

    fn nar_bytes(dir: &Path) -> Vec<u8> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut buf = Vec::new();
        rt.block_on(nar::pack(dir, &mut buf)).unwrap();
        buf
    }

    fn chunk_all(nar: &[u8]) -> Vec<Chunk> {
        let mut out = Vec::new();
        let mut c = NarChunker::default();
        // uneven feed sizes to exercise state carry-over
        for piece in nar.chunks(7 * 1024 + 13) {
            c.push(piece, &mut out);
        }
        c.finish(&mut out);
        out
    }

    fn big_file(n: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..n)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                u8::try_from((state >> 33) & 0xff).unwrap()
            })
            .collect()
    }

    #[test]
    fn concatenation_is_the_nar() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("big"), big_file(300 << 10, 1)).unwrap();
        for i in 0..50 {
            fs::write(dir.path().join(format!("small{i}")), format!("s{i}")).unwrap();
        }
        let nar = nar_bytes(dir.path());
        let chunks = chunk_all(&nar);
        let cat: Vec<u8> = chunks.iter().flat_map(|c| c.data.clone()).collect();
        assert_eq!(cat, nar);
        for c in &chunks {
            assert_eq!(c.hash, *blake3::hash(&c.data).as_bytes());
        }
    }

    #[test]
    fn identical_file_dedups_across_paths() {
        let file = big_file(600 << 10, 2);
        let a = tempfile::tempdir().unwrap();
        fs::write(a.path().join("zzz-last"), &file).unwrap();
        let b = tempfile::tempdir().unwrap();
        fs::write(b.path().join("aaa-first"), &file).unwrap();
        fs::write(b.path().join("extra"), big_file(40 << 10, 3)).unwrap();
        let ha: HashSet<Hash> = chunk_all(&nar_bytes(a.path()))
            .iter()
            .map(|c| c.hash)
            .collect();
        let chunks_b = chunk_all(&nar_bytes(b.path()));
        let shared: usize = chunks_b
            .iter()
            .filter(|c| ha.contains(&c.hash))
            .map(|c| c.data.len())
            .sum();
        // all of the repeated file's interior chunks dedup
        assert!(
            shared >= (500 << 10),
            "only {shared} shared bytes across differing NARs"
        );
    }

    #[test]
    fn small_files_coalesce() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..1000 {
            fs::write(dir.path().join(format!("f{i}")), format!("data{i}")).unwrap();
        }
        let nar = nar_bytes(dir.path());
        let chunks = chunk_all(&nar);
        assert!(
            chunks.len() <= nar.len() / MIN_SIZE + 2,
            "{} chunks for a {} byte NAR of tiny files",
            chunks.len(),
            nar.len()
        );
    }
}
