//! Byte-budget and deadline enforcement for NAR write chains, shared
//! by hub verification and worker packing so both ends enforce the
//! same MAX_NAR_BYTES cap: zstd RLE amplifies ~30,000:1, so a
//! sub-4MiB message could otherwise expand without bound and fill the
//! receiver's disk.

use std::io::{self, Write};
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::proto::MAX_NAR_BYTES;

/// Write adapter feeding a Sha256, for hashing decompressed streams.
#[derive(Default)]
pub struct HashSink(pub Sha256);

impl Write for HashSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct CappedWriter<W> {
    inner: W,
    remaining: u64,
    deadline: Option<Instant>,
}

impl<W: Write> CappedWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            remaining: MAX_NAR_BYTES,
            deadline: None,
        }
    }

    pub fn with_deadline(inner: W, deadline: Instant) -> Self {
        Self {
            deadline: Some(deadline),
            ..Self::new(inner)
        }
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for CappedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(io::Error::other("build timed out"));
        }
        if buf.len() as u64 > self.remaining {
            return Err(io::Error::other(format!(
                "NAR exceeds the {MAX_NAR_BYTES} byte limit"
            )));
        }
        let n = self.inner.write(buf)?;
        self.remaining -= n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_writes_beyond_the_cap() {
        let mut w = CappedWriter::new(Vec::new());
        w.remaining = 4;
        assert_eq!(w.write(b"abcd").unwrap(), 4);
        assert!(w.write(b"e").is_err());
        assert_eq!(w.into_inner(), b"abcd");
    }

    #[test]
    fn rejects_writes_past_the_deadline() {
        let mut w = CappedWriter::with_deadline(Vec::new(), Instant::now());
        assert!(w.write(b"x").is_err());
    }
}
