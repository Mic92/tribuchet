//! Bridges between blocking std::io streams (NAR/tar/zstd codecs) and
//! async tokio channels carrying byte chunks.

use std::io::{self, Read, Write};

use tokio::sync::mpsc;

pub const CHUNK_SIZE: usize = 1024 * 1024;

/// HTTP/2 flow-control windows. The 64 KiB h2 default caps a stream at
/// ~window/RTT, throttling NAR transfer (worst on the two-hop output
/// relay). Sized to keep several CHUNK_SIZE messages in flight.
pub const H2_STREAM_WINDOW: u32 = 4 * 1024 * 1024;
pub const H2_CONNECTION_WINDOW: u32 = 8 * 1024 * 1024;

/// `Write` implementation that emits fixed-size chunks into a tokio
/// channel. Used from blocking threads (`blocking_send`).
pub struct ChunkWriter {
    tx: mpsc::Sender<Vec<u8>>,
    buf: Vec<u8>,
}

impl ChunkWriter {
    pub fn new(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            tx,
            buf: Vec::with_capacity(CHUNK_SIZE),
        }
    }
}

impl Write for ChunkWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut rest = data;
        while !rest.is_empty() {
            let take = (CHUNK_SIZE - self.buf.len()).min(rest.len());
            self.buf.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.buf.len() == CHUNK_SIZE {
                self.flush()?;
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let chunk = std::mem::replace(&mut self.buf, Vec::with_capacity(CHUNK_SIZE));
            self.tx
                .blocking_send(chunk)
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "chunk receiver gone"))?;
        }
        Ok(())
    }
}

/// `Read` implementation over a tokio channel of byte chunks. Used from
/// blocking threads (`blocking_recv`); EOF when the sender is dropped.
pub struct ChannelReader {
    rx: mpsc::Receiver<Vec<u8>>,
    current: Vec<u8>,
    pos: usize,
}

impl ChannelReader {
    pub fn new(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            current: Vec::new(),
            pos: 0,
        }
    }
}

impl Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.current.len() {
            match self.rx.blocking_recv() {
                Some(chunk) => {
                    self.current = chunk;
                    self.pos = 0;
                }
                None => return Ok(0),
            }
        }
        let n = (self.current.len() - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.current[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}
