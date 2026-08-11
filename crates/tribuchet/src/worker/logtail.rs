//! Build-log tailing with a persisted offset, for resumed sessions.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic;

use tokio::sync::mpsc;

use super::{WorkerCtx, msg};
use crate::proto::{LogChunk, WorkerMessage, worker_message};

/// A log-replay thread; `stop()` makes it drain to EOF, then waits
/// for it.
pub(super) struct LogTail {
    pub(super) done: Arc<atomic::AtomicBool>,
    handle: std::thread::JoinHandle<()>,
}

impl LogTail {
    pub(super) fn stop(self) {
        self.done.store(true, atomic::Ordering::Relaxed);
        let _ = self.handle.join();
    }
}

/// Read position in a build dir's build.log. It is persisted as
/// log.offset so resumed sessions and later worker generations
/// continue where the previous tailer stopped.
struct LogCursor {
    file: std::fs::File,
    dir: PathBuf,
    sent: u64,
}

impl LogCursor {
    /// Open build.log at the persisted offset. A missing file means
    /// the build never started a builder, so there is no cursor.
    fn open(dir: &Path) -> Option<Self> {
        use std::io::Seek;
        let mut file = std::fs::File::open(dir.join("build.log")).ok()?;
        let sent = std::fs::read_to_string(dir.join("log.offset"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        file.seek(std::io::SeekFrom::Start(sent)).ok()?;
        Some(Self {
            file,
            dir: dir.to_path_buf(),
            sent,
        })
    }

    /// Read to EOF and persist the offset after every accepted
    /// chunk. Returns false when `emit` rejects a chunk or the file
    /// breaks.
    fn drain(&mut self, mut emit: impl FnMut(Vec<u8>) -> bool) -> bool {
        let mut buf = [0u8; 8192];
        loop {
            match self.file.read(&mut buf) {
                Ok(0) => return true,
                Err(_) => return false,
                Ok(n) => {
                    if !emit(buf[..n].to_vec()) {
                        return false;
                    }
                    self.sent += n as u64;
                    let _ = std::fs::write(self.dir.join("log.offset"), self.sent.to_string());
                }
            }
        }
    }
}

/// Stream `dir`'s build.log to `out_tx` as LogChunks for `build_id`.
/// Keeps polling past EOF until `done()` reports that nothing more
/// can arrive.
pub(super) fn tail_log(
    dir: &Path,
    build_id: &str,
    out_tx: &mpsc::Sender<WorkerMessage>,
    done: impl Fn() -> bool,
) {
    let Some(mut cursor) = LogCursor::open(dir) else {
        return;
    };
    let mut emit = |data| {
        out_tx
            .blocking_send(msg(worker_message::Msg::Log(LogChunk {
                build_id: build_id.into(),
                data,
            })))
            .is_ok()
    };
    while cursor.drain(&mut emit) && !done() {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Tail a resumed build's log on a thread until the registry entry
/// has finished (or vanished) or `stop()` is called.
pub(super) fn spawn_log_tail(
    ctx: Arc<WorkerCtx>,
    key: String,
    build_id: String,
    dir: PathBuf,
    out_tx: mpsc::Sender<WorkerMessage>,
) -> LogTail {
    let done = Arc::new(atomic::AtomicBool::new(false));
    let thread_done = done.clone();
    let handle = std::thread::spawn(move || {
        use atomic::Ordering;
        let done = || {
            thread_done.load(Ordering::Relaxed) || {
                let map = ctx.resumable.lock().unwrap();
                map.get(&key).is_none_or(|e| e.finished.is_some())
            }
        };
        tail_log(&dir, &build_id, &out_tx, done);
    });
    LogTail { done, handle }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offset(dir: &Path) -> u64 {
        std::fs::read_to_string(dir.join("log.offset"))
            .unwrap()
            .parse()
            .unwrap()
    }

    #[test]
    fn cursor_resumes_at_persisted_offset() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("build.log"), b"old-new").unwrap();
        std::fs::write(dir.path().join("log.offset"), "4").unwrap();
        let mut cursor = LogCursor::open(dir.path()).unwrap();
        let mut got = Vec::new();
        assert!(cursor.drain(|d| {
            got.extend(d);
            true
        }));
        assert_eq!(got, b"new");
        assert_eq!(offset(dir.path()), 7);
    }

    #[test]
    fn rejected_chunk_keeps_offset_for_retry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("build.log"), b"hello").unwrap();
        std::fs::write(dir.path().join("log.offset"), "0").unwrap();
        let mut cursor = LogCursor::open(dir.path()).unwrap();
        assert!(!cursor.drain(|_| false));
        assert_eq!(offset(dir.path()), 0);
    }

    #[test]
    fn missing_log_means_no_cursor() {
        let dir = tempfile::tempdir().unwrap();
        assert!(LogCursor::open(dir.path()).is_none());
    }
}
