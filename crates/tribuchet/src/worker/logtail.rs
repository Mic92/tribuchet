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

/// How far of `dir`'s build.log has already been streamed to a hub.
/// Persisted next to the log so resumed sessions and later worker
/// generations continue where the previous tailer stopped instead of
/// repeating the log from the start.
fn read_log_offset(dir: &Path) -> u64 {
    std::fs::read_to_string(dir.join("log.offset"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn write_log_offset(dir: &Path, offset: u64) {
    let _ = std::fs::write(dir.join("log.offset"), offset.to_string());
}

/// Stream `dir`'s build.log to `out_tx` as LogChunks for `build_id`,
/// starting at the persisted offset and advancing it after every
/// chunk handed to the session. Polls past EOF until `done()` says
/// nothing more can arrive (one final read has then already drained
/// what was flushed); a failed send ends it, the offset stays put.
pub(super) fn tail_log(
    dir: &Path,
    build_id: &str,
    out_tx: &mpsc::Sender<WorkerMessage>,
    done: impl Fn() -> bool,
) {
    use std::io::Seek;
    let Ok(mut file) = std::fs::File::open(dir.join("build.log")) else {
        return;
    };
    let mut sent = read_log_offset(dir);
    if file.seek(std::io::SeekFrom::Start(sent)).is_err() {
        return;
    }
    let mut buf = [0u8; 8192];
    loop {
        match file.read(&mut buf) {
            Ok(0) => {
                if done() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(_) => break,
            Ok(n) => {
                if out_tx
                    .blocking_send(msg(worker_message::Msg::Log(LogChunk {
                        build_id: build_id.into(),
                        data: buf[..n].to_vec(),
                    })))
                    .is_err()
                {
                    break;
                }
                sent += n as u64;
                write_log_offset(dir, sent);
            }
        }
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
