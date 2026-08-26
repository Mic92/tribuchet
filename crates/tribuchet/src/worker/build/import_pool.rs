//! Parallel daemon imports of staged input NARs.

use std::io;
use std::mem;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use futures_util::StreamExt as _;
use harmonia_store_path_info::ValidPathInfo;
use harmonia_store_remote::{DaemonClient, DaemonStore as _};
use tokio::io::{AsyncReadExt as _, BufReader};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::StreamReader;

use super::claims::Wake;
use crate::chunkstore::Hash;
use crate::errors::{Result, chain, err_ctx, err_msg};
use crate::worker::DaemonConn;

/// Error chain of a failed AddToStoreNar.
type ImportResult = StdResult<(), String>;

/// One in-flight daemon import, fed its verified chunks. The pool
/// fills `result` and then wakes the session loop for this path.
pub(super) struct ImportHandle {
    pub(super) result: oneshot::Receiver<ImportResult>,
    /// Yields the chunks that failed verification.
    pub(super) feeder: JoinHandle<Vec<Hash>>,
}

impl ImportHandle {
    /// `None` while the import still runs.
    pub(super) async fn finish(mut self) -> Result<Option<(ImportResult, Vec<Hash>)>> {
        let Ok(res) = self.result.try_recv() else {
            return Ok(None);
        };
        let bad = self
            .feeder
            .await
            .map_err(err_ctx("import feeder panicked"))?;
        Ok(Some((res, bad)))
    }
}

pub(super) struct ImportJob {
    pub(super) info: ValidPathInfo,
    pub(super) rx: mpsc::Receiver<Bytes>,
    pub(super) result: oneshot::Sender<ImportResult>,
    pub(super) wake: (mpsc::UnboundedSender<Wake>, Wake),
}

/// N tasks with one daemon connection each, so imports overlap the
/// download and each other instead of serializing behind one
/// AddToStoreNar. A path is dispatched only once every reference is
/// valid, so a job never waits.
pub(super) struct ImportPool {
    pub(super) job_tx: mpsc::Sender<ImportJob>,
    workers: Vec<tokio::task::JoinHandle<()>>,
}

impl ImportPool {
    pub(super) fn spawn(jobs: usize) -> Self {
        let (job_tx, job_rx) = mpsc::channel::<ImportJob>(1);
        let job_rx = Arc::new(tokio::sync::Mutex::new(job_rx));
        let workers = (0..jobs)
            .map(|_| tokio::spawn(import_worker(job_rx.clone())))
            .collect();
        Self { job_tx, workers }
    }

    pub(super) async fn shutdown(self) {
        drop(self.job_tx);
        for w in self.workers {
            w.abort();
            let _ = w.await;
        }
    }
}

async fn import_worker(job_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<ImportJob>>>) {
    let mut conn: Option<DaemonConn> = None;
    loop {
        let job = job_rx.lock().await.recv().await;
        let Some(mut job) = job else { break };
        let res = run_import(&mut conn, &mut job).await;
        let _ = job.result.send(res.map_err(|e| chain(&e)));
        let (tx, w) = job.wake;
        let _ = tx.send(w);
    }
}

async fn run_import(conn: &mut Option<DaemonConn>, job: &mut ImportJob) -> Result<()> {
    let t0 = Instant::now();
    if conn.is_none() {
        *conn = Some(
            DaemonClient::builder()
                .connect_daemon()
                .await
                .map_err(err_ctx("connecting an import daemon connection"))?,
        );
    }
    let rx = mem::replace(&mut job.rx, mpsc::channel(1).1);
    let res = import_nar(conn.as_mut().unwrap(), &job.info, rx).await;
    tracing::debug!(
        path = %job.info.path,
        import_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        "daemon import done"
    );
    if res.is_err() {
        // A failed AddToStoreNar leaves the protocol state unknown.
        *conn = None;
    }
    res
}

/// Drive one AddToStoreNar from the feeder's verified NAR bytes. The
/// daemon checks info.nar_hash on top.
async fn import_nar(
    conn: &mut DaemonConn,
    info: &ValidPathInfo,
    rx: mpsc::Receiver<Bytes>,
) -> Result<()> {
    let reader = StreamReader::new(ReceiverStream::new(rx).map(Ok::<_, io::Error>));
    // take(nar_size): a malicious hub must not stream unbounded bytes.
    let limited = BufReader::new(reader.take(info.info.nar_size));
    conn.add_to_store_nar(info, limited, false, true)
        .await
        .map_err(|e| err_msg(format!("importing {} via the daemon: {e}", info.path)))?;
    Ok(())
}
