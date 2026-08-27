//! Parallel daemon imports of staged input NARs.

use std::io;
use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;
use futures_util::StreamExt as _;
use harmonia_store_path_info::ValidPathInfo;
use harmonia_store_remote::{DaemonClient, DaemonStore as _};
use tokio::io::{AsyncReadExt as _, BufReader};
use tokio::sync::{mpsc, oneshot};
use tokio::task::spawn_blocking;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::StreamReader;

use super::chunks::feed_import;
use super::claims::Wake;
use crate::chunker::Recipe;
use crate::chunkstore::ChunkStore;
use crate::chunkstore::Hash;
use crate::errors::{Result, chain, err_ctx, err_msg};
use crate::worker::DaemonConn;

/// Error chain of a failed AddToStoreNar.
type ImportResult = StdResult<(), String>;

type ImportOutcome = (ImportResult, Vec<Hash>);

/// One queued or in-flight daemon import. The pool fills `result` and
/// then wakes the session loop for this path.
pub(super) struct ImportHandle {
    pub(super) result: oneshot::Receiver<ImportOutcome>,
}

impl ImportHandle {
    /// `None` while the import still runs.
    pub(super) fn finish(mut self) -> Result<Option<ImportOutcome>> {
        match self.result.try_recv() {
            Ok(r) => Ok(Some(r)),
            Err(oneshot::error::TryRecvError::Empty) => Ok(None),
            Err(oneshot::error::TryRecvError::Closed) => Err(err_msg("import pool gone")),
        }
    }
}

pub(super) struct ImportJob {
    pub(super) info: ValidPathInfo,
    pub(super) store: Arc<Mutex<ChunkStore>>,
    pub(super) recipe: Recipe,
    pub(super) result: oneshot::Sender<ImportOutcome>,
    pub(super) wake: (mpsc::UnboundedSender<Wake>, Wake),
}

/// N tasks with one daemon connection each, so imports overlap the
/// download and each other instead of serializing behind one
/// AddToStoreNar. A path is dispatched only once every reference is
/// valid, so a job never waits on another.
pub(super) struct ImportPool {
    pub(super) job_tx: mpsc::UnboundedSender<ImportJob>,
    workers: Vec<tokio::task::JoinHandle<()>>,
}

impl ImportPool {
    pub(super) fn spawn(jobs: usize) -> Self {
        let (job_tx, job_rx) = mpsc::unbounded_channel::<ImportJob>();
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

async fn import_worker(job_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<ImportJob>>>) {
    let mut conn: Option<DaemonConn> = None;
    loop {
        let job = job_rx.lock().await.recv().await;
        let Some(job) = job else { break };
        let (tx, rx) = mpsc::channel::<Bytes>(8);
        let (store, recipe) = (job.store, job.recipe);
        let feeder = spawn_blocking(move || feed_import(&store, &recipe, &tx));
        let res = run_import(&mut conn, &job.info, rx).await;
        let outcome = match feeder.await {
            Ok(bad) => (res.map_err(|e| chain(&e)), bad),
            Err(e) => (Err(format!("import feeder panicked: {e}")), Vec::new()),
        };
        let _ = job.result.send(outcome);
        let (tx, w) = job.wake;
        let _ = tx.send(w);
    }
}

async fn run_import(
    conn: &mut Option<DaemonConn>,
    info: &ValidPathInfo,
    rx: mpsc::Receiver<Bytes>,
) -> Result<()> {
    let t0 = Instant::now();
    if conn.is_none() {
        *conn = Some(
            DaemonClient::builder()
                .connect_daemon()
                .await
                .map_err(err_ctx("connecting an import daemon connection"))?,
        );
    }
    let res = import_nar(conn.as_mut().unwrap(), info, rx).await;
    tracing::debug!(
        path = %info.path,
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
