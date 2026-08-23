//! Parallel daemon imports of staged input NARs.

use std::mem;
use std::sync::Arc;
use std::time::Instant;

use futures_util::StreamExt as _;
use harmonia_store_path_info::ValidPathInfo;
use harmonia_store_remote::{DaemonClient, DaemonStore as _};
use std::io;
use tokio::io::AsyncReadExt as _;
use tokio::sync::{mpsc, watch};

use super::super::DaemonConn;
use crate::errors::{Result, chain, err_ctx, err_msg};

#[derive(Clone, Debug)]
pub(super) enum ImportState {
    Running,
    Done,
    Failed(String),
}

/// One in-flight daemon import, fed chunk by chunk from feed_nar.
pub(super) struct ImportHandle {
    /// Chunk sender, None once the NAR's eof arrived.
    pub(super) tx: Option<mpsc::Sender<bytes::Bytes>>,
    pub(super) done: watch::Receiver<ImportState>,
}

pub(super) struct ImportJob {
    pub(super) info: ValidPathInfo,
    pub(super) rx: mpsc::Receiver<bytes::Bytes>,
    /// Imports of this path's references: AddToStoreNar registration
    /// requires every reference valid, so the import waits for them.
    pub(super) gates: Vec<watch::Receiver<ImportState>>,
    pub(super) done: watch::Sender<ImportState>,
}

/// N tasks with one daemon connection each, so imports overlap the
/// download and each other instead of serializing behind one
/// AddToStoreNar. The hub streams references before referrers, so a
/// job's gates always point at jobs queued earlier: FIFO dispatch
/// cannot deadlock on a gate.
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
        let _ = job.done.send(match res {
            Ok(()) => ImportState::Done,
            Err(e) => ImportState::Failed(chain(&e)),
        });
    }
}

async fn run_import(conn: &mut Option<DaemonConn>, job: &mut ImportJob) -> Result<()> {
    let t0 = Instant::now();
    for gate in &mut job.gates {
        let state = gate
            .wait_for(|s| !matches!(s, ImportState::Running))
            .await
            .map_err(|_| err_msg("a reference's import was abandoned"))?;
        if let ImportState::Failed(e) = &*state {
            return Err(err_msg(format!(
                "a reference of {} failed to import: {e}",
                job.info.path
            )));
        }
    }
    if conn.is_none() {
        *conn = Some(
            DaemonClient::builder()
                .connect_daemon()
                .await
                .map_err(err_ctx("connecting an import daemon connection"))?,
        );
    }
    let rx = mem::replace(&mut job.rx, mpsc::channel(1).1);
    let gate_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
    let res = import_nar(conn.as_mut().unwrap(), &job.info, rx).await;
    tracing::debug!(
        path = %job.info.path,
        gate_ms,
        import_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX) - gate_ms,
        "daemon import done"
    );
    if res.is_err() {
        // A failed AddToStoreNar leaves the protocol state unknown.
        *conn = None;
    }
    res
}

/// Drive one AddToStoreNar: hub chunks -> zstd decode -> daemon. The
/// daemon verifies the NAR against info.nar_hash and registers the
/// path, so no separate integrity check is needed here.
async fn import_nar(
    conn: &mut DaemonConn,
    info: &ValidPathInfo,
    rx: mpsc::Receiver<bytes::Bytes>,
) -> Result<()> {
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(Ok::<_, io::Error>);
    let reader = tokio_util::io::StreamReader::new(stream);
    let dec = {
        let mut dec =
            async_compression::tokio::bufread::ZstdDecoder::new(tokio::io::BufReader::new(reader));
        // The hub stitches cached per-chunk frames with fresh run
        // frames, so the stream is multi-frame.
        dec.multiple_members(true);
        dec
    };
    // take(nar_size): the daemon reads a self-delimiting NAR, but a
    // malicious hub must not stream unbounded decompressed bytes.
    let limited = tokio::io::BufReader::new(dec.take(info.info.nar_size));
    conn.add_to_store_nar(info, limited, false, true)
        .await
        .map_err(|e| err_msg(format!("importing {} via the daemon: {e}", info.path)))?;
    Ok(())
}
