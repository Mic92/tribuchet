//! Recursive-nix extras: paths a build's outputs reference that only
//! exist on the worker, imported into the hub's local store.

use std::io;

use async_compression::tokio::bufread::ZstdDecoder;
use futures_util::StreamExt as _;
use harmonia_store_path_info::ValidPathInfo;
use harmonia_store_remote::{ConnectionPool, DaemonStore as _};
use tokio::io::{AsyncReadExt as _, BufReader};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::StreamReader;

use crate::errors::{Result, err_ctx, err_msg};
use crate::hub::state::HubState;
use crate::proto::Manifest;
use crate::store::parse_path_info;

/// In-flight AddToStoreNar of one extra. Chunk frames stream through
/// `tx` into a daemon-pool connection held by `task`.
pub(super) struct ExtraImport {
    pub(super) tx: mpsc::Sender<bytes::Bytes>,
    pub(super) task: JoinHandle<Result<()>>,
}

pub(super) fn start_extra(state: &HubState, extra: Manifest) -> Result<ExtraImport> {
    let info = extra
        .info
        .ok_or_else(|| err_msg("extra without PathInfo"))?;
    let parsed =
        parse_path_info(&extra.store_path, &info).map_err(err_ctx("parsing extra PathInfo"))?;
    let (tx, rx) = mpsc::channel::<bytes::Bytes>(8);
    let pool = state.daemon_pool.clone();
    let task = tokio::spawn(async move { import_extra(&pool, parsed, rx).await });
    Ok(ExtraImport { tx, task })
}

async fn import_extra(
    pool: &ConnectionPool,
    info: ValidPathInfo,
    rx: mpsc::Receiver<bytes::Bytes>,
) -> Result<()> {
    let mut guard = pool
        .acquire()
        .await
        .map_err(err_ctx("connecting to the local nix-daemon"))?;
    let stream = ReceiverStream::new(rx).map(Ok::<_, io::Error>);
    let mut dec = ZstdDecoder::new(BufReader::new(StreamReader::new(stream)));
    dec.multiple_members(true);
    let limited = BufReader::new(dec.take(info.info.nar_size));
    guard
        .execute(|c| c.add_to_store_nar(&info, limited, false, true))
        .await
        .map_err(|e| err_msg(format!("registering extra {} via daemon: {e}", info.path)))
}
