//! Recursive-nix extras: signature verification and daemon import of
//! store paths a build added beyond its outputs.

use std::collections::HashMap;
use std::io;

use futures_util::StreamExt as _;
use harmonia_store_remote::DaemonStore as _;
use harmonia_utils_signature::{PublicKey, Signature};
use tokio::io::AsyncReadExt as _;
use tokio::sync::mpsc;

use super::super::state::{HubState, Replay};
use crate::errors::{Result, err_ctx, err_msg};
use crate::proto::{ExtraPath, NarTransfer, attach_event, nar_transfer};
use crate::store;

/// In-flight AddToStoreNar of one recursive-nix extra. Chunks stream
/// through `tx` into a daemon-pool connection held by `task`.
pub(super) struct ExtraImport {
    tx: mpsc::Sender<bytes::Bytes>,
    task: tokio::task::JoinHandle<Result<()>>,
}

/// Verify each extra's worker signature over `path:nar_sha256_hex`
/// (the same envelope as outputs) and spawn the daemon import.
pub(super) fn start_extras(
    state: &HubState,
    vkey: &PublicKey,
    reported: Vec<ExtraPath>,
) -> Result<HashMap<String, ExtraImport>> {
    let mut out = HashMap::with_capacity(reported.len());
    for extra in reported {
        let info = extra
            .info
            .ok_or_else(|| err_msg("extra without PathInfo"))?;
        let path = info.store_path.clone();
        let sig: Signature = extra
            .signature
            .parse()
            .map_err(err_ctx("malformed extra signature"))?;
        let envelope = format!("{}:{}", path, hex::encode(&info.nar_sha256));
        if !vkey.verify(envelope.as_bytes(), &sig) {
            return Err(err_msg(format!(
                "signature verification failed for extra {path}"
            )));
        }
        let parsed = store::parse_path_info(&info).map_err(err_ctx("parsing extra PathInfo"))?;
        let (tx, rx) = mpsc::channel::<bytes::Bytes>(8);
        let pool = state.daemon_pool.clone();
        let task = tokio::spawn(async move { import_extra(&pool, parsed, rx).await });
        out.insert(path, ExtraImport { tx, task });
    }
    Ok(out)
}

async fn import_extra(
    pool: &harmonia_store_remote::ConnectionPool,
    info: harmonia_store_path_info::ValidPathInfo,
    rx: mpsc::Receiver<bytes::Bytes>,
) -> Result<()> {
    let mut guard = pool
        .acquire()
        .await
        .map_err(err_ctx("connecting to the local nix-daemon"))?;
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(Ok::<_, io::Error>);
    let reader = tokio_util::io::StreamReader::new(stream);
    let dec =
        async_compression::tokio::bufread::ZstdDecoder::new(tokio::io::BufReader::new(reader));
    let limited = tokio::io::BufReader::new(dec.take(info.info.nar_size));
    guard
        .execute(|c| c.add_to_store_nar(&info, limited, false, true))
        .await
        .map_err(|e| err_msg(format!("registering extra {} via daemon: {e}", info.path)))
}

pub(super) async fn relay_extra_chunk(
    extras: &mut HashMap<String, ExtraImport>,
    replay: &Replay,
    n: NarTransfer,
) -> Result<()> {
    let extra = extras.get_mut(&n.store_path).unwrap();
    if let Some(nar_transfer::Payload::ZstdNarChunk(chunk)) = n.payload
        && extra.tx.send(chunk.into()).await.is_err()
    {
        // rx closed does not imply failure: the import reads via
        // take(nar_size) and drops rx once done.
        let extra = extras.remove(&n.store_path).unwrap();
        extra.task.await??;
        return Err(err_msg(format!("excess extra chunks for {}", n.store_path)));
    }
    if n.eof {
        let extra = extras.remove(&n.store_path).unwrap();
        drop(extra.tx);
        extra.task.await??;
        replay
            .publish(attach_event::Event::AddedPath(n.store_path))
            .await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use harmonia_utils_signature::SecretKey;

    use super::*;
    use crate::proto::PathInfoMsg;

    /// Wrong-key signatures must fail before any daemon contact, so a
    /// compromised worker cannot plant store paths on the client.
    #[tokio::test]
    async fn extras_with_wrong_signature_are_rejected() {
        let hub_sk = SecretKey::generate("hub-trusted-key-1".into()).unwrap();
        let attacker_sk = SecretKey::generate("attacker-1".into()).unwrap();
        let vkey = hub_sk.to_public_key();

        let path = format!("/nix/store/{}-extra", "0".repeat(32));
        let nar_sha256 = vec![0u8; 32];
        let envelope = format!("{path}:{}", hex::encode(&nar_sha256));
        let bad = ExtraPath {
            info: Some(PathInfoMsg {
                build_id: String::new(),
                store_path: path.clone(),
                nar_sha256: nar_sha256.clone(),
                nar_size: 1024,
                references: vec![],
                signatures: vec![],
                deriver: String::new(),
                ca: String::new(),
            }),
            signature: attacker_sk.sign(envelope.as_bytes()).to_string(),
        };
        let state = HubState::default();
        let err = start_extras(&state, &vkey, vec![bad])
            .err()
            .expect("expected signature rejection");
        assert!(
            err.to_string().contains("signature verification failed"),
            "{err}"
        );
    }
}
