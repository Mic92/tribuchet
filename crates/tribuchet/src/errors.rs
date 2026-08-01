//! Rendering an error and its causes on one line ("outer: inner:
//! cause"), the shape anyhow's `{:#}` produced, for log lines and
//! wire-visible error strings.

use std::fmt::Write as _;

/// Error for the hub, attach and main orchestration paths, where a
/// step description plus the causing error is all that callers need.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{msg}")]
    Context {
        msg: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("{0}")]
    Msg(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Transport(#[from] tonic::transport::Error),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    StorePath(#[from] harmonia_store_path::ParseStorePathError),
    #[error(transparent)]
    Nar(#[from] crate::nar::Error),
    #[error(transparent)]
    TmpDir(#[from] crate::tmpdir::Error),
    #[error(transparent)]
    Sd(#[from] crate::sd::Error),
    #[error(transparent)]
    BuildJson(#[from] crate::build_json::Error),
    #[error(transparent)]
    Config(#[from] crate::config::Error),
    #[error(transparent)]
    Ca(#[from] crate::ca::Error),
    #[error(transparent)]
    Agent(#[from] crate::worker::agent::Error),
    #[error(transparent)]
    Grpc(#[from] tonic::Status),
    #[error("hub connection lost")]
    Send(#[from] tokio::sync::mpsc::error::SendError<crate::proto::WorkerMessage>),
    #[error(transparent)]
    Framing(#[from] sandbox_proto::framing::Error),
    #[error(transparent)]
    Sandbox(#[from] crate::worker::sandbox::Error),
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    AgentSpawn(#[from] crate::worker::agent_spawn::Error),
    #[error(transparent)]
    Secret(#[from] crate::fsutil::Error),
    #[error(transparent)]
    PathInfo(#[from] crate::store::PathInfoError),
    #[error(transparent)]
    StoreDb(#[from] harmonia_store_db::Error),
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[cfg(target_os = "macos")]
    #[error(transparent)]
    Fmt(#[from] std::fmt::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Wraps any error with a message describing the failed step.
pub fn err_ctx<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
    msg: impl Into<String>,
) -> impl FnOnce(E) -> Error {
    |source| Error::Context {
        msg: msg.into(),
        source: source.into(),
    }
}

pub fn err_msg(m: impl Into<String>) -> Error {
    Error::Msg(m.into())
}

pub fn chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut cur = e.source();
    while let Some(cause) = cur {
        let _ = write!(out, ": {cause}");
        cur = cause.source();
    }
    out
}
