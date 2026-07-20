//! Messages spoken with the macOS per-uid build agents.
//!
//! One socket-activated launchd daemon per pool user. The agents are
//! the uid pool: a connection whose `Start` is accepted holds the
//! lease. The agent runs one build at a time, keeps its scratch dir,
//! log and exit status, and survives worker restarts. Control calls
//! (`Kill`, `Adopt`, `Finish`, `Cleanup`) are accepted on any
//! connection. Only a second `Start` is refused with [`ERROR_BUSY`].

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Directory of per-agent sockets (`<n>.sock`), root-owned and only
/// group-reachable by the worker.
pub const SOCKET_DIR: &str = "/var/run/tribuchet/agents";

/// Seatbelt profile parameter carrying the agent's scratch dir. The
/// worker builds the profile without knowing that path. The agent
/// fills it in via `sandbox_init_with_parameters`.
pub const SCRATCH_DIR_PARAM: &str = "SCRATCH_DIR";

pub const METHOD_START: &str = "com.tribuchet.Agent.Start";
pub const METHOD_ADOPT: &str = "com.tribuchet.Agent.Adopt";
pub const METHOD_KILL: &str = "com.tribuchet.Agent.Kill";
pub const METHOD_FINISH: &str = "com.tribuchet.Agent.Finish";
pub const METHOD_CLEANUP: &str = "com.tribuchet.Agent.Cleanup";

/// The agent already runs a build, so the worker tries the next agent.
pub const ERROR_BUSY: &str = "com.tribuchet.Agent.Busy";
/// A control call named a build this agent does not hold.
pub const ERROR_UNKNOWN_BUILD: &str = "com.tribuchet.Agent.UnknownBuild";

/// Run one build. Attached fd 0 is the zstd tar of the build's tmp dir
/// (structured attrs, passAsFile files). The agent unpacks it into its
/// scratch dir, rewrites env values referencing `tmp_dir_in_sandbox`
/// to that dir, applies the seatbelt profile in the forked child and
/// execs the builder. Reply: [`StartReply`], then an [`ExitNotice`] on
/// the same connection when the builder exits.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StartRequest {
    pub build_id: String,
    pub builder: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    /// The hub's in-sandbox tmp dir path (e.g. "/build") that env
    /// values may reference, rewritten to the agent's scratch dir.
    pub tmp_dir_in_sandbox: String,
    /// SBPL profile text, may reference [`SCRATCH_DIR_PARAM`].
    pub profile: String,
    /// Scratch output store paths, acted on by `Finish` and `Cleanup`.
    pub outputs: Vec<String>,
}

/// Attached fd 0 is a read handle on the build's log file, so the
/// worker tails it without filesystem access to the agent-owned
/// scratch dir.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StartReply {
    pub pid: i32,
    /// The agent-owned scratch dir the build runs in (its cwd).
    pub scratch_dir: String,
}

/// Sent on the `Start`/`Adopt` connection when the builder exits.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitNotice {
    pub exit_code: i32,
}

/// Reattach to the build after a worker restart. Reply: [`AdoptReply`]
/// (log fd attached), then an [`ExitNotice`] if still running.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdoptRequest {
    pub build_id: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdoptReply {
    pub pid: i32,
    pub scratch_dir: String,
    /// Set when the builder already exited.
    pub exit_code: Option<i32>,
}

/// Kill the build's process group, then every remaining process of the
/// agent's uid except the agent itself (setsid escapes). Reply is `{}`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KillRequest {
    pub build_id: String,
}

/// After a successful exit: make the scratch output trees readable by
/// the worker so it can pack them. Reply is `{}`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinishRequest {
    pub build_id: String,
}

/// Remove the scratch dir and the scratch store outputs. The agent
/// forgets the build and exits when idle. Reply is `{}`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanupRequest {
    pub build_id: String,
}
