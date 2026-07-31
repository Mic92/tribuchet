//! Generated agent messages; see proto/agent.proto for the protocol.

include!(concat!(env!("OUT_DIR"), "/agent.rs"));

/// Directory of per-agent sockets (`<n>.sock`), root-owned and only
/// group-reachable by the worker.
pub const SOCKET_DIR: &str = "/var/run/tribuchet/agents";

/// Seatbelt profile parameter carrying the agent's scratch dir. The
/// worker builds the profile without knowing that path. The agent
/// fills it in via `sandbox_init_with_parameters`.
pub const SCRATCH_DIR_PARAM: &str = "SCRATCH_DIR";

/// The agent already runs a build, so the worker tries the next agent.
pub const ERROR_BUSY: &str = "com.tribuchet.Agent.Busy";
/// A control call named a build this agent does not hold.
pub const ERROR_UNKNOWN_BUILD: &str = "com.tribuchet.Agent.UnknownBuild";
