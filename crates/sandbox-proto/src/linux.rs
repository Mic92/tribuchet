//! Messages spoken with tribuchet-sandboxd, the Linux root daemon
//! that leases per-build user namespaces and cgroups.

use serde::{Deserialize, Serialize};

/// Default daemon socket; its presence is how the worker detects sandboxd.
pub const SOCKET_PATH: &str = "/run/tribuchet-sandboxd.sock";

pub const METHOD_ALLOCATE: &str = "com.tribuchet.Sandbox.Allocate";
pub const METHOD_PURGE: &str = "com.tribuchet.Sandbox.Purge";
pub const METHOD_OPEN_IDMAPPED: &str = "com.tribuchet.Sandbox.OpenIdmapped";

/// Lease a per-build sandbox. Attached fds: the worker-created user
/// namespace (0), a pidfd of the process holding it (1), a pidfd of
/// the sandbox setup stage (2), and the build's tmp dir (3). sandboxd
/// maps the namespace, creates the build cgroup, and moves the setup
/// stage into it -- as root, so the worker needs no write on any
/// ancestor `cgroup.procs` and thus no delegated subtree. It also
/// chowns the tmp dir tree to the leased base uid so worker-unpacked
/// files are mapped (and thus deletable) inside the build's user
/// namespace.
///
/// The reply carries [`AllocateReply`] with the delegated build cgroup
/// directory as fd 0. The lease ends when the build cgroup drains after
/// having been populated -- so builds survive worker restarts -- or when
/// the connection closes before anything ran in it; the daemon then
/// removes the cgroup and returns the uid range.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllocateRequest {
    pub build_id: String,
    /// Uids mapped into the namespace starting at in-ns 0: 1 for
    /// single-uid builds, 65536 for uid-range builds.
    pub uid_count: u32,
}

/// Empty a worker-owned directory (fd 0) of leased-uid files after the
/// lease is gone. Reply is `{}`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PurgeRequest {}

/// Open an idmapped mount of a worker-owned directory (fd 0) that
/// presents files owned by the leased uid block as worker-owned, so
/// the worker can pack outputs regardless of their permission bits.
/// The reply is `{}` with the detached mount as fd 0.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenIdmappedRequest {
    /// First host uid of the block, as leased by Allocate.
    pub uid_base: u32,
    /// Uids in the block (1 or 65536).
    pub uid_count: u32,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllocateReply {
    /// First host uid of the leased block (backs in-ns uid 0).
    pub pool_base: u32,
}
