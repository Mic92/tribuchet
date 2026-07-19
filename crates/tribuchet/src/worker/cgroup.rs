//! Per-build cgroups are created and torn down by tribuchet-sandboxd
//! (as siblings under the worker's cgroup). This module only vacates
//! the delegated unit's root cgroup and enables the memory controller
//! there, so those siblings get a `memory.max` knob. Without a
//! delegated subtree that step fails silently and builds simply run
//! without a memory limit.

use std::fs;
use std::path::PathBuf;

/// Move this process into a `main` leaf below its own cgroup (cgroup
/// v2's no-internal-process rule forbids enabling controllers while the
/// parent holds processes) and enable the memory controller for
/// siblings. Best-effort: on a non-delegated host the writes fail and
/// sandboxd's build cgroups just have no memory.max.
// Called once at worker startup. There is no macOS equivalent.
#[cfg(target_os = "linux")]
pub fn init() {
    let Ok(cg) = fs::read_to_string("/proc/self/cgroup") else {
        return;
    };
    let Some(path) = cg.lines().find_map(|l| l.strip_prefix("0::")) else {
        return;
    };
    let base = PathBuf::from(format!("/sys/fs/cgroup{}", path.trim()));
    let Ok(controllers) = fs::read_to_string(base.join("cgroup.controllers")) else {
        return;
    };
    let main = base.join("main");
    if fs::create_dir_all(&main).is_err() || fs::write(main.join("cgroup.procs"), "0").is_err() {
        tracing::info!("no delegated cgroup; per-build memory.max unavailable");
        return;
    }
    if controllers.split_whitespace().any(|c| c == "memory")
        && let Err(e) = fs::write(base.join("cgroup.subtree_control"), "+memory")
    {
        tracing::warn!("enabling +memory on {}: {e}", base.display());
    }
}
