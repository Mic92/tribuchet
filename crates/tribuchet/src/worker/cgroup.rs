//! Best-effort cgroup v2 scoping for builds.
//!
//! With a delegated cgroup (systemd `Delegate=yes`), each build runs in
//! a child cgroup with `pids.max` (and optionally `memory.max`), and
//! teardown uses `cgroup.kill`, which reaches setsid'd escapees no
//! killpg can. Without delegation builds run unscoped, with a warning.

use std::path::{Path, PathBuf};

/// Move this process into a `main` leaf below its own cgroup (cgroup
/// v2's no-internal-process rule forbids enabling controllers while the
/// parent holds processes) and enable pids/memory for siblings.
/// Returns the delegated base, or None when cgroups are unavailable.
pub fn init() -> Option<PathBuf> {
    let unavailable = |why: &str| {
        tracing::warn!("cgroup limits disabled: {why}; builds run without pids/memory caps");
        None
    };
    let Ok(cg) = std::fs::read_to_string("/proc/self/cgroup") else {
        return unavailable("cannot read /proc/self/cgroup");
    };
    let Some(path) = cg.lines().find_map(|l| l.strip_prefix("0::")) else {
        return unavailable("not on cgroup v2");
    };
    let base = PathBuf::from(format!("/sys/fs/cgroup{}", path.trim()));
    let Ok(controllers) = std::fs::read_to_string(base.join("cgroup.controllers")) else {
        return unavailable("cannot read cgroup.controllers");
    };
    if !controllers.split_whitespace().any(|c| c == "pids") {
        return unavailable("pids controller not delegated (systemd Delegate=yes?)");
    }
    let main = base.join("main");
    if std::fs::create_dir_all(&main).is_err()
        || std::fs::write(main.join("cgroup.procs"), "0").is_err()
    {
        return unavailable("cannot move into a leaf cgroup");
    }
    let mut ctrl = String::from("+pids");
    if controllers.split_whitespace().any(|c| c == "memory") {
        ctrl.push_str(" +memory");
    }
    if let Err(e) = std::fs::write(base.join("cgroup.subtree_control"), ctrl) {
        return unavailable(&format!("cannot enable controllers: {e}"));
    }
    tracing::info!(base = %base.display(), "per-build cgroup limits enabled");
    Some(base)
}

fn build_dir(base: &Path, build_id: &str) -> PathBuf {
    base.join(format!("build-{build_id}"))
}

/// Create the per-build cgroup with its limits. The spawned builder
/// enters it from pre_exec by writing to cgroup.procs.
pub fn create(base: &Path, build_id: &str, memory_max: Option<u64>) -> Option<PathBuf> {
    let dir = build_dir(base, build_id);
    let setup = || -> std::io::Result<()> {
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("pids.max"), "4096")?;
        if let Some(bytes) = memory_max {
            std::fs::write(dir.join("memory.max"), bytes.to_string())?;
        }
        Ok(())
    };
    match setup() {
        Ok(()) => Some(dir),
        Err(e) => {
            tracing::warn!(
                "creating build cgroup {}: {e}; build runs unscoped",
                dir.display()
            );
            let _ = std::fs::remove_dir(&dir);
            None
        }
    }
}

/// Hand the build's cgroup to the builder uid (Nix's `cgroups`
/// setting); nspawn inside the sandbox needs it. Best effort: without
/// it only nested container managers fail.
pub fn chown_to_builder(dir: &Path, uid: u32) {
    for p in [
        dir.to_path_buf(),
        dir.join("cgroup.procs"),
        dir.join("cgroup.threads"),
        dir.join("cgroup.subtree_control"),
    ] {
        if let Err(e) = std::os::unix::fs::chown(&p, Some(uid), Some(uid)) {
            tracing::warn!("chowning {}: {e}", p.display());
        }
    }
}

/// Kill everything left in the build's cgroup and remove it. cgroup.kill
/// reaches setsid'd survivors that escape process-group signals.
pub fn kill_and_remove(base: &Path, build_id: &str) {
    let dir = build_dir(base, build_id);
    if !dir.exists() {
        return;
    }
    let _ = std::fs::write(dir.join("cgroup.kill"), "1");
    for _ in 0..50 {
        if std::fs::remove_dir(&dir).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    tracing::warn!("could not remove build cgroup {}", dir.display());
}
