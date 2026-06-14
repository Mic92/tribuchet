//! Advertised system capabilities and feature probing.

use std::collections::HashMap;

use super::WorkerCtx;
use crate::config::WorkerConfig;

/// Nix's `uid-range` system feature: a full 65536-uid range with the
/// builder as in-namespace root (containers, systemd-nspawn).
pub(super) fn requires_uid_range(env: &HashMap<String, String>) -> bool {
    crate::build_json::required_system_features(env)
        .iter()
        .any(|f| f == "uid-range")
}

/// System features this worker can honor, advertised to the hub for
/// scheduling. Mirrors Nix's defaults. Emulated systems get only the
/// baseline: kvm is an x86 device to an emulated guest, and uid-range
/// under emulation is untested.
fn local_features(native: bool, uid_base: u32) -> Vec<String> {
    let mut features = vec![
        "nixos-test".to_owned(),
        "benchmark".to_owned(),
        "big-parallel".to_owned(),
    ];
    if cfg!(target_os = "linux") && native {
        if std::path::Path::new("/dev/kvm").exists() {
            features.push("kvm".to_owned());
        }
        if can_map_uid_range(uid_base) {
            features.push("uid-range".to_owned());
        }
    }
    features
}

/// Per-system capability list for Register; native systems get the
/// probed feature set, emulated ones only the baseline.
pub(super) fn system_caps(opts: &WorkerConfig, ctx: &WorkerCtx) -> Vec<crate::proto::SystemCaps> {
    let native = local_features(true, opts.auto_allocate_uids_base);
    let emulated = local_features(false, opts.auto_allocate_uids_base);
    opts.systems
        .iter()
        .map(|s| crate::proto::SystemCaps {
            system: s.clone(),
            features: if ctx.emulators.contains_key(s) {
                emulated.clone()
            } else {
                native.clone()
            },
        })
        .collect()
}

/// Probe whether a 65536-uid mapping actually works (root alone is not
/// enough: user namespaces may be disabled). The child unshares and the
/// parent writes the map: after CLONE_NEWUSER the child has no caps in
/// the parent namespace, so it could not map a range itself. Forks
/// because unshare(CLONE_NEWUSER) fails with EINVAL in a multithreaded
/// process; the child runs only async-signal-safe syscalls.
#[cfg(target_os = "linux")]
fn can_map_uid_range(base: u32) -> bool {
    use nix::unistd::ForkResult;
    let Ok((sync_r, sync_w)) = nix::unistd::pipe() else {
        return false;
    };
    let Ok((hold_r, hold_w)) = nix::unistd::pipe() else {
        return false;
    };
    match unsafe { nix::unistd::fork() } {
        Ok(ForkResult::Child) => {
            if nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUSER).is_err() {
                unsafe { libc::_exit(1) }
            }
            let _ = nix::unistd::write(&sync_w, b"u");
            drop(sync_w);
            // block until the parent has tried the map write
            drop(hold_w);
            let _ = nix::unistd::read(&hold_r, &mut [0u8; 1]);
            unsafe { libc::_exit(0) }
        }
        Ok(ForkResult::Parent { child }) => {
            drop(sync_w);
            let unshared = nix::unistd::read(&sync_r, &mut [0u8; 1]) == Ok(1);
            let mapped = unshared
                && std::fs::write(format!("/proc/{child}/uid_map"), format!("0 {base} 65536"))
                    .is_ok();
            drop(hold_w);
            let _ = nix::sys::wait::waitpid(child, None);
            mapped
        }
        Err(_) => false,
    }
}

#[cfg(not(target_os = "linux"))]
fn can_map_uid_range(_base: u32) -> bool {
    false
}

pub fn host_system() -> String {
    let arch = std::env::consts::ARCH;
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        os => os,
    };
    format!("{arch}-{os}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_range_detection() {
        let mut env = HashMap::new();
        assert!(!requires_uid_range(&env));
        env.insert(
            "requiredSystemFeatures".into(),
            "big-parallel uid-range".into(),
        );
        assert!(requires_uid_range(&env));

        let mut env = HashMap::new();
        env.insert(
            "__json".into(),
            r#"{"requiredSystemFeatures":["uid-range"]}"#.into(),
        );
        assert!(requires_uid_range(&env));
        let mut env = HashMap::new();
        env.insert("__json".into(), r#"{"outputHash":"x"}"#.into());
        assert!(!requires_uid_range(&env));
    }
}
