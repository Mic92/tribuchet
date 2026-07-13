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
/// and recursive-nix under emulation are untested. uid-range comes
/// from the sandboxd lease, which every Linux worker has.
fn local_features(native: bool, opts: &WorkerConfig) -> Vec<String> {
    let mut features = vec![
        "nixos-test".to_owned(),
        "benchmark".to_owned(),
        "big-parallel".to_owned(),
    ];
    if cfg!(target_os = "linux") && native {
        if std::path::Path::new("/dev/kvm").exists() {
            features.push("kvm".to_owned());
        }
        features.push("uid-range".to_owned());
    }
    if native && opts.recursive_nix {
        features.push("recursive-nix".to_owned());
    }
    features
}

/// Per-system capability list for Register; native systems get the
/// full feature set, emulated ones only the baseline.
pub(super) fn system_caps(opts: &WorkerConfig, ctx: &WorkerCtx) -> Vec<crate::proto::SystemCaps> {
    let native = local_features(true, opts);
    let emulated = local_features(false, opts);
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

    #[test]
    fn recursive_nix_advertised_only_when_enabled_and_native() {
        let toml =
            |body: &str| toml::from_str::<WorkerConfig>(&format!("hub = \"x\"\n{body}")).unwrap();
        let off = toml("");
        assert!(!local_features(true, &off).contains(&"recursive-nix".to_owned()));
        assert!(!local_features(false, &off).contains(&"recursive-nix".to_owned()));

        let on = toml("recursive-nix = true");
        assert!(local_features(true, &on).contains(&"recursive-nix".to_owned()));
        // emulated systems must not inherit the host's recursive-nix
        assert!(!local_features(false, &on).contains(&"recursive-nix".to_owned()));
    }
}
