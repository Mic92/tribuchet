//! Parser for the build.json document written by Nix's external-builders
//! feature (version 1). See
//! `nix/src/libstore/unix/build/external-derivation-builder.cc`.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildJson {
    pub version: u32,
    pub builder: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub top_tmp_dir: PathBuf,
    pub tmp_dir_in_sandbox: PathBuf,
    pub store_dir: String,
    pub system: String,
    pub input_paths: Vec<String>,
    /// Output name -> scratch store path. The same scratch paths must be
    /// populated on the client; Nix rewrites and registers them afterwards.
    pub outputs: BTreeMap<String, String>,
}

impl BuildJson {
    pub fn load(path: &Path) -> Result<Self> {
        let data =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let parsed: Self = serde_json::from_str(&data).context("parsing build.json")?;
        if parsed.version != 1 {
            bail!("unsupported build.json version {}", parsed.version);
        }
        Ok(parsed)
    }

    /// Fixed-output derivations carry `outputHash` in their environment
    /// (under structured attrs: inside the `__json` blob, the env's only
    /// key). They are granted network access in the sandbox.
    pub fn is_fixed_output(&self) -> bool {
        if self.env.contains_key("outputHash") {
            return true;
        }
        if let Some(json) = self.env.get("__json") {
            if let Ok(attrs) = serde_json::from_str::<serde_json::Value>(json) {
                return attrs.get("outputHash").is_some_and(|h| !h.is_null());
            }
        }
        false
    }
}

/// `requiredSystemFeatures` of a derivation environment, from the
/// plain space-separated variable or the structured-attrs `__json`
/// blob.
pub fn required_system_features(env: &HashMap<String, String>) -> Vec<String> {
    if let Some(features) = env.get("requiredSystemFeatures") {
        return features.split_whitespace().map(str::to_owned).collect();
    }
    if let Some(json) = env.get("__json") {
        if let Ok(attrs) = serde_json::from_str::<serde_json::Value>(json) {
            if let Some(features) = attrs
                .get("requiredSystemFeatures")
                .and_then(|v| v.as_array())
            {
                return features
                    .iter()
                    .filter_map(|f| f.as_str().map(str::to_owned))
                    .collect();
            }
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_features_from_plain_env() {
        let env = HashMap::from([(
            "requiredSystemFeatures".to_owned(),
            "kvm big-parallel".to_owned(),
        )]);
        assert_eq!(required_system_features(&env), ["kvm", "big-parallel"]);
    }

    #[test]
    fn system_features_from_structured_attrs() {
        let env = HashMap::from([(
            "__json".to_owned(),
            r#"{"requiredSystemFeatures":["kvm"]}"#.to_owned(),
        )]);
        assert_eq!(required_system_features(&env), ["kvm"]);
        assert!(required_system_features(&HashMap::new()).is_empty());
    }

    fn doc(env: &serde_json::Value) -> BuildJson {
        serde_json::from_value(serde_json::json!({
            "version": 1,
            "builder": "/bin/sh",
            "args": [],
            "env": env,
            "topTmpDir": "/tmp/x",
            "tmpDirInSandbox": "/build",
            "storeDir": "/nix/store",
            "system": "x86_64-linux",
            "inputPaths": [],
            "outputs": {},
        }))
        .unwrap()
    }

    #[test]
    fn fixed_output_detection() {
        assert!(!doc(&serde_json::json!({})).is_fixed_output());
        assert!(doc(&serde_json::json!({"outputHash": "sha256-..."})).is_fixed_output());
        // structured attrs: outputHash lives in the __json blob
        let env = serde_json::json!({"__json": "{\"outputHash\":\"sha256-...\"}"});
        assert!(doc(&env).is_fixed_output());
        let env = serde_json::json!({"__json": "{\"name\":\"x\"}"});
        assert!(!doc(&env).is_fixed_output());
    }
}
