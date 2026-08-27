//! Parser for the build.json document written by Nix's external-builders
//! feature (version 1). See
//! `nix/src/libstore/unix/build/external-derivation-builder.cc`.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("parsing build.json")]
    Parse(#[from] serde_json::Error),
    #[error("unsupported build.json version {0}")]
    UnsupportedVersion(u32),
}

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
    #[serde(default)]
    pub real_store_dir: Option<String>,
    pub system: String,
    pub input_paths: Vec<String>,
    /// Output name -> scratch store path. The same scratch paths must be
    /// populated on the client; Nix rewrites and registers them afterwards.
    pub outputs: BTreeMap<String, String>,
}

impl BuildJson {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let data = fs::read_to_string(path).map_err(|source| Error::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let parsed: Self = serde_json::from_str(&data)?;
        if parsed.version != 1 {
            return Err(Error::UnsupportedVersion(parsed.version));
        }
        Ok(parsed)
    }

    pub fn attrs(&self) -> Option<serde_json::Value> {
        self.env.get("NIX_ATTRS_JSON_FILE")?;
        let data = fs::read(self.top_tmp_dir.join("build/.attrs.json")).ok()?;
        serde_json::from_slice(&data).ok()
    }

    /// Fixed-output or `__impure`, like Nix's `!isSandboxed()`.
    pub fn network_allowed(&self, attrs: Option<&serde_json::Value>) -> bool {
        flag(&self.env, attrs, "NIX_OUTPUT_CHECKED") || flag(&self.env, attrs, "__impure")
    }
}

/// A boolean derivation attr from the env (`"1"`) or structured attrs.
pub fn flag(env: &BTreeMap<String, String>, attrs: Option<&serde_json::Value>, name: &str) -> bool {
    env.get(name).map(String::as_str) == Some("1")
        || attrs
            .and_then(|a| a.get(name))
            .and_then(serde_json::Value::as_bool)
            == Some(true)
}

/// `requiredSystemFeatures` from the plain env var or structured attrs.
pub fn required_system_features(
    env: &BTreeMap<String, String>,
    attrs: Option<&serde_json::Value>,
) -> Vec<String> {
    if let Some(features) = env.get("requiredSystemFeatures") {
        return features.split_whitespace().map(str::to_owned).collect();
    }
    if let Some(features) = attrs
        .and_then(|a| a.get("requiredSystemFeatures"))
        .and_then(|v| v.as_array())
    {
        return features
            .iter()
            .filter_map(|f| f.as_str().map(str::to_owned))
            .collect();
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_features_from_plain_env() {
        let env = BTreeMap::from([(
            "requiredSystemFeatures".to_owned(),
            "kvm big-parallel".to_owned(),
        )]);
        assert_eq!(
            required_system_features(&env, None),
            ["kvm", "big-parallel"]
        );
    }

    #[test]
    fn system_features_from_structured_attrs() {
        let attrs = serde_json::json!({"requiredSystemFeatures": ["kvm"]});
        assert_eq!(
            required_system_features(&BTreeMap::new(), Some(&attrs)),
            ["kvm"]
        );
        assert!(required_system_features(&BTreeMap::new(), None).is_empty());
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
    fn network_detection() {
        assert!(!doc(&serde_json::json!({})).network_allowed(None));
        assert!(doc(&serde_json::json!({"NIX_OUTPUT_CHECKED": "1"})).network_allowed(None));
        assert!(!doc(&serde_json::json!({"outputHash": "sha256-..."})).network_allowed(None));
        assert!(doc(&serde_json::json!({"__impure": "1"})).network_allowed(None));
        let attrs = serde_json::json!({"__impure": true});
        assert!(doc(&serde_json::json!({})).network_allowed(Some(&attrs)));
    }
}
