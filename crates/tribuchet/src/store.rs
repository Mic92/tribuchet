//! Nix store path validation.
//!
//! The hub reads these paths from disk as root and the worker
//! bind-mounts (and on macOS deletes) them, so a string that parses
//! here but escapes /nix/store would be a path-traversal primitive.

use std::collections::{BTreeSet, HashSet};
use std::error;
use std::hash::Hash;

use harmonia_store_path::StoreDir;
use harmonia_store_path_info::{NarHash, UnkeyedValidPathInfo, ValidPathInfo};

use crate::proto::PathInfoMsg;

/// Only the canonical Nix store is served; clients must not anchor
/// path validation at an arbitrary prefix.
pub const STORE_DIR: &str = "/nix/store";

/// A store path directly under the store dir: absolute, exactly one
/// component, hash-prefixed, Nix name charset (no shell/SBPL
/// metacharacters, control bytes, or path tricks).
pub fn valid_store_path(store_dir: &str, path: &str) -> bool {
    let Ok(dir) = harmonia_store_path::StoreDir::new(store_dir) else {
        return false;
    };
    dir.parse::<harmonia_store_path::StorePath>(path).is_ok()
}

#[derive(Debug, thiserror::Error)]
#[error("parsing path info {field}")]
pub struct PathInfoError {
    field: &'static str,
    #[source]
    source: Box<dyn error::Error + Send + Sync>,
}

fn field<E: error::Error + Send + Sync + 'static>(
    field: &'static str,
) -> impl Fn(E) -> PathInfoError {
    move |source| PathInfoError {
        field,
        source: Box::new(source),
    }
}

/// Wire metadata -> daemon ValidPathInfo.
pub fn parse_path_info(
    store_path: &str,
    msg: &PathInfoMsg,
) -> Result<harmonia_store_path_info::ValidPathInfo, PathInfoError> {
    let store_dir = StoreDir::default();
    Ok(ValidPathInfo {
        path: store_dir.parse(store_path).map_err(field("path"))?,
        info: UnkeyedValidPathInfo {
            deriver: (!msg.deriver.is_empty())
                .then(|| store_dir.parse(&msg.deriver))
                .transpose()
                .map_err(field("deriver"))?,
            nar_hash: NarHash::from_slice(&msg.nar_sha256).map_err(field("nar hash"))?,
            references: msg
                .references
                .iter()
                .map(|r| store_dir.parse(r))
                .collect::<Result<BTreeSet<_>, _>>()
                .map_err(field("references"))?,
            registration_time: None,
            nar_size: msg.nar_size,
            ultimate: false,
            signatures: msg
                .signatures
                .iter()
                .map(|s| s.parse())
                .collect::<Result<BTreeSet<_>, _>>()
                .map_err(field("signatures"))?,
            ca: (!msg.ca.is_empty())
                .then(|| msg.ca.parse())
                .transpose()
                .map_err(field("content address"))?,
            store_dir,
        },
    })
}

/// Iterative DFS post-order over `roots`: references before referrers.
/// `refs_of` returns only edges within the node set. Cycle-safe.
pub fn topo_order<K, I, F>(roots: I, mut refs_of: F) -> Vec<K>
where
    K: Eq + Hash + Clone,
    I: IntoIterator<Item = K>,
    F: FnMut(&K) -> Vec<K>,
{
    let mut order = Vec::new();
    let mut seen = HashSet::new();
    let mut stack: Vec<(K, bool)> = Vec::new();
    for root in roots {
        stack.push((root, false));
        while let Some((k, emit)) = stack.pop() {
            if emit {
                order.push(k);
            } else if seen.insert(k.clone()) {
                stack.push((k.clone(), true));
                for r in refs_of(&k) {
                    if !seen.contains(&r) {
                        stack.push((r, false));
                    }
                }
            }
        }
    }
    order
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 32-char base32 hash part for synthetic store paths.
    const H: &str = "00000000000000000000000000000000";

    #[test]
    fn store_path_validation() {
        fn ok(p: &str) -> bool {
            valid_store_path("/nix/store", p)
        }
        assert!(ok(&format!("/nix/store/{H}-foo")));
        assert!(ok(&format!("/nix/store/{H}-foo_1.2+x?=y")));
        // hash part is mandatory since harmonia's StorePath parser
        assert!(!ok("/nix/store/abc-foo"));
        assert!(!ok("/nix/store/"));
        assert!(!ok("/nix/store/.."));
        // leading-dot names are valid in modern Nix (and harmonia)
        assert!(ok(&format!("/nix/store/{H}-.hidden")));
        assert!(!ok(&format!("/nix/store/{H}-abc/../../etc")));
        assert!(!ok(&format!("/nix/store/{H}-abc/bin/sh")));
        assert!(!ok("/etc/shadow"));
        assert!(!ok(&format!("/nix/storeX/{H}-abc")));
        // no quotes/parens/control bytes: these strings reach the macOS
        // sandbox profile and log lines verbatim
        assert!(!ok(&format!("/nix/store/{H}-a\")(allow-default)(\"")));
        assert!(!ok(&format!("/nix/store/{H}-a\nb")));
        assert!(!ok(&format!("/nix/store/{H}-a,b")));
    }
}
