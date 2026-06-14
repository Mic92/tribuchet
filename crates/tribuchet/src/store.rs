//! Nix store path validation.
//!
//! The hub reads these paths from disk as root and the worker
//! bind-mounts (and on macOS deletes) them, so a string that parses
//! here but escapes /nix/store would be a path-traversal primitive.

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

/// Wire metadata -> daemon ValidPathInfo.
pub fn parse_path_info(
    msg: &crate::proto::PathInfoMsg,
) -> anyhow::Result<harmonia_store_path_info::ValidPathInfo> {
    use harmonia_store_path::StoreDir;
    use harmonia_store_path_info::{NarHash, UnkeyedValidPathInfo, ValidPathInfo};
    use std::collections::BTreeSet;
    let store_dir = StoreDir::default();
    Ok(ValidPathInfo {
        path: store_dir.parse(&msg.store_path)?,
        info: UnkeyedValidPathInfo {
            deriver: (!msg.deriver.is_empty())
                .then(|| store_dir.parse(&msg.deriver))
                .transpose()?,
            nar_hash: NarHash::from_slice(&msg.nar_sha256)?,
            references: msg
                .references
                .iter()
                .map(|r| store_dir.parse(r))
                .collect::<Result<BTreeSet<_>, _>>()?,
            registration_time: None,
            nar_size: msg.nar_size,
            ultimate: false,
            signatures: msg
                .signatures
                .iter()
                .map(|s| s.parse())
                .collect::<Result<BTreeSet<_>, _>>()?,
            ca: (!msg.ca.is_empty()).then(|| msg.ca.parse()).transpose()?,
            store_dir,
        },
    })
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
