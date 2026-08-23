//! Validation of hub-supplied assignment strings before they touch
//! the filesystem.

use std::fs;
use std::path::{Component, Path};

use crate::errors::{Result, err_msg};
use crate::proto::BuildAssignment;
use crate::store::{STORE_DIR, valid_store_path};

/// The worker must not trust the hub for filesystem-relevant strings:
/// build ids become path components, output paths are packed (and on
/// macOS deleted) on the host.
pub(in crate::worker) fn validate_assignment(a: &BuildAssignment) -> Result<()> {
    if a.build_id.len() != 32 || !a.build_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(err_msg(format!("invalid build id {:?}", a.build_id)));
    }
    if !a.builder.starts_with('/') {
        return Err(err_msg("builder must be an absolute path"));
    }
    let tmp = Path::new(&a.tmp_dir_in_sandbox);
    if !tmp.is_absolute()
        || tmp
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(err_msg(format!(
            "invalid tmpDirInSandbox {:?}",
            a.tmp_dir_in_sandbox
        )));
    }
    for p in a.outputs.values() {
        if !valid_store_path(STORE_DIR, p) {
            return Err(err_msg(format!("invalid output path {p:?}")));
        }
        // macOS builds write into /nix/store and cleanup deletes the
        // output, so a pre-existing path would be tampered with and
        // removed; reject it. Linux builds run in a private root with
        // a no-op cleanup, so the real path is untouched -- and
        // rejecting it would break re-dispatch of a path already valid
        // here (e.g. a fixed-output derivation built before).
        if cfg!(target_os = "macos") && fs::symlink_metadata(p).is_ok() {
            return Err(err_msg(format!(
                "output path {p} already exists on this worker"
            )));
        }
    }
    Ok(())
}
