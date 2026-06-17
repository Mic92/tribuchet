//! macOS sandbox implementation: sandbox-exec with a deny-default write profile.

use std::path::Path;
use std::process::Command;
#[cfg(test)]
use std::process::{Child, Stdio};

use anyhow::{Context, Result};

use super::SandboxSpec;
use crate::proto::BuildAssignment;

pub fn prepare(spec: &mut SandboxSpec) -> Result<()> {
    // No bind mounts on Darwin: inputs already live at their real
    // /nix/store paths (the worker imports them via the daemon),
    // so there is nothing to materialize.
    spec.binds_ro.clear();
    // env refers to tmpDirInSandbox; link it to the real build dir.
    // Darwin daemons always send a per-build tmp path here (Nix has
    // no /build on macOS), so each build gets its own symlink.
    let link = Path::new(&spec.cwd);
    // Don't trust the hub: a root worker creating a symlink at an
    // arbitrary path is a takeover primitive. Allow only tmp prefixes.
    let allowed = [
        "/tmp/",
        "/private/tmp/",
        "/private/var/folders/",
        "/var/folders/",
    ]
    .iter()
    .any(|p| spec.cwd.starts_with(p));
    if !allowed {
        anyhow::bail!("refusing tmpDirInSandbox outside tmp: {}", spec.cwd);
    }
    match std::fs::symlink_metadata(link) {
        Ok(meta) if meta.file_type().is_symlink() => {
            std::fs::remove_file(link)?; // stale link from a crashed build
        }
        Ok(_) => anyhow::bail!("tmpDirInSandbox {} already exists", spec.cwd),
        Err(_) => {}
    }
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::os::unix::fs::symlink(&spec.build_dir, link)
        .with_context(|| format!("creating {} symlink", link.display()))?;
    Ok(())
}

/// SBPL string literal escaping: a quote or backslash in an
/// interpolated path must not terminate the literal and inject
/// profile directives.
fn sb_escape(s: &str) -> Result<String> {
    if s.bytes().any(|b| b.is_ascii_control()) {
        anyhow::bail!("control character in sandbox profile path {s:?}");
    }
    Ok(s.replace('\\', "\\\\").replace('"', "\\\""))
}

pub fn command(spec: &SandboxSpec) -> Result<Command> {
    // Reads stay broad (matching Nix's Darwin sandbox) except for
    // the worker's key material; writes and signals are scoped:
    // unfiltered `(allow signal)` would let builds kill worker-uid
    // host processes, and `(subpath \"/dev\")` write access meant
    // raw-disk writes for a root worker.
    let mut profile = String::from(
        "(version 1)\n\
         (deny default)\n\
         (allow process*)\n\
         (allow signal (target same-sandbox))\n\
         (allow sysctl-read)\n\
         (allow mach-lookup)\n\
         (allow file-read*)\n\
         (allow file-ioctl)\n",
    );
    for secret in &spec.deny_read {
        // Seatbelt matches path filters against the canonical vnode
        // path; the configured paths usually live under /var, which
        // is a symlink to /private/var, so a deny on the literal
        // alone would never match. Emit both forms.
        let canonical = secret.canonicalize().unwrap_or_else(|_| secret.clone());
        let mut paths = vec![secret];
        if canonical != *secret {
            paths.push(&canonical);
        }
        for path in paths {
            profile.push_str(&format!(
                "(deny file-read* (literal \"{}\"))\n",
                sb_escape(&path.to_string_lossy())?
            ));
        }
    }
    profile.push_str("(allow file-write*\n");
    // Like deny_read above: writes resolve to the canonical vnode
    // path, so a subpath on the literal alone (e.g. a build dir under
    // the /var -> /private/var symlink) would never match. Emit both.
    let build_dir = spec.build_dir.to_string_lossy();
    for path in std::iter::once(spec.cwd.as_str())
        .chain(std::iter::once(build_dir.as_ref()))
        .chain(spec.outputs.iter().map(String::as_str))
    {
        profile.push_str(&format!("  (subpath \"{}\")\n", sb_escape(path)?));
        if let Ok(canonical) = Path::new(path).canonicalize() {
            let canonical = canonical.to_string_lossy();
            if canonical != path {
                profile.push_str(&format!("  (subpath \"{}\")\n", sb_escape(&canonical)?));
            }
        }
    }
    for dev in [
        "/dev/null",
        "/dev/zero",
        "/dev/random",
        "/dev/urandom",
        "/dev/tty",
    ] {
        profile.push_str(&format!("  (literal \"{dev}\")\n"));
    }
    profile.push_str(")\n");
    if spec.network {
        profile.push_str("(allow network*)\n(allow system-socket)\n");
    }

    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-p")
        .arg(profile)
        .arg(&spec.builder)
        .args(&spec.args);
    cmd.current_dir(&spec.cwd);
    Ok(cmd)
}

pub fn setup_error_detail_impl(_spec: &SandboxSpec) -> Option<String> {
    None
}

/// sandbox-exec takes everything on the command line.
pub const SPEC_VIA_STDIN: bool = false;

#[cfg(test)]
pub fn stdin_mode() -> Stdio {
    Stdio::null()
}

#[cfg(test)]
pub fn send_spec(_child: &mut Child, _spec: &SandboxSpec) -> Result<()> {
    Ok(())
}

pub fn cleanup(a: &BuildAssignment, dir: &Path) {
    // Outputs were written straight into /nix/store; drop them after
    // upload, and remove the /build symlink.
    for scratch in a.outputs.values() {
        let p = Path::new(scratch);
        let _ = std::fs::remove_dir_all(p);
        let _ = std::fs::remove_file(p);
    }
    // Only remove the symlink this build created (it points at our
    // build dir): a hub-chosen path that prepare() rejected must not
    // become a delete-anything primitive on a root worker.
    let link = Path::new(&a.tmp_dir_in_sandbox);
    if std::fs::read_link(link).is_ok_and(|t| t == dir.join("top").join("build")) {
        let _ = std::fs::remove_file(link);
    }
}
