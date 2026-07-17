//! macOS sandbox implementation: sandbox-exec with a deny-default write profile.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;
#[cfg(test)]
use std::process::{Child, Stdio};

use anyhow::{Context, Result};

use super::SandboxSpec;

pub fn prepare(spec: &mut SandboxSpec) -> Result<()> {
    // No bind mounts on Darwin: inputs already live at their real
    // /nix/store paths (the worker imports them via the daemon),
    // so there is nothing to materialize.
    spec.binds_ro.clear();
    // No mount namespace on macOS: use the worker's own per-build dir
    // as cwd and rewrite env values referencing the hub's
    // tmpDirInSandbox (e.g. "/build" from a Linux hub). Avoids any
    // symlink at a hub-chosen path on a root worker.
    let from = std::mem::take(&mut spec.cwd);
    let to = spec
        .build_dir
        .to_str()
        .context("build dir is not valid UTF-8")?
        .to_owned();
    let prefix = format!("{from}/");
    for v in spec.env.values_mut() {
        if *v == from {
            v.clone_from(&to);
        } else if let Some(rest) = v.strip_prefix(&prefix) {
            *v = format!("{to}/{rest}");
        }
    }
    spec.cwd = to;
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
            writeln!(
                profile,
                "(deny file-read* (literal \"{}\"))",
                sb_escape(&path.to_string_lossy())?
            )?;
        }
    }
    profile.push_str("(allow file-write*\n");
    // Like deny_read above: writes resolve to the canonical vnode
    // path, so a subpath on the literal alone (e.g. a build dir under
    // the /var -> /private/var symlink) would never match. Emit both.
    for path in std::iter::once(spec.cwd.as_str()).chain(spec.outputs.iter().map(String::as_str)) {
        writeln!(profile, "  (subpath \"{}\")", sb_escape(path)?)?;
        if let Ok(canonical) = Path::new(path).canonicalize() {
            let canonical = canonical.to_string_lossy();
            if canonical != path {
                writeln!(profile, "  (subpath \"{}\")", sb_escape(&canonical)?)?;
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
        writeln!(profile, "  (literal \"{dev}\")")?;
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

// Result-returning to mirror the Linux implementation, which writes
// the spec into the setup stage's stdin pipe and can fail.
#[cfg(test)]
#[allow(clippy::unnecessary_wraps)]
pub fn send_spec(_child: &mut Child, _spec: &SandboxSpec) -> Result<()> {
    Ok(())
}

pub fn cleanup(outputs: &[String], _dir: &Path) {
    // Outputs were written straight into /nix/store; drop them after
    // upload.
    for scratch in outputs {
        let p = Path::new(scratch);
        let _ = fs::remove_dir_all(p);
        let _ = fs::remove_file(p);
    }
}
