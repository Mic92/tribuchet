//! Build sandbox.
//!
//! Linux: user/mount/ipc/uts (and, unless fixed-output, net) namespaces;
//! input paths bind-mounted read-only at their store paths inside a
//! private root, scratch outputs created in a writable store dir, the
//! shipped tmp dir mounted at /build, minimal /dev, fresh /proc, chroot.
//! Reference: `nix/src/libstore/unix/build/derivation-builder.cc`.
//!
//! macOS: no bind mounts, so inputs are materialized in the host
//! /nix/store, /build is a symlink to the build dir, and the builder runs
//! under `sandbox-exec` with a deny-default write profile modeled on
//! Nix's `sandbox-defaults.sb` (reads stay permissive, like Nix's own
//! comparatively weak Darwin sandbox).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result};

use crate::proto::BuildAssignment;

pub struct SandboxSpec {
    pub builder: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub cwd: String,
    pub network: bool,
    /// Linux: private root directory. macOS: unused.
    pub root: PathBuf,
    /// Host build dir mounted/linked at tmpDirInSandbox ("/build").
    pub build_dir: PathBuf,
    /// (host source, absolute path inside sandbox), mounted read-only.
    pub binds_ro: Vec<(PathBuf, PathBuf)>,
    /// Scratch output store paths (used by the macOS profile).
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub outputs: Vec<String>,
}

/// Host path where the builder's output for `scratch` lands.
pub fn output_host_path(spec: &SandboxSpec, scratch: &str) -> PathBuf {
    if cfg!(target_os = "linux") {
        spec.root.join(scratch.trim_start_matches('/'))
    } else {
        PathBuf::from(scratch)
    }
}

pub fn prepare(
    a: &BuildAssignment,
    dir: &Path,
    sources: &HashMap<String, PathBuf>,
) -> Result<SandboxSpec> {
    let build_dir = dir.join("top").join("build");
    std::fs::create_dir_all(&build_dir)?;
    let mut spec = SandboxSpec {
        builder: a.builder.clone(),
        args: a.args.clone(),
        env: a.env.clone(),
        cwd: a.tmp_dir_in_sandbox.clone(),
        network: a.fixed_output,
        root: dir.join("root"),
        build_dir,
        binds_ro: sources
            .iter()
            .map(|(store_path, src)| (src.clone(), PathBuf::from(store_path)))
            .collect(),
        outputs: a.outputs.values().cloned().collect(),
    };
    spec.binds_ro.sort(); // deterministic mount order
    platform::prepare(&mut spec)?;
    Ok(spec)
}

pub fn spawn(spec: &SandboxSpec) -> Result<Child> {
    let mut cmd = platform::command(spec)?;
    cmd.env_clear()
        .envs(&spec.env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.spawn()
        .with_context(|| format!("spawning builder {}", spec.builder))
}

pub fn cleanup(a: &BuildAssignment, dir: &Path) {
    platform::cleanup(a, dir);
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use nix::mount::{mount, MsFlags};
    use nix::sched::{unshare, CloneFlags};
    use nix::unistd::{chroot, getgid, getuid, sethostname};
    use std::io;
    use std::os::unix::process::CommandExt;

    pub fn prepare(spec: &mut SandboxSpec) -> Result<()> {
        let root = &spec.root;
        for sub in ["nix/store", "build", "dev", "proc", "etc", "tmp"] {
            std::fs::create_dir_all(root.join(sub))?;
        }
        std::fs::write(
            root.join("etc/passwd"),
            "root:x:0:0:Nix build user:/build:/noshell\n\
             nixbld:x:1000:100:Nix build user:/build:/noshell\n\
             nobody:x:65534:65534:Nobody:/:/noshell\n",
        )?;
        std::fs::write(
            root.join("etc/group"),
            "root:x:0:\nnixbld:x:100:\nnogroup:x:65534:\n",
        )?;
        std::fs::write(
            root.join("etc/hosts"),
            "127.0.0.1 localhost\n::1 localhost\n",
        )?;

        for dev in ["null", "zero", "random", "urandom", "tty"] {
            let host = PathBuf::from("/dev").join(dev);
            std::fs::File::create(root.join("dev").join(dev))?;
            spec.binds_ro.push((host.clone(), host)); // dev nodes: bind, rw via node perms
        }
        for (link, target) in [
            ("dev/fd", "/proc/self/fd"),
            ("dev/stdin", "/proc/self/fd/0"),
            ("dev/stdout", "/proc/self/fd/1"),
            ("dev/stderr", "/proc/self/fd/2"),
        ] {
            std::os::unix::fs::symlink(target, root.join(link))?;
        }
        if spec.network {
            let resolv = std::fs::read("/etc/resolv.conf").unwrap_or_default();
            std::fs::write(root.join("etc/resolv.conf"), resolv)?;
        }
        Ok(())
    }

    pub fn command(spec: &SandboxSpec) -> Result<Command> {
        // Pre-create bind targets matching the source type.
        for (src, dst) in &spec.binds_ro {
            let target = spec.root.join(dst.strip_prefix("/").unwrap_or(dst));
            if target.exists() || target.symlink_metadata().is_ok() {
                continue;
            }
            if src.is_dir() {
                std::fs::create_dir_all(&target)?;
            } else {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::File::create(&target)?;
            }
        }

        let mut cmd = Command::new(&spec.builder);
        cmd.args(&spec.args);

        let root = spec.root.clone();
        let build_dir = spec.build_dir.clone();
        let binds: Vec<(PathBuf, PathBuf)> = spec.binds_ro.clone();
        let cwd = spec.cwd.clone();
        let network = spec.network;
        let uid = getuid().as_raw();
        let gid = getgid().as_raw();

        unsafe {
            cmd.pre_exec(move || setup(&root, &build_dir, &binds, &cwd, network, uid, gid));
        }
        Ok(cmd)
    }

    fn ioerr(step: &str) -> impl Fn(nix::errno::Errno) -> io::Error + '_ {
        move |e| io::Error::other(format!("{step}: {e}"))
    }

    #[allow(clippy::too_many_arguments)]
    fn setup(
        root: &Path,
        build_dir: &Path,
        binds: &[(PathBuf, PathBuf)],
        cwd: &str,
        network: bool,
        uid: u32,
        gid: u32,
    ) -> io::Result<()> {
        let _ = nix::unistd::setsid();
        let mut flags = CloneFlags::CLONE_NEWUSER
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWIPC
            | CloneFlags::CLONE_NEWUTS;
        if !network {
            flags |= CloneFlags::CLONE_NEWNET;
        }
        unshare(flags).map_err(ioerr("unshare"))?;

        let werr = |step: &str| {
            let step = step.to_string();
            move |e: io::Error| io::Error::other(format!("{step}: {e}"))
        };
        std::fs::write("/proc/self/setgroups", "deny").map_err(werr("setgroups"))?;
        std::fs::write("/proc/self/uid_map", format!("1000 {uid} 1")).map_err(werr("uid_map"))?;
        std::fs::write("/proc/self/gid_map", format!("100 {gid} 1")).map_err(werr("gid_map"))?;
        sethostname("localhost").map_err(ioerr("sethostname"))?;

        let none: Option<&str> = None;
        mount(none, "/", none, MsFlags::MS_REC | MsFlags::MS_PRIVATE, none)
            .map_err(ioerr("making / private"))?;
        mount(
            Some(root),
            root,
            none,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            none,
        )
        .map_err(ioerr("binding root"))?;

        let bind_one = |src: &Path, dst: &Path, ro: bool| -> io::Result<()> {
            let target = root.join(dst.strip_prefix("/").unwrap_or(dst));
            mount(
                Some(src),
                &target,
                none,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                none,
            )
            .map_err(|e| io::Error::other(format!("binding {}: {e}", src.display())))?;
            if ro {
                mount(
                    none,
                    &target,
                    none,
                    MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                    none,
                )
                .map_err(|e| io::Error::other(format!("remounting {} ro: {e}", src.display())))?;
            }
            Ok(())
        };
        for (src, dst) in binds {
            // /dev nodes need to stay writable.
            let ro = !dst.starts_with("/dev");
            bind_one(src, dst, ro)?;
        }
        bind_one(build_dir, Path::new("/build"), false)?;

        // A fresh proc mount needs an unmasked host /proc (denied in many
        // containers); fall back to bind-mounting the host's /proc.
        if mount(
            Some("proc"),
            &root.join("proc"),
            Some("proc"),
            MsFlags::empty(),
            none,
        )
        .is_err()
        {
            mount(
                Some("/proc"),
                &root.join("proc"),
                none,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                none,
            )
            .map_err(ioerr("bind-mounting /proc"))?;
        }

        chroot(root).map_err(ioerr("chroot"))?;
        std::env::set_current_dir(cwd)
            .map_err(|e| io::Error::other(format!("chdir {cwd}: {e}")))?;
        Ok(())
    }

    pub fn cleanup(_a: &BuildAssignment, _dir: &Path) {
        // Mounts lived in the child's namespace and died with it; the
        // build dir itself is removed by the caller.
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    pub fn prepare(spec: &mut SandboxSpec) -> Result<()> {
        // No bind mounts on Darwin: materialize cached inputs into the
        // host /nix/store (this is also the worker's input cache there).
        for (src, dst) in std::mem::take(&mut spec.binds_ro) {
            if src == dst || dst.exists() {
                continue;
            }
            std::fs::rename(&src, &dst).or_else(|_| {
                let status = Command::new("/bin/cp")
                    .args(["-a"])
                    .arg(&src)
                    .arg(&dst)
                    .status()?;
                if status.success() {
                    Ok(())
                } else {
                    anyhow::bail!("cp -a {} {} failed", src.display(), dst.display())
                }
            })?;
        }
        // env refers to tmpDirInSandbox (/build); link it to the real dir.
        let link = Path::new(&spec.cwd);
        let _ = std::fs::remove_file(link);
        std::os::unix::fs::symlink(&spec.build_dir, link)
            .with_context(|| format!("creating {} symlink", link.display()))?;
        Ok(())
    }

    pub fn command(spec: &SandboxSpec) -> Result<Command> {
        let mut profile = String::from(
            "(version 1)\n\
             (deny default)\n\
             (allow process*)\n\
             (allow signal)\n\
             (allow sysctl-read)\n\
             (allow mach-lookup)\n\
             (allow file-read*)\n\
             (allow file-ioctl)\n",
        );
        profile.push_str("(allow file-write*\n");
        for path in [
            spec.cwd.as_str(),
            &spec.build_dir.to_string_lossy(),
            "/private/tmp",
            "/dev",
        ] {
            profile.push_str(&format!("  (subpath \"{path}\")\n"));
        }
        for out in &spec.outputs {
            profile.push_str(&format!("  (subpath \"{out}\")\n"));
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

    pub fn cleanup(a: &BuildAssignment, _dir: &Path) {
        // Outputs were written straight into /nix/store; drop them after
        // upload, and remove the /build symlink.
        for scratch in a.outputs.values() {
            let p = Path::new(scratch);
            let _ = std::fs::remove_dir_all(p);
            let _ = std::fs::remove_file(p);
        }
        let _ = std::fs::remove_file(Path::new(&a.tmp_dir_in_sandbox));
    }
}
