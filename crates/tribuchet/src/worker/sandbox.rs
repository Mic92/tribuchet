//! Build sandbox.
//!
//! Linux: user/mount/ipc/uts (and, unless fixed-output, net) namespaces;
//! input paths bind-mounted read-only at their store paths inside a
//! private root, scratch outputs created in a writable store dir, the
//! shipped tmp dir mounted at /build, minimal /dev, fresh /proc, chroot.
//! Reference: `nix/src/libstore/unix/build/derivation-builder.cc`.
//!
//! macOS: no bind mounts, so inputs are materialized in the host
//! /nix/store, the per-build tmp dir path (Nix sends the real topTmpDir
//! on Darwin) is a symlink to the build dir, and the builder runs
//! under `sandbox-exec` with a deny-default write profile modeled on
//! Nix's `sandbox-defaults.sb` (reads stay permissive, like Nix's own
//! comparatively weak Darwin sandbox).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(test)]
use std::process::{Child, Stdio};

use anyhow::{Context, Result};

use crate::proto::BuildAssignment;
use crate::worker::binfmt;

/// Address pasta's in-namespace DNS forwarder listens on; written to
/// the sandbox resolv.conf for fixed-output builds.
pub const PASTA_DNS: &str = "169.254.1.53";

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SandboxSpec {
    pub builder: String,
    /// Derivation system, e.g. "i686-linux" (drives Linux personality).
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub system: String,
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
    /// Device nodes the sandbox itself provides; the only binds that
    /// stay writable. Never derived from request-supplied paths.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub binds_dev: Vec<(PathBuf, PathBuf)>,
    /// Scratch output store paths (used by the macOS profile).
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub outputs: Vec<String>,
    /// Per-build cgroup; the builder enters it from pre_exec so pids/
    /// memory limits cover the whole build, including the setup phase.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub cgroup: Option<PathBuf>,
    /// uid-range feature: host base of a 65536-uid block mapped into
    /// the user namespace, builder as in-namespace root. None = single
    /// uid mapped to 1000, like Nix without auto-allocate-uids.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub uid_range: Option<u32>,
    /// Root workers: unprivileged host uid backing fixed-output builds
    /// (pasta is rootless-only; network builds should not be backed by
    /// host root anyway).
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub fod_uid: Option<u32>,
    /// pasta binary: fixed-output builds get a private netns with
    /// user-mode NAT; host abstract sockets and loopback services
    /// stay unreachable.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub pasta: Option<PathBuf>,
    /// Static emulator binary for foreign-system builds, bound at
    /// binfmt::INTERP_PATH and registered in a per-userns binfmt_misc
    /// instance (Linux only).
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub emulator: Option<PathBuf>,
    /// Secret files the build must never read (worker signing/TLS
    /// keys). macOS: Seatbelt deny rules; Linux: defense in depth, the
    /// mount namespace already hides them.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub deny_read: Vec<PathBuf>,
}

/// Host path where the builder's output for `scratch` lands.
pub fn output_host_path(spec: &SandboxSpec, scratch: &str) -> PathBuf {
    if cfg!(target_os = "linux") {
        spec.root.join(scratch.trim_start_matches('/'))
    } else {
        PathBuf::from(scratch)
    }
}

/// Worker-side sandbox configuration for one build.
#[derive(Default)]
pub struct PrepareOpts<'a> {
    pub bin_sh: Option<&'a Path>,
    pub secrets: &'a [PathBuf],
    pub uid_range: Option<u32>,
    pub emulator: Option<&'a Path>,
    pub pasta: Option<&'a Path>,
    pub fod_uid: Option<u32>,
}

pub fn prepare(
    a: &BuildAssignment,
    dir: &Path,
    inputs: &[String],
    opts: &PrepareOpts,
) -> Result<SandboxSpec> {
    let build_dir = dir.join("top").join("build");
    std::fs::create_dir_all(&build_dir)?;
    let mut spec = SandboxSpec {
        builder: a.builder.clone(),
        system: a.system.clone(),
        args: a.args.clone(),
        env: a.env.clone(),
        cwd: a.tmp_dir_in_sandbox.clone(),
        network: a.fixed_output,
        root: dir.join("root"),
        build_dir,
        // inputs live at their real store paths (daemon import)
        binds_ro: inputs
            .iter()
            .map(|p| (PathBuf::from(p), PathBuf::from(p)))
            .collect(),
        binds_dev: Vec::new(),
        outputs: a.outputs.values().cloned().collect(),
        cgroup: None,
        uid_range: opts.uid_range,
        fod_uid: opts.fod_uid.filter(|_| a.fixed_output),
        pasta: opts.pasta.filter(|_| a.fixed_output).map(Path::to_path_buf),
        emulator: opts.emulator.map(Path::to_path_buf),
        deny_read: opts.secrets.to_vec(),
    };
    if cfg!(target_os = "linux") {
        if let Some(em) = opts.emulator {
            spec.binds_ro
                .push((em.to_owned(), PathBuf::from(binfmt::INTERP_PATH)));
        }
        if let Some(sh) = opts.bin_sh {
            // Like Nix's busybox sandbox path: shebangs and system(3)
            // need a shell at /bin/sh.
            spec.binds_ro
                .push((sh.to_owned(), PathBuf::from("/bin/sh")));
        }
    }
    spec.binds_ro.sort(); // deterministic mount order
    platform::prepare(&mut spec)?;
    Ok(spec)
}

/// Turn a prepared sandbox into a reaper spawn request plus, on
/// Linux, the pipe carrying the serialized spec to the setup stage:
/// (request, read end for the child's stdin, write end the caller
/// must fill with `send_spec_to` after the spawn).
pub fn spawn_request(
    spec: &SandboxSpec,
) -> Result<(
    crate::worker::reaper::SpawnRequest,
    Option<std::os::fd::OwnedFd>,
    Option<std::os::fd::OwnedFd>,
)> {
    let cmd = platform::command(spec)?;
    let argv: Vec<String> = std::iter::once(cmd.get_program())
        .chain(cmd.get_args())
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    let req = crate::worker::reaper::SpawnRequest {
        argv,
        env: spec
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        cwd: cmd
            .get_current_dir()
            .map(|p| p.to_string_lossy().into_owned()),
        has_stdin: platform::SPEC_VIA_STDIN,
        seq: 0,
    };
    if platform::SPEC_VIA_STDIN {
        let (r, w) = nix::unistd::pipe().context("creating spec pipe")?;
        Ok((req, Some(r), Some(w)))
    } else {
        Ok((req, None, None))
    }
}

/// Write the serialized spec into the setup stage's stdin pipe; call
/// after the reaper confirmed the spawn. No-op platform-wise on macOS
/// (no pipe exists there).
pub fn send_spec_to(spec: &SandboxSpec, w: std::os::fd::OwnedFd) -> Result<()> {
    serde_json::to_writer(std::fs::File::from(w), spec).context("sending sandbox spec")
}

/// Spawn the builder directly (unit tests only; real builds go
/// through the reaper) with stdout/stderr on `log`.
#[cfg(test)]
pub fn spawn(spec: &SandboxSpec, log: std::fs::File) -> Result<Child> {
    let mut cmd = platform::command(spec)?;
    // Own process group, so orphaned builder children can be killed
    // after the builder exits (there is no PID namespace to do it).
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    cmd.env_clear()
        .envs(&spec.env)
        .stdin(platform::stdin_mode())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning builder {}", spec.builder))?;
    platform::send_spec(&mut child, spec)?;
    Ok(child)
}

/// Setup-stage failure message, written by the stage before the host
/// filesystem became unreachable. Read by the worker when the build
/// exits nonzero.
pub fn setup_error_detail(spec: &SandboxSpec) -> Option<String> {
    platform::setup_error_detail_impl(spec)
}

/// Entry point of the re-exec'd setup stage: builds run as
/// `/proc/self/exe __sandbox_setup` with the spec on stdin, so the
/// namespace/mount/uid work runs in a fresh process instead of a
/// post-fork `pre_exec` closure, where only async-signal-safe code is
/// allowed.
#[cfg(target_os = "linux")]
pub fn setup_stage() -> ! {
    platform::setup_stage()
}

#[cfg(target_os = "linux")]
pub use platform::SETUP_STAGE_ARG;

pub fn cleanup(a: &BuildAssignment, dir: &Path) {
    platform::cleanup(a, dir);
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use nix::mount::{mount, umount2, MntFlags, MsFlags};
    use nix::sched::{unshare, CloneFlags};
    use nix::unistd::{getgid, getuid, pivot_root, sethostname};
    use std::io;

    pub fn prepare(spec: &mut SandboxSpec) -> Result<()> {
        let root = &spec.root;
        for sub in [
            "nix/store",
            "build",
            "dev",
            "dev/shm",
            "dev/pts",
            "proc",
            "sys/fs/cgroup",
            "etc",
            "tmp",
        ] {
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

        for dev in ["null", "zero", "full", "random", "urandom", "tty"] {
            let host = PathBuf::from("/dev").join(dev);
            std::fs::File::create(root.join("dev").join(dev))?;
            spec.binds_dev.push((host.clone(), host)); // dev nodes: bind, rw via node perms
        }
        // Nix's `kvm` system feature: pass the device through when the
        // host has it (VM builds, NixOS tests).
        let kvm = PathBuf::from("/dev/kvm");
        if kvm.exists() {
            std::fs::File::create(root.join("dev/kvm"))?;
            spec.binds_dev.push((kvm.clone(), kvm));
        }
        for (link, target) in [
            ("dev/fd", "/proc/self/fd"),
            ("dev/stdin", "/proc/self/fd/0"),
            ("dev/stdout", "/proc/self/fd/1"),
            ("dev/stderr", "/proc/self/fd/2"),
            ("dev/ptmx", "/dev/pts/ptmx"),
        ] {
            std::os::unix::fs::symlink(target, root.join(link))?;
        }
        if spec.network {
            // Like Nix's fixed-output setup: name resolution via files
            // and DNS only, host resolver/services/hosts copied in, host
            // CA bundle at the standard path for TLS fetches.
            std::fs::write(
                root.join("etc/nsswitch.conf"),
                "hosts: files dns\nservices: files\n",
            )?;
            for f in ["services", "hosts"] {
                if let Ok(data) = std::fs::read(Path::new("/etc").join(f)) {
                    std::fs::write(root.join("etc").join(f), data)?;
                }
            }
            if spec.pasta.is_some() {
                // pasta forwards DNS on this address; the host
                // resolv.conf may point at an unreachable loopback
                // stub (systemd-resolved).
                std::fs::write(
                    root.join("etc/resolv.conf"),
                    format!("nameserver {PASTA_DNS}\n"),
                )?;
            } else if let Ok(data) = std::fs::read("/etc/resolv.conf") {
                std::fs::write(root.join("etc/resolv.conf"), data)?;
            }
            let ca = Path::new("/etc/ssl/certs/ca-certificates.crt");
            if let Ok(real) = ca.canonicalize() {
                spec.binds_ro.push((real, ca.to_path_buf()));
            }
        }
        if let Some(uid) = spec.fod_uid {
            // The dropped-uid process performs every mount itself, so it
            // must own the whole per-build dir; 0700 keeps other FOD
            // uids out.
            if let Some(build_root) = root.parent() {
                chown_recursive(build_root, uid)?;
                std::fs::set_permissions(
                    build_root,
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                )?;
            }
        }
        if let Some(base) = spec.uid_range {
            // The builder is root inside the namespace but uid `base`
            // on the host; writable trees must be owned by the range
            // (Nix's chownToBuilder). The sandbox root itself too:
            // container payloads mkdir top-level dirs like /run.
            std::os::unix::fs::lchown(root, Some(base), Some(base))?;
            for dir in [
                root.join("nix/store"),
                root.join("etc"),
                root.join("tmp"),
                spec.build_dir
                    .parent()
                    .unwrap_or(&spec.build_dir)
                    .to_path_buf(),
            ] {
                chown_recursive(&dir, base)?;
            }
        }
        Ok(())
    }

    fn chown_recursive(path: &Path, uid: u32) -> Result<()> {
        use std::os::unix::fs::lchown;
        lchown(path, Some(uid), Some(uid))
            .with_context(|| format!("chowning {}", path.display()))?;
        if path.is_dir() && !path.is_symlink() {
            for entry in std::fs::read_dir(path)? {
                chown_recursive(&entry?.path(), uid)?;
            }
        }
        Ok(())
    }

    pub fn command(spec: &SandboxSpec) -> Result<Command> {
        // The shipped tmp dir is mounted at the request's sandbox build
        // dir; pre-create the mount point inside the private root.
        std::fs::create_dir_all(
            spec.root.join(
                Path::new(&spec.cwd)
                    .strip_prefix("/")
                    .unwrap_or(Path::new(&spec.cwd)),
            ),
        )?;
        // Pre-create bind targets matching the source type.
        for (src, dst) in spec.binds_ro.iter().chain(&spec.binds_dev) {
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

        if spec.emulator.is_some() && binfmt::register_line(&spec.system).is_none() {
            anyhow::bail!("no binfmt magic known for system {}", spec.system);
        }

        // see setup_stage() for why builds re-exec this binary
        let mut cmd = Command::new("/proc/self/exe");
        cmd.arg(SETUP_STAGE_ARG);
        Ok(cmd)
    }

    // Underscore form so that, in unit tests, libtest interprets it as
    // a filter selecting the dispatch test below.
    pub const SETUP_STAGE_ARG: &str = "__sandbox_setup";

    /// The spec travels via the setup stage's stdin.
    pub const SPEC_VIA_STDIN: bool = true;

    #[cfg(test)]
    pub fn stdin_mode() -> Stdio {
        Stdio::piped() // carries the serialized spec
    }

    #[cfg(test)]
    pub fn send_spec(child: &mut Child, spec: &SandboxSpec) -> Result<()> {
        let stdin = child.stdin.take().context("setup stage stdin missing")?;
        serde_json::to_writer(stdin, spec).context("sending sandbox spec")?;
        Ok(())
    }

    pub fn setup_stage() -> ! {
        let err = (|| -> io::Result<std::convert::Infallible> {
            let mut json = String::new();
            use std::io::Read;
            std::io::stdin().read_to_string(&mut json)?;
            let spec: SandboxSpec = serde_json::from_str(&json).map_err(io::Error::other)?;
            // The builder gets /dev/null as stdin, like under Nix.
            let null = std::fs::File::open("/dev/null")?;
            nix::unistd::dup2_stdin(&null).map_err(ioerr("dup2 stdin"))?;
            // Pre-open the error file: the fd keeps working after
            // pivot_root detaches the host filesystem, a path would not.
            let err_file = std::fs::File::create(setup_error_file(&spec.root))?;
            enter_and_exec(&spec).inspect_err(|e| {
                use std::io::Write;
                let _ = (&err_file).write_all(e.to_string().as_bytes());
            })
        })()
        .unwrap_err();
        // stderr is the build log pipe; the client sees the message.
        // Write to the fd, not via eprintln!: under the unit test the
        // stage runs inside libtest, which captures macro output.
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "sandbox setup: {err}");
        std::process::exit(121);
    }

    fn enter_and_exec(spec: &SandboxSpec) -> io::Result<std::convert::Infallible> {
        // Enter the build cgroup first, with the worker's full
        // credentials and before any namespace changes.
        if let Some(cg) = &spec.cgroup {
            std::fs::write(cg.join("cgroup.procs"), "0")
                .map_err(|e| io::Error::other(format!("entering build cgroup: {e}")))?;
        }
        let binfmt_line = match &spec.emulator {
            Some(_) => Some(binfmt::register_line(&spec.system).ok_or_else(|| {
                io::Error::other(format!("no binfmt magic known for system {}", spec.system))
            })?),
            None => None,
        };
        // Single uid 1000 (Nix default) or, for uid-range builds,
        // in-namespace root over a 65536-uid block. Emulated builds map
        // uid 0 for the binfmt registration, dropped to 1000 in setup().
        let backing_uid = spec.fod_uid.unwrap_or_else(|| getuid().as_raw());
        let backing_gid = spec.fod_uid.unwrap_or_else(|| getgid().as_raw());
        let (sandbox_uid, host_uid, uid_count) = match spec.uid_range {
            Some(base) => (0, base, 65536u32),
            None if binfmt_line.is_some() => (0, backing_uid, 1),
            None => (1000, backing_uid, 1),
        };
        let (sandbox_gid, host_gid) = match spec.uid_range {
            Some(base) => (0, base),
            None if binfmt_line.is_some() => (0, backing_gid),
            None => (100, backing_gid),
        };
        setup(&SetupParams {
            root: &spec.root,
            system: &spec.system,
            binfmt_line: binfmt_line.as_deref(),
            pasta: spec.pasta.as_deref(),
            fod_uid: spec.fod_uid,
            build_dir: &spec.build_dir,
            binds: &spec.binds_ro,
            binds_dev: &spec.binds_dev,
            cwd: &spec.cwd,
            network: spec.network,
            has_cgroup: spec.cgroup.is_some(),
            sandbox_uid,
            host_uid,
            sandbox_gid,
            host_gid,
            uid_count,
        })?;
        let prog = std::ffi::CString::new(spec.builder.as_str())
            .map_err(|_| io::Error::other("NUL in builder path"))?;
        let args: Vec<std::ffi::CString> = std::iter::once(Ok(prog.clone()))
            .chain(spec.args.iter().map(|a| std::ffi::CString::new(a.as_str())))
            .collect::<Result<_, _>>()
            .map_err(|_| io::Error::other("NUL in builder argument"))?;
        nix::unistd::execv(&prog, &args).map_err(ioerr("exec builder"))
    }

    fn existing_mount_flags(target: &Path) -> io::Result<MsFlags> {
        use nix::sys::statvfs::{statvfs, FsFlags};
        let st = statvfs(target).map_err(ioerr("statvfs"))?;
        let f = st.flags();
        let mut flags = MsFlags::empty();
        for (fs, ms) in [
            (FsFlags::ST_NOSUID, MsFlags::MS_NOSUID),
            (FsFlags::ST_NODEV, MsFlags::MS_NODEV),
            (FsFlags::ST_NOEXEC, MsFlags::MS_NOEXEC),
            (FsFlags::ST_NOATIME, MsFlags::MS_NOATIME),
            (FsFlags::ST_NODIRATIME, MsFlags::MS_NODIRATIME),
            (FsFlags::ST_RELATIME, MsFlags::MS_RELATIME),
        ] {
            if f.contains(fs) {
                flags |= ms;
            }
        }
        Ok(flags)
    }

    fn ioerr(step: &str) -> impl Fn(nix::errno::Errno) -> io::Error + '_ {
        move |e| io::Error::other(format!("{step}: {e}"))
    }

    /// Unshare and have a forked helper, still in the parent user
    /// namespace, write this process's uid/gid maps: multi-uid ranges
    /// need CAP_SETUID *there*, which the unshared process no longer
    /// has (hence uid-range requires a root worker).
    fn map_uid_range_via_helper(
        flags: CloneFlags,
        sandbox_uid: u32,
        host_uid: u32,
        sandbox_gid: u32,
        host_gid: u32,
        uid_count: u32,
    ) -> io::Result<()> {
        use nix::unistd::{read, write};
        let target = nix::unistd::getpid();
        let (req_r, req_w) = nix::unistd::pipe().map_err(ioerr("pipe"))?;
        let (ack_r, ack_w) = nix::unistd::pipe().map_err(ioerr("pipe"))?;
        match unsafe { nix::unistd::fork() }.map_err(ioerr("fork mapper"))? {
            nix::unistd::ForkResult::Child => {
                // Mapper: wait until the target has unshared, then map.
                let mut buf = [0u8; 1];
                let ok = read(&req_r, &mut buf).map(|n| n == 1).unwrap_or(false)
                    && std::fs::write(
                        format!("/proc/{target}/uid_map"),
                        format!("{sandbox_uid} {host_uid} {uid_count}"),
                    )
                    .is_ok()
                    && std::fs::write(
                        format!("/proc/{target}/gid_map"),
                        format!("{sandbox_gid} {host_gid} {uid_count}"),
                    )
                    .is_ok();
                let _ = write(&ack_w, if ok { b"K" } else { b"E" });
                unsafe { libc::_exit(0) }
            }
            nix::unistd::ForkResult::Parent { child } => {
                drop(req_r);
                drop(ack_w);
                unshare(flags).map_err(ioerr("unshare"))?;
                write(&req_w, b"x").map_err(ioerr("signaling uid mapper"))?;
                let mut buf = [0u8; 1];
                let n = read(&ack_r, &mut buf).map_err(ioerr("reading uid mapper ack"))?;
                let _ = nix::sys::wait::waitpid(child, None);
                if n != 1 || buf[0] != b'K' {
                    return Err(io::Error::other(
                        "uid-range mapping failed (is the worker root?)",
                    ));
                }
                Ok(())
            }
        }
    }

    struct PastaHelper {
        child: nix::unistd::Pid,
        req_w: std::os::fd::OwnedFd,
    }

    /// Fork a helper that stays in the host namespaces and execs pasta
    /// against this process once [`PastaHelper::attach`] is called
    /// (after unshare). pasta's parent exits once the namespace is
    /// configured, so waiting for the helper is the readiness barrier.
    fn fork_pasta_helper(bin: &Path) -> io::Result<PastaHelper> {
        let target = nix::unistd::getpid();
        let (req_r, req_w) = nix::unistd::pipe().map_err(ioerr("pipe"))?;
        match unsafe { nix::unistd::fork() }.map_err(ioerr("fork pasta helper"))? {
            nix::unistd::ForkResult::Child => {
                // Close our copy of the write end, or a build process
                // dying before attach() would never EOF the read below
                // and leak this helper forever.
                drop(req_w);
                let mut buf = [0u8; 1];
                let ok = nix::unistd::read(&req_r, &mut buf)
                    .map(|n| n == 1)
                    .unwrap_or(false);
                if !ok {
                    // build process died before signaling; nothing to do
                    unsafe { libc::_exit(1) }
                }
                // pasta's default port forwarding and host-loopback
                // mapping splice host services into the namespace, the
                // exact leak the private netns is meant to close.
                let args: Vec<std::ffi::CString> = [
                    bin.to_string_lossy().as_ref(),
                    "--config-net",
                    "--quiet",
                    "--dns-forward",
                    super::PASTA_DNS,
                    "-t",
                    "none",
                    "-u",
                    "none",
                    "-T",
                    "none",
                    "-U",
                    "none",
                    "--map-host-loopback",
                    "none",
                    &target.to_string(),
                ]
                .iter()
                .map(|s| std::ffi::CString::new(*s).unwrap())
                .collect();
                drop(req_r); // do not leak the pipe into pasta
                let _ = nix::unistd::execv(&args[0], &args);
                unsafe { libc::_exit(127) }
            }
            nix::unistd::ForkResult::Parent { child } => {
                drop(req_r);
                Ok(PastaHelper { child, req_w })
            }
        }
    }

    impl PastaHelper {
        fn attach(self) -> io::Result<()> {
            use nix::sys::wait::{waitpid, WaitStatus};
            nix::unistd::write(&self.req_w, b"x").map_err(ioerr("signaling pasta helper"))?;
            match waitpid(self.child, None) {
                Ok(WaitStatus::Exited(_, 0)) => Ok(()),
                other => Err(io::Error::other(format!(
                    "pasta failed to attach to the build netns: {other:?}"
                ))),
            }
        }
    }

    /// Bring the loopback interface up. A fresh network namespace has
    /// `lo` down; builders that talk to 127.0.0.1 (test suites) would
    /// otherwise fail, unlike under Nix's own sandbox.
    fn loopback_up() -> io::Result<()> {
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut ifr: libc::ifreq = std::mem::zeroed();
            for (i, b) in b"lo".iter().enumerate() {
                ifr.ifr_name[i] = *b as libc::c_char;
            }
            ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            let res = libc::ioctl(fd, libc::SIOCSIFFLAGS, &ifr);
            let err = io::Error::last_os_error();
            libc::close(fd);
            if res < 0 {
                return Err(err);
            }
        }
        Ok(())
    }

    /// Fork so the exec'd builder is PID 1 of the new PID namespace;
    /// this process becomes a shim that forwards the builder's exit
    /// status. When PID 1 dies the kernel kills every namespace member,
    /// so daemonized/setsid'd builder children cannot outlive the build.
    fn fork_into_pid_ns() -> io::Result<bool> {
        match unsafe { nix::unistd::fork() }.map_err(ioerr("fork"))? {
            nix::unistd::ForkResult::Child => Ok(true),
            nix::unistd::ForkResult::Parent { child } => {
                use nix::sys::wait::{waitpid, WaitStatus};
                // Drop every inherited fd: the long-lived shim must not
                // hold the log pipes (or the setup error file) open for
                // the build's whole lifetime.
                unsafe {
                    libc::syscall(libc::SYS_close_range, 3, libc::c_uint::MAX, 0);
                }
                let code = loop {
                    match waitpid(child, None) {
                        Ok(WaitStatus::Exited(_, code)) => break code,
                        Ok(WaitStatus::Signaled(_, sig, _)) => break 128 + sig as i32,
                        Ok(_) => continue,
                        Err(nix::errno::Errno::EINTR) => continue,
                        Err(_) => break 1,
                    }
                };
                unsafe { libc::_exit(code) }
            }
        }
    }

    struct SetupParams<'a> {
        root: &'a Path,
        system: &'a str,
        binfmt_line: Option<&'a str>,
        pasta: Option<&'a Path>,
        fod_uid: Option<u32>,
        build_dir: &'a Path,
        binds: &'a [(PathBuf, PathBuf)],
        binds_dev: &'a [(PathBuf, PathBuf)],
        cwd: &'a str,
        network: bool,
        has_cgroup: bool,
        sandbox_uid: u32,
        host_uid: u32,
        sandbox_gid: u32,
        host_gid: u32,
        uid_count: u32,
    }

    fn setup(p: &SetupParams) -> io::Result<()> {
        let SetupParams {
            root,
            system,
            binfmt_line,
            pasta,
            fod_uid,
            build_dir,
            binds,
            binds_dev,
            cwd,
            network,
            has_cgroup,
            sandbox_uid,
            host_uid,
            sandbox_gid,
            host_gid,
            uid_count,
        } = *p;
        let mut flags = CloneFlags::CLONE_NEWUSER
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWIPC
            | CloneFlags::CLONE_NEWUTS;
        // Network builds keep the host namespace only without pasta;
        // with it they get a private one plus user-mode NAT.
        // Drop host root before creating any namespace, so the userns
        // is owned by the unprivileged uid and rootless pasta can
        // attach to it.
        if let Some(uid) = fod_uid {
            nix::unistd::setgroups(&[]).map_err(ioerr("fod setgroups"))?;
            nix::unistd::setgid(nix::unistd::Gid::from_raw(uid)).map_err(ioerr("fod setgid"))?;
            nix::unistd::setuid(nix::unistd::Uid::from_raw(uid)).map_err(ioerr("fod setuid"))?;
            // setuid cleared the dumpable flag, which makes /proc/self
            // root-owned; restore it so the uid/gid map writes below
            // (and pasta's /proc access) work.
            nix::sys::prctl::set_dumpable(true).map_err(ioerr("set_dumpable"))?;
        }
        let private_net = !network || pasta.is_some();
        if private_net {
            flags |= CloneFlags::CLONE_NEWNET;
        }
        let pasta_helper = match pasta {
            Some(bin) if network => Some(fork_pasta_helper(bin)?),
            _ => None,
        };
        if has_cgroup {
            // Cgroup namespace rooted at the just-entered build cgroup:
            // the cgroup2 mount below then exposes only the build's own
            // delegated subtree (usable by nspawn inside the sandbox).
            flags |= CloneFlags::CLONE_NEWCGROUP;
        }
        let werr = |step: &str| {
            let step = step.to_string();
            move |e: io::Error| io::Error::other(format!("{step}: {e}"))
        };
        if uid_count == 1 {
            // Unprivileged self-mapping of the caller's own uid.
            unshare(flags).map_err(ioerr("unshare"))?;
            std::fs::write("/proc/self/setgroups", "deny").map_err(werr("setgroups"))?;
            std::fs::write(
                "/proc/self/uid_map",
                format!("{sandbox_uid} {host_uid} {uid_count}"),
            )
            .map_err(werr("uid_map"))?;
            std::fs::write(
                "/proc/self/gid_map",
                format!("{sandbox_gid} {host_gid} {uid_count}"),
            )
            .map_err(werr("gid_map"))?;
        } else {
            map_uid_range_via_helper(
                flags,
                sandbox_uid,
                host_uid,
                sandbox_gid,
                host_gid,
                uid_count,
            )?;
        }
        sethostname("localhost").map_err(ioerr("sethostname"))?;
        // "(none)" is the kernel default; fixed like Nix for determinism
        if unsafe { libc::setdomainname(c"(none)".as_ptr(), 6) } == -1 {
            return Err(io::Error::last_os_error());
        }
        if private_net {
            loopback_up().map_err(werr("bringing lo up"))?;
        }
        if let Some(helper) = pasta_helper {
            helper.attach()?;
        }

        // CLONE_NEWPID only applies to children: fork so the builder
        // runs as PID 1. Everything below runs in the child.
        if !fork_into_pid_ns()? {
            unreachable!("parent never returns");
        }

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

        let bind_one = |src: &Path, dst: &Path, ro: bool, extra: MsFlags| -> io::Result<()> {
            let target = root.join(dst.strip_prefix("/").unwrap_or(dst));
            mount(
                Some(src),
                &target,
                none,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                none,
            )
            .map_err(|e| io::Error::other(format!("binding {}: {e}", src.display())))?;
            // In a user namespace, a bind mount keeps its source's
            // locked flags (nosuid, nodev, ...); a remount that drops
            // any of them fails with EPERM, so carry them over.
            let locked = existing_mount_flags(&target)?;
            let mut remount = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | locked | extra;
            if ro {
                remount |= MsFlags::MS_RDONLY;
            }
            mount(none, &target, none, remount, none)
                .map_err(|e| io::Error::other(format!("remounting {}: {e}", src.display())))?;
            Ok(())
        };
        // Request-derived binds are always read-only; only the sandbox's
        // own device nodes stay writable. Keying writability on a path
        // prefix of a client-influenced destination would let a request
        // bind host devices read-write.
        let nosuid_nodev = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
        for (src, dst) in binds {
            bind_one(src, dst, true, nosuid_nodev)?;
        }
        for (src, dst) in binds_dev {
            bind_one(src, dst, false, MsFlags::MS_NOSUID)?;
        }
        bind_one(build_dir, Path::new(cwd), false, nosuid_nodev)?;

        mount(
            Some("tmpfs"),
            &root.join("dev/shm"),
            Some("tmpfs"),
            nosuid_nodev,
            Some("mode=1777"),
        )
        .map_err(ioerr("mounting /dev/shm"))?;
        mount(
            Some("devpts"),
            &root.join("dev/pts"),
            Some("devpts"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some("newinstance,mode=0620,ptmxmode=0666"),
        )
        .map_err(ioerr("mounting /dev/pts"))?;

        // Inside the fresh PID namespace this shows only the build's own
        // processes; the old host-/proc bind fallback exposed every host
        // PID (and /proc/<pid>/root, a chroot escape).
        mount(
            Some("proc"),
            &root.join("proc"),
            Some("proc"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            none,
        )
        .map_err(ioerr("mounting /proc"))?;

        // Like Nix: uid-range builds get a real sysfs (the userns owns
        // its netns, so the kernel allows it); container managers fail
        // without one ("VFS: Mount too revealing").
        if uid_count > 1 {
            mount(
                Some("sysfs"),
                &root.join("sys"),
                Some("sysfs"),
                MsFlags::empty(),
                none,
            )
            .map_err(ioerr("mounting /sys"))?;
        }

        if has_cgroup {
            // the cgroup namespace makes the build's own cgroup the root
            mount(
                Some("cgroup2"),
                &root.join("sys/fs/cgroup"),
                Some("cgroup2"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                none,
            )
            .map_err(ioerr("mounting /sys/fs/cgroup"))?;
        }

        // pivot_root + detach the old root: unlike a bare chroot, the
        // host filesystem is no longer reachable in this namespace.
        std::env::set_current_dir(root)
            .map_err(|e| io::Error::other(format!("chdir to root: {e}")))?;
        pivot_root(".", ".").map_err(ioerr("pivot_root"))?;
        umount2(".", MntFlags::MNT_DETACH).map_err(ioerr("detaching old root"))?;
        std::env::set_current_dir("/").map_err(|e| io::Error::other(format!("chdir /: {e}")))?;
        std::env::set_current_dir(cwd)
            .map_err(|e| io::Error::other(format!("chdir {cwd}: {e}")))?;

        if let Some(line) = binfmt_line {
            // Fresh per-userns binfmt_misc instance (kernel 6.7+).
            mount(
                Some("binfmt_misc"),
                "/proc/sys/fs/binfmt_misc",
                Some("binfmt_misc"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                none,
            )
            .map_err(ioerr(
                "mounting binfmt_misc (emulated builds need kernel 6.7+)",
            ))?;
            std::fs::write("/proc/sys/fs/binfmt_misc/register", line)
                .map_err(|e| io::Error::other(format!("registering binfmt entry: {e}")))?;
        }

        // Last-resort fork-bomb brake; the PID namespace makes the bomb
        // killable, the rlimit caps how big it can get. Clamp to the
        // inherited hard limit: raising it needs init-ns CAP_SYS_RESOURCE,
        // which the child userns does not have.
        use nix::sys::resource::{getrlimit, setrlimit, Resource};
        let (_, hard) = getrlimit(Resource::RLIMIT_NPROC).map_err(ioerr("getrlimit NPROC"))?;
        let limit = hard.min(4096);
        setrlimit(Resource::RLIMIT_NPROC, limit, limit).map_err(ioerr("setting RLIMIT_NPROC"))?;

        // Like Nix: no core dumps in outputs, a predictable umask
        // (output modes feed the NAR hash), 32-bit personality for
        // 32-bit systems, no ASLR for determinism, and no privilege
        // gain via setuid binaries.
        setrlimit(Resource::RLIMIT_CORE, 0, nix::sys::resource::RLIM_INFINITY)
            .map_err(ioerr("setting RLIMIT_CORE"))?;
        nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o022));
        if matches!(
            system,
            "i686-linux" | "armv7l-linux" | "armv6l-linux" | "armv5tel-linux"
        ) {
            // PER_LINUX32 is a base persona, not a flag bit, so the nix
            // crate's Persona bitflags cannot express it.
            if unsafe {
                libc::personality(0x0008 /* PER_LINUX32 */)
            } == -1
            {
                return Err(io::Error::last_os_error());
            }
        }
        use nix::sys::personality::{self, Persona};
        if let Ok(persona) = personality::get() {
            let _ = personality::set(persona | Persona::ADDR_NO_RANDOMIZE);
        }
        nix::sys::prctl::set_no_new_privs().map_err(ioerr("PR_SET_NO_NEW_PRIVS"))?;

        // uid-range: become the in-namespace root the mapping promised;
        // the worker's own uid is outside the mapped block. Single-uid
        // builds already run as the mapped uid.
        if uid_count > 1 {
            nix::unistd::setgroups(&[]).map_err(ioerr("setgroups"))?;
            nix::unistd::setgid(nix::unistd::Gid::from_raw(sandbox_gid))
                .map_err(ioerr("setgid"))?;
            nix::unistd::setuid(nix::unistd::Uid::from_raw(sandbox_uid))
                .map_err(ioerr("setuid"))?;
        } else if binfmt_line.is_some() {
            // binfmt registration needed in-namespace root; remap to
            // Nix's uid 1000 via a nested userns. Exec lookup falls back
            // to the ancestor namespace's binfmt instance.
            unshare(CloneFlags::CLONE_NEWUSER).map_err(ioerr("nested unshare"))?;
            std::fs::write("/proc/self/setgroups", "deny").map_err(werr("nested setgroups"))?;
            std::fs::write("/proc/self/uid_map", "1000 0 1").map_err(werr("nested uid_map"))?;
            std::fs::write("/proc/self/gid_map", "100 0 1").map_err(werr("nested gid_map"))?;
        }
        Ok(())
    }

    pub fn setup_error_file(root: &Path) -> PathBuf {
        root.with_file_name("setup-error")
    }

    pub fn setup_error_detail_impl(spec: &SandboxSpec) -> Option<String> {
        std::fs::read_to_string(setup_error_file(&spec.root))
            .ok()
            .filter(|s| !s.is_empty())
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
        // No bind mounts on Darwin: inputs already live at their real
        // /nix/store paths (the worker imports them via the daemon),
        // so there is nothing to materialize.
        spec.binds_ro.clear();
        // env refers to tmpDirInSandbox; link it to the real build dir.
        let link = Path::new(&spec.cwd);
        // Don't trust the hub: a root worker creating a symlink at an
        // arbitrary path is a takeover primitive. Allow only tmp
        // prefixes and the shared /build (serialized by the caller).
        let allowed = spec.cwd == "/build"
            || [
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
            profile.push_str(&format!(
                "(deny file-read* (literal \"{}\"))\n",
                sb_escape(&secret.to_string_lossy())?
            ));
        }
        profile.push_str("(allow file-write*\n");
        for path in [spec.cwd.as_str(), &spec.build_dir.to_string_lossy()] {
            profile.push_str(&format!("  (subpath \"{}\")\n", sb_escape(path)?));
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
        for out in &spec.outputs {
            profile.push_str(&format!("  (subpath \"{}\")\n", sb_escape(out)?));
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// Not a test: re-exec target for `sandbox_runs_builder`. There
    /// `/proc/self/exe` is the libtest binary, which treats the stage
    /// argument as a name filter selecting exactly this function.
    /// No-op in normal test runs.
    #[cfg(target_os = "linux")]
    #[test]
    fn __sandbox_setup() {
        if std::env::args().any(|a| a == SETUP_STAGE_ARG) {
            // CLONE_NEWUSER requires a single-threaded process and
            // libtest has already spawned threads; a forked child is
            // single-threaded again.
            match unsafe { nix::unistd::fork() }.expect("fork") {
                nix::unistd::ForkResult::Child => setup_stage(),
                nix::unistd::ForkResult::Parent { child } => {
                    use nix::sys::wait::{waitpid, WaitStatus};
                    let code = match waitpid(child, None) {
                        Ok(WaitStatus::Exited(_, code)) => code,
                        other => panic!("setup stage: {other:?}"),
                    };
                    std::process::exit(code);
                }
            }
        }
    }

    /// End-to-end smoke test of the Linux sandbox: namespaces, mounts,
    /// pivot_root, /proc, loopback, and exit-code plumbing through the
    /// PID-namespace shim. Requires unprivileged user namespaces.
    #[test]
    fn sandbox_runs_builder() -> Result<()> {
        if nix::sched::unshare(nix::sched::CloneFlags::empty()).is_err() {
            return Ok(()); // no namespace support in this environment
        }
        let dir = tempfile::tempdir()?;
        let mut spec = SandboxSpec {
            builder: "/bin/sh".into(),
            system: "x86_64-linux".into(),
            args: vec![
                "-c".into(),
                // sleep keeps the builder alive so the timing assertion
                // below is meaningful; environments without a sleep
                // binary (Nix's busybox /bin/sh) just exit fast.
                "test -w /build && test -d /proc/self && test -d /dev/shm || exit 1; \
                 sleep 1 2>/dev/null; exit 7"
                    .into(),
            ],
            env: HashMap::new(),
            cwd: "/build".into(),
            network: false,
            root: dir.path().join("root"),
            build_dir: dir.path().join("top/build"),
            binds_ro: ["/bin", "/usr", "/lib", "/lib64", "/nix/store"]
                .iter()
                .filter(|p| Path::new(p).exists())
                .map(|p| (PathBuf::from(p), PathBuf::from(p)))
                .collect(),
            binds_dev: vec![],
            outputs: vec![],
            cgroup: None,
            uid_range: None,
            fod_uid: None,
            pasta: None,
            emulator: None,
            deny_read: vec![],
        };
        std::fs::create_dir_all(&spec.build_dir)?;
        platform::prepare(&mut spec)?;
        let log_path = dir.path().join("build.log");
        let started = std::time::Instant::now();
        let mut child = spawn(&spec, std::fs::File::create(&log_path)?)?;
        // spawn must return as soon as the builder execs; if the PID-ns
        // shim kept std's status pipe open, spawn would block for the
        // whole build and deadlock against the unread pipe.
        assert!(
            started.elapsed() < std::time::Duration::from_millis(900),
            "spawn blocked until builder exit"
        );
        let status = child.wait()?;
        let stderr = std::fs::read_to_string(&log_path)?;
        assert_eq!(status.code(), Some(7), "{status:?} log: {stderr}");
        Ok(())
    }
}
