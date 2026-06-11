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

pub fn prepare(
    a: &BuildAssignment,
    dir: &Path,
    sources: &HashMap<String, PathBuf>,
    bin_sh: Option<&Path>,
    secrets: &[PathBuf],
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
        binds_dev: Vec::new(),
        outputs: a.outputs.values().cloned().collect(),
        cgroup: None,
        deny_read: secrets.to_vec(),
    };
    if cfg!(target_os = "linux") {
        if let Some(sh) = bin_sh {
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

pub fn spawn(spec: &SandboxSpec) -> Result<Child> {
    let mut cmd = platform::command(spec)?;
    // Own process group, so orphaned builder children can be killed
    // after the builder exits (there is no PID namespace to do it).
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    cmd.env_clear()
        .envs(&spec.env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.spawn().with_context(|| {
        let detail = platform::spawn_error_detail(spec)
            .map(|d| format!(" ({d})"))
            .unwrap_or_default();
        format!("spawning builder {}{detail}", spec.builder)
    })
}

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
    use std::os::unix::process::CommandExt;

    pub fn prepare(spec: &mut SandboxSpec) -> Result<()> {
        let root = &spec.root;
        for sub in [
            "nix/store",
            "build",
            "dev",
            "dev/shm",
            "dev/pts",
            "proc",
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

        for dev in ["null", "zero", "random", "urandom", "tty"] {
            let host = PathBuf::from("/dev").join(dev);
            std::fs::File::create(root.join("dev").join(dev))?;
            spec.binds_dev.push((host.clone(), host)); // dev nodes: bind, rw via node perms
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
            let resolv = std::fs::read("/etc/resolv.conf").unwrap_or_default();
            std::fs::write(root.join("etc/resolv.conf"), resolv)?;
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

        let mut cmd = Command::new(&spec.builder);
        cmd.args(&spec.args);

        let root = spec.root.clone();
        let build_dir = spec.build_dir.clone();
        let binds: Vec<(PathBuf, PathBuf)> = spec.binds_ro.clone();
        let binds_dev: Vec<(PathBuf, PathBuf)> = spec.binds_dev.clone();
        let cgroup_procs = spec.cgroup.as_ref().map(|c| c.join("cgroup.procs"));
        let cwd = spec.cwd.clone();
        let network = spec.network;
        let uid = getuid().as_raw();
        let gid = getgid().as_raw();

        // Pre-open the error file: an fd keeps working after pivot_root
        // detaches the host filesystem, a path would not.
        let err_file: std::fs::File = std::fs::File::create(setup_error_file(&spec.root))?;
        unsafe {
            cmd.pre_exec(move || {
                // Enter the build cgroup first, with the worker's full
                // credentials and before any namespace changes.
                if let Some(procs) = &cgroup_procs {
                    std::fs::write(procs, "0")
                        .map_err(|e| io::Error::other(format!("entering build cgroup: {e}")))?;
                }
                setup(
                    &root, &build_dir, &binds, &binds_dev, &cwd, network, uid, gid,
                )
                .inspect_err(|e| {
                    // std forwards only the errno from pre_exec to the
                    // parent, dropping our message; leave the failing
                    // step in a file the parent reads on spawn failure.
                    use std::io::Write;
                    let _ = (&err_file).write_all(e.to_string().as_bytes());
                })
            });
        }
        Ok(cmd)
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
                // Drop every inherited fd, most importantly std's CLOEXEC
                // status pipe: while the shim holds it, Command::spawn in
                // the worker would block until the build finishes (and
                // deadlock against a full, unread log pipe).
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

    #[allow(clippy::too_many_arguments)]
    fn setup(
        root: &Path,
        build_dir: &Path,
        binds: &[(PathBuf, PathBuf)],
        binds_dev: &[(PathBuf, PathBuf)],
        cwd: &str,
        network: bool,
        uid: u32,
        gid: u32,
    ) -> io::Result<()> {
        let mut flags = CloneFlags::CLONE_NEWUSER
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWPID
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
        if !network {
            loopback_up().map_err(werr("bringing lo up"))?;
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

        // pivot_root + detach the old root: unlike a bare chroot, the
        // host filesystem is no longer reachable in this namespace.
        std::env::set_current_dir(root)
            .map_err(|e| io::Error::other(format!("chdir to root: {e}")))?;
        pivot_root(".", ".").map_err(ioerr("pivot_root"))?;
        umount2(".", MntFlags::MNT_DETACH).map_err(ioerr("detaching old root"))?;
        std::env::set_current_dir("/").map_err(|e| io::Error::other(format!("chdir /: {e}")))?;
        std::env::set_current_dir(cwd)
            .map_err(|e| io::Error::other(format!("chdir {cwd}: {e}")))?;

        // Last-resort fork-bomb brake; the PID namespace makes the bomb
        // killable, the rlimit caps how big it can get. Clamp to the
        // inherited hard limit: raising it needs init-ns CAP_SYS_RESOURCE,
        // which the child userns does not have.
        use nix::sys::resource::{getrlimit, setrlimit, Resource};
        let (_, hard) = getrlimit(Resource::RLIMIT_NPROC).map_err(ioerr("getrlimit NPROC"))?;
        let limit = hard.min(4096);
        setrlimit(Resource::RLIMIT_NPROC, limit, limit).map_err(ioerr("setting RLIMIT_NPROC"))?;
        Ok(())
    }

    pub fn setup_error_file(root: &Path) -> PathBuf {
        root.with_file_name("setup-error")
    }

    pub fn spawn_error_detail(spec: &SandboxSpec) -> Option<String> {
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

    pub fn spawn_error_detail(_spec: &SandboxSpec) -> Option<String> {
        None
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
            deny_read: vec![],
        };
        std::fs::create_dir_all(&spec.build_dir)?;
        platform::prepare(&mut spec)?;
        let started = std::time::Instant::now();
        let mut child = spawn(&spec)?;
        // spawn must return as soon as the builder execs; if the PID-ns
        // shim kept std's status pipe open, spawn would block for the
        // whole build and deadlock against unread log pipes.
        assert!(
            started.elapsed() < std::time::Duration::from_millis(900),
            "spawn blocked until builder exit"
        );
        let status = child.wait()?;
        assert_eq!(status.code(), Some(7), "{status:?}");
        Ok(())
    }
}
