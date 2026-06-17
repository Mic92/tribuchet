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
#[cfg(test)]
use std::process::{Child, Stdio};

use anyhow::{Context, Result};

use super::binfmt;
use crate::proto::BuildAssignment;

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
    /// Input store paths visible to the builder; reference-scan
    /// candidates alongside outputs.
    #[serde(default)]
    pub store_inputs: Vec<String>,
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
    /// Sandbox has the host daemon socket bind-mounted in; the
    /// closure-delta producer also consults this flag.
    #[serde(default)]
    pub recursive_nix: bool,
}

/// Default daemon socket path inside the sandbox; `nix` looks here
/// unless `NIX_REMOTE` overrides.
pub const NIX_DAEMON_SOCKET: &str = "/nix/var/nix/daemon-socket/socket";

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
    /// Bind-mount the host nix-daemon socket into the sandbox so the
    /// builder can register inner-build outputs.
    pub recursive_nix: bool,
    /// Host path of the daemon socket to expose; only consulted when
    /// `recursive_nix` is set.
    pub nix_daemon_socket: Option<&'a Path>,
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
        store_inputs: inputs.to_vec(),
        cgroup: None,
        uid_range: opts.uid_range,
        fod_uid: opts.fod_uid.filter(|_| a.fixed_output),
        pasta: opts.pasta.filter(|_| a.fixed_output).map(Path::to_path_buf),
        emulator: opts.emulator.map(Path::to_path_buf),
        deny_read: opts.secrets.to_vec(),
        recursive_nix: opts.recursive_nix,
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
        if opts.recursive_nix {
            let host = opts
                .nix_daemon_socket
                .unwrap_or_else(|| Path::new(NIX_DAEMON_SOCKET));
            spec.binds_ro
                .push((host.to_path_buf(), PathBuf::from(NIX_DAEMON_SOCKET)));
            // The hub-side patched Nix points NIX_REMOTE at its own
            // topTmpDir/.nix-socket (where its in-process recursive
            // daemon would listen); redirect to the worker's daemon.
            spec.env.insert(
                "NIX_REMOTE".to_owned(),
                format!("unix://{NIX_DAEMON_SOCKET}"),
            );
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
        // The derivation env must not reach the pre-sandbox setup stage
        // (worker binary, worker host credentials): LD_PRELOAD would run
        // client code outside the sandbox. With the spec on stdin the
        // env is applied at the builder exec instead.
        env: if platform::SPEC_VIA_STDIN {
            Vec::new()
        } else {
            spec.env
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        },
        cwd: cmd
            .get_current_dir()
            .map(|p| p.to_string_lossy().into_owned()),
        has_stdin: platform::SPEC_VIA_STDIN,
        token: String::new(),
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
    cmd.env_clear();
    // Mirror the reaper: with the spec on stdin the builder env is
    // applied at the builder exec, not on the setup stage process.
    if !platform::SPEC_VIA_STDIN {
        cmd.envs(&spec.env);
    }
    cmd.stdin(platform::stdin_mode())
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
#[path = "sandbox/linux.rs"]
mod platform;

#[cfg(target_os = "macos")]
#[path = "sandbox/darwin.rs"]
mod platform;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn min_assignment() -> crate::proto::BuildAssignment {
        crate::proto::BuildAssignment {
            build_id: "0123456789abcdef0123456789abcdef".into(),
            dedupe_key: "k".into(),
            system: "x86_64-linux".into(),
            builder: "/nix/store/00000000000000000000000000000000-b/bin/b".into(),
            args: vec![],
            env: HashMap::default(),
            outputs: HashMap::default(),
            tmp_dir_in_sandbox: "/build".into(),
            store_dir: "/nix/store".into(),
            fixed_output: false,
        }
    }

    /// recursive-nix flag toggles a daemon-socket bind; without it,
    /// no /nix/var path appears in binds_ro.
    #[cfg(target_os = "linux")]
    #[test]
    fn recursive_nix_adds_the_daemon_socket_bind() -> Result<()> {
        let host = tempfile::tempdir()?;
        let host_sock = host.path().join("sock");
        std::fs::File::create(&host_sock)?;

        let off_dir = tempfile::tempdir()?;
        let off = prepare(
            &min_assignment(),
            off_dir.path(),
            &[],
            &PrepareOpts {
                recursive_nix: false,
                nix_daemon_socket: Some(&host_sock),
                ..Default::default()
            },
        )?;
        assert!(off
            .binds_ro
            .iter()
            .all(|(_, dst)| dst != Path::new(NIX_DAEMON_SOCKET)));

        let on_dir = tempfile::tempdir()?;
        let on = prepare(
            &min_assignment(),
            on_dir.path(),
            &[],
            &PrepareOpts {
                recursive_nix: true,
                nix_daemon_socket: Some(&host_sock),
                ..Default::default()
            },
        )?;
        assert!(on
            .binds_ro
            .iter()
            .any(|(src, dst)| src == &host_sock && dst == Path::new(NIX_DAEMON_SOCKET)));
        Ok(())
    }

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

    /// The derivation env is client-controlled (LD_PRELOAD, …) and must
    /// not be applied to the setup stage, which runs the worker binary
    /// with the worker's host credentials before entering the sandbox.
    #[cfg(target_os = "linux")]
    #[test]
    fn derivation_env_stays_off_the_setup_stage() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let spec = SandboxSpec {
            builder: "/bin/sh".into(),
            system: "x86_64-linux".into(),
            args: vec![],
            env: HashMap::from([("LD_PRELOAD".into(), "/nix/store/evil.so".into())]),
            cwd: "/build".into(),
            network: false,
            root: dir.path().join("root"),
            build_dir: dir.path().join("top/build"),
            binds_ro: vec![],
            store_inputs: vec![],
            recursive_nix: false,
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
        let (req, _r, _w) = spawn_request(&spec)?;
        assert!(req.env.is_empty(), "setup stage env: {:?}", req.env);
        Ok(())
    }

    /// End-to-end smoke test of the Linux sandbox: namespaces, mounts,
    /// pivot_root, /proc, loopback, and exit-code plumbing through the
    /// PID-namespace shim. Requires unprivileged user namespaces.
    #[cfg(target_os = "linux")]
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
                // $FOO asserts the derivation env reaches the builder
                // even though the setup stage runs with a clean env.
                "test -w /build && test -d /proc/self && test -d /dev/shm || exit 1; \
                 test \"$FOO\" = bar || exit 2; \
                 sleep 1 2>/dev/null; exit 7"
                    .into(),
            ],
            env: HashMap::from([("FOO".into(), "bar".into())]),
            cwd: "/build".into(),
            network: false,
            root: dir.path().join("root"),
            build_dir: dir.path().join("top/build"),
            store_inputs: vec![],
            recursive_nix: false,
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

    /// End-to-end smoke test of the Darwin sandbox: prepare's tmp-dir
    /// symlink, writes confined to the build dir, deny_read on worker
    /// secrets, and exit-code plumbing through sandbox-exec.
    #[cfg(target_os = "macos")]
    #[test]
    fn sandbox_runs_builder() -> Result<()> {
        // tempdir lives under $TMPDIR (/var/folders/...), one of the
        // tmp prefixes prepare() accepts for the cwd symlink.
        let dir = tempfile::tempdir()?;
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "key-material")?;
        let outside = dir.path().join("outside");
        let cwd = dir.path().join("build-link");
        let mut spec = SandboxSpec {
            builder: "/bin/sh".into(),
            system: "aarch64-darwin".into(),
            args: vec![
                "-c".into(),
                // Each escape attempt exits with its own code so a
                // failure names the broken rule; 7 means all held.
                // $FOO asserts the derivation env reaches the builder.
                format!(
                    "test \"$FOO\" = bar || exit 1; \
                     echo ok > out || exit 2; \
                     cat {secret} 2>/dev/null && exit 3; \
                     echo escaped > {outside} 2>/dev/null && exit 4; \
                     exit 7",
                    secret = secret.display(),
                    outside = outside.display()
                ),
            ],
            env: HashMap::from([("FOO".into(), "bar".into())]),
            cwd: cwd.to_string_lossy().into_owned(),
            network: false,
            root: dir.path().join("root"),
            build_dir: dir.path().join("top/build"),
            binds_ro: vec![],
            binds_dev: vec![],
            outputs: vec![],
            store_inputs: vec![],
            cgroup: None,
            uid_range: None,
            fod_uid: None,
            pasta: None,
            emulator: None,
            deny_read: vec![secret],
            recursive_nix: false,
        };
        std::fs::create_dir_all(&spec.build_dir)?;
        platform::prepare(&mut spec)?;
        let log_path = dir.path().join("build.log");
        let mut child = spawn(&spec, std::fs::File::create(&log_path)?)?;
        let status = child.wait()?;
        let log = std::fs::read_to_string(&log_path)?;
        assert_eq!(status.code(), Some(7), "{status:?} log: {log}");
        assert_eq!(std::fs::read_to_string(spec.build_dir.join("out"))?, "ok\n");
        Ok(())
    }
}
