//! Build sandbox.
//!
//! Linux: user/mount/ipc/uts (and, unless fixed-output, net) namespaces;
//! input paths bind-mounted read-only at their store paths inside a
//! private root, scratch outputs created in a writable store dir, the
//! shipped tmp dir mounted at /build, minimal /dev, fresh /proc, chroot.
//! Reference: `nix/src/libstore/unix/build/derivation-builder.cc`.
//!
//! macOS: builds are not run by the worker at all. Each one is leased
//! to a per-uid launchd agent that applies a seatbelt profile (see
//! worker/agent.rs and worker/agents.rs). The pieces here that stay in
//! use on macOS are the spec type (which the shared output-packing
//! code reads) and the exit/cleanup shims.

use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::{Child, Command, Stdio};

#[cfg(target_os = "linux")]
use anyhow::{Context, Result};

#[cfg(target_os = "linux")]
use super::binfmt;
use crate::netpolicy::NetPolicy;
#[cfg(target_os = "linux")]
use crate::proto::BuildAssignment;

// On macOS only the fields the shared packing code reads are used;
// the rest exists so a Linux worker's persisted spec deserializes.
#[cfg_attr(target_os = "macos", allow(dead_code))]
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SandboxSpec {
    pub builder: String,
    /// Derivation system, e.g. "i686-linux" (drives Linux personality).
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
    pub binds_dev: Vec<(PathBuf, PathBuf)>,
    /// Scratch output store paths.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub outputs: Vec<String>,
    /// Input store paths visible to the builder; reference-scan
    /// candidates alongside outputs.
    #[serde(default)]
    pub store_inputs: Vec<String>,
    /// Store objects that are themselves symlinks: (path inside the
    /// sandbox, link target). Bind-mounting such a path would silently
    /// dereference it, so they are recreated as symlinks instead.
    #[serde(default)]
    pub symlink_inputs: Vec<(PathBuf, PathBuf)>,
    /// Per-build cgroup; the builder enters it from pre_exec so the
    /// memory limit covers the whole build, including the setup phase.
    pub cgroup: Option<PathBuf>,
    /// Path to the user namespace mapped by tribuchet-sandboxd; the
    /// setup stage joins it instead of writing uid maps itself.
    #[serde(default)]
    pub leased_userns: Option<PathBuf>,
    /// Uids mapped in that namespace at in-ns 0 (1 or 65536).
    #[serde(default)]
    pub leased_uid_count: Option<u32>,
    /// Fixed-output build: private netns with the presto-pasta
    /// user-mode NAT; host abstract sockets and loopback services
    /// stay unreachable.
    #[serde(default)]
    pub net_isolation: bool,
    /// Flow policy applied to that network.
    #[serde(default)]
    pub net_policy: NetPolicy,
    /// Static emulator binary for foreign-system builds, bound at
    /// binfmt::INTERP_PATH and registered in a per-userns binfmt_misc
    /// instance.
    pub emulator: Option<PathBuf>,
    /// Secret files the build must never read (worker signing/TLS
    /// keys). Defense in depth, the mount namespace already hides them.
    pub deny_read: Vec<PathBuf>,
    /// Sandbox has the host daemon socket bind-mounted in; the
    /// closure-delta producer also consults this flag.
    #[serde(default)]
    pub recursive_nix: bool,
}

/// Default daemon socket path inside the sandbox; `nix` looks here
/// unless `NIX_REMOTE` overrides.
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
#[derive(Default)]
pub struct PrepareOpts<'a> {
    pub bin_sh: Option<&'a Path>,
    pub secrets: &'a [PathBuf],
    /// User namespace leased from tribuchet-sandboxd.
    pub leased_userns: Option<PathBuf>,
    /// Uids mapped in the leased namespace (1 or 65536).
    pub leased_uid_count: Option<u32>,
    pub emulator: Option<&'a Path>,
    /// Fixed-output builds get a private netns with user-mode NAT.
    pub net_isolation: bool,
    /// Flow policy applied to that network.
    pub net_policy: NetPolicy,
    /// Bind-mount the host nix-daemon socket into the sandbox so the
    /// builder can register inner-build outputs.
    pub recursive_nix: bool,
    /// Host path of the daemon socket to expose; only consulted when
    /// `recursive_nix` is set.
    pub nix_daemon_socket: Option<&'a Path>,
}

#[cfg(target_os = "linux")]
pub fn prepare(
    a: &BuildAssignment,
    dir: &Path,
    inputs: &[String],
    opts: &PrepareOpts,
) -> Result<SandboxSpec> {
    let build_dir = dir.join("top").join("build");
    fs::create_dir_all(&build_dir)?;
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
            .filter(|p| !Path::new(p).is_symlink())
            .map(|p| (PathBuf::from(p), PathBuf::from(p)))
            .collect(),
        symlink_inputs: inputs
            .iter()
            .filter(|p| Path::new(p).is_symlink())
            .filter_map(|p| Some((PathBuf::from(p), fs::read_link(p).ok()?)))
            .collect(),
        binds_dev: Vec::new(),
        outputs: a.outputs.values().cloned().collect(),
        store_inputs: inputs.to_vec(),
        cgroup: None,
        leased_userns: opts.leased_userns.clone(),
        leased_uid_count: opts.leased_uid_count,
        net_isolation: opts.net_isolation && a.fixed_output,
        net_policy: opts.net_policy.clone(),
        emulator: opts.emulator.map(Path::to_path_buf),
        deny_read: opts.secrets.to_vec(),
        recursive_nix: opts.recursive_nix,
    };
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
    spec.binds_ro.sort(); // deterministic mount order
    platform::prepare(&mut spec)?;
    Ok(spec)
}

/// The prepared sandbox as a spawnable command plus the write end of
/// the pipe carrying the serialized spec to the setup stage's stdin.
#[cfg(target_os = "linux")]
fn build_command(spec: &SandboxSpec) -> Result<(Command, Option<OwnedFd>)> {
    let mut cmd = platform::command(spec)?;
    // Own process group, so orphaned builder children can be killed
    // after the builder exits.
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    // The derivation env must not reach the pre-sandbox setup stage
    // (worker binary, worker host credentials): LD_PRELOAD would run
    // client code outside the sandbox. With the spec on stdin the env
    // is applied at the builder exec instead.
    cmd.env_clear();
    if !platform::SPEC_VIA_STDIN {
        cmd.envs(&spec.env);
    }
    // O_CLOEXEC: a write end inherited by a concurrently spawned
    // sibling build would keep the spec read from ever seeing EOF.
    if platform::SPEC_VIA_STDIN {
        let (r, w) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).context("creating spec pipe")?;
        cmd.stdin(Stdio::from(fs::File::from(r)));
        return Ok((cmd, Some(w)));
    }
    cmd.stdin(Stdio::null());
    Ok((cmd, None))
}

/// Spawn the sandboxed build with stdout/stderr on `log`. The build
/// is a direct child of the worker, but its state (log, exit status)
/// is persisted on disk so it survives a worker restart. The returned
/// write end must be filled with `send_spec_to` once the spec is
/// complete (the setup stage blocks on stdin until then).
#[cfg(target_os = "linux")]
pub fn spawn(spec: &SandboxSpec, log: &fs::File) -> Result<(Child, Option<OwnedFd>)> {
    let (mut cmd, spec_w) = build_command(spec)?;
    cmd.stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log.try_clone()?));
    let child = cmd
        .spawn()
        .with_context(|| format!("spawning builder {}", spec.builder))?;
    Ok((child, spec_w))
}

/// Write the serialized spec into the setup stage's stdin pipe. Call
/// after the lease filled in the cgroup.
#[cfg(target_os = "linux")]
pub fn send_spec_to(spec: &SandboxSpec, w: OwnedFd) -> Result<()> {
    serde_json::to_writer(fs::File::from(w), spec).context("sending sandbox spec")
}

/// Exit code of a finished build, persisted by the PID-1 shim. None
/// while the build is still running.
#[cfg(target_os = "linux")]
pub fn exit_status(spec: &SandboxSpec) -> Option<i32> {
    platform::exit_status_impl(spec)
}

/// Setup-stage failure message, written by the stage before the host
/// filesystem became unreachable. Read by the worker when the build
/// exits nonzero.
#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
pub fn cleanup(outputs: &[String], dir: &Path) {
    platform::cleanup(outputs, dir);
}

#[cfg(target_os = "linux")]
#[path = "sandbox/linux.rs"]
mod platform;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

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
    #[test]
    fn recursive_nix_adds_the_daemon_socket_bind() -> Result<()> {
        let host = tempfile::tempdir()?;
        let host_sock = host.path().join("sock");
        fs::File::create(&host_sock)?;

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
        assert!(
            off.binds_ro
                .iter()
                .all(|(_, dst)| dst != Path::new(NIX_DAEMON_SOCKET))
        );

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
        assert!(
            on.binds_ro
                .iter()
                .any(|(src, dst)| src == &host_sock && dst == Path::new(NIX_DAEMON_SOCKET))
        );
        Ok(())
    }

    /// Common fields for a /bin/sh test build rooted in `dir`;
    /// tests override what they exercise via struct update syntax.
    fn test_spec(dir: &Path) -> SandboxSpec {
        SandboxSpec {
            builder: "/bin/sh".into(),
            system: "x86_64-linux".into(),
            cwd: "/build".into(),
            root: dir.join("root"),
            build_dir: dir.join("top/build"),
            ..SandboxSpec::default()
        }
    }

    /// The derivation env is client-controlled (LD_PRELOAD, …) and must
    /// not be applied to the setup stage, which runs the worker binary
    /// with the worker's host credentials before entering the sandbox.
    #[test]
    fn derivation_env_stays_off_the_setup_stage() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let spec = SandboxSpec {
            env: HashMap::from([("LD_PRELOAD".into(), "/nix/store/evil.so".into())]),
            ..test_spec(dir.path())
        };
        fs::create_dir_all(&spec.build_dir)?;
        let (cmd, _w) = build_command(&spec)?;
        assert_eq!(
            cmd.get_envs().count(),
            0,
            "setup stage env: {:?}",
            cmd.get_envs().collect::<Vec<_>>()
        );
        Ok(())
    }
}
