//! Linux sandbox implementation: namespaces, bind mounts, pivot_root.

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{SandboxSpec, binfmt};

use super::{Error, step};

#[path = "linux/stage.rs"]
mod stage;
pub use stage::setup_stage;

/// Prepare the on-disk sandbox root and finalize the spec. Only the
/// scratch store is created on disk because outputs must survive the
/// namespace. The rest of the root lives on the in-namespace tmpfs,
/// so nothing stale persists across builds.
pub fn prepare_root(spec: &mut SandboxSpec) -> Result<(), Error> {
    let root = &spec.root;
    fs::create_dir_all(root.join("nix/store"))?;
    dev_binds(&mut spec.binds_dev);
    if spec.network {
        // Host CA bundle at the standard path for TLS fetches, like
        // Nix's fixed-output setup.
        let ca = Path::new("/etc/ssl/certs/ca-certificates.crt");
        if let Ok(real) = ca.canonicalize() {
            spec.binds_ro.push((real, ca.to_path_buf()));
        }
    }
    // The agent cannot chown to the leased range: the sandbox root is
    // recreated on an in-namespace tmpfs instead (mount_filesystems),
    // and the on-disk store dir the build still writes its outputs
    // into is opened up. The build dir is already owned by the leased
    // range; the group-restricted state dir keeps other users out.
    {
        fs::set_permissions(root.join("nix/store"), fs::Permissions::from_mode(0o1777))?;
    }
    Ok(())
}

/// Sandbox root skeleton: directories, /etc files, /dev symlinks.
/// Runs only on the build's in-namespace tmpfs root.
fn write_skeleton(spec: &SandboxSpec) -> Result<(), Error> {
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
        fs::create_dir_all(root.join(sub))?;
    }
    fs::write(
        root.join("etc/passwd"),
        "root:x:0:0:Nix build user:/build:/noshell\n\
         nixbld:x:1000:100:Nix build user:/build:/noshell\n\
         nobody:x:65534:65534:Nobody:/:/noshell\n",
    )?;
    fs::write(
        root.join("etc/group"),
        "root:x:0:\nnixbld:x:100:\nnogroup:x:65534:\n",
    )?;
    fs::write(
        root.join("etc/hosts"),
        "127.0.0.1 localhost\n::1 localhost\n",
    )?;
    for (link, target) in [
        ("dev/fd", "/proc/self/fd"),
        ("dev/stdin", "/proc/self/fd/0"),
        ("dev/stdout", "/proc/self/fd/1"),
        ("dev/stderr", "/proc/self/fd/2"),
        ("dev/ptmx", "/dev/pts/ptmx"),
    ] {
        symlink(target, root.join(link))?;
    }
    if spec.network {
        // Like Nix's fixed-output setup: name resolution via files
        // and DNS only, host resolver/services/hosts copied in.
        fs::write(
            root.join("etc/nsswitch.conf"),
            "hosts: files dns\nservices: files\n",
        )?;
        for f in ["services", "hosts"] {
            if let Ok(data) = fs::read(Path::new("/etc").join(f)) {
                fs::write(root.join("etc").join(f), data)?;
            }
        }
        if spec.net_isolation {
            // presto-pasta answers DNS on the gateway addresses; point
            // the sandbox at them, not the host resolv.conf whose
            // nameserver may be an unreachable loopback stub.
            let net = presto_pasta::Config::default();
            let conf = format!("nameserver {}\nnameserver {}\n", net.gateway4, net.gateway6);
            fs::write(root.join("etc/resolv.conf"), conf)?;
        } else if let Ok(data) = fs::read("/etc/resolv.conf") {
            fs::write(root.join("etc/resolv.conf"), data)?;
        }
    }
    Ok(())
}

/// Mount points for the cwd, bind targets and symlinked store inputs
/// inside the sandbox root. Like `write_skeleton`, runs only on the
/// tmpfs root.
fn create_mount_points(spec: &SandboxSpec) -> Result<(), Error> {
    // The shipped tmp dir is mounted at the request's sandbox build
    // dir; pre-create the mount point inside the private root.
    fs::create_dir_all(
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
            fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::File::create(&target)?;
        }
    }

    // Symlink store objects cannot be bind-mounted (the mount would
    // resolve them); recreate them inside the private root instead.
    for (dst, target) in &spec.symlink_inputs {
        let link = spec.root.join(dst.strip_prefix("/").unwrap_or(dst));
        if link.symlink_metadata().is_ok() {
            continue;
        }
        if let Some(parent) = link.parent() {
            fs::create_dir_all(parent)?;
        }
        symlink(target, &link)
            .map_err(step(format!("creating symlink input {}", link.display())))?;
    }
    Ok(())
}

/// Like Nix: bind-mount the host device nodes instead of mknod'ing
/// copies (impossible in a leased user namespace anyway). The mounts
/// are read-only, so a sandbox mapping a host uid that owns a node
/// cannot chmod/chown it; device I/O is unaffected by MS_RDONLY.
fn dev_binds(binds_dev: &mut Vec<(PathBuf, PathBuf)>) {
    let mut devices = vec!["null", "zero", "full", "random", "urandom", "tty"];
    // Nix's `kvm` system feature (VM builds, NixOS tests).
    if Path::new("/dev/kvm").exists() {
        devices.push("kvm");
    }
    for dev in devices {
        let host = PathBuf::from("/dev").join(dev);
        binds_dev.push((host.clone(), host));
    }
}

pub fn command(spec: &SandboxSpec) -> Result<Command, Error> {
    if spec.emulator.is_some() && binfmt::register_line(&spec.system).is_none() {
        return Err(Error::UnknownBinfmt(spec.system.clone()));
    }

    // see setup_stage() for why builds re-exec this binary. Resolve it
    // in the worker: the reaper execs this argv, and it outlives worker
    // reloads, so it must not resolve the binary in its own context.
    let exe = env::current_exe().map_err(step("resolving worker binary path"))?;
    let mut cmd = Command::new(exe);
    cmd.arg(SETUP_STAGE_ARG);
    Ok(cmd)
}

pub const SETUP_STAGE_ARG: &str = "__sandbox_setup";

/// The spec travels via the setup stage's stdin.
pub const SPEC_VIA_STDIN: bool = true;

pub fn setup_error_file(root: &Path) -> PathBuf {
    root.with_file_name("setup-error")
}

/// Where the PID-1 shim records the builder's exit code. Next to the
/// sandbox root (like the setup-error file), so the builder cannot
/// forge it.
pub fn exit_status_file(root: &Path) -> PathBuf {
    root.with_file_name("exit-status")
}

/// Setup-stage failure message, written by the stage before the host
/// filesystem became unreachable. Read by the worker when the build
/// exits nonzero.
pub fn setup_error_detail(spec: &SandboxSpec) -> Option<String> {
    fs::read_to_string(setup_error_file(&spec.root))
        .ok()
        .filter(|s| !s.is_empty())
}
