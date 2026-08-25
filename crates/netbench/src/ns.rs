//! Network topology for the benchmark: a veth pair with netem delay
//! and rate limits between the hub (root netns of our user namespace)
//! and the worker (a private netns anchored on a holder process).

use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr;

pub const HUB_ADDR: &str = "10.99.0.1";

pub fn run(argv: &[&str]) -> io::Result<()> {
    let status = Command::new(argv[0]).args(&argv[1..]).status()?;
    if !status.success() {
        return Err(io::Error::other(format!("{argv:?} failed: {status}")));
    }
    Ok(())
}

/// A process holding the worker netns open, plus an fd to join it.
pub struct WorkerNs {
    holder: Child,
    net_fd: OwnedFd,
}

impl WorkerNs {
    pub fn create() -> io::Result<Self> {
        let mut cmd = Command::new("sleep");
        cmd.arg("infinity").stdin(Stdio::null());
        // SAFETY: unshare is async-signal-safe.
        unsafe {
            cmd.pre_exec(|| match libc::unshare(libc::CLONE_NEWNET) {
                0 => Ok(()),
                _ => Err(io::Error::last_os_error()),
            });
        }
        let holder = cmd.spawn()?;
        let net_fd = File::open(format!("/proc/{}/ns/net", holder.id()))?.into();
        Ok(Self { holder, net_fd })
    }

    fn pid(&self) -> String {
        self.holder.id().to_string()
    }

    /// Join the worker netns via pre_exec on `cmd`.
    pub fn join(&self, cmd: &mut Command) {
        let fd = self.net_fd.as_raw_fd();
        // SAFETY: setns/unshare/mount are fine between fork and exec.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setns(fd, libc::CLONE_NEWNET) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}

/// veth pair with `delay_ms` one-way delay and `rate_mbit` in each
/// direction (so RTT = 2 * delay_ms).
pub fn setup_links(ns: &WorkerNs, delay_ms: u32, rate_mbit: u32, initcwnd: u32) -> io::Result<()> {
    let pid = ns.pid();
    let inner = |argv: &[&str]| -> io::Result<()> {
        let mut full = vec!["nsenter", "-t", &pid, "-n"];
        full.extend(argv);
        run(&full)
    };
    let delay = format!("{delay_ms}ms");
    let rate = format!("{rate_mbit}mbit");
    let netem = |dev| {
        [
            "tc", "qdisc", "add", "dev", dev, "root", "netem", "delay", &delay, "rate", &rate,
        ]
    };
    // Raising initcwnd sidesteps TCP slow start, exposing how much of
    // a cold run is congestion-control ramp rather than protocol.
    let cwnd = initcwnd.to_string();
    let route = |dev| {
        [
            "ip",
            "route",
            "change",
            "10.99.0.0/24",
            "dev",
            dev,
            "initcwnd",
            &cwnd,
            "initrwnd",
            &cwnd,
        ]
    };

    run(&["ip", "link", "set", "lo", "up"])?;
    run(&[
        "ip", "link", "add", "veth-h", "type", "veth", "peer", "name", "veth-w",
    ])?;
    run(&["ip", "link", "set", "veth-w", "netns", &pid])?;
    run(&["ip", "addr", "add", "10.99.0.1/24", "dev", "veth-h"])?;
    run(&["ip", "link", "set", "veth-h", "up"])?;
    inner(&["ip", "link", "set", "lo", "up"])?;
    inner(&["ip", "addr", "add", "10.99.0.2/24", "dev", "veth-w"])?;
    inner(&["ip", "link", "set", "veth-w", "up"])?;
    if delay_ms > 0 || rate_mbit > 0 {
        run(&netem("veth-h"))?;
        inner(&netem("veth-w"))?;
    }
    if initcwnd > 0 {
        run(&route("veth-h"))?;
        inner(&route("veth-w"))?;
    }
    Ok(())
}

/// pre_exec: join the worker netns, then bind the private store's
/// /nix/var/nix over the real one in a fresh mount namespace so both
/// the chroot nix-daemon socket and store db resolve to the bench
/// store.
pub fn join_worker(ns: &WorkerNs, cmd: &mut Command, store_root: &str) {
    ns.join(cmd);
    let src = CString::new(format!("{store_root}/nix/var/nix")).unwrap();
    let dst = CString::new("/nix/var/nix").unwrap();
    let root = CString::new("/").unwrap();
    // SAFETY: only async-signal-safe syscalls.
    unsafe {
        cmd.pre_exec(move || {
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::mount(
                ptr::null(),
                root.as_ptr(),
                ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                ptr::null(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::mount(
                src.as_ptr(),
                dst.as_ptr(),
                ptr::null(),
                libc::MS_BIND,
                ptr::null(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// pre_exec: overlay a scratch upper dir on /nix/store so attach can
/// unpack the output without touching the host store.
pub fn writable_store(cmd: &mut Command, wd: &Path) -> io::Result<()> {
    let upper = wd.join("upper");
    let work = wd.join("work");
    fs::create_dir_all(&upper)?;
    fs::create_dir_all(&work)?;
    let opts = CString::new(format!(
        "lowerdir=/nix/store,upperdir={},workdir={},userxattr",
        upper.display(),
        work.display()
    ))
    .unwrap();
    let dst = CString::new("/nix/store").unwrap();
    let ty = CString::new("overlay").unwrap();
    let root = CString::new("/").unwrap();
    // SAFETY: only async-signal-safe syscalls.
    unsafe {
        cmd.pre_exec(move || {
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::mount(
                ptr::null(),
                root.as_ptr(),
                ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                ptr::null(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::mount(
                ty.as_ptr(),
                dst.as_ptr(),
                ty.as_ptr(),
                0,
                opts.as_ptr().cast(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

fn cgroup_dir(name: &str) -> io::Result<PathBuf> {
    let own = fs::read_to_string("/proc/self/cgroup")?;
    let rel = own
        .lines()
        .find_map(|l| l.strip_prefix("0::/"))
        .ok_or_else(|| io::Error::other("no cgroup2 entry"))?;
    let base = Path::new("/sys/fs/cgroup").join(rel);
    let dir = base
        .parent()
        .filter(|_| base.ends_with("harness"))
        .unwrap_or(&base)
        .join(name);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Move this process into a leaf cgroup of the delegated scope so
/// siblings can enable controllers.
pub fn enter_cgroup_self(name: &str) -> io::Result<()> {
    fs::write(cgroup_dir(name)?.join("cgroup.procs"), "0")
}

/// pre_exec: start the child in its own sibling cgroup.
pub fn enter_cgroup(cmd: &mut Command, name: &str) -> io::Result<()> {
    let procs = CString::new(cgroup_dir(name)?.join("cgroup.procs").to_str().unwrap()).unwrap();
    // SAFETY: only async-signal-safe syscalls.
    unsafe {
        cmd.pre_exec(move || {
            let fd = libc::open(procs.as_ptr(), libc::O_WRONLY);
            if fd < 0 || libc::write(fd, b"0".as_ptr().cast(), 1) != 1 {
                return Err(io::Error::last_os_error());
            }
            libc::close(fd);
            Ok(())
        });
    }
    Ok(())
}

impl Drop for WorkerNs {
    fn drop(&mut self) {
        let _ = self.holder.kill();
        let _ = self.holder.wait();
    }
}
