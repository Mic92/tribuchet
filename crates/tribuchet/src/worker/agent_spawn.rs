//! Worker-spawned build agents for hosts without a service manager,
//! typically containers. The worker forks one `tribuchet agent` per
//! slot, supervises it and restarts it after it exits.

use std::fs;
use std::io;
use std::os::unix::fs::chown as chown_path;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::ExitStatus;
use std::time::{Duration, Instant};
use std::{env, thread};

use crate::errors::{Result, chain, err_ctx, err_msg};
use crate::sockpath;
use rustix::process::{Gid, Uid};
use rustix::process::{geteuid, getuid};
use rustix::thread::{
    CapabilitySet, CapabilitySets, configure_capability_in_ambient_set, set_capabilities,
    set_keep_capabilities, set_thread_groups, set_thread_res_gid, set_thread_res_uid,
};

/// Size of each agent's mapped uid block.
const UID_BLOCK: u32 = 65536;

/// One spawned agent slot.
struct Slot {
    socket: PathBuf,
    state_dir: PathBuf,
    /// Uid the agent runs as, None to stay on the worker uid.
    uid: Option<u32>,
    /// First uid of the agent's mapped block.
    uid_base: Option<u32>,
}

/// Spawn `count` agents under `<state_dir>/agents` and return their
/// socket paths once they accept connections.
pub fn spawn(state_dir: &Path, count: u32, uid_base: Option<u32>) -> Result<Vec<PathBuf>> {
    if count == 0 {
        return Err(err_msg("spawn-agents must be at least 1"));
    }
    let exe = env::current_exe().map_err(err_ctx("resolving the worker binary"))?;
    let root = geteuid().is_root();
    let uid_base = match (uid_base, root) {
        (Some(b), true) => Some(b),
        (Some(_), false) => {
            tracing::warn!("agent-uid-base ignored: the worker is not root, builds share its uid");
            None
        }
        (None, _) => {
            tracing::warn!("no agent-uid-base: builds share the worker uid");
            None
        }
    };
    let base_dir = state_dir.join("agents");
    let mut sockets = Vec::new();
    for i in 1..=count {
        let dir = base_dir.join(i.to_string());
        fs::create_dir_all(&dir)?;
        let slot = Slot {
            socket: dir.join("agent.sock"),
            state_dir: dir.clone(),
            uid: uid_base.map(|b| b + i - 1),
            uid_base: uid_base.map(|b| b + i * UID_BLOCK),
        };
        if let Some(uid) = slot.uid {
            chown_path(&dir, Some(uid), Some(uid))
                .map_err(err_ctx(format!("chowning {}", dir.display())))?;
        }
        let _ = fs::remove_file(&slot.socket);
        sockets.push(slot.socket.clone());
        thread::spawn({
            let exe = exe.clone();
            move || supervise(&exe, &slot)
        });
    }
    wait_for_sockets(&sockets)?;
    tracing::info!(
        count,
        uid_isolation = uid_base.is_some(),
        "spawned build agents"
    );
    Ok(sockets)
}

/// Restart the agent whenever it exits. Exiting after each build is
/// its normal lifecycle under a dedicated uid.
fn supervise(exe: &Path, slot: &Slot) {
    loop {
        match run_once(exe, slot) {
            Ok(status) => tracing::info!(socket = %slot.socket.display(), %status, "agent exited"),
            Err(e) => {
                tracing::warn!(socket = %slot.socket.display(), "starting agent: {}", chain(&e));
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn run_once(exe: &Path, slot: &Slot) -> Result<ExitStatus> {
    let mut cmd = Command::new(exe);
    cmd.arg("agent")
        .arg("--socket")
        .arg(&slot.socket)
        .arg("--state-dir")
        .arg(&slot.state_dir)
        .arg("--worker-uid")
        .arg(getuid().as_raw().to_string());
    if let Some(base) = slot.uid_base {
        cmd.arg("--uid-base").arg(base.to_string());
    }
    if let Some(uid) = slot.uid {
        cmd.arg("--dedicated-uid");
        // SAFETY: only async-signal-safe calls before exec.
        unsafe { cmd.pre_exec(move || confine_to(uid)) };
    }
    cmd.spawn()
        .map_err(err_ctx(format!("spawning {}", exe.display())))?
        .wait()
        .map_err(err_ctx("waiting for the agent"))
}

/// Switch the child to the agent uid while keeping the capabilities
/// the agent needs: SETUID/SETGID for its uid-block map write, CHOWN
/// for handing build cgroups to the mapped root uid.
fn confine_to(uid: u32) -> io::Result<()> {
    let keep = CapabilitySet::SETUID | CapabilitySet::SETGID | CapabilitySet::CHOWN;
    let (u, g) = (Uid::from_raw(uid), Gid::from_raw(uid));
    set_thread_groups(&[g])?;
    set_keep_capabilities(true)?;
    set_thread_res_gid(g, g, g)?;
    set_thread_res_uid(u, u, u)?;
    set_capabilities(
        None,
        CapabilitySets {
            effective: keep,
            permitted: keep,
            inheritable: keep,
        },
    )?;
    for cap in [
        CapabilitySet::SETUID,
        CapabilitySet::SETGID,
        CapabilitySet::CHOWN,
    ] {
        configure_capability_in_ambient_set(cap, true)?;
    }
    Ok(())
}

/// Wait until every agent socket accepts a connection.
fn wait_for_sockets(sockets: &[PathBuf]) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    for socket in sockets {
        loop {
            if sockpath::connect(socket).is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                return Err(err_msg(format!(
                    "agent socket {} did not come up",
                    socket.display()
                )));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    Ok(())
}
