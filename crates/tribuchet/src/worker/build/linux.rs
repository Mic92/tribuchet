//! Linux build execution: sandboxd lease, in-process sandbox stage,
//! supervision and the idmapped pack mount.

use std::fs;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{self, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use harmonia_utils_signature::SecretKey;
use nix::sys::signal;
use tokio::sync::mpsc;

use super::{ActiveBuild, pack_outputs_and_extras, unix_now};
use crate::proto::{BuildAssignment, WorkerMessage};
use crate::worker::caps::requires_uid_range;
use crate::worker::logtail::tail_log;
use crate::worker::resume::{FinishedBuild, ResumeState};
use crate::worker::{WorkerCtx, sandbox, sandboxd};

/// Credentials backing one build's sandbox.
///
/// Linux workers lease every build's sandbox from tribuchet-sandboxd:
/// a mapped user namespace (65536 uids for uid-range builds, one
/// otherwise) plus a delegated cgroup, so no build runs as the
/// worker's own uid. The sandbox setup stage joins the pre-mapped
/// namespace and no host file is chowned. macOS builds go through the
/// per-uid agents instead (see `darwin.rs`).
struct BuildOwner {
    _lease: sandboxd::SandboxLease,
}

/// Pre-spawn half of a lease: the user namespace exists (so its path
/// can go into the spec) but sandboxd has not been contacted yet.
struct OwnerPrep {
    ns: sandboxd::SandboxPrep,
    uid_count: u32,
}

impl BuildOwner {
    fn prepare(a: &BuildAssignment) -> Result<OwnerPrep> {
        Ok(OwnerPrep {
            ns: sandboxd::SandboxPrep::new()?,
            uid_count: if requires_uid_range(&a.env) { 65536 } else { 1 },
        })
    }

    /// Lease the sandbox now that the setup stage exists, so sandboxd
    /// can place it in the build cgroup. Fills in `spec.cgroup`.
    fn lease(
        ctx: &WorkerCtx,
        build_id: &str,
        prep: OwnerPrep,
        stage: i32,
        spec: &mut sandbox::SandboxSpec,
    ) -> Result<Self> {
        let socket = ctx
            .sandboxd
            .as_deref()
            .context("tribuchet-sandboxd socket unavailable")?;
        let OwnerPrep { ns, uid_count } = prep;
        let tmp_dir = spec.build_dir.parent().unwrap_or(&spec.build_dir);
        let lease = ns.allocate(
            socket,
            build_id,
            uid_count,
            nix::unistd::Pid::from_raw(stage),
            tmp_dir,
        )?;
        tracing::info!(
            build_id,
            pool_base = lease.pool_base,
            uid_count,
            "leased sandbox"
        );
        // memory.max is group-writable for the worker.
        if let Some(bytes) = ctx.build_memory_max
            && let Err(e) = fs::write(lease.cgroup().join("memory.max"), bytes.to_string())
        {
            tracing::warn!("setting memory.max on the leased cgroup: {e}");
        }
        spec.cgroup = Some(lease.cgroup().to_path_buf());
        spec.pool_base = Some(lease.pool_base);
        Ok(Self { _lease: lease })
    }
}

impl ActiveBuild {
    fn build_spec(&self, prep: &OwnerPrep) -> Result<sandbox::SandboxSpec> {
        let a = &self.assignment;
        let (leased_userns, leased_uid_count) = (Some(prep.ns.ns_path()), Some(prep.uid_count));
        let spec = sandbox::prepare(
            a,
            &self.dir,
            &self.inputs,
            &sandbox::PrepareOpts {
                bin_sh: self.ctx.sandbox_bin_sh.as_deref(),
                secrets: &self.ctx.secret_paths,
                leased_userns,
                leased_uid_count,
                emulator: self.ctx.emulators.get(&a.system).map(PathBuf::as_path),
                net_isolation: self.ctx.fod_isolation,
                net_policy: self.ctx.fod_network.clone(),
                recursive_nix: self.ctx.recursive_nix,
                nix_daemon_socket: None,
            },
        )?;
        tracing::info!(
            id = a.build_id,
            fixed_output = a.fixed_output,
            network = spec.network,
            net_isolation = spec.net_isolation,
            "sandbox network decision"
        );
        Ok(spec)
    }

    /// Runs on a blocking thread: sandboxed build, live log streaming,
    /// output packing and signing. Sends only logs; the result and
    /// output NARs go through deliver(), which can run again on a
    /// later session if this one dies first.
    pub(in crate::worker) fn execute(
        &self,
        out_tx: &mpsc::Sender<WorkerMessage>,
        signing_key: &SecretKey,
        timeout: Duration,
    ) -> Result<FinishedBuild> {
        let a = &self.assignment;
        // Spawn first, lease after: sandboxd needs the stage's pidfd to
        // move it into the build cgroup. The stage blocks on stdin
        // until the spec is sent below, so nothing runs before leasing.
        let prep = BuildOwner::prepare(a)?;
        let mut spec = self.build_spec(&prep)?;
        // Logs go through a file in the build dir, not pipes: capture
        // is decoupled from this process's lifetime, so a restarted
        // worker can resume tailing where we stopped.
        let log_file = fs::File::create(self.dir.join("build.log"))?;
        let (child, spec_w) = sandbox::spawn(&spec, &log_file)?;
        let pid = child.id().cast_signed();
        let _owner = BuildOwner::lease(&self.ctx, &a.build_id, prep, pid, &mut spec)?;
        if let Some(w) = spec_w {
            sandbox::send_spec_to(&spec, w)?;
        }
        // From here the build can be re-adopted by a restarted worker.
        // The exit status lands in the exit-status file, not only in
        // this process's wait().
        let resume = ResumeState {
            dedupe_key: a.dedupe_key.clone(),
            build_id: a.build_id.clone(),
            pid,
            spec,
            deadline_unix: unix_now() + timeout.as_secs(),
            agent_socket: None,
        };
        fs::write(self.dir.join("resume.json"), serde_json::to_vec(&resume)?)?;

        let log_done = Arc::new(atomic::AtomicBool::new(false));
        let tailer = {
            let tx = out_tx.clone();
            let build_id = a.build_id.clone();
            let log_done = log_done.clone();
            let dir = self.dir.clone();
            std::thread::spawn(move || {
                tail_log(&dir, &build_id, &tx, || log_done.load(Ordering::Relaxed));
            })
        };
        let fin = supervise(
            &self.ctx,
            &resume,
            self.dir.clone(),
            signing_key,
            Some(child),
        );
        log_done.store(true, Ordering::Relaxed);
        let _ = tailer.join();
        Ok(fin)
    }
}

/// True while the build's processes are still around: cgroup still
/// populated (Linux lease) or, without a cgroup, the shim/builder pid
/// still exists. The pid check alone would be fooled by pid reuse for
/// adopted builds, so the cgroup wins when there is one.
fn build_alive(st: &ResumeState) -> bool {
    if let Some(cg) = &st.spec.cgroup {
        return match fs::read_to_string(cg.join("cgroup.events")) {
            Ok(events) => !events.contains("populated 0"),
            Err(_) => false, // cgroup gone: lease over, build dead
        };
    }
    // EPERM means the process exists (leased uid). Only ESRCH is gone.
    signal::kill(nix::unistd::Pid::from_raw(st.pid), None) != Err(nix::errno::Errno::ESRCH)
}

/// Wait out a running build (fresh or re-adopted), pack its outputs,
/// and tear the sandbox down. Driven off the persisted `ResumeState`
/// so both entry points share one wait/kill/pack path. `child` is the
/// spawned shim for a fresh build, reaped here. An adopted build has
/// no child, its exit code comes from the persisted exit-status file.
pub(in crate::worker) fn supervise(
    ctx: &WorkerCtx,
    st: &ResumeState,
    dir: PathBuf,
    signing_key: &SecretKey,
    mut child: Option<std::process::Child>,
) -> FinishedBuild {
    // POSIX-shell style exit code of a reaped child.
    fn exit_code(status: std::process::ExitStatus) -> i32 {
        use std::os::unix::process::ExitStatusExt;
        status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
    }
    let pgrp = nix::unistd::Pid::from_raw(st.pid);
    let log_path = dir.join("build.log");
    let mut aborted: Option<String> = None;
    // Exit code of the reaped child. The exit-status file wins when it
    // exists (setup failures exit before the shim can write it).
    let mut child_code: Option<i32> = None;
    // Build gone but no exit status anywhere: bounded grace, then
    // treat as failed.
    let mut gone_since: Option<Instant> = None;
    let code = loop {
        if child_code.is_none()
            && let Some(c) = child.as_mut()
            && let Ok(Some(status)) = c.try_wait()
        {
            child_code = Some(exit_code(status));
        }
        if let Some(code) = sandbox::exit_status(&st.spec).or(child_code) {
            break code;
        }
        if build_alive(st) {
            gone_since = None;
        } else {
            let since = gone_since.get_or_insert_with(Instant::now);
            if since.elapsed() > Duration::from_secs(5) {
                aborted.get_or_insert_with(|| "build exit status was lost".into());
                break 1;
            }
        }
        if aborted.is_none() {
            let timed_out = (unix_now() >= st.deadline_unix).then(|| "build timed out".to_string());
            if let Some(r) = ctx.abort_reason(&st.dedupe_key, &log_path, timed_out) {
                aborted = Some(r);
                kill_build(pgrp, st.spec.cgroup.as_deref());
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    // Reap the shim if we spawned it and have not reaped it yet.
    if child_code.is_none()
        && let Some(mut c) = child
    {
        let _ = c.wait();
    }
    // Builder is PID 1 of its PID namespace, so its death took every
    // descendant with it; also covers macOS (no pidns) and the pre-exec
    // window.
    kill_build(pgrp, st.spec.cgroup.as_deref());
    tracing::info!(id = st.build_id, exit_code = code, aborted = ?aborted, "builder finished");
    let (exit_code, error, outputs, extras) = if let Some(reason) = aborted {
        (1, reason, vec![], vec![])
    } else if code != 0 {
        (
            code,
            sandbox::setup_error_detail(&st.spec).unwrap_or_default(),
            vec![],
            vec![],
        )
    } else {
        // At least a few minutes to pack even if the build ate its budget.
        let remaining = Duration::from_secs(st.deadline_unix.saturating_sub(unix_now()));
        let deadline = Instant::now() + remaining.max(Duration::from_mins(10));
        let pack_root = pack_mount(ctx, &st.spec);
        match tokio::runtime::Handle::current().block_on(pack_outputs_and_extras(
            &dir,
            &st.spec,
            pack_root.as_ref(),
            deadline,
            signing_key,
            &st.build_id,
        )) {
            Ok((o, e)) => (0, String::new(), o, e),
            Err(e) => (1, format!("{e:#}"), vec![], vec![]),
        }
    };
    sandbox::cleanup(&st.spec.outputs, &dir);
    FinishedBuild {
        exit_code,
        error,
        outputs,
        extras,
        dir,
        finished_at: Instant::now(),
    }
}

/// Kill a build's processes. killpg alone misses a builder that
/// setsid()'d out of the group; the shim is outside the pidns, so its
/// death does not tear it down. cgroup.kill (group-writable via
/// sandboxd) reaches everything.
fn kill_build(pgrp: nix::unistd::Pid, cgroup: Option<&Path>) {
    let _ = signal::killpg(pgrp, signal::Signal::SIGKILL);
    if let Some(cg) = cgroup {
        let _ = fs::write(cg.join("cgroup.kill"), "1");
    }
}

/// Idmapped mount of the build's private root (leased uids presented
/// as the worker), so packing reads outputs regardless of their
/// permission bits. `None` (unsupported filesystem, old sandboxd, or
/// no lease) leaves packing on the direct paths.
fn pack_mount(ctx: &WorkerCtx, spec: &sandbox::SandboxSpec) -> Option<OwnedFd> {
    let socket = ctx.sandboxd.as_deref()?;
    let (base, count) = (spec.pool_base?, spec.leased_uid_count?);
    if ctx.idmap_unsupported.load(Ordering::Relaxed) {
        return None;
    }
    match sandboxd::open_idmapped(socket, &spec.root, base, count) {
        Ok(fd) => Some(fd),
        Err(e) => {
            // Filesystem support cannot change while the worker runs;
            // other errors (a restarting sandboxd) stay retried.
            if format!("{e:#}").contains("does not support idmapped mounts") {
                ctx.idmap_unsupported.store(true, Ordering::Relaxed);
            }
            tracing::warn!("packing without an idmapped mount: {e:#}");
            None
        }
    }
}
