use super::*;
use std::collections::HashMap;
use std::os::fd::IntoRawFd;
use std::{env, thread};

use crate::tmpdir::pack_zstd_dir;
use crate::worker::agent;

/// A dev-mode agent: self-bound socket, same uid.
pub(in crate::worker) fn spawn_agent(socket: &Path, state_dir: PathBuf) -> Result<()> {
    let listener = sockpath::bind(socket)?;
    thread::spawn(move || {
        let _ = agent::run(&agent::Options {
            socket: None,
            listen_fd: Some(listener.into_raw_fd()),
            state_dir,
            worker_uid: None,
            uid_base: None,
            dedicated_uid: false,
        });
    });
    Ok(())
}

/// A dev-mode agent plus a staged tmp dir pack for it, shared by
/// the tests below.
pub(in crate::worker) fn spawn_test_agent(dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let socket = dir.join("agent.sock");
    spawn_agent(&socket, dir.join("state"))?;
    // build dir carrying .attrs.json, like the client pack
    let build = dir.join("top/build");
    fs::create_dir_all(&build)?;
    fs::write(build.join(".attrs.json"), "{}")?;
    let pack_path = dir.join("top.tmpdir.zst");
    fs::write(&pack_path, pack_zstd_dir(&build)?)?;
    Ok((socket, pack_path))
}

pub(in crate::worker) fn start_request(
    build_id: &str,
    script: String,
    outputs: Vec<String>,
) -> StartRequest {
    StartRequest {
        build_id: build_id.into(),
        builder: "/bin/sh".into(),
        args: vec!["-c".into(), script],
        // A real assignment's env carries PATH; the scripts here
        // need it for mkdir.
        env: HashMap::from([
            ("NIX_BUILD_TOP".into(), "/build".into()),
            ("PATH".into(), env::var("PATH").unwrap_or_default()),
        ]),
        tmp_dir_in_sandbox: "/build".into(),
        profile: String::new(),
        sandbox_json: None,
        outputs,
        memory_max_bytes: None,
    }
}

/// Full lifecycle against a real agent on the same uid, without a
/// seatbelt profile (not permitted inside the Nix build sandbox):
/// Start with a tmp dir tar, exit notice, Adopt of the finished
/// build, Finish, Cleanup.
#[test]
fn agent_runs_a_build_end_to_end() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (socket, pack_path) = spawn_test_agent(dir.path())?;
    let build_id = "0123456789abcdef0123456789abcdef";
    let output = dir.path().join("fake-output");
    let req = start_request(
        build_id,
        format!(
            "test -f .attrs.json || exit 2; \
             test \"$NIX_BUILD_TOP\" = \"$PWD\" || exit 3; \
             echo built; mkdir {out}; echo data > {out}/file",
            out = output.display()
        ),
        vec![output.to_string_lossy().into_owned()],
    );
    let log_path = dir.path().join("build.log");
    let log_w = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let build = AgentBuild::start(&socket, &req, &fs::File::open(&pack_path)?, &log_w)?;
    assert!(build.pid > 0);
    let exit = build.wait_exit()?;
    assert_eq!(exit.exit_code, 0);
    assert!(exit.peak_memory_bytes > 0, "no memory reported");

    let log = fs::read_to_string(&log_path)?;
    assert!(log.contains("built"), "log: {log}");

    let (_, exit) = AgentBuild::adopt(&socket, build_id)?;
    assert_eq!(exit, Some(0));

    finish(&socket, build_id)?;
    assert_eq!(fs::read_to_string(output.join("file"))?, "data\n");

    cleanup(&socket, build_id)?;
    assert!(!output.exists());
    assert!(!build.scratch_dir.exists());
    Ok(())
}

/// A stopped socket unit's file, a missing socket and one that
/// drops the call unanswered (a failing agent service) sit on top
/// of the free list. The build skips them and lands on the live
/// agent. An error the agent replies with leaves it in the pool.
#[test]
fn start_skips_unreachable_agents() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (live, pack_path) = spawn_test_agent(dir.path())?;
    let stale = dir.path().join("stale.sock");
    drop(sockpath::bind(&stale)?);
    let missing = dir.path().join("missing.sock");
    let dead = dir.path().join("dead.sock");
    let listener = sockpath::bind(&dead)?;
    thread::spawn(move || drop(listener.accept()));
    let mut sockets = vec![live.clone(), missing.clone(), stale.clone()];
    sockets.push(dead.clone());
    let pool = AgentPool::new(sockets);
    let build_id = "00000000000000000000000000000002";
    let req = start_request(build_id, "true".into(), vec![]);
    let pack = fs::File::open(&pack_path)?;
    let log = fs::File::create(dir.path().join("build.log"))?;
    let (socket, build) = pool.start(&req, &pack, &log, || false, || {})?;
    assert_eq!(socket, live);
    assert_eq!(build.wait_exit()?.exit_code, 0);
    assert_eq!(pool.down_sockets(), vec![dead, stale, missing]);
    assert_eq!(pool.usable(), 1);
    pool.release(live.clone());
    let busy = pool.start(&req, &pack, &log, || false, || {});
    assert!(busy.is_err());
    assert_eq!(pool.usable(), 1);
    cleanup(&live, build_id)
}

/// With no agent reachable a build waits instead of failing, until
/// it is cancelled or an agent is back.
#[test]
fn start_waits_for_an_agent() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (_, pack_path) = spawn_test_agent(dir.path())?;
    let socket = dir.path().join("down.sock");
    let pool = AgentPool::new(vec![socket.clone()]);
    let build_id = "00000000000000000000000000000003";
    let req = start_request(build_id, "true".into(), vec![]);
    let pack = fs::File::open(&pack_path)?;
    let log = fs::File::create(dir.path().join("build.log"))?;
    let Err(e) = pool.start(&req, &pack, &log, || true, || {}) else {
        panic!("started on an unreachable agent");
    };
    assert_eq!(chain(&e), "build cancelled");
    thread::scope(|s| {
        let started = s.spawn(|| pool.start(&req, &pack, &log, || false, || {}));
        thread::sleep(Duration::from_millis(1500));
        assert!(!started.is_finished(), "the build did not wait");
        spawn_agent(&socket, dir.path().join("down"))?;
        pool.release(socket.clone());
        let (leased, build) = started.join().unwrap()?;
        assert_eq!(leased, socket);
        assert_eq!(build.wait_exit()?.exit_code, 0);
        cleanup(&socket, build_id)
    })
}

/// The generated seatbelt profile, applied by a real agent: the
/// derivation env arrives, worker secrets are unreadable, writes
/// stay confined to the scratch dir and the declared output.
/// Skipped inside the Nix build sandbox (sandbox_init is not
/// permitted there); `nix develop -c cargo test` runs it.
#[cfg(target_os = "macos")]
#[test]
fn seatbelt_profile_confines_the_builder() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (socket, pack_path) = spawn_test_agent(dir.path())?;
    let build_id = "00000000000000000000000000000001";
    // Canonical paths: the profile's path filters only match
    // canonical paths and macOS temp dirs live under the /var
    // symlink. Real outputs are /nix/store paths, already canonical.
    let dir_path = dir.path().canonicalize()?;
    let output = dir_path.join("fake-output");
    let secret = dir_path.join("secret");
    fs::write(&secret, "key-material")?;
    let outside = dir_path.join("outside");
    let outputs = vec![output.to_string_lossy().into_owned()];
    let mut req = start_request(
        build_id,
        // Each escape attempt exits with its own code so a failure
        // names the broken rule.
        format!(
            "test \"$NIX_BUILD_TOP\" = \"$PWD\" || exit 3; \
             cat {secret} 2>/dev/null && exit 4; \
             echo escaped > {outside} 2>/dev/null && exit 5; \
             echo scratch > scratch-file || exit 6; \
             mkdir {out} && echo data > {out}/file",
            secret = secret.display(),
            outside = outside.display(),
            out = output.display()
        ),
        outputs.clone(),
    );
    req.profile = seatbelt_profile(&outputs, &[secret], false, false)?;
    let log_w = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir_path.join("build.log"))?;
    let build = AgentBuild::start(&socket, &req, &fs::File::open(&pack_path)?, &log_w)?;
    assert_eq!(build.wait_exit()?.exit_code, 0);
    assert!(!outside.exists());
    finish(&socket, build_id)?;
    assert_eq!(fs::read_to_string(output.join("file"))?, "data\n");
    cleanup(&socket, build_id)?;
    Ok(())
}
