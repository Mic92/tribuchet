//! Benchmark orchestration: CA, hub, chroot nix-daemon, worker,
//! synthesized build.json, timed attach runs.

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;

use crate::ns;

type LogRx = mpsc::Receiver<(Instant, String)>;

#[derive(Parser)]
struct Cli {
    /// One-way delay per direction in ms (RTT = 2x).
    #[arg(long, default_value_t = 10)]
    delay_ms: u32,
    /// Link rate in mbit/s (0 = unlimited).
    #[arg(long, default_value_t = 1000)]
    rate_mbit: u32,
    /// Store path whose closure is staged (must be valid on the host).
    #[arg(long)]
    closure: String,
    /// Timed attach runs. The worker store persists across runs, so
    /// run 1 is cold and later runs are warm.
    #[arg(long, default_value_t = 2)]
    runs: u32,
    /// tribuchet binary.
    #[arg(long, default_value = "target/release/tribuchet")]
    tribuchet: PathBuf,
    /// Keep the work dir (logs, stores) for inspection.
    #[arg(long)]
    keep: bool,
    /// Print the cold run's phase breakdown from the debug logs.
    #[arg(long)]
    phases: bool,
    /// Initial TCP congestion window in segments on both sides
    /// (0 = kernel default). Isolates slow start from protocol cost.
    #[arg(long, default_value_t = 0)]
    initcwnd: u32,
}

const STAGE_ENV: &str = "NETBENCH_STAGE";

pub fn main() -> ExitCode {
    if env::var_os(STAGE_ENV).is_none() {
        // Re-exec as root of a fresh user+mount+net namespace.
        let args: Vec<_> = env::args().collect();
        // Own transient scope: the worker agent manages cgroups as
        // userns root and must never touch the login session's tree.
        let err = Command::new("systemd-run")
            .args(["--user", "--scope", "--quiet", "--collect", "--"])
            .arg("unshare")
            .args([
                "-r",
                "--map-auto",
                "-m",
                "-n",
                "-p",
                "--fork",
                "--mount-proc",
                "--propagation",
                "private",
            ])
            .args(&args)
            .env(STAGE_ENV, "1")
            .exec();
        eprintln!("re-exec under unshare failed: {err}");
        return ExitCode::FAILURE;
    }
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("netbench: {e}");
            ExitCode::FAILURE
        }
    }
}

struct Setup {
    dir: Option<tempfile::TempDir>,
    wd: PathBuf,
    tribuchet: PathBuf,
    _netns: ns::WorkerNs,
    hub: Child,
    daemon: Child,
    agent: Child,
    worker: Child,
    worker_log: LogRx,
}

fn run(cli: &Cli) -> Result<(), Box<dyn Error>> {
    let mut setup = start(cli)?;
    let result = measure(cli, &setup);
    shutdown(&mut setup);
    // Runs on every exit path: either hand the tree to the user or
    // unlock the read-only imported store paths so the TempDir drop
    // can remove it. Never leave key material behind silently.
    if cli.keep {
        if let Some(dir) = setup.dir.take() {
            println!("work dir kept: {}", dir.keep().display());
        }
    } else {
        let _ = Command::new("chmod")
            .args(["-R", "u+w"])
            .arg(&setup.wd)
            .stderr(Stdio::null())
            .status();
    }
    result
}

fn measure(cli: &Cli, setup: &Setup) -> Result<(), Box<dyn Error>> {
    let (closure, nar_bytes) = query_closure(&cli.closure)?;
    println!(
        "closure: {} paths, {} MB nar | delay {}ms/way, {} mbit",
        closure.len(),
        nar_bytes >> 20,
        cli.delay_ms,
        cli.rate_mbit
    );
    let build_json = write_build_json(&setup.wd, &closure)?;
    for i in 1..=cli.runs {
        let label = if i == 1 { "cold" } else { "warm" };
        let (dispatch, staging) = attach(setup, &build_json)?;
        report(i, label, dispatch, staging, nar_bytes);
        wait_for_log(&setup.worker_log, "build result acknowledged")?;
        if i == 1 && cli.phases {
            print_phases(&setup.wd);
        }
    }
    Ok(())
}

fn start(cli: &Cli) -> Result<Setup, Box<dyn Error>> {
    // Holds CA and TLS key material: tempfile creates it 0700. Rooted
    // in the user's runtime dir when available, not world-shared /tmp.
    let base = env::var_os("XDG_RUNTIME_DIR").map_or_else(env::temp_dir, PathBuf::from);
    let dir = tempfile::Builder::new()
        .prefix("netbench-")
        .tempdir_in(base)?;
    let wd = dir.path().to_path_buf();
    let netns = ns::WorkerNs::create()?;
    ns::setup_links(&netns, cli.delay_ms, cli.rate_mbit, cli.initcwnd)?;

    let ca = wd.join("ca");
    let tb = |args: &[&str]| -> Result<(), Box<dyn Error>> {
        let st = Command::new(&cli.tribuchet)
            .args(args)
            .stdout(Stdio::null())
            .status()?;
        if !st.success() {
            return Err(format!("tribuchet {args:?}: {st}").into());
        }
        Ok(())
    };
    let ca_s = ca.to_str().unwrap();
    tb(&["ca", "init", "--dir", ca_s])?;
    tb(&["ca", "issue", ns::HUB_ADDR, "--dir", ca_s])?;
    tb(&["ca", "issue", "worker", "--dir", ca_s])?;
    fs::rename(ca.join(format!("{}.crt", ns::HUB_ADDR)), ca.join("hub.crt"))?;
    fs::rename(ca.join(format!("{}.key", ns::HUB_ADDR)), ca.join("hub.key"))?;

    let hub_toml = wd.join("hub.toml");
    fs::write(
        &hub_toml,
        format!(
            "socket = \"{wd}/hub.sock\"\nlisten = \"{}:7437\"\nconfig-dir = \"{wd}\"\n",
            ns::HUB_ADDR,
            wd = wd.display(),
        ),
    )?;
    let hub = Command::new(&cli.tribuchet)
        .args(["hub", "--config"])
        .arg(&hub_toml)
        .env(
            "RUST_LOG",
            "info,tribuchet::hub::relay=debug,tribuchet::worker::build=debug",
        )
        .stdout(log_file(&wd, "hub.log")?)
        .stderr(log_file(&wd, "hub.err")?)
        .spawn()?;

    let store_root = wd.join("wstore");
    fs::create_dir_all(store_root.join("nix/var/nix/daemon-socket"))?;
    let root_s = store_root.to_str().unwrap().to_string();
    let mut daemon_cmd = Command::new("nix");
    daemon_cmd
        .args([
            "--extra-experimental-features",
            "nix-command",
            "daemon",
            "--store",
        ])
        .arg(format!("local?root={root_s}"))
        .stdout(log_file(&wd, "daemon.log")?)
        .stderr(log_file(&wd, "daemon.err")?);
    ns::join_worker(&netns, &mut daemon_cmd, &root_s);
    let daemon = daemon_cmd.spawn()?;
    wait_for(
        || store_root.join("nix/var/nix/daemon-socket/socket").exists(),
        "nix daemon socket",
    )?;

    let (agent, worker, rx) = spawn_worker(cli, &wd, &netns, &root_s)?;

    let setup = Setup {
        dir: Some(dir),
        wd,
        tribuchet: cli.tribuchet.clone(),
        _netns: netns,
        hub,
        daemon,
        agent,
        worker,
        worker_log: rx,
    };
    wait_for_log(&setup.worker_log, "connected to hub")?;
    Ok(setup)
}

fn spawn_worker(
    cli: &Cli,
    wd: &Path,
    netns: &ns::WorkerNs,
    root_s: &str,
) -> Result<(Child, Child, LogRx), Box<dyn Error>> {
    let worker_toml = wd.join("worker.toml");
    fs::write(
        &worker_toml,
        format!(
            "hub = \"https://{}:7437\"\nstate-dir = \"{wd}/wstate\"\n\
             ca-cert = \"{ca}/ca.crt\"\ncert = \"{ca}/worker.crt\"\nkey = \"{ca}/worker.key\"\n\
             agent-sockets = [\"{wd}/agent.sock\"]\n",
            ns::HUB_ADDR,
            wd = wd.display(),
            ca = wd.join("ca").display(),
        ),
    )?;
    let agent_state = wd.join("agent");
    fs::create_dir_all(&agent_state)?;
    let mut agent_cmd = Command::new(&cli.tribuchet);
    agent_cmd
        .arg("agent")
        .arg("--socket")
        .arg(wd.join("agent.sock"))
        .arg("--state-dir")
        .arg(&agent_state)
        .stdout(log_file(wd, "agent.log")?)
        .stderr(log_file(wd, "agent.err")?);
    ns::join_worker(netns, &mut agent_cmd, root_s);
    let agent = agent_cmd.spawn()?;

    let mut worker_cmd = Command::new(&cli.tribuchet);
    worker_cmd
        .args(["worker", "--config"])
        .arg(worker_toml)
        .env(
            "RUST_LOG",
            "info,tribuchet::hub::relay=debug,tribuchet::worker::build=debug",
        )
        .stdout(Stdio::piped())
        .stderr(log_file(wd, "worker.err")?);
    ns::join_worker(netns, &mut worker_cmd, root_s);
    let mut worker = worker_cmd.spawn()?;

    let (tx, rx) = mpsc::channel();
    let stdout = worker.stdout.take().unwrap();
    let log_path = wd.join("worker.log");
    thread::spawn(move || {
        let mut out = fs::File::create(log_path).ok();
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(f) = &mut out {
                let _ = writeln!(f, "{line}");
            }
            let _ = tx.send((Instant::now(), line));
        }
    });

    Ok((agent, worker, rx))
}

fn log_file(wd: &Path, name: &str) -> io::Result<Stdio> {
    Ok(fs::File::create(wd.join(name))?.into())
}

fn wait_for(mut cond: impl FnMut() -> bool, what: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if cond() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(format!("timed out waiting for {what}"))
}

fn wait_for_log(rx: &LogRx, marker: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while let Ok((_, line)) = rx.recv_timeout(deadline - Instant::now()) {
        if line.contains(marker) {
            return Ok(());
        }
    }
    Err(format!("timed out waiting for worker log: {marker}"))
}

/// The closure's paths and total nar size from one path-info query.
fn query_closure(path: &str) -> Result<(Vec<String>, u64), Box<dyn Error>> {
    let out = Command::new("nix")
        .args([
            "--extra-experimental-features",
            "nix-command",
            "path-info",
            "-r",
            "--json",
            path,
        ])
        .env("NIX_REMOTE", "daemon")
        .output()?;
    if !out.status.success() {
        return Err(format!("nix path-info -r {path}: {}", out.status).into());
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let m = v.as_object().ok_or("unexpected path-info output")?;
    let paths = m.keys().cloned().collect();
    let nar_bytes = m.values().filter_map(|p| p["narSize"].as_u64()).sum();
    Ok((paths, nar_bytes))
}

fn write_build_json(wd: &Path, closure: &[String]) -> Result<PathBuf, Box<dyn Error>> {
    let ttmp = wd.join("ttmp");
    fs::create_dir_all(ttmp.join("build"))?;
    let mut outputs = BTreeMap::new();
    outputs.insert(
        "out",
        "/nix/store/00000000000000000000000000000000-netbench".to_string(),
    );
    let json = serde_json::json!({
        "version": 1,
        "builder": "/bin/sh",
        "args": ["-c", "exit 0"],
        "env": {},
        "topTmpDir": ttmp,
        "tmpDirInSandbox": "/build",
        "storeDir": "/nix/store",
        "system": current_system(),
        "inputPaths": closure,
        "outputs": outputs,
    });
    let path = wd.join("build.json");
    fs::write(&path, serde_json::to_vec(&json)?)?;
    Ok(path)
}

fn current_system() -> String {
    format!("{}-{}", env::consts::ARCH, env::consts::OS)
}

fn attach(setup: &Setup, build_json: &Path) -> Result<(Duration, Duration), Box<dyn Error>> {
    let t0 = Instant::now();
    let mut child = Command::new(&setup.tribuchet)
        .arg("attach")
        .arg(build_json)
        .arg("--socket")
        .arg(setup.wd.join("hub.sock"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    // The sandboxed build itself is not the benchmark: once staging
    // completes (the sandbox decision is the first post-staging log)
    // kill attach, which makes the hub cancel the build.
    let mut assigned = None;
    let mut staged = None;
    let deadline = Instant::now() + Duration::from_mins(10);
    while staged.is_none() && Instant::now() < deadline {
        match setup.worker_log.recv_timeout(Duration::from_millis(200)) {
            Ok((at, line)) if line.contains("build assigned") => assigned = Some(at),
            Ok((at, line)) if line.contains("sandbox network decision") => staged = Some(at),
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(e) => return Err(e.into()),
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let staged = staged.ok_or("timed out waiting for staging to complete")?;
    let assigned = assigned.ok_or("staging finished without an assignment marker")?;
    Ok((assigned - t0, staged - assigned))
}

/// Cold-run phase breakdown from the hub and worker debug logs.
fn print_phases(wd: &Path) {
    for (name, markers) in [
        (
            "hub.log",
            &[
                "recipes sent",
                "need-chunks received",
                "run frame sent",
                "chunk streaming done",
            ][..],
        ),
        (
            "worker.log",
            &["recipes sealed", "chunk run ingested", "daemon import done"][..],
        ),
    ] {
        let Ok(text) = fs::read_to_string(wd.join(name)) else {
            continue;
        };
        for line in text.lines() {
            if markers.iter().any(|m| line.contains(m)) {
                println!("  {}", line.trim());
            }
        }
    }
}

fn report(run: u32, label: &str, dispatch: Duration, staging: Duration, nar_bytes: u64) {
    #[allow(clippy::cast_precision_loss)]
    let mbps = nar_bytes as f64 / 1e6 / staging.as_secs_f64();
    println!(
        "run {run} ({label}): dispatch {dispatch:.2?}, staging {staging:.2?} ({mbps:.0} MB/s of nar)"
    );
}

fn shutdown(setup: &mut Setup) {
    for c in [
        &mut setup.worker,
        &mut setup.hub,
        &mut setup.agent,
        &mut setup.daemon,
    ] {
        let _ = c.kill();
        let _ = c.wait();
    }
}
