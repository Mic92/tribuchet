//! Benchmark orchestration: CA, hub, chroot nix-daemon, worker,
//! synthesized build.json, timed attach runs.

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::slice;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;

use crate::nix::{build_path, nar_size, query_closure};
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
    /// Also run the build: copy this store path into $out and time
    /// output packing and delivery.
    #[arg(long)]
    output_copy: Option<String>,
}

const STAGE_ENV: &str = "NETBENCH_STAGE";

pub fn main() -> ExitCode {
    if env::var_os(STAGE_ENV).is_none() {
        // Re-exec as root of a fresh user+mount+net namespace.
        let args: Vec<_> = env::args().collect();
        // The agent maps a full 65536-id block above root; --map-auto
        // would spend one of the subordinate ids on root.
        let (uids, gids) = match (subid_range("/etc/subuid"), subid_range("/etc/subgid")) {
            (Ok(u), Ok(g)) => (u, g),
            (Err(e), _) | (_, Err(e)) => {
                eprintln!("netbench: {e}");
                return ExitCode::FAILURE;
            }
        };
        // Own transient scope: the worker agent manages cgroups as
        // userns root and must never touch the login session's tree.
        let err = Command::new("systemd-run")
            .args([
                "--user",
                "--scope",
                "--quiet",
                "--collect",
                "-p",
                "Delegate=yes",
                "--",
            ])
            .arg("unshare")
            .arg("-r")
            .arg(format!("--map-users=1:{uids}"))
            .arg(format!("--map-groups=1:{gids}"))
            .args([
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
    if let Err(e) = ns::enter_cgroup_self("harness") {
        eprintln!("netbench: {e}");
        return ExitCode::FAILURE;
    }
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("netbench: {e}");
            ExitCode::FAILURE
        }
    }
}

/// "start:count" of the invoking user's first subordinate id range.
fn subid_range(file: &str) -> Result<String, Box<dyn Error>> {
    let user = env::var("USER")?;
    let uid = unsafe { libc::getuid() }.to_string();
    fs::read_to_string(file)?
        .lines()
        .find_map(|l| {
            let mut it = l.split(':');
            let name = it.next()?;
            (name == user || name == uid).then(|| format!("{}:{}", it.next()?, it.next()?).into())
        })
        .flatten()
        .ok_or_else(|| format!("no entry for {user} in {file}").into())
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
    if result.is_err() {
        for (n, c) in [
            ("worker", &mut setup.worker),
            ("hub", &mut setup.hub),
            ("agent", &mut setup.agent),
        ] {
            if let Ok(Some(st)) = c.try_wait() {
                eprintln!("netbench: {n} exited: {st}");
            }
        }
    }
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
    let (mut inputs, _) = query_closure(&cli.closure)?;
    let mut builder = (
        "/bin/sh".to_string(),
        vec!["-c".to_string(), "exit 0".to_string()],
    );
    let mut out_bytes = 0;
    if let Some(src) = &cli.output_copy {
        out_bytes = nar_size(slice::from_ref(src))?;
        let busybox = build_path("nixpkgs#pkgsStatic.busybox")?;
        inputs.extend(query_closure(src)?.0);
        inputs.push(busybox.clone());
        inputs.sort();
        inputs.dedup();
        builder = (
            format!("{busybox}/bin/busybox"),
            vec!["cp".into(), "-r".into(), src.clone(), OUT.into()],
        );
        println!("output: copy of {src}, {} MB nar", out_bytes >> 20);
    }
    let nar_bytes = nar_size(&inputs)?;
    println!(
        "inputs: {} paths, {} MB nar | delay {}ms/way, {} mbit",
        inputs.len(),
        nar_bytes >> 20,
        cli.delay_ms,
        cli.rate_mbit
    );
    let build_json = write_build_json(&setup.wd, &inputs, &builder.0, &builder.1)?;
    for i in 1..=cli.runs {
        let label = if i == 1 { "cold" } else { "warm" };
        let t = attach(setup, &build_json, cli.output_copy.is_some())?;
        report(i, label, &t, nar_bytes, out_bytes);
        if cli.output_copy.is_none() {
            wait_for_log(&setup.worker_log, "build result acknowledged")?;
        }
        if i == 1 && cli.phases {
            print_phases(&setup.wd);
        }
    }
    Ok(())
}

const OUT: &str = "/nix/store/00000000000000000000000000000000-netbench";

fn start(cli: &Cli) -> Result<Setup, Box<dyn Error>> {
    // Throwaway CA and TLS keys live here (files are 0600). Build uids
    // must traverse to the agent scratch dir, so not the 0700 runtime dir.
    let dir = tempfile::Builder::new().prefix("netbench-").tempdir()?;
    let wd = dir.path().to_path_buf();
    fs::set_permissions(&wd, fs::Permissions::from_mode(0o711))?;
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
        // unshare --map-auto maps 65536 subordinate ids above root
        .args(["--uid-base", "1"])
        .stdout(log_file(wd, "agent.log")?)
        .stderr(log_file(wd, "agent.err")?);
    ns::join_worker(netns, &mut agent_cmd, root_s);
    // The agent manages (and kills) its own cgroup subtree, which must
    // not contain the worker or this harness.
    ns::enter_cgroup(&mut agent_cmd, "agent")?;
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

fn write_build_json(
    wd: &Path,
    closure: &[String],
    builder: &str,
    args: &[String],
) -> Result<PathBuf, Box<dyn Error>> {
    let ttmp = wd.join("ttmp");
    fs::create_dir_all(ttmp.join("build"))?;
    let mut outputs = BTreeMap::new();
    outputs.insert("out", OUT.to_string());
    let json = serde_json::json!({
        "version": 1,
        "builder": builder,
        "args": args,
        "env": {"out": OUT},
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

#[derive(Default)]
struct Timings {
    dispatch: Duration,
    staging: Duration,
    /// builder exit -> result sent (output chunking)
    pack: Option<Duration>,
    /// result sent -> ack (chunk negotiation, upload, hub assembly)
    deliver: Option<Duration>,
}

fn attach(setup: &Setup, build_json: &Path, full: bool) -> Result<Timings, Box<dyn Error>> {
    let t0 = Instant::now();
    let mut cmd = Command::new(&setup.tribuchet);
    cmd.arg("attach")
        .arg(build_json)
        .arg("--socket")
        .arg(setup.wd.join("hub.sock"))
        .stdout(Stdio::null())
        .stderr(log_file(&setup.wd, "attach.err")?);
    if full {
        ns::writable_store(&mut cmd, &setup.wd)?;
    }
    let mut child = cmd.spawn()?;
    let last = if full {
        "build result acknowledged"
    } else {
        // The build itself is not the benchmark: once staging completes
        // kill attach, which makes the hub cancel the build.
        "sandbox network decision"
    };
    let mut marks: BTreeMap<&str, Instant> = BTreeMap::new();
    let deadline = Instant::now() + Duration::from_mins(10);
    while !marks.contains_key(last) && Instant::now() < deadline {
        match setup.worker_log.recv_timeout(Duration::from_millis(200)) {
            Ok((at, line)) => {
                for m in [
                    "build assigned",
                    "sandbox network decision",
                    "builder finished",
                    "build result sent",
                    "build result acknowledged",
                ] {
                    if line.contains(m) {
                        marks.entry(m).or_insert(at);
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(e) => return Err(e.into()),
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let get = |m: &str| {
        marks
            .get(m)
            .copied()
            .ok_or(format!("timed out waiting for: {m}"))
    };
    let assigned = get("build assigned")?;
    let staged = get("sandbox network decision")?;
    let mut t = Timings {
        dispatch: assigned - t0,
        staging: staged - assigned,
        ..Default::default()
    };
    if full {
        let fin = get("builder finished")?;
        let sent = get("build result sent")?;
        t.pack = Some(sent - fin);
        t.deliver = Some(get("build result acknowledged")? - sent);
    }
    Ok(t)
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

#[allow(clippy::cast_precision_loss)]
fn report(run: u32, label: &str, t: &Timings, nar_bytes: u64, out_bytes: u64) {
    let mbps = nar_bytes as f64 / 1e6 / t.staging.as_secs_f64();
    println!(
        "run {run} ({label}): dispatch {:.2?}, staging {:.2?} ({mbps:.0} MB/s of nar)",
        t.dispatch, t.staging
    );
    if let (Some(pack), Some(deliver)) = (t.pack, t.deliver) {
        let pm = out_bytes as f64 / 1e6 / pack.as_secs_f64();
        println!("        outputs: pack {pack:.2?} ({pm:.0} MB/s), deliver {deliver:.2?}");
    }
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
