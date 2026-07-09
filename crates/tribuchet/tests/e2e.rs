//! End-to-end test harness for the tribuchet NixOS test.
//!
//! Runs on the test-driver host and drives the `hub` and `worker` VMs over the
//! driver's vsock ssh backdoor (`sshBackdoor.enable`), one ssh ControlMaster
//! per node. libtest provides parallelism, filtering and timing; ssh
//! multiplexing keeps per-command connects cheap.
//!
//! Two phases, run as two separate invocations from the NixOS `testScript`:
//!   * `build_*`  — independent builds, multi-threaded (the default).
//!   * `lifecycle` — one serial test carrying the stateful daemon-lifecycle
//!     sequence; run with `--test-threads=1`.
//!
//! Inputs come from the driver via environment variables:
//!   TT_SSH         path to the `ssh` binary
//!   TT_SSH_CONFIG  ssh_config with the `vsock-mux/*` ProxyCommand
//!   TT_HUB_SOCK    host unix socket bridging to the hub's vsock
//!   TT_WORKER_SOCK host unix socket bridging to the worker's vsock
//!   TT_CTLDIR      writable dir for ssh control sockets
//!   TT_BASH        store path of `pkgs.bash` (for inline derivations)

// The lifecycle sequence is intentionally one long serial test; the ssh output
// struct's `timed_out` field reads naturally despite the lint.
#![allow(clippy::too_many_lines, clippy::struct_field_names)]

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::Once;
use std::thread;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Nodes and environment
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Node {
    Hub,
    Worker,
}

impl Node {
    fn name(self) -> &'static str {
        match self {
            Node::Hub => "hub",
            Node::Worker => "worker",
        }
    }

    fn sock(self) -> String {
        match self {
            Node::Hub => env("TT_HUB_SOCK"),
            Node::Worker => env("TT_WORKER_SOCK"),
        }
    }
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("missing env var {key}"))
}

fn bash() -> String {
    env("TT_BASH")
}

// ---------------------------------------------------------------------------
// ssh plumbing
// ---------------------------------------------------------------------------

fn ssh_base(node: Node) -> Vec<String> {
    let ctl = format!("{}/ctl-{}", env("TT_CTLDIR"), node.name());
    let mut args = vec!["-F".into(), env("TT_SSH_CONFIG")];
    for opt in [
        "User=root",
        "StrictHostKeyChecking=no",
        "UserKnownHostsFile=/dev/null",
        "ControlMaster=auto",
        "ControlPersist=300",
        "ConnectTimeout=10",
        "ServerAliveInterval=15",
        "LogLevel=ERROR",
    ] {
        args.push("-o".into());
        args.push(opt.into());
    }
    args.push("-o".into());
    args.push(format!("ControlPath={ctl}"));
    args.push(format!("vsock-mux/{}", node.sock()));
    args
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
    timed_out: bool,
}

impl Out {
    fn combined(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

/// Run a shell command on `node`, returning its captured output. Reader threads
/// drain stdout/stderr so large build logs cannot deadlock the pipe; the
/// command is killed if it outlasts `timeout`.
fn run_timeout(node: Node, cmd: &str, timeout: Duration) -> Out {
    ensure_ready();
    let script = format!("set -euo pipefail\n{cmd}");
    let mut child = Command::new(env("TT_SSH"))
        .args(ssh_base(node))
        .arg(&script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ssh");

    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let t_out = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        b
    });
    let t_err = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        b
    });

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        if let Some(s) = child.try_wait().expect("try_wait") {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            timed_out = true;
            break child.wait().expect("wait after kill");
        }
        thread::sleep(Duration::from_millis(100));
    };

    let stdout = String::from_utf8_lossy(&t_out.join().unwrap()).into_owned();
    let stderr = String::from_utf8_lossy(&t_err.join().unwrap()).into_owned();
    Out {
        code: status.code().unwrap_or(-1),
        stdout,
        stderr,
        timed_out,
    }
}

fn run(node: Node, cmd: &str) -> Out {
    run_timeout(node, cmd, Duration::from_mins(15))
}

/// A timeout or an ssh transport failure (exit 255) is a harness error, not a
/// test outcome.
fn check_transport(o: &Out, node: Node, cmd: &str) {
    assert!(
        !o.timed_out,
        "[{}] timed out: {cmd}\n{}",
        node.name(),
        o.combined()
    );
    assert!(
        o.code != 255,
        "[{}] ssh transport error: {cmd}\n{}",
        node.name(),
        o.combined()
    );
}

/// Run `cmd` with a custom timeout, asserting success, returning stdout.
fn succeed_t(node: Node, cmd: &str, secs: u64) -> String {
    let o = run_timeout(node, cmd, Duration::from_secs(secs));
    check_transport(&o, node, cmd);
    assert_eq!(
        o.code,
        0,
        "[{}] command failed ({}): {cmd}\n{}",
        node.name(),
        o.code,
        o.combined()
    );
    o.stdout
}

fn succeed(node: Node, cmd: &str) -> String {
    succeed_t(node, cmd, 900)
}

/// Run `cmd`, asserting a non-zero *command* exit, returning combined output.
fn fail(node: Node, cmd: &str) -> String {
    let o = run(node, cmd);
    check_transport(&o, node, cmd);
    assert_ne!(
        o.code,
        0,
        "[{}] expected failure but succeeded: {cmd}",
        node.name()
    );
    o.combined()
}

fn wait_until_succeeds(node: Node, cmd: &str, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if run(node, cmd).code == 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "[{}] wait_until_succeeds timed out after {secs}s: {cmd}",
            node.name()
        );
        thread::sleep(Duration::from_millis(500));
    }
}

/// `journalctl ... | grep -c pattern`, tolerating no matches. `grep -c` drains
/// the whole stream, so journalctl never gets SIGPIPE (unlike `grep -q`, which
/// closes the pipe early and would trip `set -o pipefail`).
fn count(node: Node, unit: &str, pattern: &str) -> i64 {
    succeed(
        node,
        &format!("journalctl -u {unit} | grep -c '{pattern}' || true"),
    )
    .trim()
    .parse()
    .unwrap_or(0)
}

fn assert_journal(node: Node, unit: &str, pattern: &str) {
    assert!(
        count(node, unit, pattern) > 0,
        "[{}] journal for {unit} missing pattern: {pattern}",
        node.name()
    );
}

fn wait_journal(node: Node, unit: &str, pattern: &str, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while count(node, unit, pattern) == 0 {
        assert!(
            Instant::now() < deadline,
            "[{}] journal for {unit} never got pattern: {pattern}",
            node.name()
        );
        thread::sleep(Duration::from_millis(500));
    }
}

fn write_file(node: Node, path: &str, content: &str) {
    // Quoted heredoc: content is written verbatim, no shell expansion or
    // quoting to worry about (no test payload contains the TTEOF sentinel).
    succeed(node, &format!("cat > {path} <<'TTEOF'\n{content}\nTTEOF"));
}

fn build_grep(nixfile: &str, needle: &str) {
    let out = succeed(Node::Hub, &format!("nix-build {nixfile} --no-out-link"));
    let out = out.trim();
    succeed(Node::Hub, &format!("grep -q '{needle}' {out}"));
}

// ---------------------------------------------------------------------------
// One-time readiness: heartbeat + wait for both nodes' sshd
// ---------------------------------------------------------------------------

static READY: Once = Once::new();

fn ensure_ready() {
    READY.call_once(|| {
        // Heartbeat so a long build never leaves the driver log silent long
        // enough to trip Nix's --max-silent-time, and to distinguish progress
        // from a hang.
        let start = Instant::now();
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(30));
                println!("[e2e] heartbeat t={}s", start.elapsed().as_secs());
            }
        });

        for node in [Node::Hub, Node::Worker] {
            let deadline = Instant::now() + Duration::from_mins(2);
            loop {
                let script = "set -euo pipefail\ntrue";
                let ok = Command::new(env("TT_SSH"))
                    .args(ssh_base(node))
                    .arg(script)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success());
                if ok {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "ssh backdoor to {} never became ready",
                    node.name()
                );
                thread::sleep(Duration::from_millis(500));
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Inline derivations that add runtime paths (must travel over the wire)
// ---------------------------------------------------------------------------

/// Write a single-derivation .nix at `path` whose builder reads `input` and
/// echoes "<line> <suffix>" to $out. Returns the store path of the added input.
fn write_echo_deriv(path: &str, name: &str, payload: &str, suffix: &str) -> String {
    let src = "/root/payload-tmp";
    succeed(Node::Hub, &format!("echo {payload} > {src}"));
    let input = succeed(Node::Hub, &format!("nix-store --add {src}"))
        .trim()
        .to_string();
    let expr = format!(
        r#"let
  bash = builtins.storePath "{bash}";
  input = builtins.storePath "{input}";
in derivation {{
  name = "{name}";
  system = "x86_64-linux";
  builder = bash + "/bin/bash";
  args = [ "-c" ("read line < " + input + "; echo \"$line {suffix}\" > $out") ];
}}
"#,
        bash = bash(),
    );
    write_file(Node::Hub, path, &expr);
    input
}

// ===========================================================================
// Parallel build subtests (`build_*`)
// ===========================================================================

#[test]
fn build_remote() {
    // Input added at runtime, so it cannot be in the worker's store image: it
    // must travel over the wire.
    write_echo_deriv(
        "/root/remote.nix",
        "tt-remote-build",
        "tribuchet-payload",
        "built-remotely",
    );
    let out = succeed(Node::Hub, "nix-build /root/remote.nix --no-out-link");
    succeed(
        Node::Hub,
        &format!("grep -q 'tribuchet-payload built-remotely' {}", out.trim()),
    );
}

#[test]
fn build_shared() {
    // Two runtime-added paths the worker lacks, the referrer embedding the
    // reference's path so Nix records the edge; several builds depend on both,
    // dispatched at once. Per-worker staging serialization must import each
    // closure in isolation instead of racing on the daemon path lock.
    succeed(Node::Hub, "head -c 4000000 /dev/urandom > /root/ref");
    let refp = succeed(Node::Hub, "nix-store --add /root/ref")
        .trim()
        .to_string();
    succeed(
        Node::Hub,
        &format!("head -c 4000000 /dev/urandom > /root/referrer; echo {refp} >> /root/referrer"),
    );
    let referrer = succeed(Node::Hub, "nix-store --add /root/referrer")
        .trim()
        .to_string();
    let expr = format!(
        r#"let
  bash = builtins.storePath "{bash}";
  referrer = builtins.storePath "{referrer}";
  mk = n: derivation {{
    name = "tt-shared-" + n;
    system = "x86_64-linux";
    builder = bash + "/bin/bash";
    args = [ "-c" ("test -s " + referrer + "; echo shared-ok-" + n + " > $out") ];
  }};
in [ (mk "a") (mk "b") (mk "c") ]
"#,
        bash = bash(),
    );
    write_file(Node::Hub, "/root/shared.nix", &expr);
    // The reference must be missing on the worker for the closure to travel.
    succeed(
        Node::Worker,
        &format!("nix-store --delete {refp} {referrer} 2>/dev/null || true"),
    );
    let outs = succeed_t(
        Node::Hub,
        "nix-build /root/shared.nix --no-out-link --max-jobs 2",
        120,
    );
    let outs: Vec<&str> = outs.split_whitespace().collect();
    assert_eq!(outs.len(), 3, "expected 3 outputs, got {outs:?}");
    for o in outs {
        succeed(Node::Hub, &format!("grep -q shared-ok- {o}"));
    }
}

#[test]
fn build_symlink_input() {
    // A store object that is itself a symlink must stay a symlink
    // inside the sandbox.
    succeed(Node::Hub, "echo symlink-target > /root/sym-target");
    let target = succeed(Node::Hub, "nix-store --add /root/sym-target")
        .trim()
        .to_string();
    succeed(Node::Hub, &format!("ln -sfn {target} /root/sym-link"));
    let link = succeed(Node::Hub, "nix-store --add /root/sym-link")
        .trim()
        .to_string();
    let expr = format!(
        r#"let
  bash = builtins.storePath "{bash}";
  link = builtins.storePath "{link}";
in derivation {{
  name = "tt-symlink-input";
  system = "x86_64-linux";
  builder = bash + "/bin/bash";
  args = [ "-c" ("test -L " + link + " && echo symlink-input-ok > $out") ];
}}
"#,
        bash = bash(),
    );
    write_file(Node::Hub, "/root/symlink-input.nix", &expr);
    // The path must be missing on the worker so it travels over the wire.
    succeed(
        Node::Worker,
        &format!("nix-store --delete {link} 2>/dev/null || true"),
    );
    let out = succeed(Node::Hub, "nix-build /root/symlink-input.nix --no-out-link");
    succeed(
        Node::Hub,
        &format!("grep -q symlink-input-ok {}", out.trim()),
    );
}

#[test]
fn build_uidrange() {
    build_grep("/etc/tt/uidrange.nix", "uid-range-ok");
}

#[test]
fn build_refgraph() {
    build_grep("/etc/tt/refgraph.nix", "refgraph-ok");
}

#[test]
fn build_structured() {
    build_grep("/etc/tt/structured.nix", "structured-ok");
}

#[test]
fn build_ca() {
    build_grep("/etc/tt/ca.nix", "ca-ok");
}

#[test]
fn build_impure() {
    // nix-build cannot print impure output paths, so use nix build.
    let out = succeed(
        Node::Hub,
        "nix build --extra-experimental-features nix-command \
         -f /etc/tt/impure.nix --no-link --print-out-paths",
    );
    succeed(Node::Hub, &format!("grep -q impure-ok {}", out.trim()));
}

#[test]
fn build_kvm() {
    if run(Node::Worker, "test -e /dev/kvm").code == 0 {
        build_grep("/etc/tt/kvm.nix", "kvm-ok");
    } else {
        // No worker serves the kvm feature and the hub cannot build it
        // locally, so the declined build (exit 222) fails.
        let err = fail(Node::Hub, "nix-build /etc/tt/kvm.nix --no-out-link 2>&1");
        assert!(err.contains("exit code 222"), "{err}");
    }
}

#[test]
fn build_kvm_emulated() {
    // An emulated system must not inherit the host's kvm feature.
    let err = fail(
        Node::Hub,
        "nix-build /etc/tt/kvm-emulated.nix --no-out-link 2>&1",
    );
    assert!(err.contains("exit code 222"), "{err}");
}

#[test]
fn build_logbomb() {
    let err = fail(
        Node::Hub,
        "nix-build /etc/tt/logbomb.nix --no-out-link 2>&1",
    );
    assert!(err.contains("exceeded the limit"), "{err}");
}

/// The fixed-output subtests share the hub's fodsrv and the worker's dnsmasq,
/// and the DNS variant restarts dnsmasq, so keep them in one test in the
/// original order rather than racing three tasks on shared network state.
#[test]
fn build_fod() {
    // FOD source on the hub, fetched by the isolated sandbox through pasta.
    succeed(
        Node::Hub,
        "mkdir -p /srv/fod && echo hello-fod > /srv/fod/data",
    );
    succeed(
        Node::Hub,
        "systemd-run --unit=fodsrv socat -U TCP-LISTEN:8765,fork,reuseaddr OPEN:/srv/fod/data,rdonly",
    );
    wait_until_succeeds(
        Node::Hub,
        "timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/8765'",
        30,
    );
    // A loopback service on the worker that must NOT be reachable from the
    // isolated sandbox.
    succeed(
        Node::Worker,
        "systemd-run --unit=loopsrv python3 -m http.server 9999 --bind 127.0.0.1",
    );
    wait_until_succeeds(
        Node::Worker,
        "timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/9999'",
        30,
    );

    // 1) fetch via the hub's IP, isolated from the worker's loopback socket
    build_grep("/etc/tt/fod.nix", "hello-fod");

    // 2) resolve fod-hosts.test via the worker's /etc/hosts (files source)
    succeed(Node::Worker, "grep -q fod-hosts.test /etc/hosts");
    build_grep("/etc/tt/fod-hosts.nix", "hello-fod");

    // 3) resolve fod-dns.test only via dnsmasq, through pasta's DNS forwarder
    let hubip = succeed(Node::Worker, "getent hosts hub | awk '{print $1}'")
        .trim()
        .to_string();
    succeed(
        Node::Worker,
        &format!("echo '{hubip} fod-dns.test' > /var/lib/dnsmasq-fod/fod.hosts"),
    );
    succeed(Node::Worker, "systemctl restart dnsmasq");
    wait_until_succeeds(Node::Worker, "getent hosts fod-dns.test", 30);
    fail(Node::Worker, "grep -q fod-dns.test /etc/hosts");
    build_grep("/etc/tt/fod-dns.nix", "hello-fod");
}

#[test]
fn build_cross() {
    let out = succeed(Node::Hub, "nix-build /etc/tt/cross.nix --no-out-link");
    let out = out.trim();
    succeed(Node::Hub, &format!("grep -q aarch64 {out}"));
    succeed(Node::Hub, &format!("grep -qx 1000 {out}"));
}

#[test]
fn build_recursive() {
    let out = succeed(Node::Hub, "nix-build /etc/tt/recursive.nix --no-out-link");
    let inner = succeed(Node::Hub, &format!("cat {}", out.trim()))
        .trim()
        .to_string();
    // The closure-delta must have travelled: the inner path is registered in
    // the hub's store, not just referenced.
    succeed(Node::Hub, &format!("nix-store --check-validity {inner}"));
    succeed(Node::Hub, &format!("grep -q recursive-payload {inner}"));
    // And the worker really added it locally too.
    succeed(Node::Worker, &format!("nix-store --check-validity {inner}"));
}

#[test]
fn build_nspawn() {
    // Longest build: boots a NixOS container inside the remote build.
    let out = succeed_t(
        Node::Hub,
        "nix-build /etc/tt/nspawn.nix --no-out-link",
        1800,
    );
    succeed(
        Node::Hub,
        &format!("[[ $(cat {}/msg) = 'Hello World' ]]", out.trim()),
    );
}

// ===========================================================================
// Serial daemon-lifecycle sequence (run with --test-threads=1)
// ===========================================================================

#[test]
fn lifecycle() {
    // Own remote build establishes a path we can validate at the end; no
    // in-memory state crosses from the parallel invocation.
    let unique = write_echo_deriv(
        "/root/life.nix",
        "tt-life-build",
        "lifecycle-payload",
        "built-remotely",
    );
    let out = succeed(Node::Hub, "nix-build /root/life.nix --no-out-link");
    succeed(
        Node::Hub,
        &format!("grep -q 'lifecycle-payload built-remotely' {}", out.trim()),
    );

    // --- hub restart: socket activation keeps clients connectable ---------
    succeed(Node::Hub, "systemctl restart tribuchet-hub");
    let out = succeed(
        Node::Hub,
        "nix-build /root/life.nix --no-out-link 2>/dev/null",
    );
    succeed(
        Node::Hub,
        &format!("grep -q 'lifecycle-payload built-remotely' {}", out.trim()),
    );

    // --- restart hub + reload worker mid-build cancels nothing ------------
    let assigned = count(Node::Worker, "tribuchet-worker", "build assigned");
    succeed(
        Node::Hub,
        "rm -f /tmp/drain.ok && systemd-run --unit=drainbuild bash -lc \
         'nix-build /etc/tt/drain.nix --no-out-link > /tmp/drain.out && touch /tmp/drain.ok'",
    );
    wait_until_succeeds(
        Node::Worker,
        &format!("[ $(journalctl -u tribuchet-worker | grep -c 'build assigned') -gt {assigned} ]"),
        60,
    );
    succeed(Node::Worker, "systemctl reload tribuchet-worker");
    succeed(Node::Hub, "systemctl restart --no-block tribuchet-hub");
    wait_until_succeeds(Node::Hub, "test -f /tmp/drain.ok", 120);
    let out = succeed(Node::Hub, "cat /tmp/drain.out");
    succeed(
        Node::Hub,
        &format!("grep -q drained-not-cancelled {}", out.trim()),
    );
    wait_until_succeeds(Node::Worker, "systemctl is-active tribuchet-worker", 60);
    wait_until_succeeds(Node::Hub, "systemctl is-active tribuchet-hub", 60);

    // --- resubmitting a previously resumed derivation builds again --------
    succeed_t(
        Node::Hub,
        "nix-build /etc/tt/drain.nix --no-out-link --check",
        120,
    );

    // --- max-log-size applies to a build adopted across a reload ----------
    let assigned = count(Node::Worker, "tribuchet-worker", "build assigned");
    succeed(
        Node::Hub,
        "systemd-run --unit=slowlogbuild \
         -p StandardOutput=file:/tmp/slowlog.out -p StandardError=file:/tmp/slowlog.out \
         bash -lc 'nix-build /etc/tt/slowlog.nix --no-out-link'",
    );
    wait_until_succeeds(
        Node::Worker,
        &format!("[ $(journalctl -u tribuchet-worker | grep -c 'build assigned') -gt {assigned} ]"),
        60,
    );
    succeed(Node::Worker, "systemctl reload tribuchet-worker");
    wait_until_succeeds(
        Node::Hub,
        "grep -q 'exceeded the limit' /tmp/slowlog.out",
        120,
    );

    // --- worker reload mid-build re-adopts the running build ---------------
    let assigned = count(Node::Worker, "tribuchet-worker", "build assigned");
    let adopted = count(Node::Worker, "tribuchet-worker", "adopted running build");
    succeed(
        Node::Hub,
        "rm -f /tmp/reload.ok && systemd-run --unit=reloadbuild bash -lc \
         'nix-build /etc/tt/reload.nix --no-out-link > /tmp/reload.out && touch /tmp/reload.ok'",
    );
    wait_until_succeeds(
        Node::Worker,
        &format!("[ $(journalctl -u tribuchet-worker | grep -c 'build assigned') -gt {assigned} ]"),
        60,
    );
    // Settings changes also arrive via reload: bump max-jobs in the config.
    succeed(
        Node::Worker,
        "cp --remove-destination $(readlink -f /etc/tribuchet/worker.toml) /etc/tribuchet/worker.toml \
         && sed -i 's/max-jobs = 2/max-jobs = 3/' /etc/tribuchet/worker.toml",
    );
    succeed(Node::Worker, "systemctl reload tribuchet-worker");
    wait_until_succeeds(Node::Hub, "test -f /tmp/reload.ok", 120);
    let out = succeed(Node::Hub, "cat /tmp/reload.out");
    succeed(
        Node::Hub,
        &format!("grep -q reload-survived {}", out.trim()),
    );
    let adopted_now = count(Node::Worker, "tribuchet-worker", "adopted running build");
    assert!(
        adopted_now > adopted,
        "reload did not adopt the running build"
    );
    // The marker is only printed after the reload; seeing it in the client's
    // log means the adopted build streamed live logs through the new generation.
    assert_journal(Node::Hub, "reloadbuild", "log-after-reload");
    // The new generation logs its configuration: the max-jobs bump survived.
    assert_journal(Node::Worker, "tribuchet-worker", "max_jobs: 3");

    // --- killing the client cancels the build on the worker ---------------
    succeed(
        Node::Hub,
        "systemd-run --unit=cancelbuild bash -lc 'nix-build /etc/tt/cancel.nix --no-out-link'",
    );
    // bracket trick: do not match the pgrep wrapper's own cmdline
    wait_until_succeeds(Node::Worker, "pgrep -f 'cancel-marker-runnin[g]'", 60);
    succeed(Node::Hub, "systemctl kill --signal=SIGKILL cancelbuild");
    wait_until_succeeds(Node::Worker, "! pgrep -f 'cancel-marker-runnin[g]'", 60);
    assert_journal(Node::Hub, "tribuchet-hub", "cancelling build");

    // --- the cancelled derivation builds fine when asked again ------------
    let out = succeed_t(Node::Hub, "nix-build /etc/tt/cancel.nix --no-out-link", 120);
    succeed(Node::Hub, &format!("grep -q cancel-done {}", out.trim()));

    // --- concurrent builds share one worker session (quiet slot) ----------
    let t0 = Instant::now();
    succeed(
        Node::Hub,
        "nix-build /etc/tt/par.nix --no-out-link --max-jobs 2",
    );
    let elapsed = t0.elapsed().as_secs();
    assert!(
        elapsed < 27,
        "builds did not overlap: {elapsed}s (serial would be >=30s)"
    );

    // --- no worker: build is declined and falls back to a local build -----
    succeed(Node::Worker, "systemctl stop tribuchet-worker");
    // Let the hub observe the session tear down so it no longer counts capable.
    succeed(Node::Hub, "sleep 3");
    write_echo_deriv(
        "/root/fallback.nix",
        "tt-fallback-build",
        "fallback-payload",
        "built-locally",
    );
    let out = succeed_t(Node::Hub, "nix-build /root/fallback.nix --no-out-link", 120);
    succeed(
        Node::Hub,
        &format!("grep -q 'fallback-payload built-locally' {}", out.trim()),
    );
    assert_journal(Node::Hub, "tribuchet-hub", "no capable worker; declining");
    succeed(Node::Worker, "systemctl start tribuchet-worker");
    wait_journal(Node::Hub, "tribuchet-hub", "worker registered", 60);

    // --- build really ran on the worker -----------------------------------
    assert_journal(Node::Worker, "tribuchet-worker", "builder finished");
    assert_journal(
        Node::Worker,
        "tribuchet-worker",
        "per-build cgroup scoping enabled",
    );
    assert_journal(Node::Hub, "tribuchet-hub", "dispatching build");
    // Inputs are imported through the worker's nix-daemon and registered as
    // valid paths in its Nix database.
    succeed(
        Node::Worker,
        &format!("nix-store --check-validity {unique}"),
    );
}
