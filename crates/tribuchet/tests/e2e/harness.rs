use std::env as std_env;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::Once;
use std::thread;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Nodes and environment
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub enum Node {
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

pub fn env(key: &str) -> String {
    std_env::var(key).unwrap_or_else(|_| panic!("missing env var {key}"))
}

pub fn bash() -> String {
    env("TT_BASH")
}

// ---------------------------------------------------------------------------
// ssh plumbing
// ---------------------------------------------------------------------------

fn ssh_base(node: Node) -> Vec<String> {
    let mut args = vec!["-F".into(), env("TT_SSH_CONFIG")];
    for opt in [
        "User=root",
        "StrictHostKeyChecking=no",
        "UserKnownHostsFile=/dev/null",
        // No ControlMaster: multiplexed sessions share the master's
        // fate, and one test flooding the connection killed them all.
        "ConnectTimeout=10",
        "ServerAliveInterval=30",
        "ServerAliveCountMax=10",
        "LogLevel=ERROR",
    ] {
        args.push("-o".into());
        args.push(opt.into());
    }
    args.push(format!("vsock-mux/{}", node.sock()));
    args
}

pub struct Out {
    pub code: i32,
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
    // A connect-phase failure happens before the remote command runs,
    // so retrying cannot re-execute anything.
    for _ in 0..3 {
        let o = run_once(node, cmd, timeout);
        if o.code == 255 && !o.timed_out && connect_failed(&o.stderr) {
            thread::sleep(Duration::from_secs(2));
            continue;
        }
        return o;
    }
    run_once(node, cmd, timeout)
}

fn connect_failed(stderr: &str) -> bool {
    [
        "banner exchange",
        "Connection refused",
        "Connection timed out",
        "Connection closed by remote host",
        "kex_exchange_identification",
    ]
    .iter()
    .any(|m| stderr.contains(m))
}

fn run_once(node: Node, cmd: &str, timeout: Duration) -> Out {
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

pub fn run(node: Node, cmd: &str) -> Out {
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
pub fn succeed_t(node: Node, cmd: &str, secs: u64) -> String {
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

pub fn succeed(node: Node, cmd: &str) -> String {
    succeed_t(node, cmd, 900)
}

/// Run `cmd`, asserting a non-zero *command* exit, returning combined output.
pub fn fail(node: Node, cmd: &str) -> String {
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

pub fn wait_until_succeeds(node: Node, cmd: &str, secs: u64) {
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
pub fn count(node: Node, unit: &str, pattern: &str) -> i64 {
    succeed(
        node,
        &format!("journalctl -u {unit} | grep -c '{pattern}' || true"),
    )
    .trim()
    .parse()
    .unwrap_or(0)
}

pub fn assert_journal(node: Node, unit: &str, pattern: &str) {
    assert!(
        count(node, unit, pattern) > 0,
        "[{}] journal for {unit} missing pattern: {pattern}",
        node.name()
    );
}

pub fn wait_journal(node: Node, unit: &str, pattern: &str, secs: u64) {
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

pub fn write_file(node: Node, path: &str, content: &str) {
    // Quoted heredoc: content is written verbatim, no shell expansion or
    // quoting to worry about (no test payload contains the TTEOF sentinel).
    succeed(node, &format!("cat > {path} <<'TTEOF'\n{content}\nTTEOF"));
}

pub fn build_grep(nixfile: &str, needle: &str) {
    let out = succeed(Node::Hub, &format!("nix-build {nixfile} --no-out-link"));
    let out = out.trim();
    succeed(Node::Hub, &format!("grep -q '{needle}' {out}"));
}

// ---------------------------------------------------------------------------
// One-time readiness: heartbeat + wait for both nodes' sshd
// ---------------------------------------------------------------------------

static READY: Once = Once::new();

pub fn ensure_ready() {
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
pub fn write_echo_deriv(path: &str, name: &str, payload: &str, suffix: &str) -> String {
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
