#!/usr/bin/env python3
"""Drive the two-runner e2e workflow.

One script with subcommands keeps the orchestration in one place and
out of the YAML; the workflow steps just call ``run.py <cmd>``.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import textwrap
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
BIN = REPO / "result" / "bin" / "tribuchet"
SANDBOXD_BIN = REPO / "result" / "bin" / "tribuchet-sandboxd"
HUB_LOG = REPO / "hub.log"
WORKER_LOG = REPO / "worker.log"
SANDBOXD_LOG = REPO / "sandboxd.log"


def run(cmd: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(cmd), file=sys.stderr)
    cp: subprocess.CompletedProcess[str] = subprocess.run(  # type: ignore[call-overload]
        cmd, check=True, text=True, **kw
    )
    return cp


def out(cmd: list[str]) -> str:
    return run(cmd, stdout=subprocess.PIPE).stdout.strip()


def sudo_write(path: str, content: str, *, append: bool = False) -> None:
    """Write a root-owned config file without shell quoting games."""
    run(
        ["sudo", "tee", "-a" if append else "--", path],
        input=content,
        stdout=subprocess.DEVNULL,
    )


def wait_for(
    pred: Callable[[], bool], *, timeout: int, interval: float = 1.0, what: str
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return
        time.sleep(interval)
    raise SystemExit(f"timed out after {timeout}s waiting for {what}")


def log_contains(path: Path, needle: str) -> bool:
    return path.exists() and needle in path.read_text(errors="replace")


def spawn_daemon(argv: list[str], log: Path) -> subprocess.Popen[bytes]:
    """Start a long-running process with its output captured to *log*
    (owned by the unprivileged runner so later steps can read it).
    ``start_new_session`` detaches it from this Python process so it
    survives the step boundary."""
    print("+", " ".join(argv), ">", log, file=sys.stderr)
    with log.open("wb") as fh:
        # Popen dups the fd; closing our handle is fine afterwards.
        return subprocess.Popen(
            argv, stdout=fh, stderr=subprocess.STDOUT, start_new_session=True
        )


# ---------------------------------------------------------------- hub ----


def hub_start(systems: list[str]) -> None:
    run(["sudo", "mkdir", "-p", "/etc/tribuchet", "/run/tribuchet"])

    # auth=tailscale: no TLS material; identity via tailscaled whois.
    # Restrict to tag:ci so only this workflow's runners can register.
    # worker-grace-secs covers the slowest matrix worker (macOS install
    # + cold cache) so per-system builds wait instead of declining.
    sudo_write(
        "/etc/tribuchet/hub.toml",
        textwrap.dedent(
            """\
            auth = "tailscale"
            listen = "0.0.0.0:7437"
            socket = "/run/tribuchet/hub.sock"
            config-dir = "/etc/tribuchet"
            worker-grace-secs = 600
            tailscale-allowed-tags = ["tag:ci"]
            """
        ),
    )

    # nix-daemon execs this as a nixbld* user, which cannot traverse
    # /home/runner; resolve to the world-readable /nix/store path.
    sudo_write(
        "/usr/local/bin/tribuchet-attach",
        f'#!/bin/sh\nexec {BIN.resolve()} attach "$1" --socket /run/tribuchet/hub.sock\n',
    )
    run(["sudo", "chmod", "+x", "/usr/local/bin/tribuchet-attach"])

    # `args` is required by the external-builders schema even when empty.
    eb = json.dumps(
        [
            {
                "systems": systems,
                "program": "/usr/local/bin/tribuchet-attach",
                "args": [],
            }
        ]
    )
    sudo_write(
        "/etc/nix/nix.conf",
        f"extra-experimental-features = external-builders\nexternal-builders = {eb}\n",
        append=True,
    )
    run(["sudo", "systemctl", "restart", "nix-daemon"])

    # Hub binds the attach socket to group nixbld and reads topTmpDir
    # owned by build users; both need root.
    proc = spawn_daemon(
        [
            "sudo",
            "RUST_LOG=info",
            str(BIN),
            "hub",
            "--config",
            "/etc/tribuchet/hub.toml",
        ],
        HUB_LOG,
    )
    wait_for(
        lambda: log_contains(HUB_LOG, "hub running") or proc.poll() is not None,
        timeout=30,
        what="hub to start",
    )
    if not log_contains(HUB_LOG, "hub running"):
        sys.stderr.write(HUB_LOG.read_text())
        raise SystemExit("hub did not start")

    (REPO / "addr.txt").write_text(out(["tailscale", "ip", "-4"]) + "\n")
    print(HUB_LOG.read_text())


def hub_build(systems: list[str]) -> None:
    wait_for(
        lambda: log_contains(HUB_LOG, "worker registered"),
        timeout=360,
        interval=2,
        what="a worker to register",
    )

    # The flake-locked nixpkgs is what nixbot built and cached.
    nixpkgs = out(["nix", "eval", "--raw", "--inputs-from", ".", "nixpkgs#path"])

    def build(probe: str, suffix: str) -> list[str]:
        # One nix-build for all systems: the hub queues each derivation
        # and dispatches it once the matching worker registers (within
        # worker-grace-secs), so per-system arrival order does not matter.
        paths = out(
            [
                "nix-build",
                "--no-out-link",
                "--max-jobs",
                str(len(systems)),
                "-I",
                f"nixpkgs={nixpkgs}",
                "--argstr",
                "runId",
                os.environ["GITHUB_RUN_ID"],
                "--arg",
                "systems",
                "[ " + " ".join(f'"{s}"' for s in systems) + " ]",
                str(REPO / ".github/scripts/e2e" / probe),
            ]
        ).splitlines()
        if len(paths) != len(systems):
            raise SystemExit(f"expected {len(systems)} outputs, got {paths!r}")
        for path in paths:
            payload = Path(path).read_text().strip()
            if not payload.endswith(suffix):
                raise SystemExit(f"unexpected build output in {path}: {payload!r}")
        return paths

    build("probe.nix", "-via-tailnet")
    build("probe-fod.nix", "fod-dns-ok")  # DNS + TLS from inside the sandbox
    if not log_contains(HUB_LOG, "dispatching build"):
        raise SystemExit("hub never dispatched a build")


# ------------------------------------------------------------- worker ----


def fetch_artifact(name: str, dest: str) -> None:
    """Poll for a sibling job's artifact in the same workflow run."""
    run_id = os.environ["GITHUB_RUN_ID"]

    def attempt() -> bool:
        r = subprocess.run(
            ["gh", "run", "download", run_id, "-n", name, "-D", dest],
            capture_output=True,
        )
        return r.returncode == 0

    wait_for(attempt, timeout=600, interval=5, what=f"artifact {name}")


def gh_api(path: str) -> Any | None:
    """GET the GitHub REST API via ``gh``; ``None`` on transient errors so
    poll-loop callers treat them as "not yet". ``gh`` carries its own CA
    bundle, which the macOS runner's Python lacks."""
    r = subprocess.run(
        ["gh", "api", f"repos/{os.environ['GITHUB_REPOSITORY']}/{path}"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def wait_buildbot(sha: str) -> None:
    """Block until the buildbot check run for *sha* succeeds, so the
    build below fetches nixbot's closure instead of rebuilding. Tolerates
    a not-yet-listed check (push fires before buildbot registers one)."""
    name = "buildbot/nix-build"

    def ready() -> bool:
        data = gh_api(f"commits/{sha}/check-runs?check_name={name}")
        if data is None:
            return False
        runs = data.get("check_runs", [])
        if not runs or any(r.get("status") != "completed" for r in runs):
            return False
        # Fail fast instead of waiting the full timeout: a red buildbot would
        # otherwise hang every push-triggered e2e until the deadline.
        if any(r.get("conclusion") != "success" for r in runs):
            raise SystemExit(f"{name} on {sha[:8]} did not succeed; skipping e2e")
        return True

    wait_for(ready, timeout=1800, interval=15, what=f"{name} on {sha[:8]}")


def job_conclusion(name: str) -> str | None:
    """Conclusion of a sibling job in this run, or ``None`` while it is
    still running / on transient API errors."""
    data = gh_api(f"actions/runs/{os.environ['GITHUB_RUN_ID']}/jobs")
    if data is None:
        return None
    for j in data.get("jobs", []):
        if j["name"] == name:
            c: str | None = j.get("conclusion")
            return c
    return None


def start_sandboxd(user: str) -> None:
    """Root daemon leasing per-build sandboxes to the unprivileged worker."""
    proc = spawn_daemon(
        [
            "sudo",
            "RUST_LOG=info",
            str(SANDBOXD_BIN),
            "--worker-user",
            user,
        ],
        SANDBOXD_LOG,
    )
    wait_for(
        lambda: (
            Path("/run/tribuchet-sandboxd.sock").exists() or proc.poll() is not None
        ),
        timeout=30,
        what="sandboxd to start",
    )
    if proc.poll() is not None:
        sys.stderr.write(SANDBOXD_LOG.read_text())
        raise SystemExit("sandboxd exited")


def worker_run(hub_ip: str) -> None:
    run(["sudo", "mkdir", "-p", "/etc/tribuchet", "/var/lib/tribuchet"])
    sudo_write(
        "/etc/tribuchet/worker.toml",
        textwrap.dedent(
            f"""\
            hub = "http://{hub_ip}:7437"
            auth = "tailscale"
            max-jobs = 1
            state-dir = "/var/lib/tribuchet"
            """
        ),
    )

    worker_cmd = [
        "RUST_LOG=info",
        str(BIN),
        "worker",
        "--config",
        "/etc/tribuchet/worker.toml",
    ]
    if sys.platform == "linux":
        # The Linux worker is unprivileged: it runs as the runner user and
        # leases each build's user namespace and cgroup from sandboxd.
        # Importing inputs through nix-daemon without signatures needs a
        # trusted user.
        user = out(["id", "-un"])
        run(["sudo", "chown", user, "/var/lib/tribuchet"])
        # Ubuntu 24.04 blocks unprivileged user namespaces by default
        run(["sudo", "sysctl", "-w", "kernel.apparmor_restrict_unprivileged_userns=0"])
        sudo_write("/etc/nix/nix.conf", f"trusted-users = root {user}\n", append=True)
        run(["sudo", "systemctl", "restart", "nix-daemon"])
        start_sandboxd(user)
        proc = spawn_daemon(["env", *worker_cmd], WORKER_LOG)
    else:
        # macOS: root for the Seatbelt sandbox and nix-daemon trust.
        proc = spawn_daemon(["sudo", *worker_cmd], WORKER_LOG)

    def finished() -> bool:
        if proc.poll() is not None:
            return True
        c = job_conclusion("hub")
        if c is None:
            return False
        if c != "success":
            sys.stderr.write(WORKER_LOG.read_text())
            raise SystemExit(f"hub job concluded {c!r}; aborting")
        return True

    wait_for(finished, timeout=900, interval=5, what="hub to finish")
    if not log_contains(WORKER_LOG, "builder finished"):
        sys.stderr.write(WORKER_LOG.read_text())
        raise SystemExit("worker never ran a build")


# ---------------------------------------------------------------- cli ----


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hub-start")
    p.add_argument("--systems", nargs="+", required=True)
    p = sub.add_parser("hub-build")
    p.add_argument("--systems", nargs="+", required=True)
    p = sub.add_parser("worker")
    p.add_argument("--hub-ip", required=True)
    p = sub.add_parser("fetch-artifact")
    p.add_argument("name")
    p.add_argument("dest")
    p = sub.add_parser("wait-buildbot")
    p.add_argument("sha")
    args = ap.parse_args()

    match args.cmd:
        case "hub-start":
            hub_start(args.systems)
        case "hub-build":
            hub_build(args.systems)
        case "worker":
            worker_run(args.hub_ip)
        case "fetch-artifact":
            fetch_artifact(args.name, args.dest)
        case "wait-buildbot":
            wait_buildbot(args.sha)


if __name__ == "__main__":
    main()
