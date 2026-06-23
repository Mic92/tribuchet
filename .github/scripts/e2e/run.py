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
import urllib.request
from collections.abc import Callable
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
BIN = REPO / "result" / "bin" / "tribuchet"
HUB_LOG = REPO / "hub.log"
WORKER_LOG = REPO / "worker.log"


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


def hub_start() -> None:
    run(["sudo", "mkdir", "-p", "/etc/tribuchet", "/run/tribuchet"])

    # auth=tailscale: no TLS material; identity via tailscaled whois.
    # Restrict to tag:ci so only this workflow's runners can register.
    sudo_write(
        "/etc/tribuchet/hub.toml",
        textwrap.dedent(
            """\
            auth = "tailscale"
            listen = "0.0.0.0:7437"
            socket = "/run/tribuchet/hub.sock"
            config-dir = "/etc/tribuchet"
            worker-grace-secs = 90
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

    # Route x86_64-linux builds through tribuchet. `args` is required by
    # the external-builders schema even when empty.
    eb = json.dumps(
        [
            {
                "systems": ["x86_64-linux"],
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


def hub_build() -> None:
    wait_for(
        lambda: log_contains(HUB_LOG, "worker registered"),
        timeout=360,
        interval=2,
        what="a worker to register",
    )

    nixpkgs = out(["nix", "eval", "--raw", "nixpkgs#path"])
    result = out(
        [
            "nix-build",
            "--no-out-link",
            "-I",
            f"nixpkgs={nixpkgs}",
            "--argstr",
            "runId",
            os.environ["GITHUB_RUN_ID"],
            str(REPO / ".github/scripts/e2e/probe.nix"),
        ]
    )
    payload = Path(result).read_text()
    if "built-on-worker-via-tailnet" not in payload:
        raise SystemExit(f"unexpected build output: {payload!r}")
    if not log_contains(HUB_LOG, "dispatching build"):
        raise SystemExit("hub never dispatched the build")
    (REPO / "done").touch()


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


def artifact_exists(name: str) -> bool:
    """Cheaper than `gh run download` for a presence poll."""
    repo = os.environ["GITHUB_REPOSITORY"]
    run_id = os.environ["GITHUB_RUN_ID"]
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/artifacts",
        headers={
            "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.load(r)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        # Transient API errors are "not yet"; the wait loop keeps polling.
        return False
    return any(a["name"] == name for a in data.get("artifacts", []))


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

    # Root for the Linux sandbox (mount/user namespaces) and for
    # importing inputs through nix-daemon as a trusted user.
    proc = spawn_daemon(
        [
            "sudo",
            "RUST_LOG=info",
            str(BIN),
            "worker",
            "--config",
            "/etc/tribuchet/worker.toml",
        ],
        WORKER_LOG,
    )

    run_id = os.environ["GITHUB_RUN_ID"]
    attempt = os.environ["GITHUB_RUN_ATTEMPT"]
    done = f"hub-done-{run_id}-{attempt}"
    wait_for(
        lambda: proc.poll() is not None or artifact_exists(done),
        timeout=900,
        interval=5,
        what="hub to finish",
    )
    if not log_contains(WORKER_LOG, "builder finished"):
        sys.stderr.write(WORKER_LOG.read_text())
        raise SystemExit("worker never ran a build")


# ---------------------------------------------------------------- cli ----


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("hub-start")
    sub.add_parser("hub-build")
    p = sub.add_parser("worker")
    p.add_argument("--hub-ip", required=True)
    p = sub.add_parser("fetch-artifact")
    p.add_argument("name")
    p.add_argument("dest")
    args = ap.parse_args()

    match args.cmd:
        case "hub-start":
            hub_start()
        case "hub-build":
            hub_build()
        case "worker":
            worker_run(args.hub_ip)
        case "fetch-artifact":
            fetch_artifact(args.name, args.dest)


if __name__ == "__main__":
    main()
