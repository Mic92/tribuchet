#!/usr/bin/env bash
# Start `tribuchet worker` against the hub's tailnet IP and keep it
# alive until the hub job has uploaded its `done` artifact.
set -euxo pipefail

: "${HUB_TS_IP:?}"
bin=$PWD/result/bin/tribuchet
done_artifact="hub-done-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"

sudo mkdir -p /etc/tribuchet /var/lib/tribuchet
sudo tee /etc/tribuchet/worker.toml >/dev/null <<EOF
hub = "http://${HUB_TS_IP}:7437"
auth = "tailscale"
max-jobs = 1
state-dir = "/var/lib/tribuchet"
EOF

# Root for the Linux sandbox (mount/user namespaces) and for importing
# inputs through nix-daemon as a trusted user. Redirect stays
# unprivileged so later steps can read the log.
# shellcheck disable=SC2024
sudo RUST_LOG=info "${bin}" worker --config /etc/tribuchet/worker.toml >worker.log 2>&1 &
echo $! >worker.pid

for _ in $(seq 1 180); do
  kill -0 "$(cat worker.pid)" 2>/dev/null || {
    cat worker.log
    exit 1
  }
  if gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/artifacts" \
    -q '.artifacts[].name' 2>/dev/null | grep -qx "${done_artifact}"; then
    break
  fi
  sleep 5
done

grep -q 'builder finished' worker.log
