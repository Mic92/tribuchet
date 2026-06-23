#!/usr/bin/env bash
# Configure nix-daemon for external-builders, start `tribuchet hub` in
# tailscale-auth mode, and write the hub's tailnet IPv4 to addr.txt for
# the worker job to download.
set -euxo pipefail

bin=$PWD/result/bin/tribuchet

sudo mkdir -p /etc/tribuchet /run/tribuchet

# auth=tailscale: no TLS material; identity via tailscaled whois.
# Restrict to tag:ci so only this workflow's runners can register.
sudo tee /etc/tribuchet/hub.toml >/dev/null <<'EOF'
auth = "tailscale"
listen = "0.0.0.0:7437"
socket = "/run/tribuchet/hub.sock"
config-dir = "/etc/tribuchet"
worker-grace-secs = 90
tailscale-allowed-tags = ["tag:ci"]
EOF

# nix-daemon execs this for every external build.
sudo tee /usr/local/bin/tribuchet-attach >/dev/null <<EOF
#!/bin/sh
exec ${bin} attach "\$1" --socket /run/tribuchet/hub.sock
EOF
sudo chmod +x /usr/local/bin/tribuchet-attach

# Route x86_64-linux builds through tribuchet.
sudo tee -a /etc/nix/nix.conf >/dev/null <<'EOF'
extra-experimental-features = external-builders
external-builders = [{"systems":["x86_64-linux"],"program":"/usr/local/bin/tribuchet-attach"}]
EOF
sudo systemctl restart nix-daemon

# Hub binds the attach socket to group nixbld; needs root for that and
# for reading topTmpDir owned by build users. The redirect runs as the
# unprivileged runner user on purpose so later steps can read the log.
# shellcheck disable=SC2024
sudo RUST_LOG=info "${bin}" hub --config /etc/tribuchet/hub.toml >hub.log 2>&1 &
echo $! >hub.pid
for _ in $(seq 1 30); do
  grep -q 'hub running' hub.log && break
  kill -0 "$(cat hub.pid)" 2>/dev/null || break
  sleep 1
done
grep -q 'hub running' hub.log || {
  cat hub.log
  exit 1
}

tailscale ip -4 >addr.txt
cat addr.txt hub.log
