#!/usr/bin/env bash
# Wait for a worker to register, then run a unique derivation through
# external-builders and assert it was dispatched.
set -euxo pipefail

for _ in $(seq 1 180); do
  grep -q 'worker registered' hub.log && break
  sleep 2
done
grep -q 'worker registered' hub.log || {
  cat hub.log
  exit 1
}

out=$(nix-build --no-out-link \
  -I nixpkgs="$(nix eval --raw nixpkgs#path)" \
  --argstr runId "${GITHUB_RUN_ID}" \
  .github/scripts/e2e/probe.nix)
grep -q built-on-worker-via-tailnet "${out}"
grep -q 'dispatching build' hub.log
touch ./done
