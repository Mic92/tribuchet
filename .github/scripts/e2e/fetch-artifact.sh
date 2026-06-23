#!/usr/bin/env bash
# Poll for a sibling job's artifact in the same workflow run.
# Usage: fetch-artifact.sh <artifact-name> <dest-dir>
set -euo pipefail

name=$1
dest=$2
for _ in $(seq 1 120); do
  if gh run download "${GITHUB_RUN_ID}" -n "${name}" -D "${dest}" 2>/dev/null; then
    exit 0
  fi
  sleep 5
done
echo "artifact ${name} did not appear" >&2
exit 1
