#!/usr/bin/env bash
# treefmt check: cap source files at 600 lines to force module splits.
set -euo pipefail
max=600
rc=0
for f in "$@"; do
  lines=$(wc -l <"$f")
  if [ "$lines" -gt "$max" ]; then
    echo "error: $f has $lines lines (max $max); split it into submodules" >&2
    rc=1
  fi
done
exit "$rc"
