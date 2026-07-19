# Logs ~64KB per second: slow enough to restart the worker before the
# 1MB max-log-size is reached, fast enough to exceed it soon after, so
# the limit must be enforced on the re-adopted build.
{ bash }:
derivation {
  name = "tt-slowlog";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  # bash builtins only: the sandbox has no coreutils
  args = [
    "-c"
    "while [ $SECONDS -lt 100 ]; do printf 'x%.0s' {1..65536}; echo; t=$((SECONDS+1)); while [ $SECONDS -lt $t ]; do :; done; done; echo never > $out"
  ];
}
