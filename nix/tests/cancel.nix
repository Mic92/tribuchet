# First run: the test kills the nix-build client mid-build and expects
# the hub to cancel the build on the worker (well before the 30s are
# up). Second run: the same derivation must build to completion,
# proving the cancellation left no stale per-derivation state behind.
{ bash }:
derivation {
  name = "tt-cancel";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  args = [
    "-c"
    "echo cancel-marker-running >&2; while [ $SECONDS -lt 30 ]; do :; done; echo cancel-done > $out"
  ];
}
