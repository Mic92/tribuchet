# Never finishes on its own; the test kills the nix-build client and
# expects the hub to cancel the build on the worker.
{ bash }:
derivation {
  name = "tt-cancel";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  args = [
    "-c"
    "echo cancel-marker-running >&2; while :; do :; done"
  ];
}
