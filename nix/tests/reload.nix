# reload survivor: keeps building across a worker reload (handover).
{ bash }:
derivation {
  name = "tt-reload";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  # busy-wait 15s of wall clock: long enough to reload the worker
  # while this build is executing
  args = [
    "-c"
    "while [ $SECONDS -lt 15 ]; do :; done; echo reload-survived > $out"
  ];
}
