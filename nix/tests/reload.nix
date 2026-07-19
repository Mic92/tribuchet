# restart survivor: keeps building across a worker restart.
{ bash }:
derivation {
  name = "tt-reload";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  # busy-wait 15s of wall clock: long enough to restart the worker
  # while this build is executing. The log line near the end shows up
  # only if the new worker instance streams the adopted build's log.
  args = [
    "-c"
    "while [ $SECONDS -lt 15 ]; do :; done; echo log-after-reload >&2; echo reload-survived > $out"
  ];
}
