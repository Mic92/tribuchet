{ bash }:
derivation {
  name = "tt-drain";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  # busy-wait 20s of wall clock: long enough to restart both daemons
  # while this build is executing.
  args = [
    "-c"
    "while [ $SECONDS -lt 20 ]; do :; done; echo drained-not-cancelled > $out"
  ];
}
