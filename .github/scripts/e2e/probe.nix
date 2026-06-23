# Trivial derivation the e2e workflow builds through tribuchet.
# `runId` makes the output uncacheable so it always reaches the worker.
{
  runId,
  pkgs ? import <nixpkgs> { },
}:
derivation {
  name = "tribuchet-e2e-${runId}";
  system = "x86_64-linux";
  # A store-path builder gives the derivation an input closure that
  # tribuchet must ship to the worker; /bin/sh would not exist in the
  # sandbox.
  builder = "${pkgs.bash}/bin/bash";
  args = [
    "-c"
    "echo built-on-worker-via-tailnet > $out"
  ];
}
