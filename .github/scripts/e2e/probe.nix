# Trivial per-system derivations the e2e workflow builds through
# tribuchet. `runId` makes the outputs uncacheable so each one always
# reaches its worker.
{
  runId,
  systems,
  nixpkgs ? <nixpkgs>,
}:
let
  one = system: {
    name = system;
    value = derivation {
      name = "tribuchet-e2e-${system}-${runId}";
      inherit system;
      # A store-path builder gives the derivation an input closure that
      # tribuchet must ship to the worker; /bin/sh would not exist in
      # the Linux sandbox.
      builder = "${(import nixpkgs { inherit system; }).bash}/bin/bash";
      args = [
        "-c"
        "echo built-on-${system}-via-tailnet > $out"
      ];
    };
  };
in
builtins.listToAttrs (map one systems)
