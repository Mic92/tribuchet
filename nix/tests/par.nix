{ bash }:
let
  mk =
    n:
    derivation {
      name = "tt-par-${n}";
      system = "x86_64-linux";
      builder = builtins.storePath bash + "/bin/bash";
      # busy-wait 15s of wall clock; two of these finishing in
      # well under 30s proves they overlapped on the worker
      args = [
        "-c"
        "while [ $SECONDS -lt 15 ]; do :; done; echo done-$n > $out"
      ];
      inherit n;
    };
in
[
  (mk "a")
  (mk "b")
]
