# Impure derivation: rebuilt every time, output content-addressed.
{ bash }:
derivation {
  name = "tt-impure";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  __impure = true;
  args = [
    "-c"
    "echo impure-ok > $out"
  ];
}
