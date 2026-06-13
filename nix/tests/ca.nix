# Floating content-addressed derivation: the scratch output is hashed
# and moved to its final content-addressed path by Nix after the
# remote build returns.
{ bash }:
derivation {
  name = "tt-ca";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  __contentAddressed = true;
  outputHashMode = "recursive";
  outputHashAlgo = "sha256";
  args = [
    "-c"
    "echo ca-ok > $out"
  ];
}
