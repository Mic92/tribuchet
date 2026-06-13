# exportReferencesGraph: Nix writes the closure registration info into
# the build's temp dir before the builder runs; with external builders
# that file travels to the worker inside the topTmpDir tarball.
{ bash }:
let
  bashPath = builtins.storePath bash;
in
derivation {
  name = "tt-refgraph";
  system = "x86_64-linux";
  builder = bashPath + "/bin/bash";
  exportReferencesGraph = [
    "graph"
    bashPath
  ];
  args = [
    "-c"
    ''
      ok=
      while IFS= read -r line; do
        case "$line" in
          *${bashPath}*) ok=1 ;;
        esac
      done < graph
      [ -n "$ok" ] && echo refgraph-ok > $out
    ''
  ];
}
