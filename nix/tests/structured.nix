# __structuredAttrs build: outputs and the exportReferencesGraph
# closure arrive via .attrs.sh / .attrs.json in the build dir instead
# of environment variables.
{ bash }:
let
  bashPath = builtins.storePath bash;
in
derivation {
  name = "tt-structured";
  system = "x86_64-linux";
  builder = bashPath + "/bin/bash";
  __structuredAttrs = true;
  exportReferencesGraph.graph = [ bashPath ];
  args = [
    "-c"
    ''
      . "$NIX_ATTRS_SH_FILE"
      json=$(< "$NIX_ATTRS_JSON_FILE")
      case "$json" in
        *${bashPath}*) echo structured-ok > "''${outputs[out]}" ;;
      esac
    ''
  ];
}
