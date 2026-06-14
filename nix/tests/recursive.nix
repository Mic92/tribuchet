# Recursive-nix: the builder uses nix-store --add to register a new
# CA path through the worker's nix-daemon (reached via the sandbox
# bind-mount), and references it from $out. The worker must scan
# against all valid paths, pack the new path as a closure-delta
# extra, and ship it; the hub must import it and report it back to
# the patched Nix via result.json's addedPaths.
{ bash, nix }:
let
  bashPath = builtins.storePath bash;
  nixPath = builtins.storePath nix;
in
derivation {
  name = "tt-recursive";
  system = "x86_64-linux";
  builder = bashPath + "/bin/bash";
  requiredSystemFeatures = [ "recursive-nix" ];
  PATH = "${nixPath}/bin";
  # Nix sets NIX_REMOTE to a per-build .nix-socket for in-process
  # recursive-nix; override it to the bind-mounted worker daemon.
  NIX_REMOTE = "daemon";
  args = [
    "-c"
    ''
      set -e
      payload=$NIX_BUILD_TOP/payload
      echo recursive-payload > "$payload"
      inner=$(nix-store --add "$payload")
      # The new path is not bind-mounted back into the sandbox; the
      # hub-side check confirms it landed in the worker's store.
      case "$inner" in /nix/store/*-payload) ;; *) echo "bad path $inner" >&2; exit 1 ;; esac
      printf '%s\n' "$inner" > $out
    ''
  ];
}
