# The test stops the whole worker unit while this build runs and
# expects systemd to kill the build subtree and sandboxd to reap the
# leased cgroup; the build never finishes.
{ bash }:
derivation {
  name = "tt-stop";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  args = [
    "-c"
    ''
      echo stop-marker-running >&2
      while [ $SECONDS -lt 120 ]; do :; done
      echo not-reached > $out
    ''
  ];
}
