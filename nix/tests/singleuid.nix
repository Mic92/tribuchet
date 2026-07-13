# Regular build: a single leased uid, so the builder never runs as
# the worker's own uid or as sandbox root.
{ bash }:
derivation {
  name = "tt-single-uid";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  args = [
    "-c"
    ''
      [ "$EUID" = 1000 ] || exit 1
      read -r inner outer count < /proc/self/uid_map
      [ "$inner" = 1000 ] && [ "$count" = 1 ] || exit 1
      [ -w /sys/fs/cgroup/cgroup.procs ] || exit 1
      # skeleton lives on an in-namespace tmpfs owned by the build
      [ -O / ] && [ -O /etc ] || exit 1
      # the e2e test checks the backing uid is not the worker's
      echo "single-uid-ok $outer" > $out
    ''
  ];
}
