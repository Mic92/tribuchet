# uid-range build on a rootless worker: in-namespace root over a leased
# 65536-uid range with a delegated cgroup.
{ bash }:
derivation {
  name = "tt-uid-range-rootless";
  system = "x86_64-linux";
  requiredSystemFeatures = [ "uid-range" ];
  builder = builtins.storePath bash + "/bin/bash";
  args = [
    "-c"
    ''
      [ "$EUID" = 0 ] || exit 1
      read -r _ _ count < /proc/self/uid_map
      [ "$count" = 65536 ] || exit 1
      [ -w /sys/fs/cgroup/cgroup.procs ] || exit 1
      echo uid-range-rootless-ok > $out
    ''
  ];
}
