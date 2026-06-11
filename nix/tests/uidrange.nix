# uid-range build: in-namespace root with a delegated cgroup.
{ bash }:
derivation {
  name = "tt-uid-range";
  system = "x86_64-linux";
  requiredSystemFeatures = [ "uid-range" ];
  builder = builtins.storePath bash + "/bin/bash";
  args = [
    "-c"
    ''[ "$EUID" = 0 ] && [ -w /sys/fs/cgroup/cgroup.procs ] && echo uid-range-ok > $out''
  ];
}
