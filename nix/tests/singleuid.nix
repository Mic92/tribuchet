# Regular build: a single leased uid, so the builder never runs as
# the worker's own uid or as sandbox root. checkCgroup is off for
# workers without a delegated cgroup, e.g. the container route.
{
  bash,
  checkCgroup ? true,
}:
derivation {
  name = "tt-single-uid";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  checkCgroup = if checkCgroup then "1" else "";
  args = [
    "-c"
    ''
      [ "$EUID" = 1000 ] || exit 1
      read -r inner outer count < /proc/self/uid_map
      [ "$inner" = 1000 ] && [ "$count" = 1 ] || exit 1
      if [ "$checkCgroup" = 1 ]; then
        [ -w /sys/fs/cgroup/cgroup.procs ] || exit 1
      fi
      # no worker fds leak into the builder: only stdio (plus the fd
      # the shell needs to list the directory)
      for fd in /proc/self/fd/*; do [ "''${fd##*/}" -le 3 ] || exit 1; done
      # skeleton lives on an in-namespace tmpfs owned by the build
      [ -O / ] && [ -O /etc ] || exit 1
      # the e2e test checks the backing uid is not the worker's
      echo "single-uid-ok $outer" > $out
    ''
  ];
}
