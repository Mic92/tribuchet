# Grows past build-memory-max-bytes and memory.max must OOM-kill it.
# Bounded at 3 GiB so a missing limit fails instead of panicking the VM.
{ bash }:
derivation {
  name = "tt-memhog";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  args = [
    "-c"
    "x=aaaaaaaaaaaaaaaa; while [ \${#x} -lt 3221225472 ]; do x=$x$x; done"
  ];
}
