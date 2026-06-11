# Foreign-system build via binfmt emulation: must report the foreign
# architecture and run as uid 1000.
{ busybox }:
derivation {
  name = "tt-cross";
  system = "aarch64-linux";
  builder = builtins.storePath busybox + "/bin/busybox";
  args = [
    "sh"
    "-c"
    ''"$builder" uname -m > $out; "$builder" id -u >> $out''
  ];
}
