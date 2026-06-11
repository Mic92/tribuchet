# Requires the kvm system feature and expects the device in the sandbox.
{
  bash,
  system ? "x86_64-linux",
}:
derivation {
  name = "tt-kvm";
  inherit system;
  requiredSystemFeatures = [ "kvm" ];
  builder = builtins.storePath bash + "/bin/bash";
  args = [
    "-c"
    "[ -e /dev/kvm ] && echo kvm-ok > $out"
  ];
}
