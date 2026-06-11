# Requires the kvm system feature and expects the device in the sandbox.
{ bash }:
derivation {
  name = "tt-kvm";
  system = "x86_64-linux";
  requiredSystemFeatures = [ "kvm" ];
  builder = builtins.storePath bash + "/bin/bash";
  args = [
    "-c"
    "[ -e /dev/kvm ] && echo kvm-ok > $out"
  ];
}
