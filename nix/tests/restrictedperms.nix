# The builder restricts its output to owner-only permissions (like
# python's dist outputs). The worker packs as an unprivileged uid
# while the files belong to the leased build uid, so reading them
# takes the idmapped pack mount.
{
  bash,
  coreutils,
}:
derivation {
  name = "tt-restricted-perms";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  PATH = "${builtins.storePath coreutils}/bin";
  args = [
    "-c"
    ''
      mkdir -p $out/private
      echo restricted-perms-ok > $out/private/data
      chmod 0600 $out/private/data
      chmod 0700 $out/private $out
    ''
  ];
}
