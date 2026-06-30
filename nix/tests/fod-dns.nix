# Like fod.nix, but reaches the hub's TCP server through a hostname so
# the build resolves a name with getaddrinfo. Caller picks a name that
# resolves via /etc/hosts or only via DNS.
{ bash, host }:
derivation {
  name = "tt-fod-dns";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  args = [
    "-c"
    ''
      exec 3<>/dev/tcp/${host}/8765
      while IFS= read -r l <&3; do printf '%s\n' "$l"; done > $out
    ''
  ];
  outputHashAlgo = "sha256";
  outputHashMode = "flat";
  outputHash = "fba0ea84c93fbcbfff10a9b33bc33409b5fd15eff0540b7b4389d691cde59fe8";
}
