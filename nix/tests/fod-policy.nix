# Asserts the worker's `[fod-network]` deny rule blocks the hub's
# second port (denied SYNs are dropped, so the connect attempt times
# out) while the allowed port still serves the fixed output.
{
  bash,
  coreutils,
  hubIp,
}:
derivation {
  name = "tt-fod-policy";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  PATH = "${builtins.storePath coreutils}/bin:${builtins.storePath bash}/bin";
  args = [
    "-c"
    ''
      if timeout 5 bash -c 'exec 3<>/dev/tcp/${hubIp}/8766' 2>/dev/null; then
        echo "denied port 8766 was reachable from the FOD netns" >&2
        exit 1
      fi
      exec 3<>/dev/tcp/${hubIp}/8765
      while IFS= read -r l <&3; do printf '%s\n' "$l"; done > $out
    ''
  ];
  outputHashAlgo = "sha256";
  outputHashMode = "flat";
  outputHash = "fba0ea84c93fbcbfff10a9b33bc33409b5fd15eff0540b7b4389d691cde59fe8";
}
