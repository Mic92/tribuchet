# Fetches from the hub's TCP server through pasta and asserts the
# worker's loopback service is unreachable from the sandbox.
{ bash, hubIp }:
derivation {
  name = "tt-fod";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  args = [
    "-c"
    ''
      if (exec 3<>/dev/tcp/127.0.0.1/9999) 2>/dev/null; then
        echo "worker loopback leaked into FOD netns" >&2
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
