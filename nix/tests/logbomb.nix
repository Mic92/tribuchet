# Logs forever; the worker must kill it at --max-log-size.
{ bash }:
derivation {
  name = "tt-logbomb";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  args = [
    "-c"
    "while :; do echo spamspamspamspamspamspamspamspamspamspamspam; done"
  ];
}
