# The test stops the whole worker unit while this build runs. With
# KillMode=process the build keeps running and the restarted worker
# re-adopts it.
{ bash }:
derivation {
  name = "tt-stop";
  system = "x86_64-linux";
  builder = builtins.storePath bash + "/bin/bash";
  args = [
    "-c"
    ''
      echo stop-marker-running >&2
      while [ $SECONDS -lt 30 ]; do :; done
      echo stop-survived > $out
    ''
  ];
}
