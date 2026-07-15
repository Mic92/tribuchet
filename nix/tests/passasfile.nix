# writeText-style derivation: the passAsFile .attr file is unpacked
# into /build by the worker (unmapped uid in the build's userns) and
# `mv` must still be able to unlink it.
{
  bash,
  coreutils,
}:
derivation {
  name = "tt-pass-as-file";
  system = "x86_64-linux";
  builder = "${builtins.storePath bash}/bin/bash";
  PATH = "${builtins.storePath coreutils}/bin";
  passAsFile = [ "text" ];
  text = "pass-as-file-ok";
  args = [
    "-c"
    ''mv "$textPath" $out''
  ];
}
