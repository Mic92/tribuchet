# OCI image for the worker: the entrypoint starts a nix-daemon for
# the container's own store, then the worker with its spawned agents.
# Config and keys come from a mounted /etc/tribuchet.
{
  dockerTools,
  writeShellScript,
  writeTextDir,
  tribuchet,
  nix,
  cacert,
  bashInteractive,
  coreutils,
}:
let
  entrypoint = writeShellScript "tribuchet-worker-entrypoint" ''
    set -eu
    nix-daemon &
    exec tribuchet worker --config /etc/tribuchet/worker.toml
  '';
  # auto-GC so imported inputs do not fill the store
  nixConf = writeTextDir "etc/nix/nix.conf" ''
    min-free = 1073741824
    max-free = 5368709120
  '';
in
dockerTools.buildLayeredImage {
  name = "tribuchet-worker";
  tag = "latest";
  contents = [
    tribuchet
    nix
    cacert
    bashInteractive
    coreutils
    dockerTools.fakeNss
    nixConf
  ];
  extraCommands = ''
    mkdir -p tmp var/lib/tribuchet/worker etc/tribuchet nix/var/nix
  '';
  config = {
    Entrypoint = [ entrypoint ];
    Env = [
      "SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt"
      "PATH=/bin"
    ];
  };
}
