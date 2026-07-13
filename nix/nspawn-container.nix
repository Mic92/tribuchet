# Boot a NixOS container with systemd-nspawn inside a uid-range build;
# adapted from Nix's tests/nixos/containers/systemd-nspawn.nix.
{ nixpkgs }:

let

  machine =
    { config, pkgs, ... }:
    {
      system.stateVersion = "22.05";
      boot.isContainer = true;
      systemd.services.console-getty.enable = false;
      networking.dhcpcd.enable = false;

      systemd.services.test = {
        wantedBy = [ "multi-user.target" ];
        script = ''
          source /.env
          echo "Hello World" > $out/msg
        '';
        unitConfig = {
          FailureAction = "exit-force";
          FailureActionExitStatus = 42;
          SuccessAction = "exit-force";
        };
      };
    };

  cfg = (
    import (nixpkgs + "/nixos/lib/eval-config.nix") {
      modules = [ machine ];
      system = "x86_64-linux";
    }
  );

  config = cfg.config;

in

with cfg._module.args.pkgs;

runCommand "tt-nspawn"
  {
    buildInputs = [ config.system.path ];
    requiredSystemFeatures = [ "uid-range" ];
    toplevel = config.system.build.toplevel;
  }
  ''
    root=$(pwd)/root
    mkdir -p $root $root/etc

    export > $root/.env
    # Somehow systemd silently dies without this directory.
    mkdir $root/usr

    # Make /run a tmpfs to shut up a systemd warning.
    mkdir -p /run
    mount -t tmpfs none /run

    mkdir -p $out

    touch /etc/os-release
    echo a5ea3f98dedc0278b6f3cc8c37eeaeac > /etc/machine-id

    SYSTEMD_NSPAWN_UNIFIED_HIERARCHY=1 \
      ${config.systemd.package}/bin/systemd-nspawn \
      --keep-unit \
      -M ${config.networking.hostName} -D "$root" \
      --register=no \
      --resolv-conf=off \
      --bind-ro=/nix/store \
      --bind=$out \
      --bind=/proc:/run/host/proc \
      --bind=/sys:/run/host/sys \
      --private-network \
      $toplevel/init
  ''
