# nix-darwin module for the tribuchet hub and worker.
#
# Worker: launchd has no ExecReload, so zero-downtime upgrades work
# like on NixOS, just driven from activation: the daemon execs a
# stable symlink in the state dir, activation flips it to the new
# package and sends SIGHUP, and the reaper execs a fresh worker
# generation that re-adopts running builds. The plist contains neither
# the package store path nor the settings (those live in
# /etc/tribuchet/worker.toml), so neither a package bump nor a
# settings change makes nix-darwin restart the daemon; both arrive via
# the SIGHUP reload.
#
# Hub: launchd holds the attach socket and the worker port (the hub
# adopts them via launch_activate_socket), so hub restarts never
# refuse connections, clients just queue.
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.tribuchet-worker;
  hub = config.services.tribuchet-hub;
  defaultPackage = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
  execLink = "${cfg.stateDir}/exec";
  label = "org.nixos.tribuchet-worker";
  format = pkgs.formats.toml { };
  workerToml = format.generate "worker.toml" ({ state-dir = toString cfg.stateDir; } // cfg.settings);
  hubToml = format.generate "hub.toml" (
    {
      socket = toString hub.socketPath;
      listen = "${hub.listenAddress}:${toString hub.port}";
      config-dir = toString hub.configDir;
    }
    // hub.settings
  );
in
{
  options.services.tribuchet-hub = {
    enable = lib.mkEnableOption "tribuchet build hub";
    package = lib.mkOption {
      type = lib.types.package;
      default = defaultPackage;
      defaultText = lib.literalExpression "tribuchet";
      description = "Package providing bin/tribuchet.";
    };
    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "0.0.0.0";
      description = "Address the worker-facing gRPC listener binds to.";
    };
    port = lib.mkOption {
      type = lib.types.port;
      default = 7437;
      description = "Port of the worker-facing gRPC listener.";
    };
    socketPath = lib.mkOption {
      type = lib.types.path;
      default = "/var/run/tribuchet/hub.sock";
      description = "Unix socket `tribuchet attach` (Nix's external builder) connects to.";
    };
    configDir = lib.mkOption {
      type = lib.types.path;
      default = "/etc/tribuchet";
      description = "Directory with the CA material and hub TLS key pair.";
    };
    settings = lib.mkOption {
      type = format.type;
      default = { };
      description = "Extra settings merged into hub.toml.";
    };
    logFile = lib.mkOption {
      type = lib.types.path;
      default = "/var/log/tribuchet-hub.log";
      description = "launchd stdout/stderr destination.";
    };
  };

  options.services.tribuchet-worker = {
    enable = lib.mkEnableOption "tribuchet build worker";
    package = lib.mkOption {
      type = lib.types.package;
      default = defaultPackage;
      defaultText = lib.literalExpression "tribuchet";
      description = "Package providing bin/tribuchet.";
    };
    stateDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/tribuchet";
      description = "State directory: TLS material, build dirs, exec symlink.";
    };
    settings = lib.mkOption {
      type = format.type;
      example = lib.literalExpression ''
        {
          hub = "https://hub.example.org:7437";
          max-jobs = 4;
        }
      '';
      description = ''
        Contents of worker.toml. Changes are applied with a SIGHUP
        reload, so running builds survive them. The `hub` key is
        required.
      '';
    };
    logFile = lib.mkOption {
      type = lib.types.path;
      default = "/var/log/tribuchet-worker.log";
      description = "launchd stdout/stderr destination.";
    };
  };

  config = lib.mkMerge [
    (lib.mkIf hub.enable {
      environment.etc."tribuchet/hub.toml".source = hubToml;
      launchd.daemons.tribuchet-hub.serviceConfig = {
        ProgramArguments = [
          (lib.getExe' hub.package "tribuchet")
          "hub"
          "--config"
          "/etc/tribuchet/hub.toml"
        ];
        # launchd owns the listeners (socket activation): the hub
        # adopts them by these names via launch_activate_socket, so
        # they keep accepting across hub restarts.
        Sockets = {
          attach = {
            SockPathName = toString hub.socketPath;
            # 0660; launchd cannot set a group, so until the hub starts
            # and chowns the path to nixbld only root can connect.
            SockPathMode = 432;
          };
          workers = {
            SockNodeName = hub.listenAddress;
            SockServiceName = toString hub.port;
          };
        };
        KeepAlive = true;
        RunAtLoad = true;
        StandardOutPath = toString hub.logFile;
        StandardErrorPath = toString hub.logFile;
        EnvironmentVariables.RUST_LOG = "info";
      };
    })

    (lib.mkIf cfg.enable {
      environment.etc."tribuchet/worker.toml".source = workerToml;
      launchd.daemons.tribuchet-worker.serviceConfig = {
        ProgramArguments = [
          execLink
          "worker"
          "--config"
          "/etc/tribuchet/worker.toml"
        ];
        KeepAlive = true;
        RunAtLoad = true;
        StandardOutPath = toString cfg.logFile;
        StandardErrorPath = toString cfg.logFile;
        EnvironmentVariables.RUST_LOG = "info";
      };

      # The symlink must point at the new package before launchd could
      # (re)start the daemon; the SIGHUP afterwards hands running builds
      # over to the new binary.
      system.activationScripts.preActivation.text = ''
        mkdir -p ${lib.escapeShellArg (toString cfg.stateDir)}
        ln -sfn ${lib.getExe' cfg.package "tribuchet"} ${lib.escapeShellArg execLink}
      '';
      system.activationScripts.postActivation.text = ''
        /bin/launchctl kill SIGHUP system/${label} 2>/dev/null || true
      '';
    })
  ];
}
