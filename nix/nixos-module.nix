# NixOS module for the tribuchet hub and worker.
#
# Hub: socket-activated (systemd holds the attach socket and the worker
# port), so hub restarts never refuse connections, clients just queue.
# Worker: a small reaper process is the main pid; the unit execs the
# worker through a stable /run symlink and reloads instead of
# restarting on package changes, so running builds survive upgrades
# (the reaper execs a fresh worker generation that re-adopts them).
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  hub = config.services.tribuchet-hub;
  worker = config.services.tribuchet-worker;
  defaultPackage = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
  format = pkgs.formats.toml { };
  hubToml = format.generate "hub.toml" (
    {
      socket = toString hub.socketPath;
      listen = "${hub.listenAddress}:${toString hub.port}";
      config-dir = toString hub.configDir;
    }
    // hub.settings
  );
  workerToml = format.generate "worker.toml" worker.settings;
  workerExec = "/run/tribuchet-worker/exec";
  flipWorkerExec = "${pkgs.coreutils}/bin/ln -sfn ${lib.getExe' worker.package "tribuchet"} ${workerExec}";
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
    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the worker port in the firewall.";
    };
    socketPath = lib.mkOption {
      type = lib.types.path;
      default = "/run/tribuchet/hub.sock";
      description = "Unix socket `tribuchet attach` (Nix's external builder) connects to.";
    };
    socketGroup = lib.mkOption {
      type = lib.types.str;
      default = "nixbld";
      description = "Group allowed to connect to the attach socket.";
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
  };

  options.services.tribuchet-worker = {
    enable = lib.mkEnableOption "tribuchet build worker";
    package = lib.mkOption {
      type = lib.types.package;
      default = defaultPackage;
      defaultText = lib.literalExpression "tribuchet";
      description = "Package providing bin/tribuchet.";
    };
    settings = lib.mkOption {
      type = format.type;
      example = lib.literalExpression ''
        {
          hub = "https://hub.example.org:7437";
          max-jobs = 4;
          max-log-size = 67108864;
          emulate.aarch64-linux = "''${pkgs.pkgsStatic.qemu-user}/bin/qemu-aarch64";
        }
      '';
      description = ''
        Contents of worker.toml. Changes are applied with a reload, so
        running builds survive them. The `hub` key is required.
      '';
    };
  };

  config = lib.mkMerge [
    (lib.mkIf hub.enable {
      networking.firewall.allowedTCPPorts = lib.optional hub.openFirewall hub.port;
      systemd.sockets.tribuchet-hub = {
        wantedBy = [ "sockets.target" ];
        listenStreams = [
          (toString hub.socketPath)
          "${hub.listenAddress}:${toString hub.port}"
        ];
        socketConfig = {
          SocketGroup = hub.socketGroup;
          SocketMode = "0660";
        };
      };
      environment.etc."tribuchet/hub.toml".source = hubToml;
      systemd.services.tribuchet-hub = {
        wantedBy = [ "multi-user.target" ];
        restartTriggers = [ hubToml ];
        serviceConfig = {
          Type = "notify";
          ExecStart = "${lib.getExe' hub.package "tribuchet"} hub --config /etc/tribuchet/hub.toml";
          RuntimeDirectory = "tribuchet";
          # Never unlink the activated socket's path on service stop;
          # the listener in systemd must stay reachable across restarts.
          RuntimeDirectoryPreserve = true;
          Environment = "RUST_LOG=info";
          WatchdogSec = "30";
          Restart = "on-failure";
        };
      };
    })

    (lib.mkIf worker.enable {
      environment.etc."tribuchet/worker.toml".source = workerToml;
      systemd.services.tribuchet-worker = {
        wantedBy = [ "multi-user.target" ];
        # only ExecReload carries the package store path, so a new
        # package reloads instead of restarting; settings changes also
        # arrive via reload (the fresh worker generation re-reads the
        # config file). With reloadIfChanged a restart trigger causes
        # a reload, and unlike reloadTriggers it does not warn about
        # the combination.
        reloadIfChanged = true;
        restartTriggers = [ workerToml ];
        serviceConfig = {
          Type = "notify";
          # READY/watchdog come from the worker child; the main pid
          # is the build reaper it was exec'd by.
          NotifyAccess = "all";
          WatchdogSec = "30";
          ExecStartPre = flipWorkerExec;
          ExecReload = [
            flipWorkerExec
            "${pkgs.coreutils}/bin/kill -HUP $MAINPID"
          ];
          ExecStart = "${workerExec} worker --config /etc/tribuchet/worker.toml";
          RuntimeDirectory = "tribuchet-worker";
          StateDirectory = "tribuchet";
          Environment = "RUST_LOG=info";
          # delegate the cgroup subtree so the worker can apply
          # per-build pids/memory limits and cgroup.kill teardown
          Delegate = true;
          Restart = "on-failure";
        };
      };
    })
  ];
}
