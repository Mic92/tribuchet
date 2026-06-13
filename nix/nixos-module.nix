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
    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Additional arguments passed to `tribuchet hub`.";
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
    hub = lib.mkOption {
      type = lib.types.str;
      example = "https://hub.example.org:7437";
      description = "URL of the hub's worker endpoint.";
    };
    maxJobs = lib.mkOption {
      type = lib.types.ints.positive;
      default = 1;
      description = "Concurrent build slots advertised to the hub.";
    };
    maxLogSize = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 0;
      description = "Kill builds whose log exceeds this many bytes (0 disables).";
    };
    emulate = lib.mkOption {
      type = lib.types.attrsOf lib.types.path;
      default = { };
      example = lib.literalExpression ''{ aarch64-linux = "''${pkgs.pkgsStatic.qemu-user}/bin/qemu-aarch64"; }'';
      description = "Extra systems to advertise, built under the given static emulator.";
    };
    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Additional arguments passed to `tribuchet worker`.";
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
      systemd.services.tribuchet-hub = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "notify";
          ExecStart = lib.escapeShellArgs (
            [
              (lib.getExe' hub.package "tribuchet")
              "hub"
              "--socket"
              (toString hub.socketPath)
              "--listen"
              "${hub.listenAddress}:${toString hub.port}"
              "--config-dir"
              (toString hub.configDir)
            ]
            ++ hub.extraArgs
          );
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
      systemd.services.tribuchet-worker = {
        wantedBy = [ "multi-user.target" ];
        # only ExecReload carries the package store path, so a new
        # package reloads instead of restarting
        reloadIfChanged = true;
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
          ExecStart = lib.escapeShellArgs (
            [
              workerExec
              "worker"
              "--hub"
              worker.hub
              "--state-dir"
              "/var/lib/tribuchet"
              "--max-jobs"
              (toString worker.maxJobs)
              "--max-log-size"
              (toString worker.maxLogSize)
            ]
            ++ lib.concatLists (
              lib.mapAttrsToList (system: emulator: [
                "--emulate"
                "${system}=${emulator}"
              ]) worker.emulate
            )
            ++ worker.extraArgs
          );
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
