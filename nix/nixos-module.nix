# NixOS module for the tribuchet hub and worker.
#
# Hub: socket-activated (systemd holds the attach socket and the worker
# port), so hub restarts never refuse connections, clients just queue.
# Worker and agents: see worker-units.nix.
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
  workerUnits = import ./worker-units.nix {
    inherit pkgs lib;
    inherit (worker)
      package
      agents
      agentUidBase
      keyFile
      ;
    workerUnit = "tribuchet-worker";
    agentUnit = "tribuchet-agent@";
    workerToml = "/etc/tribuchet/worker.toml";
  };
  hubToml = format.generate "hub.toml" (
    {
      socket = toString hub.socketPath;
      listen = "${hub.listenAddress}:${toString hub.port}";
      config-dir = toString hub.configDir;
    }
    // hub.settings
  );
  workerToml = format.generate "worker.toml" (
    {
      agent-sockets-dir = workerUnits.agentSocketsDir;
    }
    // worker.settings
  );
  attachWrapper = pkgs.writeShellScript "tribuchet-attach" ''
    exec ${lib.getExe' hub.package "tribuchet"} attach "$1" --socket ${hub.socketPath}
  '';
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
    externalBuilders = {
      enable = lib.mkEnableOption "routing this machine's nix-daemon builds through the hub (experimental external-builders feature)";
      dynamic = lib.mkEnableOption ''
        deriving external-builders and max-jobs from the workers
        currently connected to the hub instead of the static `systems`
        list. The hub writes a nix.conf fragment on every worker
        register/deregister; a path unit restarts nix-daemon to apply
        it (in-flight build children survive the restart)
      '';
      systems = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ pkgs.stdenv.hostPlatform.system ];
        defaultText = lib.literalExpression "[ pkgs.stdenv.hostPlatform.system ]";
        description = "Systems handed to tribuchet instead of being built locally (static mode; ignored when `dynamic` is set).";
      };
      nixConfigPath = lib.mkOption {
        type = lib.types.path;
        default = "/run/tribuchet/nix.conf";
        description = "Path of the hub-generated nix.conf fragment (dynamic mode).";
      };
      oversubscribePercent = lib.mkOption {
        type = lib.types.ints.positive;
        default = 200;
        description = ''
          Percent to scale summed worker capacity by for the emitted
          max-jobs (200 = 2x), capped. Oversubscribing keeps every
          worker's hub queue fed regardless of the system mix Nix admits
          into its single global slot pool and hides the
          submit/dispatch/result/next-admit round trip. The surplus just
          parks in the hub queue (an attach process plus a build goal on
          this host, nothing staged until dispatch).
        '';
      };
      maxJobsCap = lib.mkOption {
        type = lib.types.ints.positive;
        default = 256;
        description = ''
          Ceiling on the emitted max-jobs. Bounds the local-build burst
          if every worker vanishes and offloaded builds fall back to
          local execution. `id-count` must cover it: an external build
          still reserves an auto-allocated uid slot on this host, and
          the slot pool holds `id-count / 65536` of them.
        '';
      };
      nixPackage = lib.mkOption {
        type = lib.types.package;
        default = pkgs.nixVersions.latest;
        defaultText = lib.literalExpression "pkgs.nixVersions.latest";
        description = "Nix package to use; must support the external-builders experimental feature.";
      };
      patchNix = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Patch Nix so uid-range derivations reach the external builder
          and so a declined build (no worker for the system) falls back
          to a local build instead of failing.
        '';
      };
      recursiveNix = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Patch Nix so external builders see recursive-nix derivations
          and can populate the registered output closure via a
          `result.json` sidecar. Off by default; only useful when a
          tribuchet worker advertises the `recursive-nix` feature.
        '';
      };
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
    keyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        TLS client key for the hub connection, loaded through systemd
        LoadCredential so it may stay root-owned (e.g. a sops secret).
        Passed to the worker via TRIBUCHET_KEY; leave `settings.key`
        unset when using this.
      '';
    };
    agents = lib.mkOption {
      type = lib.types.either lib.types.ints.positive (lib.types.enum [ "auto" ]);
      default = "auto";
      description = "Build agent count, or \"auto\" for one per CPU, decided at boot.";
    };
    agentUidBase = lib.mkOption {
      type = lib.types.int;
      default = 1325400064;
      description = ''
        First uid of the agents' 65536-uid blocks (agent i maps block
        i-1). The default starts right after nix-daemon's
        auto-allocate-uids range so the two never hand out the same
        uids on one host.
      '';
    };
    settings = lib.mkOption {
      type = format.type;
      example = lib.literalExpression ''
        {
          hub = "https://hub.example.org:7437";
          max-jobs = 4;
          max-log-size = 67108864;
          emulate.aarch64-linux = "''${pkgs.pkgsStatic.qemu-user}/bin/qemu-aarch64";
          # flow policy for the fixed-output build network:
          # ordered rules, first match wins, then `default`
          fod-network = {
            default = "allow";
            rules = [
              {
                action = "deny";
                dst = "10.0.0.0/8";
              }
              {
                action = "deny";
                proto = "tcp";
                dst = "any";
                ports = [ "25" "465" "587" ];
              }
            ];
          };
        }
      '';
      description = ''
        Contents of worker.toml. Changes are applied with a reload, so
        running builds survive them. The `hub` key is required.
      '';
    };
  };

  config = lib.mkMerge [
    # independent of `enable` so the hub can run as a flakelet
    (lib.mkIf hub.externalBuilders.enable {
      nix.package =
        let
          patches =
            lib.optionals hub.externalBuilders.patchNix [
              ./patches/external-builders-uid-range.patch
              ./patches/external-builders-decline-fallback.patch
            ]
            ++ lib.optional hub.externalBuilders.recursiveNix ./patches/recursive-nix-external-builders.patch;
        in
        if patches == [ ] then
          hub.externalBuilders.nixPackage
        else
          hub.externalBuilders.nixPackage.appendPatches patches;
      nix.settings = {
        experimental-features = [ "external-builders" ];
      }
      // lib.optionalAttrs (!hub.externalBuilders.dynamic) {
        external-builders = builtins.toJSON [
          {
            systems = hub.externalBuilders.systems;
            program = attachWrapper;
            args = [ ];
          }
        ];
      };
    })

    (lib.mkIf (hub.externalBuilders.enable && hub.externalBuilders.dynamic) {
      # The hub owns external-builders/max-jobs; nix.conf just includes
      # its fragment (soft include: nix still starts if it is absent).
      nix.extraOptions = "!include ${hub.externalBuilders.nixConfigPath}\n";
      services.tribuchet-hub.settings.nix-config = {
        path = toString hub.externalBuilders.nixConfigPath;
        attach-program = toString attachWrapper;
        oversubscribe-percent = hub.externalBuilders.oversubscribePercent;
        max-jobs-cap = hub.externalBuilders.maxJobsCap;
      };
      # Apply a regenerated fragment: restart swaps only the daemon's
      # accept loop, in-flight build children keep running.
      systemd.paths.tribuchet-nix-reload = {
        wantedBy = [ "multi-user.target" ];
        pathConfig.PathModified = toString hub.externalBuilders.nixConfigPath;
      };
      systemd.services.tribuchet-nix-reload = {
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.systemd}/bin/systemctl try-restart nix-daemon.service";
        };
      };
    })

    {
      networking.firewall.allowedTCPPorts = lib.optional hub.openFirewall hub.port;
    }

    (lib.mkIf hub.enable {
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
          # staging chunk cache
          CacheDirectory = "tribuchet";
          Environment = [
            "RUST_LOG=info"
            "XDG_CACHE_HOME=/var/cache"
          ];
          WatchdogSec = "30";
          Restart = "on-failure";
        };
      };
    })

    (lib.mkIf worker.enable {
      environment.etc."tribuchet/worker.toml".source = workerToml;

      # the worker imports build inputs through the nix-daemon without
      # signatures, which only trusted users may do
      nix.settings.trusted-users = [ "tribuchet" ];

      systemd.generators = lib.mapAttrs' (
        n: v: lib.nameValuePair "tribuchet-${n}" v
      ) workerUnits.generators;

      systemd.sockets = {
        "tribuchet-agent@" = removeAttrs workerUnits.agentSocketConfig [ "wantedBy" ];
      }
      // lib.listToAttrs (
        map (
          i:
          lib.nameValuePair "tribuchet-agent@${i}" {
            overrideStrategy = "asDropin";
            wantedBy = [ "sockets.target" ];
          }
        ) workerUnits.agentInstances
      );

      systemd.services = {
        "tribuchet-agent@" = workerUnits.agentServiceConfig;
        tribuchet-worker = workerUnits.workerServiceConfig // {
          restartTriggers = [ workerToml ];
        };
      };
    })
  ];
}
