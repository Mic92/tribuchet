# NixOS module for the tribuchet hub and worker.
#
# Hub: socket-activated (systemd holds the attach socket and the worker
# port), so hub restarts never refuse connections, clients just queue.
# Worker: runs unprivileged as tribuchet and leases every build to a
# per-uid agent (tribuchet-agent-N, socket-activated), which owns the
# builder process and its user namespace, so builds survive worker
# stops and restarts. A restarted worker re-adopts them from the
# state persisted in its build dirs, so package upgrades and settings
# changes are plain restarts.
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
  # One per-uid build agent per concurrent build. With max-jobs unset
  # the worker uses min(cores, agents), so provision a generous
  # ceiling. Idle agents are socket-activated and cost nothing.
  agentCount = worker.settings.max-jobs or 64;
  agentIds = lib.range 1 agentCount;
  agentUser = i: "tribuchet-agent-${toString i}";
  agentInstance = i: "tribuchet-agent@${toString i}";
  forEachAgent = f: lib.listToAttrs (map (i: lib.nameValuePair (agentUser i) (f i)) agentIds);
  agentSocket = i: "/run/tribuchet/agents/${toString i}.sock";
  # ExecStart cannot resolve the worker's uid, which the agent needs
  # for its peer-uid check. Takes the instance number as $1.
  agentStart = pkgs.writeShellScript "tribuchet-agent" ''
    exec ${lib.getExe' worker.package "tribuchet"} agent \
      --state-dir "/var/lib/tribuchet/a$1" \
      --uid-base "$(( ${toString worker.agentUidBase} + ($1 - 1) * 65536 ))" \
      --worker-uid "$(${lib.getExe' pkgs.coreutils "id"} -u tribuchet)"
  '';
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
      agent-sockets = map agentSocket agentIds;
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
    (lib.mkIf (hub.enable && hub.externalBuilders.enable) {
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

    (lib.mkIf (hub.enable && hub.externalBuilders.enable && hub.externalBuilders.dynamic) {
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

      # One build user per agent. Builds run as (or map) that agent's
      # uid, never the worker's, so a running build can neither tamper
      # with the worker nor leave files it cannot delete.
      users.users = {
        tribuchet = {
          isSystemUser = true;
          group = "tribuchet";
        };
      }
      // forEachAgent (i: {
        isSystemUser = true;
        group = agentUser i;
        # /dev/kvm for kvm-requiring builds
        extraGroups = [ "kvm" ];
      });
      users.groups = {
        tribuchet = { };
      }
      // forEachAgent (_: { });

      # One socket-activated agent per build user. systemd owns the
      # socket, the agent starts on the first connection and exits
      # after each build's Cleanup. The socket mode is open because
      # the agent itself only accepts connections from the worker uid.
      systemd.sockets = {
        "tribuchet-agent@" = {
          listenStreams = [ "/run/tribuchet/agents/%i.sock" ];
          socketConfig.SocketMode = "0666";
        };
      }
      // lib.listToAttrs (
        map (
          i:
          lib.nameValuePair (agentInstance i) {
            overrideStrategy = "asDropin";
            wantedBy = [ "sockets.target" ];
          }
        ) agentIds
      );

      systemd.services = {
        "tribuchet-agent@" = {
          # Exiting after every build is the agent's normal lifecycle,
          # not a crash loop.
          unitConfig.StartLimitIntervalSec = 0;
          serviceConfig = {
            ExecStart = "${agentStart} %i";
            User = "tribuchet-agent-%i";
            Group = "tribuchet-agent-%i";
            StateDirectory = "tribuchet/a%i";
            # Traverse-only for the worker and the uid block: the
            # per-build scratch dirs under scratch/ are world-writable
            # for the block, but their names are random and the missing
            # read bit hides them.
            StateDirectoryMode = "0711";
            # Writing the uid/gid maps of the agent's pre-mapped user
            # namespace needs CAP_SETUID/CAP_SETGID over the uid block;
            # the agent drops both right after the write. CAP_CHOWN
            # stays: each build cgroup is handed to its mapped root uid.
            AmbientCapabilities = [
              "CAP_SETUID"
              "CAP_SETGID"
              "CAP_CHOWN"
            ];
            CapabilityBoundingSet = [
              "CAP_SETUID"
              "CAP_SETGID"
              "CAP_CHOWN"
            ];
            # delegate the cgroup subtree so the agent can create the
            # per-build cgroup the sandbox roots its cgroup namespace in
            Delegate = true;
            # Builders inherit this; match nix-daemon so they are not
            # stuck at the systemd default soft limit of 1024 and fail
            # with EMFILE.
            LimitNOFILE = 1048576;
            Environment = "RUST_LOG=info";
          };
        };
        tribuchet-worker = {
          wantedBy = [ "multi-user.target" ];
          # the agent sockets must exist before the worker leases builds
          wants = map (i: "${agentInstance i}.socket") agentIds;
          after = map (i: "${agentInstance i}.socket") agentIds;
          restartTriggers = [ workerToml ];
          serviceConfig = {
            Type = "notify";
            LoadCredential = lib.optional (worker.keyFile != null) "worker-key:${worker.keyFile}";
            User = "tribuchet";
            Group = "tribuchet";
            WatchdogSec = "30";
            ExecStart = "${lib.getExe' worker.package "tribuchet"} worker --config /etc/tribuchet/worker.toml";
            # Running builds live in the agent services and are
            # re-adopted by the next worker instance.
            StateDirectory = "tribuchet/worker";
            Environment = [
              "RUST_LOG=info"
            ]
            ++ lib.optional (worker.keyFile != null) "TRIBUCHET_KEY=%d/worker-key";
            # the worker itself only stages inputs and packs outputs;
            # store writes go through the nix-daemon socket
            NoNewPrivileges = true;
            PrivateTmp = true;
            ProtectHome = true;
            ProtectSystem = "strict";
            RestrictSUIDSGID = true;
            Restart = "on-failure";
          };
        };
      };
    })
  ];
}
