# nix-darwin module for the tribuchet hub and worker.
#
# Worker: runs unprivileged as _tribuchet and leases every build to a
# per-uid agent (_tribuchetbldN, socket-activated LaunchDaemon), which
# owns the builder process, so builds survive worker restarts. The
# daemon execs a stable symlink in the state dir, so the plist
# contains neither the package store path nor the settings (those
# live in /etc/tribuchet/worker.toml). Activation flips the symlink
# to the new package and restarts the daemon via launchctl kickstart.
#
# Hub: runs unprivileged as _tribuchet. launchd holds the attach
# socket and the worker port (the hub adopts them via
# launch_activate_socket), so hub restarts never refuse connections,
# clients just queue.
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
  agentIds = lib.range 1 cfg.agents;
  # launchd cannot set a socket group and the rootless hub cannot
  # chown the socket, so this directory carries the nixbld restriction.
  attachDir = lib.escapeShellArg (dirOf (toString hub.socketPath));
  agentUser = i: "_tribuchetbld${toString i}";
  agentSocket = i: "/var/run/tribuchet/agents/${toString i}.sock";
  agentStateDir = i: "/var/lib/tribuchet-agents/${toString i}";
  # nixbld gid: build users must be able to create their outputs in
  # the group-writable /nix/store.
  nixbldGid = 350;
  workerToml = format.generate "worker.toml" (
    {
      state-dir = toString cfg.stateDir;
      agent-sockets = map agentSocket agentIds;
      max-jobs = cfg.agents;
    }
    // cfg.settings
  );
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
      default = "/var/lib/tribuchet-hub/attach.sock";
      description = ''
        Unix socket `tribuchet attach` (Nix's external builder)
        connects to. Its directory is made root:nixbld 0750 at
        activation, so keep it out of /var/run (wiped at boot).
      '';
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
    agents = lib.mkOption {
      type = lib.types.ints.positive;
      default = 4;
      description = ''
        Number of per-uid build agents. Bounds concurrent builds and
        sets the worker's max-jobs (overridable via `settings`, but
        never above the agent count).
      '';
    };
    uid = lib.mkOption {
      type = lib.types.int;
      default = 400;
      description = "Uid of the _tribuchet worker user.";
    };
    agentUidBase = lib.mkOption {
      type = lib.types.int;
      default = 401;
      description = "First uid of the _tribuchetbldN agent users (one per agent).";
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
        Contents of worker.toml. Changes are applied by restarting
        the daemon at activation. The `hub` key is required.
      '';
    };
    logFile = lib.mkOption {
      type = lib.types.path;
      default = "/var/log/tribuchet-worker.log";
      description = "launchd stdout/stderr destination.";
    };
  };

  config = lib.mkMerge [
    # Hub and worker share the _tribuchet user. It is in nixbld (build
    # users must write /nix/store) and trusted by the nix-daemon (the
    # worker imports inputs, the hub queries and exports store paths).
    (lib.mkIf (hub.enable || cfg.enable) {
      users.knownUsers = [ "_tribuchet" ];
      users.users._tribuchet = {
        uid = cfg.uid;
        gid = nixbldGid;
        home = "/var/empty";
        shell = "/usr/bin/false";
        description = "tribuchet";
      };
      nix.settings.trusted-users = [ "_tribuchet" ];
      # The hub TLS key pair and CA material must be readable by
      # _tribuchet only.
      system.activationScripts.preActivation.text = ''
        mkdir -p /etc/tribuchet
        chown -R ${toString cfg.uid} /etc/tribuchet
        chmod 0700 /etc/tribuchet
      '';
    })

    (lib.mkIf hub.enable {
      environment.etc."tribuchet/hub.toml".source = hubToml;
      launchd.daemons.tribuchet-hub.serviceConfig = {
        ProgramArguments = [
          (lib.getExe' hub.package "tribuchet")
          "hub"
          "--config"
          "/etc/tribuchet/hub.toml"
        ];
        UserName = "_tribuchet";
        # launchd owns the listeners (socket activation): the hub
        # adopts them by these names via launch_activate_socket, so
        # they keep accepting across hub restarts.
        Sockets = {
          attach = {
            SockPathName = toString hub.socketPath;
            # The socket itself is open. Its root:nixbld 0750 directory
            # (created below) restricts who can reach it, and the hub
            # refuses to serve without that restriction.
            SockPathMode = 438; # 0666
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
      system.activationScripts.preActivation.text = ''
        mkdir -p ${attachDir}
        chown root:${toString nixbldGid} ${attachDir}
        chmod 0750 ${attachDir}
        touch ${lib.escapeShellArg (toString hub.logFile)}
        chown ${toString cfg.uid} ${lib.escapeShellArg (toString hub.logFile)}
      '';
    })

    (lib.mkIf cfg.enable {
      environment.etc."tribuchet/worker.toml".source = workerToml;

      # One build user per agent, in nixbld so they can create their
      # outputs in /nix/store.
      users.knownUsers = map agentUser agentIds;
      users.users = lib.mkMerge (
        map (i: {
          ${agentUser i} = {
            uid = cfg.agentUidBase + i - 1;
            gid = nixbldGid;
            home = "/var/empty";
            shell = "/usr/bin/false";
            description = "tribuchet build agent ${toString i}";
          };
        }) agentIds
      );

      launchd.daemons = lib.mkMerge (
        [
          {
            tribuchet-worker.serviceConfig = {
              ProgramArguments = [
                execLink
                "worker"
                "--config"
                "/etc/tribuchet/worker.toml"
              ];
              UserName = "_tribuchet";
              KeepAlive = true;
              RunAtLoad = true;
              StandardOutPath = toString cfg.logFile;
              StandardErrorPath = toString cfg.logFile;
              EnvironmentVariables.RUST_LOG = "info";
            };
          }
        ]
        # One socket-activated agent per build user. launchd owns the
        # socket, the agent starts on the first connection and exits
        # after each build's Cleanup. The socket mode is open because
        # the agent itself only accepts connections from the worker
        # uid (getpeereid).
        ++ map (i: {
          "tribuchet-agent-${toString i}".serviceConfig = {
            ProgramArguments = [
              (lib.getExe' cfg.package "tribuchet")
              "agent"
              "--state-dir"
              (agentStateDir i)
              "--worker-uid"
              (toString cfg.uid)
            ];
            UserName = agentUser i;
            Sockets.agent = {
              SockPathName = agentSocket i;
              SockPathMode = 438; # 0666
            };
            StandardOutPath = "/var/log/tribuchet-agent-${toString i}.log";
            StandardErrorPath = "/var/log/tribuchet-agent-${toString i}.log";
            EnvironmentVariables.RUST_LOG = "info";
          };
        }) agentIds
      );

      # The symlink must point at the new package before launchd
      # (re)starts the daemon. The kickstart afterwards restarts the
      # worker on the new binary and settings; running builds stay in
      # their agents and are re-adopted.
      system.activationScripts.preActivation.text = ''
        mkdir -p ${lib.escapeShellArg (toString cfg.stateDir)}
        chown ${toString cfg.uid} ${lib.escapeShellArg (toString cfg.stateDir)}
        touch ${lib.escapeShellArg (toString cfg.logFile)}
        chown ${toString cfg.uid} ${lib.escapeShellArg (toString cfg.logFile)}
        ln -sfn ${lib.getExe' cfg.package "tribuchet"} ${lib.escapeShellArg execLink}
        ${lib.concatMapStrings (i: ''
          mkdir -p ${agentStateDir i}
          chown ${toString (cfg.agentUidBase + i - 1)} ${agentStateDir i}
          chmod 0700 ${agentStateDir i}
          touch /var/log/tribuchet-agent-${toString i}.log
          chown ${toString (cfg.agentUidBase + i - 1)} /var/log/tribuchet-agent-${toString i}.log
        '') agentIds}
      '';
      system.activationScripts.postActivation.text = ''
        /bin/launchctl kickstart -k system/${label} 2>/dev/null || true
      '';
    })
  ];
}
