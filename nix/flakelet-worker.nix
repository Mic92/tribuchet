# flakelet module for the worker and its per-uid build agents.
# The host must still provide the `tribuchet` and `tribuchet-agent-N`
# users (uids cannot come from a flakelet) and add tribuchet to
# nix.settings.trusted-users. See nix/nixos-module.nix for the rationale
# behind the agent architecture.
{ crane }:
{ types, ... }:
{
  options = {
    agents = {
      type = types.int;
      defaultFunc = { options, ... }: options.worker.max-jobs or 64;
      description = "Upper bound on build agents. The machine runs min(nproc, agents).";
    };
    agentUidBase = {
      type = types.int;
      default = 1325400064;
      description = "First uid of the agents' 65536-uid blocks.";
    };
    keyFile = {
      type = types.option types.string;
      description = "TLS client key for the hub connection, loaded via LoadCredential.";
    };
    worker = {
      type = types.attrsOf types.any;
      description = "Contents of worker.toml; the hub key is required.";
    };
  };

  impl =
    { options, inputs }:
    let
      inherit (inputs.nixpkgs) pkgs lib;
      inherit (inputs.flakelet) name;
      package = pkgs.callPackage ./package.nix { craneLib = crane.mkLib pkgs; };
      format = pkgs.formats.toml { };
      inherit (options) keyFile;
      # Not under a RuntimeDirectory: systemd creates the socket parents and
      # nothing removes them while agents keep running across worker stops.
      agentSocketsDir = "/run/tribuchet/agents";
      # ExecStart cannot do arithmetic or resolve the worker's uid.
      agentStart = pkgs.writeShellScript "tribuchet-agent" ''
        exec ${lib.getExe' package "tribuchet"} agent \
          --state-dir "/var/lib/tribuchet/a$1" \
          --uid-base "$(( ${toString options.agentUidBase} + ($1 - 1) * 65536 ))" \
          --worker-uid "$(${lib.getExe' pkgs.coreutils "id"} -u tribuchet)"
      '';
      workerToml = format.generate "worker.toml" (
        {
          agent-sockets-dir = agentSocketsDir;
        }
        // options.worker
      );
    in
    {
      # One agent per CPU up to options.agents, decided on the machine.
      generators.agents = pkgs.writeShellScript "agents" ''
        n=$(nproc)
        [ "$n" -gt ${toString options.agents} ] && n=${toString options.agents}
        mkdir -p "$1/sockets.target.wants" "$1/${name}.service.wants"
        for i in $(seq "$n"); do
          ln -s /run/systemd/system/${name}-agent@.socket "$1/sockets.target.wants/${name}-agent@$i.socket"
          ln -s /run/systemd/system/${name}-agent@.socket "$1/${name}.service.wants/${name}-agent@$i.socket"
        done
      '';

      sockets."agent@" = {
        description = "tribuchet build agent %i socket";
        wantedBy = [ "sockets.target" ];
        before = [ "${name}.service" ];
        socketConfig = {
          ListenStream = "${agentSocketsDir}/%i.sock";
          # The agent itself only accepts connections from the worker uid.
          SocketMode = "0666";
        };
      };

      services."agent@" = {
        description = "tribuchet build agent %i";
        # Exiting after every build is the agent's normal lifecycle.
        unitConfig.StartLimitIntervalSec = 0;
        # One build per activation: let it finish, the next lease runs the
        # new ExecStart.
        restartIfChanged = false;
        serviceConfig = {
          ExecStart = "${agentStart} %i";
          User = "tribuchet-agent-%i";
          Group = "tribuchet-agent-%i";
          StateDirectory = "tribuchet/a%i";
          StateDirectoryMode = "0711";
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
          Delegate = true;
          LimitNOFILE = 1048576;
          Environment = "RUST_LOG=info";
        };
      };

      services.${name} = {
        description = "tribuchet build worker";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "notify";
          User = "tribuchet";
          Group = "tribuchet";
          WatchdogSec = "30";
          ExecStart = "${lib.getExe' package "tribuchet"} worker --config ${workerToml}";
          StateDirectory = "tribuchet/worker";
          Environment = [
            "RUST_LOG=info"
          ]
          ++ lib.optional (keyFile != null) "TRIBUCHET_KEY=%d/worker-key";
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectHome = true;
          ProtectSystem = "strict";
          RestrictSUIDSGID = true;
          Restart = "on-failure";
        }
        // lib.optionalAttrs (keyFile != null) {
          LoadCredential = "worker-key:${keyFile}";
        };
      };
    };
}
