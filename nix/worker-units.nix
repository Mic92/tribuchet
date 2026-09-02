# Worker and agent units shared by the NixOS module and the flakelet.
# The worker runs unprivileged and leases every build to a per-uid,
# socket-activated agent, which owns the builder process and its user
# namespace, so builds survive worker restarts. Users are DynamicUser:
# a host that defines tribuchet / tribuchet-agent-N statically wins.
{
  pkgs,
  lib,
  package,
  # unit names differ: tribuchet-worker / tribuchet-agent@ vs <name> / <name>-agent@
  workerUnit,
  agentUnit,
  # integer or "auto" (one per CPU, decided by a generator on the machine)
  agents,
  agentUidBase,
  keyFile,
  workerToml,
}:
let
  auto = agents == "auto";
  agentIds = map toString (lib.range 1 agents);
  agentSocket = i: "${agentUnit}${i}.socket";
  stateDir = "/var/lib/tribuchet/a%i";
  # ExecStart cannot do arithmetic or resolve the worker's uid
  agentStart = pkgs.writeShellScript "tribuchet-agent" ''
    exec ${lib.getExe' package "tribuchet"} agent \
      --state-dir "/var/lib/tribuchet/a$1" \
      --uid-base "$(( ${toString agentUidBase} + ($1 - 1) * 65536 ))" \
      --worker-uid "$(${lib.getExe' pkgs.coreutils "id"} -u tribuchet)"
  '';
in
{
  # Not under a RuntimeDirectory: systemd creates the socket parents and
  # nothing removes them while agents keep running across worker stops.
  agentSocketsDir = "/run/tribuchet/agents";

  generators = lib.optionalAttrs auto {
    agents = pkgs.writeShellScript "tribuchet-agents" ''
      exec ${lib.getExe' package "tribuchet"} agent-generator \
        --worker-unit ${workerUnit}.service --template ${agentSocket ""} "$@"
    '';
  };

  agentInstances = lib.optionals (!auto) agentIds;

  # The socket mode is open because the agent itself only accepts
  # connections from the worker uid.
  agentSocketConfig = {
    description = "tribuchet build agent %i socket";
    wantedBy = [ "sockets.target" ];
    before = [ "${workerUnit}.service" ];
    socketConfig = {
      ListenStream = "/run/tribuchet/agents/%i.sock";
      SocketMode = "0666";
    };
  };

  agentServiceConfig = {
    description = "tribuchet build agent %i";
    # Exiting after every build is the agent's normal lifecycle.
    unitConfig.StartLimitIntervalSec = 0;
    # One build per activation: let it finish, the next lease runs the
    # new ExecStart.
    restartIfChanged = false;
    serviceConfig = {
      ExecStart = "${agentStart} %i";
      DynamicUser = true;
      User = "tribuchet-agent-%i";
      # Not StateDirectory: DynamicUser would move it below the 0700
      # /var/lib/private, out of reach for the worker and the uid block.
      # Traverse-only: the per-build scratch dirs are world-writable for
      # the block, but their names are random.
      ExecStartPre = [
        # scratch may belong to a previous DynamicUser uid
        "+${pkgs.coreutils}/bin/rm -rf ${stateDir}/scratch"
        "+${pkgs.coreutils}/bin/install -d -m 0711 -o tribuchet-agent-%i -g tribuchet-agent-%i ${stateDir}"
      ];
      ReadWritePaths = "/var/lib/tribuchet";
      # Writing the uid/gid maps of the agent's user namespace needs
      # CAP_SETUID/CAP_SETGID over the uid block, dropped right after.
      # CAP_CHOWN stays: each build cgroup is handed to its mapped root.
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
      # the per-build cgroup the sandbox roots its cgroup namespace in
      Delegate = true;
      # Builders inherit this; match nix-daemon to avoid EMFILE.
      LimitNOFILE = 1048576;
      Environment = "RUST_LOG=info";
    };
  };

  workerServiceConfig = {
    description = "tribuchet build worker";
    wantedBy = [ "multi-user.target" ];
    # the agent sockets must exist before the worker leases builds
    wants = lib.optionals (!auto) (map agentSocket agentIds);
    after = lib.optionals (!auto) (map agentSocket agentIds);
    serviceConfig = {
      Type = "notify";
      DynamicUser = true;
      User = "tribuchet";
      WatchdogSec = "30";
      ExecStart = "${lib.getExe' package "tribuchet"} worker --config ${workerToml}";
      # Running builds live in the agent services and are re-adopted by
      # the next worker instance.
      StateDirectory = "tribuchet/worker";
      Environment = [
        "RUST_LOG=info"
      ]
      ++ lib.optional (keyFile != null) "TRIBUCHET_KEY=%d/worker-key";
      ProtectHome = true;
      Restart = "on-failure";
    }
    // lib.optionalAttrs (keyFile != null) {
      LoadCredential = "worker-key:${keyFile}";
    };
  };
}
