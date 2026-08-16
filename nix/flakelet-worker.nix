# flakelet module for the worker and its per-uid build agents.
# The host must still provide the `tribuchet` and `tribuchet-agent-N`
# users (uids cannot come from a flakelet) and add tribuchet to
# nix.settings.trusted-users; see nix/nixos-module.nix for the rationale
# behind the agent architecture.
self:
{
  pkgs,
  flakeletLib,
  name,
  settings,
  ...
}:
let
  lib = pkgs.lib;
  package = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
  format = pkgs.formats.toml { };
  agentCount = settings.agents or settings.worker.max-jobs or 64;
  agentIds = lib.range 1 agentCount;
  agentUidBase = settings.agentUidBase or 1325400064;
  # Not under a RuntimeDirectory: systemd creates the socket parents and
  # nothing removes them while agents keep running across worker stops.
  agentSocket = i: "/run/tribuchet/agents/${toString i}.sock";
  agentStart =
    i:
    pkgs.writeShellScript "tribuchet-agent-${toString i}" ''
      exec ${lib.getExe' package "tribuchet"} agent \
        --state-dir "/var/lib/tribuchet/a${toString i}" \
        --uid-base ${toString (agentUidBase + (i - 1) * 65536)} \
        --worker-uid "$(${lib.getExe' pkgs.coreutils "id"} -u tribuchet)"
    '';
  workerToml = format.generate "worker.toml" (
    {
      agent-sockets = map agentSocket agentIds;
    }
    // settings.worker or { }
  );
  forEachAgent = f: lib.listToAttrs (map (i: lib.nameValuePair "agent-${toString i}" (f i)) agentIds);
in
flakeletLib.mkService {
  sockets = forEachAgent (i: {
    description = "tribuchet build agent ${toString i} socket";
    wantedBy = [ "sockets.target" ];
    socketConfig = {
      ListenStream = agentSocket i;
      # The agent itself only accepts connections from the worker uid.
      SocketMode = "0666";
    };
  });

  services =
    forEachAgent (i: {
      description = "tribuchet build agent ${toString i}";
      # Exiting after every build is the agent's normal lifecycle.
      unitConfig.StartLimitIntervalSec = 0;
      serviceConfig = {
        ExecStart = agentStart i;
        User = "tribuchet-agent-${toString i}";
        Group = "tribuchet-agent-${toString i}";
        StateDirectory = "tribuchet/a${toString i}";
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
    })
    // {
      ${name} = {
        description = "tribuchet build worker";
        wantedBy = [ "multi-user.target" ];
        wants = map (i: "${name}-agent-${toString i}.socket") agentIds;
        after = map (i: "${name}-agent-${toString i}.socket") agentIds;
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
          ++ lib.optional (settings ? keyFile) "TRIBUCHET_KEY=%d/worker-key";
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectHome = true;
          ProtectSystem = "strict";
          RestrictSUIDSGID = true;
          Restart = "on-failure";
        }
        // lib.optionalAttrs (settings ? keyFile) {
          LoadCredential = "worker-key:${settings.keyFile}";
        };
      };
    };
}
