# flakelet module for the hub (https://github.com/Mic92/flakelet).
# Ships only the units; firewall, the patched nix.package and the
# nix.conf include stay host configuration.
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
  listenAddress = settings.listenAddress or "0.0.0.0";
  port = settings.port or 7437;
  socketPath = settings.socketPath or "/run/${name}/hub.sock";
  configDir = settings.configDir or "/etc/tribuchet";
  attachWrapper = pkgs.writeShellScript "tribuchet-attach" ''
    exec ${lib.getExe' package "tribuchet"} attach "$1" --socket ${socketPath}
  '';
  hubToml = format.generate "hub.toml" (
    {
      socket = socketPath;
      listen = "${listenAddress}:${toString port}";
      config-dir = configDir;
    }
    # Dynamic external-builders: the hub rewrites the host's nix.conf
    # fragment as workers come and go. The attach program lives in this
    # flakelet's closure, so generations keep it gc-rooted.
    // lib.optionalAttrs (settings ? nixConfigPath) {
      nix-config = {
        path = settings.nixConfigPath;
        attach-program = toString attachWrapper;
        oversubscribe-percent = settings.oversubscribePercent or 200;
        max-jobs-cap = settings.maxJobsCap or 256;
      };
    }
    // settings.hub or { }
  );
in
flakeletLib.mkService {
  sockets.${name} = {
    description = "tribuchet hub sockets";
    wantedBy = [ "sockets.target" ];
    socketConfig = {
      ListenStream = [
        socketPath
        "${listenAddress}:${toString port}"
      ];
      SocketGroup = settings.socketGroup or "nixbld";
      SocketMode = "0660";
      # Owned by the socket unit so a service stop keeps the path.
      RuntimeDirectory = name;
    };
  };

  services.${name} = {
    description = "tribuchet build hub";
    wantedBy = [ "multi-user.target" ];
    requires = [ "${name}.socket" ];
    after = [ "${name}.socket" ];
    serviceConfig = {
      Type = "notify";
      ExecStart = "${lib.getExe' package "tribuchet"} hub --config ${hubToml}";
      RuntimeDirectory = name;
      RuntimeDirectoryPreserve = true;
      Environment = "RUST_LOG=info";
      WatchdogSec = "30";
      Restart = "on-failure";
    };
  };
}
