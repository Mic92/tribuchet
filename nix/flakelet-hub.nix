# flakelet module for the hub (https://github.com/Mic92/flakelet).
# Ships only the units; firewall, the patched nix.package and the
# nix.conf include stay host configuration.
self:
{ types, ... }:
{
  options = {
    listenAddress = {
      type = types.string;
      default = "0.0.0.0";
      description = "Address of the worker-facing gRPC listener.";
    };
    port = {
      type = types.number;
      default = 7437;
      description = "Port of the worker-facing gRPC listener.";
    };
    socketPath = {
      type = types.option types.string;
      description = "Attach socket path; defaults to /run/<name>/hub.sock.";
    };
    socketGroup = {
      type = types.string;
      default = "nixbld";
      description = "Group allowed to connect to the attach socket.";
    };
    configDir = {
      type = types.string;
      default = "/etc/tribuchet";
      description = "Directory with the CA material and hub TLS key pair.";
    };
    nixConfigPath = {
      type = types.option types.string;
      description = "Enable dynamic external-builders: path of the hub-written nix.conf fragment.";
    };
    oversubscribePercent = {
      type = types.number;
      default = 200;
    };
    maxJobsCap = {
      type = types.number;
      default = 256;
    };
    hub = {
      type = types.attrsOf types.any;
      default = { };
      description = "Extra hub.toml settings, merged verbatim.";
    };
  };

  impl =
    {
      options,
      pkgs,
      name,
      ...
    }:
    let
      lib = pkgs.lib;
      package = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      format = pkgs.formats.toml { };
      inherit (options) listenAddress port configDir;
      socketPath = if options.socketPath == null then "/run/${name}/hub.sock" else options.socketPath;
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
        // lib.optionalAttrs (options.nixConfigPath != null) {
          nix-config = {
            path = options.nixConfigPath;
            attach-program = toString attachWrapper;
            oversubscribe-percent = options.oversubscribePercent;
            max-jobs-cap = options.maxJobsCap;
          };
        }
        // options.hub
      );
    in
    {
      sockets.${name} = {
        description = "tribuchet hub sockets";
        wantedBy = [ "sockets.target" ];
        socketConfig = {
          ListenStream = [
            socketPath
            "${listenAddress}:${toString port}"
          ];
          SocketGroup = options.socketGroup;
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
    };
}
