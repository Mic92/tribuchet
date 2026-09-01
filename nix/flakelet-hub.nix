# flakelet module for the hub (https://github.com/Mic92/flakelet).
# Ships only the units. Firewall and externalBuilders stay host
# configuration (services.tribuchet-hub.* without `enable`).
{ crane }:
{ types, ... }:
{
  options = {
    listenAddress = {
      type = types.string;
      default = "0.0.0.0";
      description = "Address of the worker-facing gRPC listener.";
    };
    port = {
      type = types.int;
      default = 7437;
      description = "Port of the worker-facing gRPC listener.";
    };
    socketPath = {
      type = types.string;
      defaultFunc = { inputs, ... }: "/run/${inputs.flakelet.name}/hub.sock";
      description = "Attach socket path.";
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
      type = types.int;
      default = 200;
    };
    maxJobsCap = {
      type = types.int;
      default = 256;
    };
    hub = {
      type = types.attrsOf types.any;
      default = { };
      description = "Extra hub.toml settings, merged verbatim.";
    };
  };

  impl =
    { options, inputs }:
    let
      inherit (inputs.nixpkgs) pkgs lib;
      inherit (inputs.flakelet) name;
      # Built against the host's nixpkgs like every flakelet; crane is a
      # pure library and brings no nixpkgs of its own.
      package = pkgs.callPackage ./package.nix { craneLib = crane.mkLib pkgs; };
      format = pkgs.formats.toml { };
      inherit (options)
        listenAddress
        port
        configDir
        socketPath
        ;
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
          CacheDirectory = name;
          Environment = [
            "RUST_LOG=info"
            "XDG_CACHE_HOME=/var/cache/${name}"
          ];
          WatchdogSec = "30";
          Restart = "on-failure";
        };
      };

      exports.ports.workers = { inherit port; };
    }
    # The listeners are systemd's, so only the metrics endpoint proves the
    # hub process serves; Type=notify covers startup otherwise.
    // lib.optionalAttrs (options.hub ? "metrics-listen") {
      healthCheck = pkgs.writeShellScript "${name}-health" ''
        exec ${lib.getExe pkgs.curl} -sf --max-time 5 --retry 5 --retry-all-errors --retry-delay 2 \
          -o /dev/null http://${options.hub."metrics-listen"}/metrics
      '';
    };
}
