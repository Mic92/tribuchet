# flakelet module for the worker and its build agents, see
# nix/worker-units.nix. The host only has to add tribuchet to
# nix.settings.trusted-users.
{ crane }:
{ types, ... }:
{
  options = {
    agents = {
      type = types.union [
        types.int
        (types.enum "auto" [ "auto" ])
      ];
      default = "auto";
      description = "Build agent count, or \"auto\" for one per CPU, decided on the machine.";
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
      units = import ./worker-units.nix {
        inherit pkgs lib;
        package = pkgs.callPackage ./package.nix { craneLib = crane.mkLib pkgs; };
        workerUnit = name;
        agentUnit = "${name}-agent@";
        inherit (options) agents agentUidBase keyFile;
        workerToml = (pkgs.formats.toml { }).generate "worker.toml" (
          {
            agent-sockets-dir = units.agentSocketsDir;
          }
          // options.worker
        );
      };
    in
    {
      inherit (units) generators;
      sockets."agent@" = units.agentSocketConfig // {
        instances = units.agentInstances;
      };
      services."agent@" = units.agentServiceConfig;
      services.${name} = units.workerServiceConfig;
    };
}
