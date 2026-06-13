# nix-darwin module for the tribuchet worker.
#
# launchd has no ExecReload, so zero-downtime upgrades work like on
# NixOS, just driven from activation: the daemon execs a stable
# symlink in the state dir, activation flips it to the new package and
# sends SIGHUP, and the reaper execs a fresh worker generation that
# re-adopts running builds. The plist never contains the package store
# path, so a package bump does not make nix-darwin restart the daemon;
# changing an option that is part of the command line still does (and
# kills running builds).
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.tribuchet-worker;
  execLink = "${cfg.stateDir}/exec";
  label = "org.nixos.tribuchet-worker";
in
{
  options.services.tribuchet-worker = {
    enable = lib.mkEnableOption "tribuchet build worker";
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "tribuchet";
      description = "Package providing bin/tribuchet.";
    };
    hub = lib.mkOption {
      type = lib.types.str;
      example = "https://hub.example.org:7437";
      description = "URL of the hub's worker endpoint.";
    };
    stateDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/tribuchet";
      description = "State directory: TLS material, build dirs, exec symlink.";
    };
    maxJobs = lib.mkOption {
      type = lib.types.ints.positive;
      default = 1;
      description = "Concurrent build slots advertised to the hub.";
    };
    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Additional arguments passed to `tribuchet worker`.";
    };
    logFile = lib.mkOption {
      type = lib.types.path;
      default = "/var/log/tribuchet-worker.log";
      description = "launchd stdout/stderr destination.";
    };
  };

  config = lib.mkIf cfg.enable {
    launchd.daemons.tribuchet-worker.serviceConfig = {
      ProgramArguments = [
        execLink
        "worker"
        "--hub"
        cfg.hub
        "--state-dir"
        (toString cfg.stateDir)
        "--max-jobs"
        (toString cfg.maxJobs)
      ]
      ++ cfg.extraArgs;
      KeepAlive = true;
      RunAtLoad = true;
      StandardOutPath = toString cfg.logFile;
      StandardErrorPath = toString cfg.logFile;
      EnvironmentVariables.RUST_LOG = "info";
    };

    # The symlink must point at the new package before launchd could
    # (re)start the daemon; the SIGHUP afterwards hands running builds
    # over to the new binary.
    system.activationScripts.preActivation.text = ''
      mkdir -p ${lib.escapeShellArg (toString cfg.stateDir)}
      ln -sfn ${lib.getExe' cfg.package "tribuchet"} ${lib.escapeShellArg execLink}
    '';
    system.activationScripts.postActivation.text = ''
      /bin/launchctl kill SIGHUP system/${label} 2>/dev/null || true
    '';
  };
}
