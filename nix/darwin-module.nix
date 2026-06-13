# nix-darwin module for the tribuchet worker.
#
# launchd has no ExecReload, so zero-downtime upgrades work like on
# NixOS, just driven from activation: the daemon execs a stable
# symlink in the state dir, activation flips it to the new package and
# sends SIGHUP, and the reaper execs a fresh worker generation that
# re-adopts running builds. The plist contains neither the package
# store path nor the settings (those live in /etc/tribuchet/worker.toml),
# so neither a package bump nor a settings change makes
# nix-darwin restart the daemon; both arrive via the SIGHUP reload.
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
  format = pkgs.formats.toml { };
  workerToml = format.generate "worker.toml" ({ state-dir = toString cfg.stateDir; } // cfg.settings);
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
    stateDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/tribuchet";
      description = "State directory: TLS material, build dirs, exec symlink.";
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
        Contents of worker.toml. Changes are applied with a SIGHUP
        reload, so running builds survive them. The `hub` key is
        required.
      '';
    };
    logFile = lib.mkOption {
      type = lib.types.path;
      default = "/var/log/tribuchet-worker.log";
      description = "launchd stdout/stderr destination.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.etc."tribuchet/worker.toml".source = workerToml;
    launchd.daemons.tribuchet-worker.serviceConfig = {
      ProgramArguments = [
        execLink
        "worker"
        "--config"
        "/etc/tribuchet/worker.toml"
      ];
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
