# Minimal hercules-ci-effects compatible mkEffect/runIf as understood by
# nixbot, inlined so this flake does not depend on the nixbot flake.
{
  pkgs,
  lib ? pkgs.lib,
}:
let
  # Fetches a workload-identity ID token from nixbot inside the effect
  # sandbox. Usage: nixbot-id-token <audience>
  idTokenScript = pkgs.writeShellApplication {
    name = "nixbot-id-token";
    runtimeInputs = [
      pkgs.curl
      pkgs.jq
    ];
    text = ''
      if [[ -z "''${NIXBOT_ID_TOKEN_REQUEST_URL:-}" || -z "''${NIXBOT_ID_TOKEN_REQUEST_TOKEN:-}" ]]; then
        echo "nixbot-id-token: no ID token endpoint available; declare the audience in the effect's idTokenAudiences" >&2
        exit 1
      fi
      jq -cn --arg audience "$1" '$ARGS.named' \
        | curl -fsS --max-time 30 \
            -H "Authorization: Bearer $NIXBOT_ID_TOKEN_REQUEST_TOKEN" \
            -H "Content-Type: application/json" \
            --data-binary @- "$NIXBOT_ID_TOKEN_REQUEST_URL" \
        | jq -re .token
    '';
  };
in
{
  mkEffect =
    {
      effectScript ? "",
      name ? "effect",
      inputs ? [ ],
      idTokenAudiences ? [ ],
    }:
    pkgs.stdenvNoCC.mkDerivation {
      inherit name effectScript;
      isEffect = true;
      __hci_effect_fsroot_copy = pkgs.runCommand "mkEffect-root" { } ''
        mkdir -p $out/bin $out/usr/bin
        ln -s ${lib.getExe pkgs.bash} $out/bin/sh
        ln -s ${pkgs.coreutils}/bin/env $out/usr/bin/env
      '';
      secretsMap = builtins.toJSON { };
      idTokenAudiences = builtins.toJSON idTokenAudiences;
      nativeBuildInputs = [
        pkgs.cacert
        pkgs.curl
        pkgs.jq
      ]
      ++ lib.optional (idTokenAudiences != [ ]) idTokenScript
      ++ inputs;
      phases = [
        "initPhase"
        "effectPhase"
      ];
      initPhase = ''
        exec </dev/null
        export HOME=/build/home
        mkdir -p "$HOME"
        echo "root:x:$(id -u):$(id -g):root:$HOME:/bin/sh" >> /etc/passwd
        mkdir -p ~/.ssh
        echo "BatchMode yes" >> ~/.ssh/config
      '';
      effectPhase = ''eval "$effectScript"'';
    };

  # A false condition still evaluates/builds the effect's closure.
  runIf =
    condition: effect:
    if condition then
      { run = effect; }
    else
      {
        dependencies = effect.inputDerivation // {
          isEffect = false;
          buildDependenciesOnly = true;
        };
      };
}
