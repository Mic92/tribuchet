# Ask the flakelet relays to update hub and workers, authorized by this
# repo's nixbot id token (rule "tribuchet" in Mic92/dotfiles
# nixosModules/flakelet-relay).
{ pkgs, effects }:
let
  flakelet-push = pkgs.callPackage ./flakelet-push.nix { };
in
{ primaryRepo, ... }:
{
  onPush.default.outputs.effects.deploy = effects.runIf ((primaryRepo.branch or null) == "main") (
    effects.mkEffect {
      name = "deploy";
      idTokenAudiences = [ "flakelet-relay" ];
      inputs = [ flakelet-push ];
      effectScript = ''
        export FLAKELET_RELAY_TOKEN_COMMAND="nixbot-id-token flakelet-relay"
        flakelet-push --relay-srv thalheim.io deploy \
          eve/tribuchet-hub --wave eliza/tribuchet-worker jamie/tribuchet-worker
      '';
    }
  );
}
