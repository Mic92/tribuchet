# Enqueue `flakelet update` on the hub and worker hosts, authorized by a
# step-ca ssh certificate for this repo's main branch.
{ pkgs, effects }:
let
  hosts = [
    "eve.r"
    "eliza.r"
    "jamie.r"
  ];
in
{ primaryRepo, ... }:
{
  onPush.default.outputs.effects.deploy = effects.runIf ((primaryRepo.branch or null) == "main") (
    effects.mkEffect {
      name = "deploy";
      idTokenAudiences = [ "step-ca-ssh" ];
      inputs = [
        pkgs.step-cli
        pkgs.openssh
      ];
      effectScript = ''
        export STEPPATH=$PWD/.step
        step ca bootstrap --ca-url https://ca.r \
          --fingerprint 759759ea7dc7d635d761ce19a07bc0b3ab02212318e05b49d2b194c60414b84a

        ssh-keygen -t ed25519 -N "" -q -f ./id_deploy
        step ssh certificate --sign --provisioner nixbot \
          --token "$(nixbot-id-token step-ca-ssh)" \
          deploy ./id_deploy.pub

        rc=0
        for host in ${toString hosts}; do
          ssh -i ./id_deploy \
            -o CertificateFile=./id_deploy-cert.pub \
            -o UserKnownHostsFile=$PWD/known_hosts \
            -o StrictHostKeyChecking=accept-new \
            -o ConnectTimeout=10 \
            "flakelet-deploy@$host" || rc=1
        done
        exit $rc
      '';
    }
  );
}
