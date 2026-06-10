# NixOS VM test: a real nix-daemon on `hub` routes a build through the
# external-builders feature to tribuchet, which dispatches it to `worker`
# over mTLS and unpacks the signed outputs back into the hub's store.
{ tribuchet }:
{ pkgs, lib, ... }:
let
  attachWrapper = pkgs.writeShellScript "tribuchet-attach" ''
    export RUST_LOG=info
    exec ${tribuchet}/bin/tribuchet attach "$1" --socket /run/tribuchet/hub.sock
  '';

  # Only present in the hub's store: forces a NAR transfer to the worker,
  # whose store image does not contain it.
  uniqueInput = pkgs.writeText "tribuchet-test-input" "tribuchet-payload";

  testExpr = pkgs.writeText "tt-test.nix" ''
    let
      bash = builtins.storePath ${builtins.toJSON "${pkgs.bash}"};
      unique = builtins.storePath ${builtins.toJSON "${uniqueInput}"};
    in
    derivation {
      name = "tt-remote-build";
      system = "x86_64-linux";
      builder = "''${bash}/bin/bash";
      args = [
        "-c"
        "read line < ''${unique}; echo \"$line built-remotely\" > $out"
      ];
    }
  '';
in
{
  name = "tribuchet";

  nodes = {
    hub =
      { pkgs, ... }:
      {
        environment.systemPackages = [ tribuchet ];
        networking.firewall.allowedTCPPorts = [ 7437 ];
        virtualisation.writableStore = true;
        virtualisation.additionalPaths = [
          pkgs.bash
          uniqueInput
          testExpr
        ];

        nix.package = pkgs.nixVersions.latest;
        nix.settings = {
          experimental-features = [ "external-builders" ];
          external-builders = builtins.toJSON [
            {
              systems = [ "x86_64-linux" ];
              program = "${attachWrapper}";
              args = [ ];
            }
          ];
          substituters = lib.mkForce [ ];
        };

        systemd.services.tribuchet-hub = {
          # started by the test script once certificates exist
          wantedBy = lib.mkForce [ ];
          serviceConfig = {
            ExecStart = "${tribuchet}/bin/tribuchet hub --socket /run/tribuchet/hub.sock --listen 0.0.0.0:7437 --config-dir /etc/tribuchet";
            RuntimeDirectory = "tribuchet";
            Environment = "RUST_LOG=info";
          };
        };
      };

    worker =
      { pkgs, ... }:
      {
        environment.systemPackages = [ tribuchet ];
        # Private store image instead of the shared host store, so input
        # paths the worker lacks really travel over the wire.
        virtualisation.useNixStoreImage = true;
        virtualisation.writableStore = true;

        systemd.services.tribuchet-worker = {
          # started by the test script once certificates exist
          wantedBy = lib.mkForce [ ];
          serviceConfig = {
            ExecStart = "${tribuchet}/bin/tribuchet worker --hub https://hub:7437 --state-dir /var/lib/tribuchet";
            StateDirectory = "tribuchet";
            Environment = "RUST_LOG=info";
          };
        };
      };
  };

  testScript = ''
    start_all()
    hub.wait_for_unit("multi-user.target")
    worker.wait_for_unit("multi-user.target")

    with subtest("certificate authority"):
        hub.succeed("tribuchet ca init --dir /root/ca")
        hub.succeed("tribuchet ca issue hub --dir /root/ca")
        hub.succeed("tribuchet ca issue worker --dir /root/ca")
        hub.succeed("mkdir -p /etc/tribuchet/ca")
        hub.succeed("cp /root/ca/hub.crt /root/ca/hub.key /root/ca/ca.crt /etc/tribuchet/ca/")
        worker.succeed("mkdir -p /var/lib/tribuchet/tls")
        for f in ["worker.crt", "worker.key", "ca.crt"]:
            pem = hub.succeed(f"cat /root/ca/{f}")
            worker.succeed(f"cat > /var/lib/tribuchet/tls/{f} << 'PEMEOF'\n{pem}PEMEOF")

    with subtest("worker registers at hub over mTLS"):
        hub.succeed("systemctl start tribuchet-hub")
        worker.succeed("systemctl start tribuchet-worker")
        hub.wait_until_succeeds(
            "journalctl -u tribuchet-hub | grep -q 'worker registered'"
        )

    with subtest("nix-daemon builds remotely via external-builders"):
        out = hub.succeed("nix-build ${testExpr} --no-out-link").strip()
        hub.succeed(f"grep -q 'tribuchet-payload built-remotely' {out}")

    with subtest("build really ran on the worker"):
        worker.succeed("journalctl -u tribuchet-worker | grep -q 'builder finished'")
        hub.succeed("journalctl -u tribuchet-hub | grep -q 'dispatching build'")
        # the unique input was not in the worker store image: it must
        # have been transferred
        worker.succeed("test -e /var/lib/tribuchet/store/$(basename ${uniqueInput})")
  '';
}
