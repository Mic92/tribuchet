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
        virtualisation.additionalPaths = [ pkgs.bash ];

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
            # delegate the cgroup subtree so the worker can apply
            # per-build pids/memory limits and cgroup.kill teardown
            Delegate = true;
            Restart = "on-failure";
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
        # The input is added at runtime, so it cannot be in the worker's
        # store image: it must travel over the wire.
        hub.succeed("echo tribuchet-payload > /root/payload")
        unique = hub.succeed("nix-store --add /root/payload").strip()
        hub.succeed(
            "cat > /root/test.nix << 'NIXEOF'\n"
            "let\n"
            "  bash = builtins.storePath \"${pkgs.bash}\";\n"
            f"  unique = builtins.storePath \"{unique}\";\n"
            "in derivation {\n"
            "  name = \"tt-remote-build\";\n"
            "  system = \"x86_64-linux\";\n"
            "  builder = bash + \"/bin/bash\";\n"
            "  args = [ \"-c\" (\"read line < \" + unique + \"; echo \\\"$line built-remotely\\\" > $out\") ];\n"
            "}\n"
            "NIXEOF"
        )
        out = hub.succeed("nix-build /root/test.nix --no-out-link").strip()
        hub.succeed(f"grep -q 'tribuchet-payload built-remotely' {out}")

    with subtest("build really ran on the worker"):
        worker.succeed("journalctl -u tribuchet-worker | grep -q 'builder finished'")
        worker.succeed("journalctl -u tribuchet-worker | grep -q 'per-build cgroup limits enabled'")
        hub.succeed("journalctl -u tribuchet-hub | grep -q 'dispatching build'")
        import os
        worker.succeed(f"test -e /var/lib/tribuchet/store/{os.path.basename(unique)}")
  '';
}
