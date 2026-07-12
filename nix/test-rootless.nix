# NixOS VM test: a worker running as an unprivileged user leases uid
# ranges from systemd-nsresourced and builds a uid-range derivation
# dispatched by the hub.
{
  tribuchet,
  nixosModule,
  nsresourcedModule,
}:
{ pkgs, lib, ... }:
let
  nspawn = import ./nspawn-container.nix { nixpkgs = pkgs.path; };
in
{
  name = "tribuchet-rootless";

  defaults.documentation.enable = false;

  nodes = {
    hub =
      { pkgs, ... }:
      {
        environment.systemPackages = [ tribuchet ];
        networking.firewall.allowedTCPPorts = [ 7437 ];
        virtualisation.writableStore = true;
        # container eval and closure streaming need room
        virtualisation.memorySize = 4096;
        virtualisation.diskSize = 4096;
        virtualisation.additionalPaths = [
          pkgs.bash
          pkgs.stdenvNoCC
          nspawn.toplevel
        ];

        nix.settings = {
          # let the daemon accept uid-range builds; tribuchet's worker
          # provides the actual uid range
          system-features = [ "uid-range" ];
          substituters = lib.mkForce [ ];
        };

        environment.etc."tt/uidrange-rootless.nix".text = ''
          import ${./tests/uidrange-rootless.nix} { bash = "${pkgs.bash}"; }
        '';
        environment.etc."tt/singleuid-rootless.nix".text = ''
          import ${./tests/singleuid-rootless.nix} { bash = "${pkgs.bash}"; }
        '';
        environment.etc."tt/nspawn.nix".text = ''
          import ${./nspawn-container.nix} { nixpkgs = ${pkgs.path}; }
        '';

        imports = [ nixosModule ];
        services.tribuchet-hub = {
          enable = true;
          externalBuilders.enable = true;
          package = tribuchet;
        };
        # started by the test script once certificates exist
        systemd.sockets.tribuchet-hub.wantedBy = lib.mkForce [ ];
        systemd.services.tribuchet-hub.wantedBy = lib.mkForce [ ];
      };

    worker =
      { pkgs, ... }:
      {
        environment.systemPackages = [ tribuchet ];
        # Private store image instead of the shared host store, so input
        # paths the worker lacks really travel over the wire.
        virtualisation.useNixStoreImage = true;
        virtualisation.writableStore = true;
        # booting a NixOS container inside the sandbox needs room
        virtualisation.memorySize = 4096;
        virtualisation.diskSize = 4096;
        virtualisation.additionalPaths = [
          pkgs.stdenvNoCC
          nspawn.toplevel
        ];

        imports = [
          nixosModule
          nsresourcedModule
        ];
        services.nsresourced.enable = true;

        # The worker imports input NARs through the nix-daemon without
        # signatures, which only trusted users may do.
        nix.settings.trusted-users = [ "tribuchet" ];
        users.users.tribuchet = {
          isSystemUser = true;
          group = "tribuchet";
        };
        users.groups.tribuchet = { };

        services.tribuchet-worker = {
          enable = true;
          package = tribuchet;
          settings = {
            hub = "https://hub:7437";
            max-jobs = 2;
          };
        };
        systemd.services.tribuchet-worker.serviceConfig = {
          User = "tribuchet";
          Group = "tribuchet";
        };
        # started by the test script once certificates exist
        systemd.services.tribuchet-worker.wantedBy = lib.mkForce [ ];
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
        worker.succeed("chown -R tribuchet:tribuchet /var/lib/tribuchet")

    with subtest("rootless worker registers"):
        worker.wait_for_unit("systemd-nsresourced.socket")
        hub.succeed("systemctl start tribuchet-hub.socket tribuchet-hub")
        worker.succeed("systemctl start tribuchet-worker")
        hub.wait_until_succeeds(
            "journalctl -u tribuchet-hub | grep -q 'worker registered'"
        )

    with subtest("uid-range build runs in a leased user namespace"):
        path = hub.succeed("nix-build /etc/tt/uidrange-rootless.nix --no-out-link").strip()
        out = hub.succeed(f"cat {path}")
        assert "uid-range-rootless-ok" in out, out
        worker.succeed("journalctl -u tribuchet-worker | grep -q 'leased uid range'")

    with subtest("nspawn container boots inside a leased uid-range build"):
        path = hub.succeed("nix-build /etc/tt/nspawn.nix --no-out-link").strip()
        out = hub.succeed(f"cat {path}/msg")
        assert "Hello World" in out, out

    with subtest("regular build runs as a leased single uid"):
        path = hub.succeed("nix-build /etc/tt/singleuid-rootless.nix --no-out-link").strip()
        out = hub.succeed(f"cat {path}")
        assert "single-uid-rootless-ok" in out, out
        # the builder must not run as the worker's own uid
        backing_uid = out.split()[-1]
        worker_uid = worker.succeed("id -u tribuchet").strip()
        assert backing_uid != worker_uid, out

    with subtest("leased build dirs are cleaned up"):
        worker.wait_until_succeeds(
            "test -z \"$(ls /var/lib/tribuchet/builds 2>/dev/null)\""
        )
        worker.fail("journalctl -u tribuchet-worker | grep 'cleaning up'")
  '';
}
