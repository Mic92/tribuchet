# NixOS VM test: a worker running as an unprivileged user leases uid
# ranges from systemd-nsresourced and builds a uid-range derivation
# dispatched by the hub.
{
  tribuchet,
  nixosModule,
  nsresourcedModule,
}:
{ pkgs, lib, ... }:
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
        virtualisation.additionalPaths = [ pkgs.bash ];

        nix.settings = {
          # let the daemon accept uid-range builds; tribuchet's worker
          # provides the actual uid range
          system-features = [ "uid-range" ];
          substituters = lib.mkForce [ ];
        };

        environment.etc."tt/uidrange-rootless.nix".text = ''
          import ${./tests/uidrange-rootless.nix} { bash = "${pkgs.bash}"; }
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
        virtualisation.memorySize = 2048;

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
        out = hub.succeed("cat $(nix-build /etc/tt/uidrange-rootless.nix --no-out-link)")
        assert "uid-range-rootless-ok" in out, out
        worker.succeed("journalctl -u tribuchet-worker | grep -q 'leased uid range'")
  '';
}
