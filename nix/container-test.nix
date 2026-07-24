# Container route: the worker runs from the OCI image under rootful
# podman with the tribuchet seccomp profile and spawns its own agents.
{
  tribuchet,
  workerImage,
  seccompProfile,
  nixosModule,
}:
{ pkgs, lib, ... }:
{
  name = "tribuchet-container";

  defaults.documentation.enable = false;

  nodes = {
    hub =
      { pkgs, ... }:
      {
        environment.systemPackages = [ tribuchet ];
        networking.firewall.allowedTCPPorts = [ 7437 ];
        virtualisation.writableStore = true;
        virtualisation.memorySize = 2048;
        virtualisation.diskSize = 4096;
        virtualisation.additionalPaths = [ pkgs.bash ];

        nix.settings = {
          substituters = lib.mkForce [ ];
          max-jobs = 4;
        };

        environment.etc."tt/singleuid.nix".text = ''
          import ${./tests/singleuid.nix} {
            bash = "${pkgs.bash}";
            # containers give the agents no delegated cgroup
            checkCgroup = false;
          }
        '';

        imports = [ nixosModule ];
        services.tribuchet-hub = {
          enable = true;
          package = tribuchet;
          externalBuilders = {
            enable = true;
            systems = [ "x86_64-linux" ];
          };
        };
        # started by the test script once certificates exist
        systemd.sockets.tribuchet-hub.wantedBy = lib.mkForce [ ];
        systemd.services.tribuchet-hub.wantedBy = lib.mkForce [ ];
      };

    worker =
      { nodes, pkgs, ... }:
      let
        workerToml = pkgs.writeText "worker.toml" ''
          hub = "https://hub:7437"
          key = "/etc/tribuchet/tls/worker.key"
          cert = "/etc/tribuchet/tls/worker.crt"
          ca-cert = "/etc/tribuchet/tls/ca.crt"
          spawn-agents = 2
          agent-uid-base = 1325400064
          max-jobs = 2
        '';
      in
      {
        virtualisation.memorySize = 4096;
        virtualisation.diskSize = 8192;
        virtualisation.oci-containers = {
          backend = "podman";
          containers.worker = {
            image = "tribuchet-worker:latest";
            imageFile = workerImage;
            autoStart = false;
            volumes = [
              "${workerToml}:/etc/tribuchet/worker.toml:ro"
              "/root/tls:/etc/tribuchet/tls:ro"
            ];
            extraOptions = [
              "--network=host"
              "--add-host=hub:${nodes.hub.networking.primaryIPAddress}"
              "--cgroupns=private"
              "--security-opt=seccomp=${seccompProfile}"
              # a masked /proc breaks proc mounts in the build's namespaces
              "--security-opt=unmask=ALL"
            ];
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
        worker.succeed("mkdir -p /root/tls")
        for f in ["worker.crt", "worker.key", "ca.crt"]:
            pem = hub.succeed(f"cat /root/ca/{f}")
            worker.succeed(f"cat > /root/tls/{f} << 'PEMEOF'\n{pem}PEMEOF")

    with subtest("containerized worker registers at the hub"):
        hub.succeed("systemctl start tribuchet-hub.socket")
        hub.succeed("systemctl start tribuchet-hub")
        worker.succeed("systemctl start podman-worker")
        hub.wait_until_succeeds(
            "journalctl -u tribuchet-hub | grep -q 'worker registered'"
        )

    with subtest("agents run under their own uids"):
        worker.wait_until_succeeds(
            "journalctl -u podman-worker | grep 'spawned build agents' | grep -q 'uid_isolation=true'"
        )

    with subtest("single-uid build"):
        hub.succeed("nix-build /etc/tt/singleuid.nix --no-out-link")
  '';
}
