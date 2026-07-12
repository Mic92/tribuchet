# NixOS VM test: a real nix-daemon on `hub` routes a build through the
# external-builders feature to tribuchet, which dispatches it to `worker`
# over mTLS and unpacks the signed outputs back into the hub's store.
{ tribuchet, nixosModule }:
{ pkgs, lib, ... }:
let
  # evaluated here so the container closure can be pre-seeded into both
  # VM stores; the hub re-evaluates the same expression at test time
  nspawn = import ./nspawn-container.nix { nixpkgs = pkgs.path; };

in
{
  name = "tribuchet";

  # Faster eval
  defaults.documentation.enable = false;

  # The e2e harness runs on the driver host and drives both VMs over the
  # vsock ssh backdoor, so independent subtests run concurrently.
  sshBackdoor.enable = true;
  # required by sshBackdoor (asserted in the test framework)
  defaults.virtualisation.qemu.enableSharedMemory = true;

  nodes = {
    hub =
      {
        pkgs,
        nodes,
        ...
      }:
      {
        environment.systemPackages = [
          tribuchet
          pkgs.socat
        ];
        networking.firewall.allowedTCPPorts = [
          7437
          8765
        ];
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
          experimental-features = [
            "ca-derivations"
            "impure-derivations"
            "recursive-nix"
          ];
          # let the daemon accept uid-range builds; tribuchet's worker
          # provides the actual uid range
          system-features = [ "uid-range" ];
          substituters = lib.mkForce [ ];
          # dispatch several external builds at once so parallel subtests
          # actually overlap instead of queueing on the hub daemon
          max-jobs = 8;
        };

        # Test derivations are real files in nix/tests/ (single level
        # of quoting); the shims inject store paths and node addresses.
        environment.etc."tt/par.nix".text = ''
          import ${./tests/par.nix} { bash = "${pkgs.bash}"; }
        '';
        environment.etc."tt/nspawn.nix".text = ''
          import ${./nspawn-container.nix} { nixpkgs = ${pkgs.path}; }
        '';
        environment.etc."tt/kvm.nix".text = ''
          import ${./tests/kvm.nix} { bash = "${pkgs.bash}"; }
        '';
        environment.etc."tt/kvm-emulated.nix".text = ''
          import ${./tests/kvm.nix} {
            bash = "${pkgs.bash}";
            system = "aarch64-linux";
          }
        '';
        environment.etc."tt/uidrange.nix".text = ''
          import ${./tests/uidrange.nix} { bash = "${pkgs.bash}"; }
        '';
        environment.etc."tt/fod.nix".text = ''
          import ${./tests/fod.nix} {
            bash = "${pkgs.bash}";
            hubIp = "${nodes.hub.networking.primaryIPAddress}";
          }
        '';
        environment.etc."tt/fod-dns.nix".text = ''
          import ${./tests/fod-dns.nix} {
            bash = "${pkgs.bash}";
            host = "fod-dns.test";
          }
        '';
        environment.etc."tt/fod-hosts.nix".text = ''
          import ${./tests/fod-dns.nix} {
            bash = "${pkgs.bash}";
            host = "fod-hosts.test";
          }
        '';
        environment.etc."tt/logbomb.nix".text = ''
          import ${./tests/logbomb.nix} { bash = "${pkgs.bash}"; }
        '';
        environment.etc."tt/drain.nix".text = ''
          import ${./tests/drain.nix} { bash = "${pkgs.bash}"; }
        '';
        environment.etc."tt/reload.nix".text = ''
          import ${./tests/reload.nix} { bash = "${pkgs.bash}"; }
        '';
        environment.etc."tt/cancel.nix".text = ''
          import ${./tests/cancel.nix} { bash = "${pkgs.bash}"; }
        '';
        environment.etc."tt/slowlog.nix".text = ''
          import ${./tests/slowlog.nix} { bash = "${pkgs.bash}"; }
        '';
        environment.etc."tt/refgraph.nix".text = ''
          import ${./tests/refgraph.nix} { bash = "${pkgs.bash}"; }
        '';
        environment.etc."tt/structured.nix".text = ''
          import ${./tests/structured.nix} { bash = "${pkgs.bash}"; }
        '';
        environment.etc."tt/ca.nix".text = ''
          import ${./tests/ca.nix} { bash = "${pkgs.bash}"; }
        '';
        environment.etc."tt/impure.nix".text = ''
          import ${./tests/impure.nix} { bash = "${pkgs.bash}"; }
        '';
        environment.etc."tt/cross.nix".text = ''
          import ${./tests/cross.nix} {
            busybox = "${pkgs.pkgsCross.aarch64-multiplatform.pkgsStatic.busybox}";
          }
        '';
        environment.etc."tt/recursive.nix".text = ''
          import ${./tests/recursive.nix} {
            bash = "${pkgs.bash}";
            nix = "${pkgs.nixVersions.latest}";
          }
        '';

        imports = [ nixosModule ];
        services.tribuchet-hub = {
          enable = true;
          # keep the no-worker decline quick for the fallback subtest
          settings.worker-grace-secs = 2;
          externalBuilders = {
            enable = true;
            recursiveNix = true;
            systems = [
              "x86_64-linux"
              "aarch64-linux"
            ];
          };
          package = tribuchet;
        };
        # started by the test script once certificates exist
        systemd.sockets.tribuchet-hub.wantedBy = lib.mkForce [ ];
        systemd.services.tribuchet-hub.wantedBy = lib.mkForce [ ];
      };

    worker =
      { pkgs, nodes, ... }:
      {
        # Resolvable only via /etc/hosts; the FOD-via-files subtest
        # fetches the hub through this name.
        networking.hosts."${nodes.hub.networking.primaryIPAddress}" = [ "fod-hosts.test" ];
        environment.systemPackages = [
          tribuchet
          pkgs.python3
        ];
        # Resolver for the FOD-via-DNS subtest; presto-pasta forwards the
        # sandbox's queries here. The record is dropped into addn-hosts
        # at test time, once the hub IP is known.
        services.dnsmasq = {
          enable = true;
          resolveLocalQueries = false;
          settings = {
            no-resolv = true;
            addn-hosts = "/var/lib/dnsmasq-fod";
          };
        };
        systemd.tmpfiles.rules = [ "d /var/lib/dnsmasq-fod 0755 root root -" ];
        networking.nameservers = [ "127.0.0.1" ];
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

        imports = [ nixosModule ];
        services.tribuchet-worker = {
          enable = true;
          package = tribuchet;
          settings = {
            hub = "https://hub:7437";
            max-jobs = 2;
            max-log-size = 1048576;
            recursive-nix = true;
            emulate.aarch64-linux = "${pkgs.pkgsStatic.qemu-user}/bin/qemu-aarch64";
          };
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

    with subtest("worker registers at hub over mTLS"):
        hub.succeed("systemctl start tribuchet-hub.socket")
        hub.succeed("systemctl start tribuchet-hub")
        worker.succeed("systemctl start tribuchet-worker")
        hub.wait_until_succeeds(
            "journalctl -u tribuchet-hub | grep -q 'worker registered'"
        )

    with subtest("worker sshd reachable for the harness backdoor"):
        hub.wait_for_unit("sshd.service")
        worker.wait_for_unit("sshd.service")

    # Hand off to the Rust e2e harness. It runs on the driver host and drives
    # both VMs over the vsock ssh backdoor, so independent subtests overlap.
    import os, subprocess, tempfile

    ctldir = tempfile.mkdtemp(prefix="tt-ssh-")
    e2e_env = dict(os.environ)
    e2e_env.update({
        "TT_SSH": "${pkgs.openssh}/bin/ssh",
        "TT_SSH_CONFIG": "${pkgs.systemd}/lib/systemd/ssh_config.d/20-systemd-ssh-proxy.conf",
        "TT_HUB_SOCK": str(hub.vsock_host),
        "TT_WORKER_SOCK": str(worker.vsock_host),
        "TT_CTLDIR": ctldir,
        "TT_BASH": "${pkgs.bash}",
    })
    e2e = "${tribuchet.e2eTests}/bin/tribuchet-e2e"

    # Phase 1: independent builds, multi-threaded. The worker/hub max-jobs
    # queues bound real build concurrency; test-threads only caps ssh sessions.
    with subtest("parallel builds"):
        subprocess.run(
            [e2e, "build_", "--nocapture", "--test-threads=8"],
            env=e2e_env, check=True,
        )

    # Phase 2: the stateful daemon-lifecycle sequence, serial and in order.
    # Must run after phase 1: it restarts/reloads/stops the daemons.
    with subtest("daemon lifecycle"):
        subprocess.run(
            [e2e, "lifecycle", "--nocapture", "--test-threads=1"],
            env=e2e_env, check=True,
        )
  '';
}
