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

  # evaluated here so the container closure can be pre-seeded into both
  # VM stores; the hub re-evaluates the same expression at test time
  nspawn = import ./nspawn-container.nix { nixpkgs = pkgs.path; };

in
{
  name = "tribuchet";

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

        # patched so uid-range derivations reach the external builder
        # (upstream rejects them before invoking it)
        nix.package = pkgs.nixVersions.latest.appendPatches [
          ./patches/external-builders-uid-range.patch
        ];
        nix.settings = {
          experimental-features = [ "external-builders" ];
          # let the daemon accept uid-range builds; tribuchet's worker
          # provides the actual uid range
          system-features = [ "uid-range" ];
          external-builders = builtins.toJSON [
            {
              systems = [
                "x86_64-linux"
                "aarch64-linux"
              ];
              program = "${attachWrapper}";
              args = [ ];
            }
          ];
          substituters = lib.mkForce [ ];
        };

        # test derivations (etc files avoid heredoc quoting in testScript)
        environment.etc."tt/par.nix".text = ''
          let
            bash = builtins.storePath "${pkgs.bash}";
            mk = n: derivation {
              name = "tt-par-''${n}";
              system = "x86_64-linux";
              builder = bash + "/bin/bash";
              # busy-wait 15s of wall clock; two of these finishing in
              # well under 30s proves they overlapped on the worker
              args = [ "-c" "while [ $SECONDS -lt 15 ]; do :; done; echo done-$n > $out" ];
              inherit n;
            };
          in [ (mk "a") (mk "b") ]
        '';
        environment.etc."tt/nspawn.nix".text = ''
          import ${./nspawn-container.nix} { nixpkgs = ${pkgs.path}; }
        '';
        environment.etc."tt/uidrange.nix".text = ''
          let
            bash = builtins.storePath "${pkgs.bash}";
          in derivation {
            name = "tt-uid-range";
            system = "x86_64-linux";
            requiredSystemFeatures = [ "uid-range" ];
            builder = bash + "/bin/bash";
            args = [ "-c" "[ \"$EUID\" = 0 ] && [ -w /sys/fs/cgroup/cgroup.procs ] && echo uid-range-ok > $out" ];
          }
        '';

        # Fetches from the hub's HTTP server through pasta and asserts
        # the worker's loopback service is unreachable from the sandbox.
        environment.etc."tt/fod.nix".text = ''
          let
            bash = builtins.storePath "${pkgs.bash}";
          in
          derivation {
            name = "tt-fod";
            system = "x86_64-linux";
            builder = bash + "/bin/bash";
            args = [
              "-c"
              '''
                if (exec 3<>/dev/tcp/127.0.0.1/9999) 2>/dev/null; then
                  echo "worker loopback leaked into FOD netns" >&2
                  exit 1
                fi
                exec 3<>/dev/tcp/${nodes.hub.networking.primaryIPAddress}/8765
                while IFS= read -r l <&3; do printf '%s\n' "$l"; done > $out
              '''
            ];
            outputHashAlgo = "sha256";
            outputHashMode = "flat";
            outputHash = "fba0ea84c93fbcbfff10a9b33bc33409b5fd15eff0540b7b4389d691cde59fe8";
          }
        '';

        environment.etc."tt/cross.nix".text = ''
          let
            busybox = builtins.storePath "${pkgs.pkgsCross.aarch64-multiplatform.pkgsStatic.busybox}";
          in
          derivation {
            name = "tt-cross";
            system = "aarch64-linux";
            builder = busybox + "/bin/busybox";
            args = [
              "sh"
              "-c"
              "\"$builder\" uname -m > $out; \"$builder\" id -u >> $out"
            ];
          }
        '';

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
        environment.systemPackages = [
          tribuchet
          pkgs.python3
        ];
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

        systemd.services.tribuchet-worker = {
          # started by the test script once certificates exist
          wantedBy = lib.mkForce [ ];
          serviceConfig = {
            ExecStart = "${tribuchet}/bin/tribuchet worker --hub https://hub:7437 --state-dir /var/lib/tribuchet --max-jobs 2 --emulate aarch64-linux=${pkgs.pkgsStatic.qemu-user}/bin/qemu-aarch64";
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

    with subtest("concurrent builds share one worker session"):
        import time
        t0 = time.time()
        hub.succeed("nix-build /etc/tt/par.nix --no-out-link --max-jobs 2")
        elapsed = time.time() - t0
        assert elapsed < 27, f"builds did not overlap: {elapsed:.0f}s (serial would be >=30s)"

    with subtest("uid-range build runs as sandbox root with a cgroup"):
        out = hub.succeed("nix-build /etc/tt/uidrange.nix --no-out-link").strip()
        hub.succeed(f"grep -q uid-range-ok {out}")

    with subtest("fixed-output build fetches through pasta, isolated from host sockets"):
        hub.succeed("mkdir -p /srv/fod && echo hello-fod > /srv/fod/data")
        hub.succeed(
            "systemd-run --unit=fodsrv socat -U TCP-LISTEN:8765,fork,reuseaddr OPEN:/srv/fod/data,rdonly"
        )
        hub.wait_for_open_port(8765)
        # loopback service on the worker that must NOT be reachable
        worker.succeed("systemd-run --unit=loopsrv python3 -m http.server 9999 --bind 127.0.0.1")
        worker.wait_for_open_port(9999)
        out = hub.succeed("nix-build /etc/tt/fod.nix --no-out-link").strip()
        hub.succeed(f"grep -q hello-fod {out}")

    with subtest("aarch64 build runs under per-sandbox binfmt emulation"):
        out = hub.succeed("nix-build /etc/tt/cross.nix --no-out-link").strip()
        hub.succeed(f"grep -q aarch64 {out}")
        hub.succeed(f"grep -qx 1000 {out}")

    with subtest("systemd-nspawn boots a NixOS container in a remote build"):
        out = hub.succeed("nix-build /etc/tt/nspawn.nix --no-out-link", timeout=1800).strip()
        hub.succeed(f"[[ $(cat {out}/msg) = 'Hello World' ]]")

    with subtest("build really ran on the worker"):
        worker.succeed("journalctl -u tribuchet-worker | grep -q 'builder finished'")
        worker.succeed("journalctl -u tribuchet-worker | grep -q 'per-build cgroup limits enabled'")
        hub.succeed("journalctl -u tribuchet-hub | grep -q 'dispatching build'")
        import os
        worker.succeed(f"test -e /var/lib/tribuchet/store/{os.path.basename(unique)}")
  '';
}
