# NixOS VM test: a real nix-daemon on `hub` routes a build through the
# external-builders feature to tribuchet, which dispatches it to `worker`
# over mTLS and unpacks the signed outputs back into the hub's store.
{ tribuchet, nixosModule }:
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
        environment.etc."tt/cross.nix".text = ''
          import ${./tests/cross.nix} {
            busybox = "${pkgs.pkgsCross.aarch64-multiplatform.pkgsStatic.busybox}";
          }
        '';

        imports = [ nixosModule ];
        services.tribuchet-hub = {
          enable = true;
          package = tribuchet;
        };
        # started by the test script once certificates exist
        systemd.sockets.tribuchet-hub.wantedBy = lib.mkForce [ ];
        systemd.services.tribuchet-hub.wantedBy = lib.mkForce [ ];
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

        imports = [ nixosModule ];
        services.tribuchet-worker = {
          enable = true;
          package = tribuchet;
          settings = {
            hub = "https://hub:7437";
            max-jobs = 2;
            max-log-size = 1048576;
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

    with subtest("hub restart: socket activation keeps clients connectable"):
        # Type=notify means this only returns once the new hub serves.
        hub.succeed("systemctl restart tribuchet-hub")
        # The activated unix socket accepts immediately; the build
        # waits for the worker to re-register rather than failing.
        out = hub.succeed(
            "nix-build /root/test.nix --no-out-link 2>/dev/null"
        ).strip()
        hub.succeed(f"grep -q 'tribuchet-payload built-remotely' {out}")

    with subtest("restarting hub and worker mid-build cancels nothing"):
        assigned = int(worker.succeed(
            "journalctl -u tribuchet-worker | grep -c 'build assigned' || true"
        ).strip())
        # systemd-run: the build must survive this command returning.
        hub.succeed(
            "rm -f /tmp/drain.ok && systemd-run --unit=drainbuild bash -lc "
            "'nix-build /etc/tt/drain.nix --no-out-link > /tmp/drain.out "
            "&& touch /tmp/drain.ok'"
        )
        worker.wait_until_succeeds(
            f"[ $(journalctl -u tribuchet-worker | grep -c 'build assigned') -gt {assigned} ]",
            timeout=60,
        )
        # Hub restart and worker reload at once, mid-build: the hub
        # exits immediately (attach reconnects and resubmits; the
        # worker resumes by dedupe key) and the worker generation is
        # replaced while the build keeps running.
        worker.succeed("systemctl reload tribuchet-worker")
        hub.succeed("systemctl restart --no-block tribuchet-hub")
        hub.wait_until_succeeds("test -f /tmp/drain.ok", timeout=120)
        out = hub.succeed("cat /tmp/drain.out").strip()
        hub.succeed(f"grep -q drained-not-cancelled {out}")
        worker.wait_until_succeeds("systemctl is-active tribuchet-worker")
        hub.wait_until_succeeds("systemctl is-active tribuchet-hub")

    with subtest("resubmitting a previously resumed derivation builds again"):
        # Same dedupe key as the resumed build above: it must go
        # through normal admission, not the one-shot resumable fast
        # path of the worker's registration.
        hub.succeed("nix-build /etc/tt/drain.nix --no-out-link --check", timeout=120)

    with subtest("max-log-size applies to a build adopted across a reload"):
        assigned = int(worker.succeed(
            "journalctl -u tribuchet-worker | grep -c 'build assigned' || true"
        ).strip())
        hub.succeed(
            "systemd-run --unit=slowlogbuild bash -lc "
            "'nix-build /etc/tt/slowlog.nix --no-out-link'"
        )
        worker.wait_until_succeeds(
            f"[ $(journalctl -u tribuchet-worker | grep -c 'build assigned') -gt {assigned} ]",
            timeout=60,
        )
        # ~64KB/s of log: the reload lands well before the 1MB limit,
        # so only the re-adopted build can exceed it.
        worker.succeed("systemctl reload tribuchet-worker")
        hub.wait_until_succeeds(
            "journalctl -u slowlogbuild | grep -q 'exceeded the limit'", timeout=120
        )

    with subtest("worker reload mid-build re-adopts the running build"):
        assigned = int(worker.succeed(
            "journalctl -u tribuchet-worker | grep -c 'build assigned' || true"
        ).strip())
        # baseline: the earlier dual-restart subtest also adopts a build
        adopted = int(worker.succeed(
            "journalctl -u tribuchet-worker | grep -c 'adopted running build' || true"
        ).strip())
        hub.succeed(
            "rm -f /tmp/reload.ok && systemd-run --unit=reloadbuild bash -lc "
            "'nix-build /etc/tt/reload.nix --no-out-link > /tmp/reload.out "
            "&& touch /tmp/reload.ok'"
        )
        worker.wait_until_succeeds(
            f"[ $(journalctl -u tribuchet-worker | grep -c 'build assigned') -gt {assigned} ]",
            timeout=60,
        )
        # Settings changes also arrive via reload: the new worker
        # generation re-reads the config file.
        worker.succeed(
            "cp --remove-destination $(readlink -f /etc/tribuchet/worker.toml) /etc/tribuchet/worker.toml"
            " && sed -i 's/max-jobs = 2/max-jobs = 3/' /etc/tribuchet/worker.toml"
        )
        # Reload mid-build: the reaper execs a new worker generation;
        # the builder process keeps running and the new worker adopts
        # it, delivering the result when it finishes.
        worker.succeed("systemctl reload tribuchet-worker")
        hub.wait_until_succeeds("test -f /tmp/reload.ok", timeout=120)
        out = hub.succeed("cat /tmp/reload.out").strip()
        hub.succeed(f"grep -q reload-survived {out}")
        worker.succeed(
            f"[ $(journalctl -u tribuchet-worker | grep -c 'adopted running build') -gt {adopted} ]"
        )
        # the marker is only printed after the reload, so seeing it in
        # the client's build log means the adopted build streamed live
        # logs through the new worker generation
        hub.succeed("journalctl -u reloadbuild | grep -q log-after-reload")
        # the new generation logs its configuration: the max-jobs bump
        # made it through the reload
        worker.succeed("journalctl -u tribuchet-worker | grep -q 'max_jobs: 3'")

    with subtest("killing the client cancels the build on the worker"):
        hub.succeed(
            "systemd-run --unit=cancelbuild bash -lc "
            "'nix-build /etc/tt/cancel.nix --no-out-link'"
        )
        # bracket trick: do not match the pgrep wrapper's own cmdline
        worker.wait_until_succeeds("pgrep -f 'cancel-marker-runnin[g]'", timeout=60)
        hub.succeed("systemctl kill --signal=SIGKILL cancelbuild")
        # the hub notices the lost attach client and tells the worker;
        # the builder process must disappear without a worker restart
        worker.wait_until_succeeds("! pgrep -f 'cancel-marker-runnin[g]'", timeout=60)
        hub.succeed("journalctl -u tribuchet-hub | grep -q 'cancelling build'")

    with subtest("the cancelled derivation builds fine when asked again"):
        # Same dedupe key as the build cancelled above: a stale cancel
        # flag would kill it on its first supervision tick.
        out = hub.succeed("nix-build /etc/tt/cancel.nix --no-out-link", timeout=120).strip()
        hub.succeed(f"grep -q cancel-done {out}")

    with subtest("concurrent builds share one worker session"):
        import time
        t0 = time.time()
        hub.succeed("nix-build /etc/tt/par.nix --no-out-link --max-jobs 2")
        elapsed = time.time() - t0
        assert elapsed < 27, f"builds did not overlap: {elapsed:.0f}s (serial would be >=30s)"

    with subtest("uid-range build runs as sandbox root with a cgroup"):
        out = hub.succeed("nix-build /etc/tt/uidrange.nix --no-out-link").strip()
        hub.succeed(f"grep -q uid-range-ok {out}")

    with subtest("kvm feature: scheduled and device passed through, or rejected"):
        if worker.execute("test -e /dev/kvm")[0] == 0:
            out = hub.succeed("nix-build /etc/tt/kvm.nix --no-out-link").strip()
            hub.succeed(f"grep -q kvm-ok {out}")
        else:
            err = hub.fail("nix-build /etc/tt/kvm.nix --no-out-link 2>&1")
            assert "no connected worker" in err, err

    with subtest("emulated system does not inherit the host's kvm feature"):
        err = hub.fail("nix-build /etc/tt/kvm-emulated.nix --no-out-link 2>&1")
        assert "no connected worker" in err, err

    with subtest("runaway build log is killed at max-log-size"):
        err = hub.fail("nix-build /etc/tt/logbomb.nix --no-out-link 2>&1")
        assert "exceeded the limit" in err, err

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
        # inputs are imported through the worker's nix-daemon and
        # registered as valid paths in its Nix database
        worker.succeed(f"nix-store --check-validity {unique}")
  '';
}
