# NixOS VM test for `auth = "tailscale"`: a headscale control plane
# brings hub and worker onto a tailnet, the hub runs without TLS and
# resolves the peer via tailscaled's LocalAPI whois, and a build goes
# through end to end. The worker registers under a tailscale hostname
# distinct from its machine hostname, so the test would fail if the
# hub used the self-reported name instead of the whois-asserted one.
{ tribuchet, nixosModule }:
{ pkgs, lib, ... }:
let
  stunPort = 3478;
  hsPort = 8080;
  tlsCert = pkgs.runCommand "headscale-cert" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
      -out cert.pem -keyout key.pem \
      -subj '/CN=hub' -addext 'subjectAltName=DNS:hub'
    mkdir $out && cp cert.pem key.pem $out
  '';
in
{
  name = "tribuchet-tailscale";
  defaults.documentation.enable = false;

  nodes = {
    hub =
      { pkgs, ... }:
      {
        imports = [ nixosModule ];

        # headscale + DERP colocated with the hub keeps the test at two VMs.
        services.headscale = {
          enable = true;
          port = hsPort;
          settings = {
            server_url = "https://hub";
            ip_prefixes = [ "100.64.0.0/10" ];
            derp = {
              server = {
                enabled = true;
                region_id = 999;
                stun_listen_addr = "0.0.0.0:${toString stunPort}";
              };
              urls = [ ];
            };
            dns = {
              base_domain = "tailnet";
              override_local_dns = false;
            };
          };
        };
        services.nginx = {
          enable = true;
          virtualHosts.hub = {
            addSSL = true;
            sslCertificate = "${tlsCert}/cert.pem";
            sslCertificateKey = "${tlsCert}/key.pem";
            locations."/" = {
              proxyPass = "http://127.0.0.1:${toString hsPort}";
              proxyWebsockets = true;
            };
          };
        };
        services.tailscale.enable = true;
        security.pki.certificateFiles = [ "${tlsCert}/cert.pem" ];
        networking.firewall = {
          allowedTCPPorts = [
            80
            443
            7437
          ];
          allowedUDPPorts = [ stunPort ];
        };

        virtualisation.memorySize = 2048;
        virtualisation.writableStore = true;
        virtualisation.additionalPaths = [ pkgs.bash ];
        nix.settings.substituters = lib.mkForce [ ];

        environment.systemPackages = [ pkgs.headscale ];

        services.tribuchet-hub = {
          enable = true;
          package = tribuchet;
          settings = {
            auth = "tailscale";
            worker-grace-secs = 2;
          };
          externalBuilders = {
            enable = true;
            systems = [ "x86_64-linux" ];
          };
        };
        # started by the test script once tailscale is up
        systemd.sockets.tribuchet-hub.wantedBy = lib.mkForce [ ];
        systemd.services.tribuchet-hub.wantedBy = lib.mkForce [ ];
      };

    worker =
      { pkgs, ... }:
      {
        imports = [ nixosModule ];

        services.tailscale.enable = true;
        security.pki.certificateFiles = [ "${tlsCert}/cert.pem" ];

        virtualisation.memorySize = 2048;
        virtualisation.useNixStoreImage = true;
        virtualisation.writableStore = true;

        services.tribuchet-worker = {
          enable = true;
          package = tribuchet;
          settings = {
            # placeholder; the test script substitutes the hub's
            # tailnet IP so the connection arrives from a tailnet
            # address (whois only knows those)
            hub = "http://HUB_TS_IP:7437";
            auth = "tailscale";
            max-jobs = 1;
          };
        };
        systemd.services.tribuchet-worker.wantedBy = lib.mkForce [ ];
      };
  };

  testScript = ''
    start_all()
    hub.wait_for_unit("headscale")
    hub.wait_for_open_port(443)
    hub.wait_for_unit("tailscaled")
    worker.wait_for_unit("tailscaled")

    hub.succeed("headscale users create test")
    authkey = hub.succeed("headscale preauthkeys -u 1 create --reusable").strip()

    hub.succeed(
        f"tailscale up --login-server https://hub --auth-key {authkey} --hostname hub"
    )
    # A distinct tailscale hostname proves the hub takes the
    # whois-derived name, not the worker's self-reported hostname().
    worker.succeed(
        f"tailscale up --login-server https://hub --auth-key {authkey} --hostname tt-worker"
    )
    worker.wait_until_succeeds("tailscale ping hub", timeout=60)

    hub_ts_ip = hub.succeed("tailscale ip -4").strip()
    worker.succeed(
        "cp --remove-destination "
        "$(readlink -f /etc/tribuchet/worker.toml) /etc/tribuchet/worker.toml"
        f" && sed -i 's/HUB_TS_IP/{hub_ts_ip}/' /etc/tribuchet/worker.toml"
    )

    hub.succeed("systemctl start tribuchet-hub.socket tribuchet-hub")
    worker.succeed("systemctl start tribuchet-worker")
    hub.wait_until_succeeds(
        "journalctl -u tribuchet-hub | grep -q 'worker registered worker=\"tt-worker\"'",
        timeout=60,
    )

    with subtest("a build dispatches over the tailnet"):
        hub.succeed("echo tailscale-auth-payload > /root/payload")
        unique = hub.succeed("nix-store --add /root/payload").strip()
        hub.succeed(
            "cat > /root/test.nix << 'EOF'\n"
            "let\n"
            '  bash = builtins.storePath "${pkgs.bash}";\n'
            f'  unique = builtins.storePath "{unique}";\n'
            "in derivation {\n"
            '  name = "tt-tailscale";\n'
            '  system = "x86_64-linux";\n'
            '  builder = bash + "/bin/bash";\n'
            '  args = [ "-c" ("read l < " + unique + "; echo \\"$l ok\\" > $out") ];\n'
            "}\n"
            "EOF"
        )
        out = hub.succeed("nix-build /root/test.nix --no-out-link").strip()
        hub.succeed(f"grep -q 'tailscale-auth-payload ok' {out}")
        hub.succeed("journalctl -u tribuchet-hub | grep -q 'dispatching build'")
        worker.succeed("journalctl -u tribuchet-worker | grep -q 'builder finished'")

    with subtest("a non-tailnet peer is rejected"):
        # Dial the hub over the plain VM network: whois has no entry
        # for that source address, so the session must be refused.
        worker.succeed(
            "sed -i 's|http://.*:7437|http://hub:7437|' /etc/tribuchet/worker.toml"
        )
        worker.succeed("systemctl restart tribuchet-worker")
        hub.wait_until_succeeds(
            "journalctl -u tribuchet-hub | grep -q 'tailscale whois failed'",
            timeout=30,
        )
  '';
}
