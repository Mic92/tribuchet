{
  description = "tribuchet - RBE-style remote build execution for Nix";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  # only used to evaluate the darwin module in checks
  inputs.nix-darwin = {
    url = "github:nix-darwin/nix-darwin";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      nix-darwin,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        # Nix patched to let external builders implement recursive-nix:
        # the rejection in external-derivation-builder.cc is dropped,
        # and a result.json sidecar populates addedPaths so the output
        # reference scan sees inner-built paths. Off-tree because the
        # change is not upstream; opt in via
        # services.tribuchet-hub.externalBuilders.recursiveNix.
        nix-recursive = pkgs.nixVersions.latest.appendPatches [
          ./nix/patches/recursive-nix-external-builders.patch
        ];

        default = pkgs.rustPlatform.buildRustPackage (
          {
            pname = "tribuchet";
            version = "0.1.0";
            src = self;
            cargoLock = {
              lockFile = ./Cargo.lock;
              # harmonia crates come from one pinned git rev; builtin
              # fetchGit avoids enumerating an outputHash per crate
              allowBuiltinFetchGit = true;
            };
            nativeBuildInputs = [ pkgs.protobuf ];
            PROTOC = "${pkgs.protobuf}/bin/protoc";
            # sandbox_runs_builder needs CAP_SYS_ADMIN that the outer
            # Nix builder sandbox does not grant; `nix develop -c
            # cargo test` runs it.
            checkFlags = [
              "--skip=worker::sandbox::tests::sandbox_runs_builder"
            ];
          }
          // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
            # default network backend for fixed-output builds
            TRIBUCHET_PASTA = "${pkgs.passt}/bin/pasta";
          }
        );
      });

      darwinModules.default = import ./nix/darwin-module.nix self;

      nixosModules.default = import ./nix/nixos-module.nix self;

      # CI builds every package and devShell on every system, plus the
      # x86_64-linux-only checks below.
      checks = forAllSystems (
        pkgs:
        let
          inherit (pkgs.stdenv.hostPlatform) system;
          prefix = p: nixpkgs.lib.mapAttrs' (n: nixpkgs.lib.nameValuePair "${p}-${n}");
        in
        prefix "package" self.packages.${system}
        // prefix "devshell" self.devShells.${system}
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          nixos-test = pkgs.testers.runNixOSTest (
            import ./nix/test.nix {
              tribuchet = self.packages.x86_64-linux.default;
              nixosModule = self.nixosModules.default;
            }
          );

          # Evaluation-only check of the darwin module (the launchd plist
          # and activation script); building a darwin system needs a mac.
          darwin-module =
            let
              eval = nix-darwin.lib.darwinSystem {
                modules = [
                  self.darwinModules.default
                  {
                    nixpkgs.hostPlatform = "aarch64-darwin";
                    system.stateVersion = 6;
                    services.tribuchet-hub.enable = true;
                    services.tribuchet-worker = {
                      enable = true;
                      settings.hub = "https://hub.example.org:7437";
                    };
                  }
                ];
              };
            in
            pkgs.writeText "tribuchet-darwin-module" (
              # plists reference the aarch64-darwin package; drop the
              # context so the check stays eval-only on Linux
              builtins.unsafeDiscardStringContext (
                builtins.toJSON {
                  hub = eval.config.launchd.daemons.tribuchet-hub.serviceConfig;
                  worker = eval.config.launchd.daemons.tribuchet-worker.serviceConfig;
                  activation = eval.config.system.activationScripts.postActivation.text;
                }
              )
            );
        }
      );

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer
            protobuf
          ];
          PROTOC = "${pkgs.protobuf}/bin/protoc";
        };
      });
    };
}
