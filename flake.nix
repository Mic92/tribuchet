{
  description = "tribuchet - RBE-style remote build execution for Nix";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.crane.url = "github:ipetkov/crane";
  inputs.treefmt-nix = {
    url = "github:numtide/treefmt-nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  # only used to evaluate the darwin module in checks
  inputs.nix-darwin = {
    url = "github:nix-darwin/nix-darwin";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      crane,
      nix-darwin,
      treefmt-nix,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      treefmtFor = pkgs: treefmt-nix.lib.evalModule pkgs ./nix/treefmt.nix;
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

        default = pkgs.callPackage ./nix/package.nix {
          craneLib = crane.mkLib pkgs;
        };
      });

      formatter = forAllSystems (pkgs: (treefmtFor pkgs).config.build.wrapper);

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
        // {
          treefmt = (treefmtFor pkgs).config.build.check self;

          # nixbot pushes this closure, so downstream CI fetches the
          # input sources from cache.thalheim.io instead of GitHub.
          flake-inputs = pkgs.linkFarm "flake-inputs" (
            nixpkgs.lib.mapAttrsToList (name: i: {
              inherit name;
              path = i.outPath;
            }) (builtins.removeAttrs inputs [ "self" ])
          );
        }
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          nixos-test = pkgs.testers.runNixOSTest (
            import ./nix/test.nix {
              tribuchet = self.packages.x86_64-linux.default;
              nixosModule = self.nixosModules.default;
            }
          );

          nixos-test-tailscale = pkgs.testers.runNixOSTest (
            import ./nix/test-tailscale.nix {
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
            (treefmtFor pkgs).config.build.wrapper
          ];
          PROTOC = "${pkgs.protobuf}/bin/protoc";
        };
      });
    };
}
