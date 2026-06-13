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
          }
          // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
            # default network backend for fixed-output builds
            TRIBUCHET_PASTA = "${pkgs.passt}/bin/pasta";
          }
        );
      });

      darwinModules.worker = import ./nix/darwin-module.nix self;
      darwinModules.default = self.darwinModules.worker;

      checks.x86_64-linux.nixos-test = nixpkgs.legacyPackages.x86_64-linux.testers.runNixOSTest (
        import ./nix/test.nix { tribuchet = self.packages.x86_64-linux.default; }
      );

      # Evaluation-only check of the darwin module (the launchd plist
      # and activation script); building a darwin system needs a mac.
      checks.x86_64-linux.darwin-worker-module =
        let
          eval = nix-darwin.lib.darwinSystem {
            modules = [
              self.darwinModules.worker
              {
                nixpkgs.hostPlatform = "aarch64-darwin";
                system.stateVersion = 6;
                services.tribuchet-worker = {
                  enable = true;
                  hub = "https://hub.example.org:7437";
                };
              }
            ];
          };
        in
        nixpkgs.legacyPackages.x86_64-linux.writeText "tribuchet-darwin-worker-module" (
          builtins.toJSON {
            daemon = eval.config.launchd.daemons.tribuchet-worker.serviceConfig;
            activation = eval.config.system.activationScripts.postActivation.text;
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
