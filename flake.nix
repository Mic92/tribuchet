{
  description = "tribuchet - RBE-style remote build execution for Nix";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
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

      checks.x86_64-linux.nixos-test = nixpkgs.legacyPackages.x86_64-linux.testers.runNixOSTest (
        import ./nix/test.nix { tribuchet = self.packages.x86_64-linux.default; }
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
