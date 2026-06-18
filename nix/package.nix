{
  lib,
  rustPlatform,
  stdenv,
  protobuf,
  passt,
}:
let
  # repository root is one level up from this file
  root = ./..;
in
rustPlatform.buildRustPackage (
  {
    pname = "tribuchet";
    version = "0.1.0";
    src = lib.fileset.toSource {
      inherit root;
      fileset = lib.fileset.unions [
        (root + "/Cargo.toml")
        (root + "/Cargo.lock")
        (root + "/crates")
      ];
    };
    cargoLock = {
      lockFile = root + "/Cargo.lock";
      # harmonia crates come from one pinned git rev; builtin
      # fetchGit avoids enumerating an outputHash per crate
      allowBuiltinFetchGit = true;
    };
    nativeBuildInputs = [ protobuf ];
    PROTOC = "${protobuf}/bin/protoc";
    # sandbox_runs_builder needs CAP_SYS_ADMIN that the outer
    # Nix builder sandbox does not grant; `nix develop -c
    # cargo test` runs it.
    checkFlags = [
      "--skip=worker::sandbox::tests::sandbox_runs_builder"
    ];
  }
  // lib.optionalAttrs stdenv.isLinux {
    # default network backend for fixed-output builds
    TRIBUCHET_PASTA = "${passt}/bin/pasta";
  }
)
