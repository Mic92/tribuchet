{
  lib,
  stdenv,
  craneLib,
  protobuf,
  passt,
  busybox-sandbox-shell,
}:
let
  # repository root is one level up from this file
  root = ./..;
  src = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.unions [
      (root + "/Cargo.toml")
      (root + "/Cargo.lock")
      (root + "/crates")
    ];
  };

  commonArgs = {
    pname = "tribuchet";
    version = "0.1.0";
    inherit src;
    strictDeps = true;
    nativeBuildInputs = [ protobuf ];
    PROTOC = "${protobuf}/bin/protoc";
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
in
craneLib.buildPackage (
  commonArgs
  // {
    inherit cargoArtifacts;
    # sandbox_runs_builder needs CAP_SYS_ADMIN that the outer
    # Nix builder sandbox does not grant; `nix develop -c
    # cargo test` runs it.
    cargoTestExtraArgs = "-- --skip=worker::sandbox::tests::sandbox_runs_builder";
    passthru = { inherit cargoArtifacts; };
  }
  // lib.optionalAttrs stdenv.isLinux {
    # default network backend for fixed-output builds
    TRIBUCHET_PASTA = "${passt}/bin/pasta";
    # static /bin/sh for the sandbox, as Nix uses for its sandbox-shell
    TRIBUCHET_BIN_SH = "${busybox-sandbox-shell}/bin/busybox";
  }
)
