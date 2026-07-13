{
  lib,
  stdenv,
  craneLib,
  protobuf,
  busybox-sandbox-shell,
  jq,
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
    # tribuchet-sandboxd is Linux-only (user namespaces, cgroups)
    cargoExtraArgs = lib.optionalString (!stdenv.isLinux) "--workspace --exclude tribuchet-sandboxd";
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;

  # Compile the feature-gated NixOS e2e harness (crates/tribuchet/tests/e2e.rs)
  # to a standalone test binary. The NixOS test invokes it on the driver host
  # to drive the VMs over the vsock ssh backdoor; libtest gives parallelism,
  # filtering and per-test timing.
  e2eTests = craneLib.mkCargoDerivation (
    commonArgs
    // {
      inherit cargoArtifacts;
      pnameSuffix = "-e2e";
      doInstallCargoArtifacts = false;
      nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ jq ];
      buildPhaseCargoCommand = ''
        cargoWithProfile test --no-run --features e2e --test e2e \
          --message-format=json > $TMPDIR/cargo.json
      '';
      installPhaseCommand = ''
        mkdir -p $out/bin
        bin=$(jq -r 'select(.reason=="compiler-artifact" and .target.name=="e2e" and .profile.test==true) | .executable // empty' $TMPDIR/cargo.json | tail -1)
        [ -n "$bin" ] || { echo "e2e test binary not found" >&2; exit 1; }
        cp "$bin" $out/bin/tribuchet-e2e
      '';
    }
  );
in
craneLib.buildPackage (
  commonArgs
  // {
    inherit cargoArtifacts;
    passthru = { inherit cargoArtifacts e2eTests; };
  }
  // lib.optionalAttrs stdenv.isDarwin {
    # nested sandbox-exec is not permitted inside the Nix build sandbox;
    # `nix develop -c cargo test` runs it
    cargoTestExtraArgs = "-- --skip=worker::sandbox::tests::sandbox_runs_builder";
  }
  // lib.optionalAttrs stdenv.isLinux {
    # default network backend for fixed-output builds
    # static /bin/sh for the sandbox, as Nix uses for its sandbox-shell
    TRIBUCHET_BIN_SH = "${busybox-sandbox-shell}/bin/busybox";
  }
)
