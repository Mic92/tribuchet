use std::{env, error};

fn main() -> Result<(), Box<dyn error::Error>> {
    println!("cargo:rerun-if-changed=proto/tribuchet.proto");
    // BTreeMap maps encode deterministically. The hub hashes the
    // encoded BuildRequest as its dedupe key.
    tonic_prost_build::configure()
        .btree_map(".")
        .compile_protos(&["proto/tribuchet.proto"], &["proto"])?;
    // Baked-in default for --sandbox-bin-sh (set by the Nix package).
    println!("cargo:rerun-if-env-changed=TRIBUCHET_BIN_SH");
    if let Ok(p) = env::var("TRIBUCHET_BIN_SH") {
        println!("cargo:rustc-env=TRIBUCHET_BIN_SH={p}");
    }
    Ok(())
}
