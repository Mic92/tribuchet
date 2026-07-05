fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/tribuchet.proto");
    tonic_prost_build::compile_protos("proto/tribuchet.proto")?;
    // Baked-in default for --pasta (set by the Nix package).
    println!("cargo:rerun-if-env-changed=TRIBUCHET_PASTA");
    if let Ok(p) = std::env::var("TRIBUCHET_PASTA") {
        println!("cargo:rustc-env=TRIBUCHET_PASTA={p}");
    }
    // Baked-in default for --sandbox-bin-sh (set by the Nix package).
    println!("cargo:rerun-if-env-changed=TRIBUCHET_BIN_SH");
    if let Ok(p) = std::env::var("TRIBUCHET_BIN_SH") {
        println!("cargo:rustc-env=TRIBUCHET_BIN_SH={p}");
    }
    Ok(())
}
