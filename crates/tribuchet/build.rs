fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::compile_protos("proto/tribuchet.proto")?;
    // Baked-in default for --pasta (set by the Nix package).
    println!("cargo:rerun-if-env-changed=TRIBUCHET_PASTA");
    if let Ok(p) = std::env::var("TRIBUCHET_PASTA") {
        println!("cargo:rustc-env=TRIBUCHET_PASTA={p}");
    }
    Ok(())
}
