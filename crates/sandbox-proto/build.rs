use std::error;

fn main() -> Result<(), Box<dyn error::Error>> {
    println!("cargo:rerun-if-changed=proto/agent.proto");
    prost_build::Config::new()
        // StartRequest dwarfs the other Call variants (clippy
        // large_enum_variant).
        .boxed(".agent.Call.call.start")
        .compile_protos(&["proto/agent.proto"], &["proto"])?;
    Ok(())
}
