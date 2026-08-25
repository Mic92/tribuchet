//! Store queries through the host nix CLI.

use std::error::Error;
use std::process::{Command, Stdio};

fn path_info(args: &[&str]) -> Result<serde_json::Map<String, serde_json::Value>, Box<dyn Error>> {
    let out = Command::new("nix")
        .args([
            "--extra-experimental-features",
            "nix-command",
            "path-info",
            "--json",
        ])
        .args(args)
        .env("NIX_REMOTE", "daemon")
        .output()?;
    if !out.status.success() {
        return Err(format!("nix path-info {args:?}: {}", out.status).into());
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    Ok(v.as_object()
        .cloned()
        .ok_or("unexpected path-info output")?)
}

/// The closure's paths and total nar size.
pub fn query_closure(path: &str) -> Result<(Vec<String>, u64), Box<dyn Error>> {
    let m = path_info(&["-r", path])?;
    let paths = m.keys().cloned().collect();
    let nar_bytes = m.values().filter_map(|p| p["narSize"].as_u64()).sum();
    Ok((paths, nar_bytes))
}

/// Summed nar size of exactly these paths.
pub fn nar_size(paths: &[String]) -> Result<u64, Box<dyn Error>> {
    let args: Vec<&str> = paths.iter().map(String::as_str).collect();
    Ok(path_info(&args)?
        .values()
        .filter_map(|p| p["narSize"].as_u64())
        .sum())
}

pub fn build_path(installable: &str) -> Result<String, Box<dyn Error>> {
    let out = Command::new("nix")
        .args(["build", "--no-link", "--print-out-paths", installable])
        .env("NIX_REMOTE", "daemon")
        .stderr(Stdio::inherit())
        .output()?;
    if !out.status.success() {
        return Err(format!("nix build {installable}: {}", out.status).into());
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}
