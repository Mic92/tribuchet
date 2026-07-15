mod attach;
mod build_json;
mod ca;
mod chunkio;
mod config;
mod fsutil;
mod hub;
mod nar;
mod netpolicy;
mod proto;
mod rt;
mod sd;
mod store;
mod tailscale;
mod worker;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// RBE-style remote build execution for Nix, driven by the
/// `external-builders` experimental feature.
#[derive(Parser)]
#[command(name = "tribuchet", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// External-builders shim invoked by Nix; forwards the build to the hub.
    Attach {
        /// Path to the build.json written by Nix.
        build_json: PathBuf,
        /// Hub unix socket.
        #[arg(long, default_value = "/run/tribuchet/hub.sock")]
        socket: PathBuf,
    },
    /// Scheduler and NAR relay; runs next to nix-daemon.
    Hub {
        /// TOML configuration file.
        #[arg(long, default_value = "/etc/tribuchet/hub.toml")]
        config: PathBuf,
    },
    /// Build worker; dials the hub and executes sandboxed builds.
    Worker {
        /// TOML configuration file; re-read on every reload.
        #[arg(long, default_value = "/etc/tribuchet/worker.toml")]
        config: PathBuf,
    },
    /// Certificate authority management (init CA, issue worker certs).
    Ca {
        #[command(subcommand)]
        action: ca::CaAction,
    },
}

fn main() -> anyhow::Result<()> {
    // Builds re-exec this binary as the sandbox setup stage; divert
    // before clap and tracing touch anything.
    #[cfg(target_os = "linux")]
    match std::env::args().nth(1).as_deref() {
        Some(worker::sandbox::SETUP_STAGE_ARG) => worker::sandbox::setup_stage(),
        Some(worker::sandbox::CLEANUP_STAGE_ARG) => worker::sandbox::cleanup_stage(),
        _ => {}
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Attach { build_json, socket } => attach::run(&build_json, &socket),
        Command::Hub { config } => {
            let cfg: config::HubConfig = config::load(&config)?;
            hub::run(cfg)
        }
        Command::Worker { config } => {
            let mut cfg: config::WorkerConfig = config::load(&config)?;
            cfg.apply_env_overrides();
            tracing::info!(?cfg, "worker configuration");
            worker::run(cfg)
        }
        Command::Ca { action } => ca::run(action),
    }
}
