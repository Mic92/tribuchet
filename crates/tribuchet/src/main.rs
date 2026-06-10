mod attach;
mod build_json;
mod ca;
mod hub;
mod proto;
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
        #[arg(long, default_value = "/run/tribuchet/hub.sock")]
        socket: PathBuf,
        /// gRPC listen address for workers.
        #[arg(long, default_value = "0.0.0.0:7437")]
        listen: String,
        #[arg(long, default_value = "/etc/tribuchet")]
        config_dir: PathBuf,
    },
    /// Build worker; dials the hub and executes sandboxed builds.
    Worker {
        /// Hub gRPC address, e.g. https://hub.example.org:7437
        #[arg(long)]
        hub: String,
        #[arg(long, default_value = "/var/lib/tribuchet")]
        state_dir: PathBuf,
    },
    /// Certificate authority management (init CA, issue worker certs).
    Ca {
        #[command(subcommand)]
        action: ca::CaAction,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Attach { build_json, socket } => attach::run(&build_json, &socket),
        Command::Hub {
            socket,
            listen,
            config_dir,
        } => hub::run(&socket, &listen, &config_dir),
        Command::Worker { hub, state_dir } => worker::run(&hub, &state_dir),
        Command::Ca { action } => ca::run(action),
    }
}
