mod attach;
mod build_json;
mod ca;
mod chunker;
mod chunkio;
mod chunkstore;
mod config;
mod errors;
mod fsutil;
mod hub;
mod nar;
mod netpolicy;
mod proto;
mod rt;
mod sd;
mod sockpath;
mod store;
mod tailscale;
mod tmpdir;
mod worker;

#[cfg(target_os = "linux")]
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

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
    /// Per-uid build agent, one per pool user.
    Agent {
        /// Unix socket to bind when not socket-activated.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Inherited listening socket (worker-spawned agents).
        #[arg(long)]
        listen_fd: Option<i32>,
        /// Directory for per-build scratch dirs.
        #[arg(long)]
        state_dir: PathBuf,
        /// Uid allowed to lease builds (the worker user).
        #[arg(long)]
        worker_uid: Option<u32>,
        /// First uid of the agent's 65536-uid block (Linux).
        #[arg(long)]
        uid_base: Option<u32>,
        /// The agent owns its uid even without socket activation.
        #[arg(long)]
        dedicated_uid: bool,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tribuchet: {}", errors::chain(&e));
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), errors::Error> {
    // Builds re-exec this binary as the sandbox setup stage; divert
    // before clap and tracing touch anything.
    #[cfg(target_os = "linux")]
    if env::args().nth(1).as_deref() == Some(worker::sandbox::SETUP_STAGE_ARG) {
        worker::sandbox::setup_stage();
    }
    // Same for the build agent's userns filesystem helper.
    #[cfg(target_os = "linux")]
    if env::args().nth(1).as_deref() == Some(worker::agent::FS_HELPER_ARG) {
        worker::agent::fs_helper_stage();
    }
    // And for the agent's userns holder child.
    #[cfg(target_os = "linux")]
    if env::args().nth(1).as_deref() == Some(worker::USERNS_HOLD_ARG) {
        worker::userns_hold_stage();
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
        Command::Ca { action } => Ok(ca::run(action)?),
        Command::Agent {
            socket,
            listen_fd,
            state_dir,
            worker_uid,
            uid_base,
            dedicated_uid,
        } => Ok(worker::agent::run(&worker::agent::Options {
            socket,
            listen_fd,
            state_dir,
            worker_uid,
            uid_base,
            dedicated_uid,
        })?),
    }
}
