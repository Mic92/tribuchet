mod attach;
mod build_json;
mod ca;
mod chunkio;
mod hub;
mod nar;
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
        /// Systems this worker builds for (default: host system).
        #[arg(long = "system")]
        systems: Vec<String>,
        #[arg(long, default_value = "/var/lib/tribuchet/tls/ca.crt")]
        ca_cert: PathBuf,
        #[arg(long, default_value = "/var/lib/tribuchet/tls/worker.crt")]
        cert: PathBuf,
        #[arg(long, default_value = "/var/lib/tribuchet/tls/worker.key")]
        key: PathBuf,
        /// Kill builds running longer than this many seconds.
        #[arg(long, default_value_t = 24 * 3600)]
        build_timeout_secs: u64,
        /// Static shell bound at /bin/sh inside the sandbox (Linux),
        /// e.g. a busybox sh; without it #!/bin/sh shebangs fail.
        #[arg(long)]
        sandbox_bin_sh: Option<PathBuf>,
        /// Byte budget for the input NAR cache; least-recently-used
        /// entries are evicted past it.
        #[arg(long, default_value_t = 100 * 1024 * 1024 * 1024)]
        cache_max_bytes: u64,
        /// memory.max for each build's cgroup (Linux; needs a delegated
        /// cgroup, e.g. systemd Delegate=yes). Unlimited when unset.
        #[arg(long)]
        build_memory_max_bytes: Option<u64>,
        /// Concurrent build slots.
        #[arg(long, default_value_t = 1)]
        max_jobs: u32,
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
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
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
        Command::Worker {
            hub,
            state_dir,
            mut systems,
            ca_cert,
            cert,
            key,
            build_timeout_secs,
            sandbox_bin_sh,
            cache_max_bytes,
            build_memory_max_bytes,
            max_jobs,
        } => {
            if systems.is_empty() {
                systems.push(worker::host_system());
            }
            worker::run(worker::WorkerOpts {
                hub,
                state_dir,
                systems,
                ca_cert,
                cert,
                key,
                build_timeout: std::time::Duration::from_secs(build_timeout_secs),
                sandbox_bin_sh,
                cache_max_bytes,
                build_memory_max: build_memory_max_bytes,
                max_jobs,
            })
        }
        Command::Ca { action } => ca::run(action),
    }
}
