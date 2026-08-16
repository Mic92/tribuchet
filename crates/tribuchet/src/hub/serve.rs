//! Hub bootstrap: sockets, TLS, auth configuration and server startup.

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs as unix_fs;
#[cfg(target_os = "macos")]
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use harmonia_utils_signature::PublicKey;
use nix::unistd::Group;
use rustix::fs::Mode;
use rustix::process::umask;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use super::metrics;
use super::state::HubState;
use super::submit::AttachSvc;
use super::{PeerAuth, WorkerSvc};
use crate::config::{Auth, HubConfig};
use crate::errors::{Result, chain, err_ctx, err_msg};
use crate::fsutil::io_ctx;
use crate::proto::worker_hub_server::WorkerHubServer;
use crate::proto::{MAX_MSG_SIZE, attach_hub_server};
use crate::{chunkio, rt, sd};

/// Bind the attach socket ourselves (no socket activation).
///
/// attach runs as a nix build user: restrict the socket to that group
/// (anyone who can reach it can have store paths packed and shipped).
/// Resolve the group *before* binding and bind with a tight umask so
/// the socket is never connectable by others, not even briefly.
fn bind_attach_socket(socket: &Path) -> Result<tokio::net::UnixListener> {
    if let Some(parent) = socket.parent() {
        fs::create_dir_all(parent).map_err(io_ctx("creating", parent))?;
    }
    // Refuse to replace the socket of a live hub: unlinking it would
    // leave all new attaches with ECONNREFUSED while the old hub runs.
    if UnixStream::connect(socket).is_ok() {
        return Err(err_msg(format!(
            "another hub is already serving {}",
            socket.display()
        )));
    }
    let _ = fs::remove_file(socket);
    let Ok(Some(group)) = Group::from_name("nixbld") else {
        return Err(err_msg(
            "group nixbld not found; refusing to serve a hub socket without a group to restrict it to",
        ));
    };
    let old_umask = umask(Mode::from_bits_truncate(0o117));
    let uds = tokio::net::UnixListener::bind(socket);
    umask(old_umask);
    let uds = uds?;
    {
        unix_fs::chown(socket, None, Some(group.gid.as_raw()))
            .map_err(io_ctx("chowning", socket))?;
        fs::set_permissions(socket, fs::Permissions::from_mode(0o660))
            .map_err(io_ctx("setting permissions on", socket))?;
    }
    Ok(uds)
}

/// Verify that a launchd-bound attach socket sits in a directory only
/// the nixbld group can reach. launchd's `Sockets` dictionary has a
/// mode key but no group key and the rootless hub cannot chown the
/// root-owned socket, so the parent directory carries the restriction
/// bind_attach_socket() puts on the socket itself.
#[cfg(target_os = "macos")]
fn check_attach_socket_dir(socket: &Path) -> Result<()> {
    let Some(group) = Group::from_name("nixbld").map_err(err_ctx("looking up group nixbld"))?
    else {
        return Err(err_msg(
            "group nixbld not found; refusing to serve a hub socket without a group to restrict it to",
        ));
    };
    let dir = socket
        .parent()
        .ok_or_else(|| err_msg("attach socket has no parent"))?;
    let meta = fs::metadata(dir).map_err(io_ctx("inspecting", dir))?;
    if meta.gid() != group.gid.as_raw() || meta.mode() & 0o007 != 0 {
        return Err(err_msg(format!(
            "{} must be group nixbld with no access for others to restrict the attach socket",
            dir.display()
        )));
    }
    Ok(())
}

/// Optional operator pinning of worker signing keys (one Nix-format
/// "name:base64" public key per line, '#' comments; same syntax as
/// nix.conf trusted-public-keys). Without it, output signatures only
/// authenticate the TLS channel, not a particular worker.
fn load_trusted_keys(config_dir: &Path) -> Result<Option<Arc<Vec<PublicKey>>>> {
    match fs::read_to_string(config_dir.join("trusted-signing-keys")) {
        Ok(data) => {
            let mut keys = Vec::new();
            for line in data.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                keys.push(line.parse::<PublicKey>().map_err(|e| {
                    err_msg(format!("bad key in trusted-signing-keys: {line}: {e}"))
                })?);
            }
            tracing::info!(count = keys.len(), "worker signing keys pinned");
            Ok(Some(Arc::new(keys)))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            tracing::warn!(
                "no trusted-signing-keys file in {}; accepting any signing key from \
                 transport-authenticated workers",
                config_dir.display()
            );
            Ok(None)
        }
        Err(e) => Err(err_ctx("reading trusted-signing-keys")(e)),
    }
}

fn configure_auth(
    cfg: &HubConfig,
    config_dir: &Path,
) -> Result<(Option<ServerTlsConfig>, PeerAuth)> {
    Ok(match cfg.auth {
        Auth::Mtls => {
            let ca_dir = config_dir.join("ca");
            let identity = Identity::from_pem(
                fs::read(ca_dir.join("hub.crt")).map_err(err_ctx("reading hub.crt"))?,
                fs::read(ca_dir.join("hub.key")).map_err(err_ctx("reading hub.key"))?,
            );
            let ca = Certificate::from_pem(
                fs::read(ca_dir.join("ca.crt")).map_err(err_ctx("reading ca.crt"))?,
            );
            (
                Some(ServerTlsConfig::new().identity(identity).client_ca_root(ca)),
                PeerAuth::Mtls,
            )
        }
        Auth::Tailscale => {
            tracing::info!(
                socket = %cfg.tailscale_socket.display(),
                allowed_tags = ?cfg.tailscale_allowed_tags,
                "tailscale auth: TLS disabled, identity via tailscaled whois"
            );
            (
                None,
                PeerAuth::Tailscale {
                    socket: cfg.tailscale_socket.clone(),
                    allowed_tags: cfg.tailscale_allowed_tags.clone(),
                },
            )
        }
    })
}

pub fn run(cfg: HubConfig) -> Result<()> {
    let rt = rt::runtime("trib-hub").map_err(err_ctx("creating the tokio runtime"))?;
    rt.block_on(run_async(cfg))
}

async fn run_async(cfg: HubConfig) -> Result<()> {
    let socket = cfg.socket.as_path();
    let listen = cfg.listen.as_str();
    let config_dir = cfg.config_dir.as_path();
    let state = Arc::new(HubState::new(
        Duration::from_secs(cfg.worker_grace_secs),
        cfg.nix_config.clone(),
    ));

    let (tls, peer_auth) = configure_auth(&cfg, config_dir)?;
    let trusted_keys = load_trusted_keys(config_dir)?;

    // Listeners come from systemd socket activation when available
    // (they survive hub restarts; clients queue instead of getting
    // ECONNREFUSED), otherwise we bind ourselves.
    let activated = sd::activated_sockets()?;
    let tcp = match activated.tcp {
        Some(l) => tokio::net::TcpListener::from_std(l)
            .map_err(err_ctx("adopting activated TCP socket"))?,
        // Bind TCP eagerly: a second hub instance must fail here on
        // EADDRINUSE *before* it clobbers the live hub's unix socket
        // below.
        None => tokio::net::TcpListener::bind(
            listen
                .parse::<SocketAddr>()
                .map_err(err_ctx("parsing listen address"))?,
        )
        .await
        .map_err(err_ctx("binding worker listen address"))?,
    };
    let mut builder = Server::builder();
    if let Some(tls) = tls {
        builder = builder.tls_config(tls)?;
    }
    let worker_server = builder
        // Detect dead/half-open worker connections instead of relying on
        // the workers' own traffic.
        .http2_keepalive_interval(Some(Duration::from_secs(30)))
        .http2_keepalive_timeout(Some(Duration::from_secs(20)))
        .initial_stream_window_size(Some(chunkio::H2_STREAM_WINDOW))
        .initial_connection_window_size(Some(chunkio::H2_CONNECTION_WINDOW))
        .add_service(
            WorkerHubServer::new(WorkerSvc {
                state: state.clone(),
                auth: Arc::new(peer_auth),
                trusted_keys,
            })
            .max_decoding_message_size(MAX_MSG_SIZE)
            .max_encoding_message_size(MAX_MSG_SIZE),
        )
        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(tcp));

    let uds = match activated.unix {
        // Activated socket: systemd owns the path, mode and group
        // (SocketGroup=/SocketMode= in the .socket unit). launchd has
        // no group key, so on macOS the socket's directory carries the
        // group restriction.
        Some(l) => {
            #[cfg(target_os = "macos")]
            check_attach_socket_dir(socket)?;
            tokio::net::UnixListener::from_std(l)
                .map_err(err_ctx("adopting activated unix socket"))?
        }
        None => bind_attach_socket(socket)?,
    };
    let attach_server = Server::builder()
        .initial_stream_window_size(Some(chunkio::H2_STREAM_WINDOW))
        .initial_connection_window_size(Some(chunkio::H2_CONNECTION_WINDOW))
        .add_service(
            attach_hub_server::AttachHubServer::new(AttachSvc {
                state: state.clone(),
            })
            .max_decoding_message_size(MAX_MSG_SIZE)
            .max_encoding_message_size(MAX_MSG_SIZE),
        )
        .serve_with_incoming(UnixListenerStream::new(uds));

    if let Some(metrics_addr) = cfg.metrics_listen.clone() {
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = metrics::serve(state, metrics_addr).await {
                let e = chain(&e);
                tracing::error!("metrics endpoint stopped: {e}");
            }
        });
    }

    tracing::info!(listen, socket = %socket.display(), "hub running");
    sd::notify_ready();
    sd::spawn_watchdog();
    let servers = async {
        tokio::try_join!(
            async { worker_server.await.map_err(err_ctx("worker gRPC server")) },
            async { attach_server.await.map_err(err_ctx("attach gRPC server")) },
        )
    };
    // No drain on SIGTERM: hub state is reconstructed by the
    // replacement instance from worker re-registration (resumable
    // build keys) and attach resubmission (deterministic dedupe
    // keys), so exiting immediately cancels nothing.
    tokio::select! {
        res = servers => res.map(|_| ()),
        () = sd::stop_requested() => {
            tracing::info!("SIGTERM: exiting, builds resume against the replacement instance");
            Ok(())
        }
    }
}
