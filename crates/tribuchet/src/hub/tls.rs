//! mTLS for the worker listener, with the trust roots read per
//! handshake rather than once at startup.
//!
//! A hub is usually configured from more than one root: our own CA for
//! hub-issued worker certificates, and a SPIRE trust bundle for
//! SVID-carrying ones. Both are files some other unit writes, and a
//! bundle is rewritten whenever the trust domain rotates. Reading them
//! at startup makes the hub's start order depend on those units and
//! makes rotation need a restart, so the deployment grows a unit that
//! waits for the files, splices them together and restarts the hub.
//!
//! Read them when a worker connects instead: the hub starts before
//! SPIRE has written anything, a rotated bundle takes effect on the
//! next connection, and the files stay separate.
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::SystemTime;

use tokio_stream::StreamExt as _;

use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use tokio_rustls::rustls::{
    self, DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig,
};

use crate::errors::{Result, err_ctx, err_msg};

/// What the roots were loaded from, so a reload is skipped while the
/// files are untouched. Mtime and length together: a rewrite that keeps
/// the length still moves the mtime, and a bundle written within the
/// mtime's resolution still changes its length when the roots differ.
type Stamp = Vec<Option<(SystemTime, u64)>>;

fn stamp(files: &[PathBuf]) -> Stamp {
    files
        .iter()
        .map(|f| {
            let m = fs::metadata(f).ok()?;
            Some((m.modified().ok()?, m.len()))
        })
        .collect()
}

fn load_roots(files: &[PathBuf]) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for f in files {
        let pem = fs::read(f).map_err(err_ctx(format!("reading trust file {}", f.display())))?;
        let certs = CertificateDer::pem_slice_iter(&pem)
            .collect::<StdResult<Vec<_>, _>>()
            .map_err(err_ctx(format!("parsing trust file {}", f.display())))?;
        if certs.is_empty() {
            return Err(err_msg(format!(
                "trust file {} has no certificate",
                f.display()
            )));
        }
        for c in certs {
            roots
                .add(c)
                .map_err(err_ctx(format!("adding a root from {}", f.display())))?;
        }
    }
    Ok(roots)
}

/// A `ClientCertVerifier` that rebuilds itself from the trust files
/// whenever they change.
#[derive(Debug)]
pub(super) struct ReloadingVerifier {
    files: Vec<PathBuf>,
    /// The verifier in use and the stamp it was built from. `None` when
    /// the files could not be read: every handshake then retries, so a
    /// hub that started before SPIRE wrote its bundle recovers on its
    /// own.
    current: Mutex<Option<(Stamp, Arc<dyn ClientCertVerifier>)>>,
}

impl ReloadingVerifier {
    pub(super) fn new(files: Vec<PathBuf>) -> Self {
        Self {
            files,
            current: Mutex::new(None),
        }
    }

    /// The verifier for this handshake. An unreadable or unparsable
    /// trust file fails the connection rather than falling back to the
    /// roots from before it changed: trusting a stale set is the one
    /// outcome worse than refusing the worker, which retries anyway.
    fn verifier(&self) -> StdResult<Arc<dyn ClientCertVerifier>, rustls::Error> {
        let now = stamp(&self.files);
        let mut cur = self.current.lock().unwrap();
        if let Some((seen, v)) = cur.as_ref()
            && *seen == now
        {
            return Ok(v.clone());
        }
        let roots = load_roots(&self.files)
            .map_err(|e| rustls::Error::General(format!("trust roots: {e}")))?;
        let built = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| rustls::Error::General(format!("client verifier: {e}")))?;
        *cur = Some((now, built.clone()));
        tracing::info!(files = ?self.files, "loaded trust roots");
        Ok(built)
    }
}

impl ClientCertVerifier for ReloadingVerifier {
    /// Empty: the hint names the CAs whose certificates the client may
    /// send, and ours send the one SVID or hub-issued chain they have.
    /// Returning the current set would mean holding a borrow of
    /// something that reloads underneath it.
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> StdResult<ClientCertVerified, rustls::Error> {
        self.verifier()?
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> StdResult<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        self.verifier()?.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> StdResult<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        self.verifier()?.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        // Before any handshake there is nothing loaded yet, and this
        // answers for the provider, not for the roots.
        tokio_rustls::rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The hub's own certificate and key. Unlike the trust roots these come
/// from clan vars, written before the unit starts.
fn identity(
    cert: &Path,
    key: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_pem = fs::read(cert).map_err(err_ctx("reading hub.crt"))?;
    let certs = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<StdResult<Vec<_>, _>>()
        .map_err(err_ctx("parsing hub.crt"))?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(err_ctx("reading hub.key"))?;
    Ok((certs, key))
}

pub(super) fn server_config(
    cert: &Path,
    key: &Path,
    trust_files: Vec<PathBuf>,
) -> Result<ServerConfig> {
    let (certs, key) = identity(cert, key)?;
    let mut cfg = ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(ReloadingVerifier::new(trust_files)))
        .with_single_cert(certs, key)
        .map_err(err_ctx("building the TLS server config"))?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(cfg)
}

/// What a connection proved about its peer: the certificate chain for
/// mTLS, the address for the tailscale mode that has no TLS at all.
/// Attached to the request the way tonic's own TLS does it, since we
/// accept the connections ourselves.
#[derive(Clone)]
pub(super) struct PeerInfo {
    pub(super) certs: Vec<CertificateDer<'static>>,
    pub(super) remote_addr: Option<SocketAddr>,
}

/// A worker connection, with TLS when the hub is configured for mTLS.
pub(super) enum Stream {
    Tls(Box<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>),
    Plain(tokio::net::TcpStream),
}

impl Stream {
    fn io(&mut self) -> Pin<&mut (dyn AsyncReadWrite + Send + Unpin)> {
        match self {
            Self::Tls(s) => Pin::new(&mut **s),
            Self::Plain(s) => Pin::new(s),
        }
    }
}

/// One name for the two stream types, so the delegation below is not
/// written twice.
trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite> AsyncReadWrite for T {}

impl tonic::transport::server::Connected for Stream {
    type ConnectInfo = PeerInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        match self {
            Self::Tls(s) => PeerInfo {
                certs: s
                    .get_ref()
                    .1
                    .peer_certificates()
                    .map(<[CertificateDer<'static>]>::to_vec)
                    .unwrap_or_default(),
                remote_addr: s.get_ref().0.peer_addr().ok(),
            },
            Self::Plain(s) => PeerInfo {
                certs: Vec::new(),
                remote_addr: s.peer_addr().ok(),
            },
        }
    }
}

impl tokio::io::AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.io().poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.io().poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io().poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io().poll_shutdown(cx)
    }
}

/// Accepted connections, one handshake per incoming TCP stream. A
/// handshake that fails is logged and dropped: a worker presenting a
/// certificate we do not trust must not take the listener down, and
/// with the roots read per handshake it may simply be early.
pub(super) fn incoming(
    tcp: tokio::net::TcpListener,
    config: Option<ServerConfig>,
) -> impl tokio_stream::Stream<Item = io::Result<Stream>> {
    let acceptor = config.map(|c| tokio_rustls::TlsAcceptor::from(Arc::new(c)));
    tokio_stream::wrappers::TcpListenerStream::new(tcp)
        .then(move |conn| {
            let acceptor = acceptor.clone();
            async move {
                let sock = match conn {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "accepting a worker connection");
                        return None;
                    }
                };
                let Some(acceptor) = acceptor else {
                    return Some(Ok(Stream::Plain(sock)));
                };
                match acceptor.accept(sock).await {
                    Ok(s) => Some(Ok(Stream::Tls(Box::new(s)))),
                    Err(e) => {
                        tracing::warn!(error = %e, "worker TLS handshake failed");
                        None
                    }
                }
            }
        })
        .filter_map(|c| c)
}

#[cfg(test)]
mod tests {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    use super::*;

    fn ca_pem(name: &str) -> String {
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn roots_come_from_every_file() {
        let dir = tempfile::tempdir().unwrap();
        let a = write(dir.path(), "a.pem", &ca_pem("one"));
        let b = write(dir.path(), "b.pem", &ca_pem("two"));
        assert_eq!(load_roots(&[a, b]).unwrap().len(), 2);
    }

    #[test]
    fn a_missing_file_is_an_error_now_and_fine_once_written() {
        // The hub may start before whatever writes the bundle: the
        // verifier must not cache the failure.
        let dir = tempfile::tempdir().unwrap();
        let late = dir.path().join("late.pem");
        let v = ReloadingVerifier::new(vec![late.clone()]);
        assert!(v.verifier().is_err());
        fs::write(&late, ca_pem("late")).unwrap();
        assert!(v.verifier().is_ok());
    }

    #[test]
    fn a_rewritten_file_is_picked_up() {
        let dir = tempfile::tempdir().unwrap();
        let first = ca_pem("first");
        let f = write(dir.path(), "roots.pem", &first);
        let v = ReloadingVerifier::new(vec![f.clone()]);
        v.verifier().unwrap();
        let before = v.current.lock().unwrap().as_ref().unwrap().0.clone();
        fs::write(&f, format!("{first}{}", ca_pem("second"))).unwrap();
        v.verifier().unwrap();
        let after = v.current.lock().unwrap().as_ref().unwrap().0.clone();
        assert_ne!(before, after, "the stamp did not change");
        assert_eq!(load_roots(&[f]).unwrap().len(), 2);
    }
}
