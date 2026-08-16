//! `tribuchet ca`: minimal certificate authority for hub/worker mTLS.
//!
//! `init` creates a CA key and self-signed root; `issue` signs a leaf
//! certificate whose SAN is the given name (use the hub's public
//! hostname for the hub certificate so rustls hostname verification
//! works on workers).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use clap::Subcommand;

use crate::fsutil;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Rcgen(#[from] rcgen::Error),
    #[error(transparent)]
    Secret(#[from] fsutil::Error),
    #[error("reading {0}")]
    Read(&'static str, #[source] io::Error),
    #[error("invalid certificate name {0:?}")]
    InvalidName(String),
    #[error("{0} already exists; refusing to overwrite key material")]
    Exists(PathBuf),
}

#[derive(Subcommand)]
pub enum CaAction {
    /// Create a new CA key and root certificate.
    Init {
        #[arg(long, default_value = "/etc/tribuchet/ca")]
        dir: PathBuf,
    },
    /// Issue a certificate for a worker or the hub (name = SAN/hostname).
    Issue {
        name: String,
        #[arg(long, default_value = "/etc/tribuchet/ca")]
        dir: PathBuf,
    },
}

fn write_private(path: &Path, data: &str) -> Result<(), Error> {
    Ok(fsutil::write_secret(path, data.as_bytes())?)
}

/// Issued names become file names and certificate SANs; restrict them
/// to a single hostname-like component so `../x` cannot escape the CA
/// dir and `ca` cannot clobber the root key.
fn validate_name(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name == "ca"
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        || name.starts_with('.')
    {
        return Err(Error::InvalidName(name.to_owned()));
    }
    Ok(())
}

fn refuse_overwrite(path: &Path) -> Result<(), Error> {
    if path.exists() {
        return Err(Error::Exists(path.to_path_buf()));
    }
    Ok(())
}

fn validity(params: &mut CertificateParams, days: i64) {
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(days);
}

pub fn run(action: CaAction) -> Result<(), Error> {
    match action {
        CaAction::Init { dir } => {
            fs::create_dir_all(&dir)?;
            refuse_overwrite(&dir.join("ca.key"))?;
            refuse_overwrite(&dir.join("ca.crt"))?;
            let key = KeyPair::generate()?;
            let mut params = CertificateParams::new(vec!["tribuchet-ca".into()])?;
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            validity(&mut params, 10 * 365);
            let cert = params.self_signed(&key)?;
            write_private(&dir.join("ca.key"), &key.serialize_pem())?;
            fs::write(dir.join("ca.crt"), cert.pem())?;
            println!("CA created in {}", dir.display());
            Ok(())
        }
        CaAction::Issue { name, dir } => {
            validate_name(&name)?;
            refuse_overwrite(&dir.join(format!("{name}.key")))?;
            refuse_overwrite(&dir.join(format!("{name}.crt")))?;
            let ca_key = KeyPair::from_pem(
                &fs::read_to_string(dir.join("ca.key")).map_err(|e| Error::Read("ca.key", e))?,
            )?;
            let ca_pem =
                fs::read_to_string(dir.join("ca.crt")).map_err(|e| Error::Read("ca.crt", e))?;
            let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key)?;

            let key = KeyPair::generate()?;
            let mut params = CertificateParams::new(vec![name.clone()])?;
            validity(&mut params, 2 * 365);
            let cert = params.signed_by(&key, &issuer)?;

            write_private(&dir.join(format!("{name}.key")), &key.serialize_pem())?;
            fs::write(dir.join(format!("{name}.crt")), cert.pem())?;
            println!("issued {name}.crt / {name}.key in {}", dir.display());
            Ok(())
        }
    }
}
