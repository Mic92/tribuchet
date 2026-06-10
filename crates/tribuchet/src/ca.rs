//! `tribuchet ca`: minimal certificate authority for hub/worker mTLS.
//!
//! `init` creates a CA key and self-signed root; `issue` signs a leaf
//! certificate whose SAN is the given name (use the hub's public
//! hostname for the hub certificate so rustls hostname verification
//! works on workers).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Subcommand;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

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

fn write_private(path: &Path, data: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, data)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn run(action: CaAction) -> Result<()> {
    match action {
        CaAction::Init { dir } => {
            fs::create_dir_all(&dir)?;
            let key = KeyPair::generate()?;
            let mut params = CertificateParams::new(vec!["tribuchet-ca".into()])?;
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let cert = params.self_signed(&key)?;
            write_private(&dir.join("ca.key"), &key.serialize_pem())?;
            fs::write(dir.join("ca.crt"), cert.pem())?;
            println!("CA created in {}", dir.display());
            Ok(())
        }
        CaAction::Issue { name, dir } => {
            let ca_key = KeyPair::from_pem(
                &fs::read_to_string(dir.join("ca.key")).context("reading ca.key")?,
            )?;
            let ca_pem = fs::read_to_string(dir.join("ca.crt")).context("reading ca.crt")?;
            let ca_params = CertificateParams::from_ca_cert_pem(&ca_pem)?;
            let ca_cert = ca_params.self_signed(&ca_key)?;

            let key = KeyPair::generate()?;
            let params = CertificateParams::new(vec![name.clone()])?;
            let cert = params.signed_by(&key, &ca_cert, &ca_key)?;

            write_private(&dir.join(format!("{name}.key")), &key.serialize_pem())?;
            fs::write(dir.join(format!("{name}.crt")), cert.pem())?;
            println!("issued {name}.crt / {name}.key in {}", dir.display());
            Ok(())
        }
    }
}
