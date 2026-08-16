use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
#[error("{step} {path}")]
pub struct Error {
    step: &'static str,
    path: PathBuf,
    #[source]
    source: io::Error,
}

fn step(step: &'static str, path: &Path) -> impl Fn(io::Error) -> Error {
    let path = path.to_path_buf();
    move |source| Error {
        step,
        path: path.clone(),
        source,
    }
}

/// Write a secret file atomically with mode 0600: created via a temp
/// file so it is never world-readable (fs::write + chmod would race)
/// and a torn write cannot leave a short key behind.
pub fn write_secret(path: &Path, data: &[u8]) -> Result<(), Error> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(step("creating", &tmp))?;
    f.write_all(data).map_err(step("writing", &tmp))?;
    f.sync_all().map_err(step("syncing", &tmp))?;
    fs::rename(&tmp, path).map_err(step("renaming into", path))?;
    Ok(())
}

/// Remove whatever is at `path` without following a symlink at `path`.
pub fn remove_path_all(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => {
            let _ = fs::remove_dir_all(path);
        }
        Ok(_) => {
            let _ = fs::remove_file(path);
        }
        Err(_) => {}
    }
}
