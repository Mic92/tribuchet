use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
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

/// Prefix "step /path" onto an io::Error, preserving its ErrorKind;
/// std's fs errors carry no path.
pub fn io_ctx(step: &'static str, path: &Path) -> impl FnOnce(io::Error) -> io::Error {
    move |e| io::Error::new(e.kind(), format!("{step} {}: {e}", path.display()))
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

/// `remove_dir_all` that chmods read-only directories first.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub fn force_remove_dir_all(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {}
        r => return r,
    }
    let mut stack = vec![path.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.is_dir() {
            let _ = fs::set_permissions(&p, fs::Permissions::from_mode(meta.mode() | 0o700));
            if let Ok(rd) = fs::read_dir(&p) {
                stack.extend(rd.flatten().map(|e| e.path()));
            }
        }
    }
    fs::remove_dir_all(path)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn force_remove_read_only_tree() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("ro/inner");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("f"), b"x").unwrap();
        fs::set_permissions(t.path().join("ro/inner"), fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(t.path().join("ro"), fs::Permissions::from_mode(0o555)).unwrap();
        force_remove_dir_all(&t.path().join("ro")).unwrap();
        assert!(!t.path().join("ro").exists());
    }
}
