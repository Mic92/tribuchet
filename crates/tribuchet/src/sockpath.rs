//! Unix socket bind/connect that tolerate paths beyond the sun_path
//! limit by chdir'ing into the parent and using the bare filename,
//! like Nix does. The process-global chdir is guarded by a lock.

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Mutex;

static CWD_LOCK: Mutex<()> = Mutex::new(());

pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    match UnixListener::bind(path) {
        Err(e) if too_long(&e) => in_parent_dir(path, |p| UnixListener::bind(p)),
        res => res,
    }
}

pub fn connect(path: &Path) -> std::io::Result<UnixStream> {
    match UnixStream::connect(path) {
        Err(e) if too_long(&e) => in_parent_dir(path, |p| UnixStream::connect(p)),
        res => res,
    }
}

fn too_long(e: &std::io::Error) -> bool {
    // Rust reports an over-long path as InvalidInput before the syscall.
    e.kind() == std::io::ErrorKind::InvalidInput || e.raw_os_error() == Some(libc::ENAMETOOLONG)
}

fn in_parent_dir<T>(
    path: &Path,
    f: impl FnOnce(&Path) -> std::io::Result<T>,
) -> std::io::Result<T> {
    let err = || std::io::Error::new(std::io::ErrorKind::InvalidInput, "socket path unusable");
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let (Some(parent), Some(name)) = (parent, path.file_name()) else {
        return Err(err());
    };
    let _guard = CWD_LOCK.lock().unwrap();
    let old = std::env::current_dir()?;
    std::env::set_current_dir(parent)?;
    let res = f(Path::new(name));
    let _ = std::env::set_current_dir(old);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_socket_paths_bind_and_connect() {
        let dir = tempfile::tempdir().unwrap();
        let deep = dir.path().join("a".repeat(60)).join("b".repeat(60));
        std::fs::create_dir_all(&deep).unwrap();
        let sock = deep.join("agent.sock");
        assert!(sock.as_os_str().len() > 104);
        let listener = bind(&sock).unwrap();
        let client = std::thread::spawn(move || connect(&sock).unwrap());
        listener.accept().unwrap();
        client.join().unwrap();
    }
}
