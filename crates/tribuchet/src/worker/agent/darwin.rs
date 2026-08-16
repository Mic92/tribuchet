//! macOS side of the agent: launchd socket activation, seatbelt
//! confinement and the libproc-based uid sweep.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::ptr;

use sandbox_proto::agent::{SCRATCH_DIR_PARAM, StartRequest};

use super::{Build, Error, Options, make_readable, spawn_plain, stage_scratch};
use crate::sd;

/// Per-agent confinement state. macOS confinement is per build (the
/// seatbelt profile arrives with the Start request), so nothing is
/// set up at agent startup.
pub(super) struct Confinement;

impl Confinement {
    pub(super) fn init(_opts: &Options) -> Result<Self, Error> {
        Ok(Self)
    }

    /// Nothing to exempt from the kill sweep.
    pub(super) fn exempt_pid(&self) -> Option<i32> {
        None
    }
}

/// The agent runs the builder as its own uid, so it unpacks the tmp
/// dir itself.
pub(super) fn stage_tmp_dir(
    _confinement: &Confinement,
    _scratch_root: &Path,
    build_dir: &Path,
    pack: OwnedFd,
) -> Result<(), Error> {
    stage_scratch(fs::File::from(pack), build_dir)
}

/// Exec the builder under the request's seatbelt profile. Outputs land
/// at their real store paths, so there is no private sandbox root.
pub(super) fn spawn_builder(
    _confinement: &Confinement,
    req: &StartRequest,
    _scratch_root: &Path,
    build_dir: &Path,
    log: &fs::File,
) -> Result<(Child, Option<PathBuf>), Error> {
    Ok((spawn_plain(req, build_dir, log)?, None))
}

/// Make outputs readable for the worker; they live at their real
/// store paths and are agent-owned.
pub(super) fn finish(_confinement: &Confinement, _root: Option<&Path>, outputs: &[String]) {
    for out in outputs {
        make_readable(Path::new(out));
    }
}

/// Remove a stale scratch tree before a new build. The agent's own
/// uid owns everything, so a plain removal suffices.
pub(super) fn clean_scratch(_confinement: &Confinement, scratch_root: &Path) -> Result<(), Error> {
    match fs::remove_dir_all(scratch_root) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

/// Remove the build's scratch tree and its store-path outputs; the
/// sticky store dir lets the owning agent delete them.
pub(super) fn cleanup(_confinement: &Confinement, build: &Build) {
    let _ = fs::remove_dir_all(&build.scratch_root);
    for out in &build.outputs {
        let _ = fs::remove_dir_all(out);
        let _ = fs::remove_file(out);
    }
}

/// Apply the request's seatbelt profile in the forked child right
/// before exec.
pub(super) fn confine(cmd: &mut Command, req: &StartRequest, build_dir: &str) -> Result<(), Error> {
    use std::os::unix::process::CommandExt;
    if req.profile.is_empty() {
        return Ok(());
    }
    let seatbelt = Seatbelt::new(&req.profile, &[(SCRATCH_DIR_PARAM, build_dir)])?;
    // SAFETY: sandbox_init_with_parameters is called with pointers
    // into memory owned by the moved-in Seatbelt; no allocation
    // happens after fork.
    unsafe {
        cmd.pre_exec(move || seatbelt.apply());
    }
    Ok(())
}

/// launchd-held listener (socket named "agent" in the plist), or None
/// when not launchd-activated.
pub(super) fn activated_unix_listener() -> Result<Option<UnixListener>, Error> {
    Ok(sd::launchd_unix_listener("agent")?)
}

pub(super) fn peer_uid(conn: &UnixStream) -> Result<u32, Error> {
    let (uid, _) = nix::unistd::getpeereid(conn).map_err(io::Error::from)?;
    Ok(uid.as_raw())
}

/// No per-build memory limit on macOS.
pub(super) fn oom_killed(_confinement: &Confinement, _build_id: &str) -> bool {
    false
}

/// Pids owned by this uid, via libproc's proc_listpids (macOS has no
/// /proc to enumerate).
pub(super) fn own_uid_pids() -> Vec<i32> {
    // From <libproc.h>; the libc crate binds proc_listpids but not the
    // filter constants.
    const PROC_UID_ONLY: u32 = 2;
    let uid = rustix::process::getuid().as_raw();
    // Sized generously instead of the size-probe round trip: the uid
    // runs one build plus the agent, and a truncated list only means
    // the next sweep iteration picks up the rest.
    let mut pids = vec![0i32; 4096];
    let bytes = unsafe {
        libc::proc_listpids(
            PROC_UID_ONLY,
            uid,
            pids.as_mut_ptr().cast(),
            (pids.len() * size_of::<i32>()) as libc::c_int,
        )
    };
    if bytes <= 0 {
        tracing::warn!("proc_listpids failed, kill sweep degraded to the process group");
        return Vec::new();
    }
    pids.truncate(bytes as usize / size_of::<i32>());
    pids.retain(|&pid| pid > 0);
    pids
}

/// Pre-allocated arguments for `sandbox_init_with_parameters`, so the
/// post-fork hook only makes the libc call.
struct Seatbelt {
    profile: CString,
    // key/value CStrings backing the pointer array
    _params: Vec<CString>,
    param_ptrs: Vec<*const libc::c_char>,
}

// The raw pointers point into the CStrings owned by the same struct.
unsafe impl Send for Seatbelt {}
unsafe impl Sync for Seatbelt {}

impl Seatbelt {
    fn new(profile: &str, params: &[(&str, &str)]) -> Result<Self, Error> {
        let profile = CString::new(profile)?;
        let mut owned = Vec::new();
        for (k, v) in params {
            owned.push(CString::new(*k)?);
            owned.push(CString::new(*v)?);
        }
        let mut param_ptrs: Vec<*const libc::c_char> = owned.iter().map(|c| c.as_ptr()).collect();
        param_ptrs.push(ptr::null());
        Ok(Self {
            profile,
            _params: owned,
            param_ptrs,
        })
    }

    fn apply(&self) -> io::Result<()> {
        unsafe extern "C" {
            fn sandbox_init_with_parameters(
                profile: *const libc::c_char,
                flags: u64,
                parameters: *const *const libc::c_char,
                errorbuf: *mut *mut libc::c_char,
            ) -> libc::c_int;
            fn sandbox_free_error(errorbuf: *mut libc::c_char);
        }
        let mut err: *mut libc::c_char = ptr::null_mut();
        let rc = unsafe {
            sandbox_init_with_parameters(
                self.profile.as_ptr(),
                0,
                self.param_ptrs.as_ptr(),
                &raw mut err,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        // Post-fork: report the errno-style failure without touching
        // the (heap-allocated) error string beyond freeing it.
        if !err.is_null() {
            unsafe { sandbox_free_error(err) };
        }
        Err(io::Error::other("sandbox_init_with_parameters failed"))
    }
}
