//! Shared tokio runtime construction and thread naming, so a profile or
//! `top -H` can tell which role (and which kind of work) a thread runs.

use std::io;

/// A multi-threaded runtime whose worker and blocking-pool threads carry
/// `name`. Mirrors the defaults of `Runtime::new` otherwise.
pub fn runtime(name: &'static str) -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name(name)
        .build()
}

/// Rename the calling OS thread (Linux caps the name at 15 bytes). Used
/// to tag blocking-pool threads by the work they currently run, which the
/// runtime otherwise names uniformly.
pub fn name_current_thread(name: &str) {
    #[cfg(target_os = "linux")]
    if let Ok(c) = std::ffi::CString::new(name) {
        // SAFETY: `c` is a valid NUL-terminated string for the call's
        // duration and pthread_self() is always valid for this thread.
        unsafe {
            libc::pthread_setname_np(libc::pthread_self(), c.as_ptr());
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = name;
}
