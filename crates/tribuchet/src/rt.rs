//! Shared tokio runtime construction and thread naming, so a profile or
//! `top -H` can tell which role (and which kind of work) a thread runs.

#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::io;
#[cfg(test)]
use std::panic::{AssertUnwindSafe, catch_unwind};

#[cfg(target_os = "linux")]
use rustix::thread::set_name;
#[cfg(test)]
use tokio::runtime::Handle;

/// A multi-threaded runtime whose worker and blocking-pool threads carry
/// `name`. Mirrors the defaults of `Runtime::new` otherwise.
pub fn runtime(name: &'static str) -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name(name)
        .build()
}

/// Rename the calling OS thread (Linux caps the name at 15 bytes), to tag
/// blocking-pool threads that the runtime otherwise names uniformly.
pub fn name_current_thread(name: &str) {
    #[cfg(target_os = "linux")]
    if let Ok(c) = CString::new(name) {
        let _ = set_name(&c);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = name;
}

/// Whether the calling thread is in a runtime's async context: one of
/// its workers, or a thread inside `block_on`. Blocking it stalls the
/// tasks that thread polls. Tokio refuses to `block_on` there, and
/// only there: not on the blocking pool, nor inside `block_in_place`.
#[cfg(test)]
pub(crate) fn drives_tasks() -> bool {
    Handle::try_current()
        .is_ok_and(|rt| catch_unwind(AssertUnwindSafe(|| rt.block_on(async {}))).is_err())
}

#[cfg(test)]
mod tests {
    use tokio::task::block_in_place;

    use super::*;

    #[test]
    fn drives_tasks_only_on_an_async_worker() {
        assert!(!drives_tasks(), "a plain thread");
        let rt = runtime("trib-test").unwrap();
        let on =
            |f: fn() -> bool| rt.block_on(async move { tokio::spawn(async move { f() }).await });
        assert!(on(drives_tasks).unwrap(), "an async task");
        assert!(
            !on(|| block_in_place(drives_tasks)).unwrap(),
            "in block_in_place"
        );
        let pool = rt.block_on(rt.spawn_blocking(drives_tasks)).unwrap();
        assert!(!pool, "the blocking pool");
    }
}
