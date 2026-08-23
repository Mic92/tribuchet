//! Same-machine staging benchmark: real hub and worker separated by a
//! veth pair with injected latency and rate limits (netem), a real
//! closure staged from the host store into a private chroot store.
//!
//! Runs unprivileged by re-execing itself under `unshare -r -m -n`.
//! The build fails at the agent lease, which cleanly marks the end of
//! staging; the attach wall time is the measurement.

use std::process::ExitCode;

#[cfg(target_os = "linux")]
mod bench;
#[cfg(target_os = "linux")]
mod ns;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    bench::main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("netbench only runs on Linux");
    ExitCode::FAILURE
}
