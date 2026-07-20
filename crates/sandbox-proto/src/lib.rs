//! Wire protocols between the tribuchet worker and its per-host
//! privilege helpers: tribuchet-sandboxd on Linux, the per-uid build
//! agents on macOS.
//!
//! The message types are plain serde structs with no OS calls, so both
//! platform modules compile and unit-test everywhere; only the daemons
//! that speak them are platform-gated.

pub mod framing;
pub mod linux;
