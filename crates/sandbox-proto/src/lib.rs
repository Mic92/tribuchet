//! Wire protocol between the tribuchet worker and the per-uid build
//! agents.
//!
//! The message types are plain serde structs with no OS calls; only
//! the daemon speaking them cares about the platform.

pub mod agent;
pub mod framing;
