//! Wire protocol between the tribuchet worker and the per-uid build
//! agents: protobuf messages (proto/agent.proto) framed over a unix
//! socket that also carries file descriptors.

pub mod agent;
pub mod framing;
