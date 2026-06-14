//! Generated gRPC types for the tribuchet protocol.
#![expect(clippy::pedantic, reason = "tonic-generated code")]

tonic::include_proto!("tribuchet.v1");

/// gRPC message size cap. Metadata messages (BuildRequest, PathOffer)
/// carry the whole input closure; tonic's 4 MiB default rejects large
/// but legitimate closures.
pub const MAX_MSG_SIZE: usize = 64 * 1024 * 1024;
