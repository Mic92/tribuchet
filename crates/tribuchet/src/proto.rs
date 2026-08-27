//! Generated gRPC types for the tribuchet protocol.
#![allow(
    clippy::pedantic,
    clippy::large_enum_variant,
    reason = "tonic-generated code"
)]

tonic::include_proto!("tribuchet.v1");

/// gRPC message size cap. Metadata messages (BuildRequest, BuildAssignment)
/// carry the whole input closure; tonic's 4 MiB default rejects large
/// but legitimate closures.
pub const MAX_MSG_SIZE: usize = 64 * 1024 * 1024;

/// Exit code the shim returns when the hub declines a build (no capable
/// worker); a patched Nix treats it as "build locally instead".
pub const DECLINE_EXIT_CODE: i32 = 222;

/// Cap on a single NAR transfer in either direction, enforced by both
/// hub and worker; a `truncate -s 1P $out` build would otherwise tie
/// up the peer and fill its disk.
pub const MAX_NAR_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// Cap on input re-request rounds per build, enforced by both ends;
/// the missing set shrinks each round, so a hub that cannot deliver
/// fails the build instead of looping.
pub const MAX_RESEND_ROUNDS: u32 = 3;

impl TmpDirArchive {
    pub fn chunk(build_id: &str, zstd_chunk: Vec<u8>) -> Self {
        Self {
            build_id: build_id.into(),
            zstd_chunk,
            eof: false,
        }
    }

    pub fn eof(build_id: &str) -> Self {
        Self {
            build_id: build_id.into(),
            zstd_chunk: Vec::new(),
            eof: true,
        }
    }
}
