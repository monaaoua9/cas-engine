use crate::hash::Hash;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("object {0} not found")]
    NotFound(Hash),

    #[error("chunk {0} is referenced but missing from the store")]
    MissingChunk(Hash),

    #[error("chunk {0} failed its integrity check")]
    Corrupt(Hash),

    #[error("manifest {0} failed its integrity check")]
    CorruptManifest(Hash),

    #[error("segment {0} is damaged in the middle, refusing to truncate")]
    CorruptSegment(u32),

    #[error("malformed manifest: {0}")]
    BadManifest(&'static str),

    #[error("store is locked by another process")]
    Locked,

    #[error("invalid hash: {0}")]
    InvalidHash(String),

    #[error("invalid config: {0}")]
    InvalidConfig(&'static str),

    #[error("chunk index out of range")]
    OutOfRange,
}

pub type Result<T> = std::result::Result<T, Error>;
