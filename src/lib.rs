//! Content-addressed, immutable object store.
//!
//! Data is split into content-defined chunks (Rabin fingerprint), each chunk
//! is keyed by its BLAKE3 hash, and an object is named by the Merkle root of
//! its chunk list. See the README for the on-disk layout.

pub mod backup;
pub mod chunker;
mod cursor;
pub mod error;
pub mod hash;
pub mod index;
pub mod manifest;
pub mod merkle;
pub mod segment;
pub mod snapshot;
pub mod store;
pub mod tree;

pub use chunker::{Algorithm, Chunker, ChunkerConfig};
pub use error::{Error, Result};
pub use hash::Hash;
pub use manifest::{ChunkRef, Manifest};
pub use merkle::{MerkleTree, Proof};
pub use snapshot::{Retention, Snapshot};
pub use store::{ObjectReader, Store, StoreConfig};
pub use tree::{Entry, Kind, Tree};
