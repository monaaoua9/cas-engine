//! Content-addressed, immutable object store.
//!
//! Data is split into content-defined chunks (Rabin fingerprint), each chunk
//! is keyed by its BLAKE3 hash, and an object is named by the Merkle root of
//! its chunk list. See the README for the on-disk layout.

pub mod backup;
pub mod bench;
pub mod chunker;
pub mod client;
pub mod crypto;
mod cursor;
pub mod dav;
pub mod error;
pub mod format;
pub mod hash;
pub mod http;
pub mod index;
pub mod json;
pub mod manifest;
pub mod merkle;
pub mod metrics;
pub mod repair;
pub mod segment;
pub mod server;
pub mod snapshot;
pub mod store;
pub mod sync;
pub mod timefmt;
pub mod transform;
pub mod tree;
pub mod units;
pub mod wire;

pub use chunker::{Algorithm, Chunker, ChunkerConfig};
pub use crypto::{Kdf, Password};
pub use error::{Error, Result};
pub use hash::Hash;
pub use manifest::{ChunkRef, Manifest};
pub use merkle::{MerkleTree, Proof};
pub use snapshot::{Retention, Snapshot};
pub use store::{ObjectReader, Store, StoreConfig};
pub use transform::Compression;
pub use tree::{Entry, Kind, Tree};
