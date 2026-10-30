//! Copying objects and snapshots between stores. Both ends are a `Peer`: a
//! local `Store`, or a `Client` talking to a remote one. Chunks travel as
//! stored (codec byte and payload), so compressed data stays compressed and an
//! encrypted store never shows plaintext to the wire; the receiver decodes and
//! re-hashes every chunk before keeping it.

use std::collections::HashSet;

use crate::error::{Error, Result};
use crate::hash::Hash;
use crate::store::Store;

pub trait Peer {
    /// The subset of `ids` this side does not have.
    fn missing_chunks(&mut self, ids: &[Hash]) -> Result<Vec<Hash>>;
    fn has_object(&mut self, id: &Hash) -> Result<bool>;
    fn get_chunk(&mut self, id: &Hash) -> Result<(u8, Vec<u8>)>;
    fn put_chunk(&mut self, id: &Hash, codec: u8, payload: Vec<u8>) -> Result<()>;
    fn get_manifest(&mut self, id: &Hash) -> Result<Vec<u8>>;
    fn put_manifest(&mut self, id: &Hash, raw: Vec<u8>) -> Result<()>;
    /// Distinct chunk ids an object is made of. Whoever holds the keys has to answer this.
    fn manifest_chunks(&mut self, id: &Hash) -> Result<Vec<Hash>>;
    fn list_objects(&mut self) -> Result<Vec<Hash>>;
    fn list_snapshots(&mut self) -> Result<Vec<String>>;
    fn get_snapshot(&mut self, name: &str) -> Result<Vec<u8>>;
    /// True if it was new here, false if an identical snapshot was already present.
    fn put_snapshot(&mut self, name: &str, raw: Vec<u8>) -> Result<bool>;
    fn snapshot_members(&mut self, name: &str) -> Result<Vec<Hash>>;
}

impl Peer for Store {
    fn missing_chunks(&mut self, ids: &[Hash]) -> Result<Vec<Hash>> {
        Ok(ids.iter().filter(|h| !self.has_chunk(h)).copied().collect())
    }

    fn has_object(&mut self, id: &Hash) -> Result<bool> {
        Ok(self.contains(id))
    }

    fn get_chunk(&mut self, id: &Hash) -> Result<(u8, Vec<u8>)> {
        self.read_chunk_raw(id)
    }

    fn put_chunk(&mut self, id: &Hash, codec: u8, payload: Vec<u8>) -> Result<()> {
        self.write_chunk_raw(id, codec, payload, false).map(drop)
    }

    fn get_manifest(&mut self, id: &Hash) -> Result<Vec<u8>> {
        self.manifest_bytes(id)
    }

    fn put_manifest(&mut self, id: &Hash, raw: Vec<u8>) -> Result<()> {
        self.put_manifest_bytes(id, raw).map(drop)
    }

    fn manifest_chunks(&mut self, id: &Hash) -> Result<Vec<Hash>> {
        self.manifest_chunk_ids(id)
    }

    fn list_objects(&mut self) -> Result<Vec<Hash>> {
        self.list()
    }

    fn list_snapshots(&mut self) -> Result<Vec<String>> {
        Ok(self.snapshot_list()?.into_iter().map(|s| s.name).collect())
    }

    fn get_snapshot(&mut self, name: &str) -> Result<Vec<u8>> {
        self.snapshot_bytes(name)
    }

    fn put_snapshot(&mut self, name: &str, raw: Vec<u8>) -> Result<bool> {
        self.put_snapshot_bytes(name, raw)
    }

    fn snapshot_members(&mut self, name: &str) -> Result<Vec<Hash>> {
        Store::snapshot_members(self, name)
    }
}

impl Store {
    /// Distinct chunk ids of an object, in the order they first appear.
    pub fn manifest_chunk_ids(&self, id: &Hash) -> Result<Vec<Hash>> {
        let mut seen = HashSet::new();
        Ok(self.manifest(id)?.chunks.iter().map(|c| c.hash).filter(|h| seen.insert(*h)).collect())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub objects_sent: u64,
    pub objects_skipped: u64,
    pub chunks_sent: u64,
    /// Payload bytes of the chunks that crossed, after compression and encryption.
    pub bytes_sent: u64,
    pub snapshots_sent: u64,
    pub snapshots_skipped: u64,
    /// Snapshots both sides have under the same name but with different contents; left alone.
    pub conflicts: Vec<String>,
}

/// Copies one object: its missing chunks first, then the manifest, so the receiver
/// never holds a manifest that points at something it doesn't have.
pub fn copy_object(src: &mut dyn Peer, dst: &mut dyn Peer, id: &Hash, rep: &mut SyncReport) -> Result<()> {
    if dst.has_object(id)? {
        rep.objects_skipped += 1;
        return Ok(());
    }
    let wanted = src.manifest_chunks(id)?;
    for h in dst.missing_chunks(&wanted)? {
        let (codec, payload) = src.get_chunk(&h)?;
        rep.bytes_sent += payload.len() as u64;
        rep.chunks_sent += 1;
        dst.put_chunk(&h, codec, payload)?;
    }
    let raw = src.get_manifest(id)?;
    dst.put_manifest(id, raw)?;
    rep.objects_sent += 1;
    Ok(())
}

pub fn copy_snapshot(src: &mut dyn Peer, dst: &mut dyn Peer, name: &str, rep: &mut SyncReport) -> Result<()> {
    let raw = src.get_snapshot(name)?;
    for id in src.snapshot_members(name)? {
        copy_object(src, dst, &id, rep)?;
    }
    match dst.put_snapshot(name, raw) {
        Ok(true) => rep.snapshots_sent += 1,
        Ok(false) => rep.snapshots_skipped += 1,
        Err(Error::SnapshotExists(_)) => rep.conflicts.push(name.to_string()),
        Err(e) => return Err(e),
    }
    Ok(())
}

/// Every snapshot, then every object that no snapshot covered.
pub fn copy_all(src: &mut dyn Peer, dst: &mut dyn Peer) -> Result<SyncReport> {
    let mut rep = SyncReport::default();
    for name in src.list_snapshots()? {
        copy_snapshot(src, dst, &name, &mut rep)?;
    }
    for id in src.list_objects()? {
        copy_object(src, dst, &id, &mut rep)?;
    }
    Ok(rep)
}
