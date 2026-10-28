use crate::error::{Error, Result};
use crate::hash::{HASH_LEN, Hash};
use crate::merkle::{self, MerkleTree};

const MAGIC: &[u8; 4] = b"CASM";
const VERSION: u8 = 1;
const HEADER: usize = 4 + 1 + 8 + 4;
const ENTRY: usize = HASH_LEN + 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkRef {
    pub hash: Hash,
    pub len: u32,
}

impl ChunkRef {
    pub fn leaf(&self) -> Hash {
        merkle::leaf_hash(&self.hash, self.len)
    }
}

/// Ordered recipe for one stored object. The object's id is the Merkle root
/// over its chunk refs, so the id alone pins down content, order and sizes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub size: u64,
    pub chunks: Vec<ChunkRef>,
}

impl Manifest {
    pub fn new(chunks: Vec<ChunkRef>) -> Manifest {
        let size = chunks.iter().map(|c| c.len as u64).sum();
        Manifest { size, chunks }
    }

    pub fn tree(&self) -> MerkleTree {
        MerkleTree::from_leaves(self.chunks.iter().map(ChunkRef::leaf).collect())
    }

    pub fn id(&self) -> Hash {
        self.tree().root()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + self.chunks.len() * ENTRY + HASH_LEN);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&(self.chunks.len() as u32).to_le_bytes());
        for c in &self.chunks {
            out.extend_from_slice(c.hash.as_bytes());
            out.extend_from_slice(&c.len.to_le_bytes());
        }
        let sum = Hash::of(&out);
        out.extend_from_slice(sum.as_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Manifest> {
        if buf.len() < HEADER + HASH_LEN {
            return Err(Error::BadManifest("too short"));
        }
        let (body, sum) = buf.split_at(buf.len() - HASH_LEN);
        if Hash::of(body).as_bytes() != sum {
            return Err(Error::BadManifest("checksum mismatch"));
        }
        if &body[..4] != MAGIC {
            return Err(Error::BadManifest("bad magic"));
        }
        if body[4] != VERSION {
            return Err(Error::BadManifest("unsupported version"));
        }

        let size = u64::from_le_bytes(body[5..13].try_into().unwrap());
        let count = u32::from_le_bytes(body[13..17].try_into().unwrap()) as usize;
        let rest = &body[HEADER..];
        if rest.len() != count * ENTRY {
            return Err(Error::BadManifest("entry count does not match length"));
        }

        let chunks: Vec<ChunkRef> = rest
            .chunks(ENTRY)
            .map(|e| ChunkRef {
                hash: Hash::from_bytes(e[..HASH_LEN].try_into().unwrap()),
                len: u32::from_le_bytes(e[HASH_LEN..].try_into().unwrap()),
            })
            .collect();

        let m = Manifest { size, chunks };
        if m.chunks.iter().map(|c| c.len as u64).sum::<u64>() != size {
            return Err(Error::BadManifest("size does not match chunk lengths"));
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        Manifest::new((0..5u32).map(|i| ChunkRef { hash: Hash::of(&i.to_le_bytes()), len: 100 + i }).collect())
    }

    #[test]
    fn roundtrip() {
        let m = sample();
        assert_eq!(Manifest::decode(&m.encode()).unwrap(), m);
    }

    #[test]
    fn any_flipped_byte_is_rejected() {
        let enc = sample().encode();
        for i in 0..enc.len() {
            let mut bad = enc.clone();
            bad[i] ^= 0x40;
            assert!(Manifest::decode(&bad).is_err(), "byte {i}");
        }
    }

    #[test]
    fn id_depends_on_order_and_length() {
        let m = sample();
        let mut swapped = m.clone();
        swapped.chunks.swap(0, 1);
        assert_ne!(m.id(), swapped.id());

        let mut resized = m.clone();
        resized.chunks[0].len += 1;
        assert_ne!(m.id(), resized.id());
    }
}
