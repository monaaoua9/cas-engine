use crate::hash::Hash;

// Distinct prefixes for leaves and inner nodes so a 64-byte leaf payload can
// never be passed off as a pair of child hashes (second-preimage on the tree).
const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;
const EMPTY_TAG: u8 = 0x02;

fn finish(h: blake3::Hasher) -> Hash {
    Hash::from_bytes(*h.finalize().as_bytes())
}

pub fn leaf_hash(chunk: &Hash, len: u32) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[LEAF_TAG]);
    h.update(&len.to_le_bytes());
    h.update(chunk.as_bytes());
    finish(h)
}

fn node_hash(l: &Hash, r: &Hash) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[NODE_TAG]);
    h.update(l.as_bytes());
    h.update(r.as_bytes());
    finish(h)
}

pub fn empty_root() -> Hash {
    Hash::of(&[EMPTY_TAG])
}

/// Binary Merkle tree. An odd node at the end of a level is promoted as-is
/// instead of being paired with a copy of itself, which avoids the classic
/// duplicate-leaf collision (two different leaf lists, same root).
pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    pub fn from_leaves(leaves: Vec<Hash>) -> MerkleTree {
        if leaves.is_empty() {
            return MerkleTree { levels: vec![] };
        }
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let next = levels
                .last()
                .unwrap()
                .chunks(2)
                .map(|p| match p {
                    [l, r] => node_hash(l, r),
                    [l] => *l,
                    _ => unreachable!(),
                })
                .collect();
            levels.push(next);
        }
        MerkleTree { levels }
    }

    pub fn root(&self) -> Hash {
        self.levels.last().map(|l| l[0]).unwrap_or_else(empty_root)
    }

    pub fn leaf_count(&self) -> usize {
        self.levels.first().map_or(0, Vec::len)
    }

    pub fn proof(&self, index: usize) -> Option<Proof> {
        if index >= self.leaf_count() {
            return None;
        }
        let mut siblings = Vec::new();
        let mut i = index;
        for level in &self.levels[..self.levels.len() - 1] {
            if i % 2 == 1 {
                siblings.push(level[i - 1]);
            } else if i + 1 < level.len() {
                siblings.push(level[i + 1]);
            }
            i /= 2;
        }
        Some(Proof { index, leaf_count: self.leaf_count(), siblings })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub index: usize,
    pub leaf_count: usize,
    pub siblings: Vec<Hash>,
}

impl Proof {
    pub fn verify(&self, leaf: Hash, root: &Hash) -> bool {
        if self.index >= self.leaf_count {
            return false;
        }
        let mut cur = leaf;
        let mut i = self.index;
        let mut width = self.leaf_count;
        let mut sibs = self.siblings.iter();

        // replay the same shape the builder walked; position is bound by
        // (index, leaf_count), not by anything the prover can choose
        while width > 1 {
            if i % 2 == 1 {
                let Some(s) = sibs.next() else { return false };
                cur = node_hash(s, &cur);
            } else if i + 1 < width {
                let Some(s) = sibs.next() else { return false };
                cur = node_hash(&cur, s);
            }
            i /= 2;
            width = width.div_ceil(2);
        }
        sibs.next().is_none() && cur == *root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n).map(|i| leaf_hash(&Hash::of(&i.to_le_bytes()), 10)).collect()
    }

    #[test]
    fn every_leaf_proves_for_every_size() {
        for n in 1..=40 {
            let ls = leaves(n);
            let t = MerkleTree::from_leaves(ls.clone());
            let root = t.root();
            for (i, l) in ls.iter().enumerate() {
                let p = t.proof(i).unwrap();
                assert!(p.verify(*l, &root), "n={n} i={i}");
            }
        }
    }

    #[test]
    fn wrong_leaf_or_position_fails() {
        let ls = leaves(9);
        let t = MerkleTree::from_leaves(ls.clone());
        let root = t.root();

        let p = t.proof(3).unwrap();
        assert!(!p.verify(ls[4], &root));

        let mut moved = p.clone();
        moved.index = 2;
        assert!(!moved.verify(ls[3], &root));

        let mut longer = p.clone();
        longer.siblings.push(Hash::of(b"x"));
        assert!(!longer.verify(ls[3], &root));
    }

    #[test]
    fn odd_promotion_does_not_collide() {
        let a = MerkleTree::from_leaves(leaves(3)).root();
        let mut dup = leaves(3);
        dup.push(*dup.last().unwrap());
        let b = MerkleTree::from_leaves(dup).root();
        assert_ne!(a, b);
    }

    #[test]
    fn empty_and_single() {
        assert_eq!(MerkleTree::from_leaves(vec![]).root(), empty_root());
        assert!(MerkleTree::from_leaves(vec![]).proof(0).is_none());
        let l = leaves(1);
        assert_eq!(MerkleTree::from_leaves(l.clone()).root(), l[0]);
    }
}
