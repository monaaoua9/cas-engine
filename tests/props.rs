use std::collections::HashMap;

use cas::chunker::Chunker;
use cas::manifest::{ChunkRef, Manifest};
use cas::merkle::{MerkleTree, leaf_hash};
use cas::{ChunkerConfig, Hash, Store, StoreConfig, segment};
use proptest::prelude::*;

fn small_chunks() -> ChunkerConfig {
    ChunkerConfig { min_size: 512, avg_size: 2048, max_size: 8192 }
}

fn store_cfg() -> StoreConfig {
    StoreConfig { chunker: small_chunks(), segment_size: 16 << 10, gc_threshold: 0.0 }
}

fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

// overlapping payloads so dedup and shared refcounts actually get exercised
fn pool() -> Vec<Vec<u8>> {
    let a = noise(30_000, 1);
    let mut b = a.clone();
    b.extend(noise(9_000, 2));
    let mut c = noise(2_000, 3);
    c.extend_from_slice(&a[10_000..25_000]);
    vec![a, b, c, vec![], noise(700, 4), noise(45_000, 5)]
}

#[derive(Debug, Clone)]
enum Op {
    Put(usize),
    Remove(usize),
    Gc,
    Reopen,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0..6usize).prop_map(Op::Put),
        3 => (0..6usize).prop_map(Op::Remove),
        2 => Just(Op::Gc),
        1 => Just(Op::Reopen),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(40))]

    // random put / remove / gc / reopen sequences against a plain HashMap
    #[test]
    fn store_matches_model(ops in prop::collection::vec(op(), 1..30)) {
        let dir = tempfile::tempdir().unwrap();
        let pool = pool();
        let mut store = Some(Store::open(dir.path(), store_cfg()).unwrap());
        let mut ids: Vec<Option<Hash>> = vec![None; pool.len()];
        let mut model: HashMap<Hash, usize> = HashMap::new();

        for o in ops {
            let s = store.as_mut().unwrap();
            match o {
                Op::Put(i) => {
                    let r = s.put_bytes(&pool[i]).unwrap();
                    prop_assert_eq!(r.existed, model.contains_key(&r.id));
                    ids[i] = Some(r.id);
                    model.insert(r.id, i);
                }
                Op::Remove(i) => {
                    if let Some(id) = ids[i] {
                        prop_assert_eq!(s.remove(&id).unwrap(), model.remove(&id).is_some());
                    }
                }
                Op::Gc => {
                    s.gc().unwrap();
                    prop_assert_eq!(s.stats().unwrap().dead_chunks, 0);
                }
                Op::Reopen => {
                    drop(store.take());
                    store = Some(Store::open(dir.path(), store_cfg()).unwrap());
                }
            }

            let s = store.as_ref().unwrap();
            let mut want: Vec<Hash> = model.keys().copied().collect();
            want.sort();
            prop_assert_eq!(s.list().unwrap(), want);
            for (id, &i) in &model {
                prop_assert_eq!(&s.read_to_vec(id).unwrap(), &pool[i]);
            }
        }

        let s = store.as_ref().unwrap();
        prop_assert!(s.scrub().unwrap().corrupt.is_empty());
        for id in model.keys() {
            s.verify(id).unwrap();
        }
    }

    #[test]
    fn chunker_reassembles_and_respects_bounds(data in prop::collection::vec(any::<u8>(), 0..120_000)) {
        let cfg = small_chunks();
        let chunks: Vec<_> = Chunker::new(&data[..], cfg).unwrap().map(|c| c.unwrap()).collect();

        let joined: Vec<u8> = chunks.iter().flat_map(|c| c.data.iter().copied()).collect();
        prop_assert_eq!(&joined, &data);
        if let Some((last, rest)) = chunks.split_last() {
            for c in rest {
                prop_assert!(c.data.len() > cfg.min_size && c.data.len() <= cfg.max_size);
            }
            prop_assert!(last.data.len() <= cfg.max_size);
        }
    }

    // reading the source in awkward pieces must not move any boundary
    #[test]
    fn chunking_ignores_read_sizes(data in prop::collection::vec(any::<u8>(), 0..60_000), step in 1usize..5000) {
        struct Trickle<'a>(&'a [u8], usize);
        impl std::io::Read for Trickle<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = buf.len().min(self.1).min(self.0.len());
                buf[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let whole: Vec<_> = Chunker::new(&data[..], small_chunks()).unwrap().map(|c| c.unwrap().data).collect();
        let dribbled: Vec<_> = Chunker::new(Trickle(&data, step), small_chunks()).unwrap().map(|c| c.unwrap().data).collect();
        prop_assert_eq!(whole, dribbled);
    }

    #[test]
    fn manifest_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        let _ = Manifest::decode(&bytes);
    }

    #[test]
    fn manifest_roundtrip(refs in prop::collection::vec((any::<[u8; 32]>(), 1u32..100_000), 0..60)) {
        let m = Manifest::new(refs.into_iter().map(|(h, len)| ChunkRef { hash: Hash::from_bytes(h), len }).collect());
        prop_assert_eq!(Manifest::decode(&m.encode()).unwrap(), m);
    }

    #[test]
    fn every_proof_verifies_and_tampering_fails(n in 1usize..300, pick in any::<prop::sample::Index>(), flip in any::<prop::sample::Index>()) {
        let leaves: Vec<Hash> = (0..n).map(|i| leaf_hash(&Hash::of(&i.to_le_bytes()), 1)).collect();
        let t = MerkleTree::from_leaves(leaves.clone());
        let root = t.root();
        let i = pick.index(n);

        let p = t.proof(i).unwrap();
        prop_assert!(p.verify(leaves[i], &root));

        if !p.siblings.is_empty() {
            let mut bad = p.clone();
            let k = flip.index(bad.siblings.len());
            let mut raw = *bad.siblings[k].as_bytes();
            raw[0] ^= 1;
            bad.siblings[k] = Hash::from_bytes(raw);
            prop_assert!(!bad.verify(leaves[i], &root));
        }
        if n > 1 {
            prop_assert!(!p.verify(leaves[(i + 1) % n], &root));
        }
    }

    #[test]
    fn segment_scan_survives_garbage(bytes in prop::collection::vec(any::<u8>(), 0..2000)) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("seg");
        std::fs::write(&p, &bytes).unwrap();
        let s = segment::scan(&p).unwrap();
        prop_assert!(s.valid_end <= s.file_len);
    }

    // cut a well-formed segment anywhere: what comes back is a clean prefix
    #[test]
    fn segment_scan_of_truncated_stream_is_a_prefix(
        payloads in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..200), 1..12),
        cut in any::<prop::sample::Index>(),
    ) {
        let mut stream = Vec::new();
        let mut ends = Vec::new();
        for p in &payloads {
            stream.extend(segment::encode_record(&Hash::of(p), p));
            ends.push(stream.len());
        }
        let cut_at = cut.index(stream.len() + 1);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg");
        std::fs::write(&path, &stream[..cut_at]).unwrap();

        let s = segment::scan(&path).unwrap();
        let whole = ends.iter().filter(|&&e| e <= cut_at).count();
        prop_assert_eq!(s.records.len(), whole);
        prop_assert_eq!(s.valid_end as usize, if whole == 0 { 0 } else { ends[whole - 1] });
        for (r, p) in s.records.iter().zip(&payloads) {
            prop_assert_eq!(r.hash, Hash::of(p));
        }
    }
}
