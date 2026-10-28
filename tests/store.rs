use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};

use cas::{ChunkerConfig, Error, Hash, Store, StoreConfig};

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

fn cfg() -> StoreConfig {
    StoreConfig {
        chunker: ChunkerConfig { min_size: 1 << 10, avg_size: 4 << 10, max_size: 16 << 10, ..ChunkerConfig::default() },
        segment_size: 64 << 10,
        gc_threshold: 0.3,
    }
}

#[test]
fn roundtrip_various_sizes() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), cfg()).unwrap();
    for (i, len) in [0usize, 1, 47, 1024, 5000, 100_000, 700_000].into_iter().enumerate() {
        let data = noise(len, i as u64 + 1);
        let r = s.put_bytes(&data).unwrap();
        assert_eq!(r.size, len as u64);
        assert_eq!(s.read_to_vec(&r.id).unwrap(), data, "len {len}");
        s.verify(&r.id).unwrap();
    }
}

#[test]
fn identical_objects_dedupe_completely() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), cfg()).unwrap();
    let data = noise(300_000, 5);

    let a = s.put_bytes(&data).unwrap();
    let b = s.put_bytes(&data).unwrap();
    assert_eq!(a.id, b.id);
    assert!(!a.existed && b.existed);
    assert_eq!(b.new_chunks, 0);
    assert_eq!(s.list().unwrap().len(), 1);
}

#[test]
fn similar_objects_share_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), cfg()).unwrap();
    let base = noise(400_000, 8);
    let mut edited = base.clone();
    edited[200_000..200_016].copy_from_slice(b"0123456789abcdef");

    s.put_bytes(&base).unwrap();
    let r = s.put_bytes(&edited).unwrap();
    assert!(r.new_chunks * 10 < r.chunks, "{} of {} chunks were new", r.new_chunks, r.chunks);
}

#[test]
fn shared_chunks_survive_removal_of_one_owner() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), cfg()).unwrap();
    let base = noise(300_000, 21);
    let mut other = base.clone();
    other.extend(noise(50_000, 22));

    let a = s.put_bytes(&base).unwrap().id;
    let b = s.put_bytes(&other).unwrap().id;

    assert!(s.remove(&a).unwrap());
    s.gc().unwrap();
    assert_eq!(s.read_to_vec(&b).unwrap(), other);
    s.verify(&b).unwrap();
}

#[test]
fn gc_reclaims_space_and_keeps_survivors() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), cfg()).unwrap();
    let keep = noise(200_000, 1);
    let drop_me = noise(600_000, 2);

    let k = s.put_bytes(&keep).unwrap().id;
    let d = s.put_bytes(&drop_me).unwrap().id;
    let before = s.stats().unwrap();

    assert!(s.remove(&d).unwrap());
    assert!(!s.remove(&d).unwrap());
    assert!(s.stats().unwrap().dead_chunks > 0);

    let rep = s.gc().unwrap();
    assert!(rep.segments_removed > 0 && rep.bytes_reclaimed > 0);

    let after = s.stats().unwrap();
    assert_eq!(after.dead_chunks, 0);
    assert!(after.segments < before.segments);
    assert_eq!(s.read_to_vec(&k).unwrap(), keep);
    assert!(matches!(s.read_to_vec(&d), Err(Error::NotFound(_))));
}

#[test]
fn reopen_keeps_everything() {
    let dir = tempfile::tempdir().unwrap();
    let data = noise(250_000, 3);
    let id = {
        let mut s = Store::open(dir.path(), cfg()).unwrap();
        s.put_bytes(&data).unwrap().id
    };
    let s = Store::open(dir.path(), cfg()).unwrap();
    assert_eq!(s.read_to_vec(&id).unwrap(), data);
}

#[test]
fn deleted_index_is_rebuilt_with_correct_refcounts() {
    let dir = tempfile::tempdir().unwrap();
    let a = noise(200_000, 11);
    let b = noise(150_000, 12);
    let (ia, ib) = {
        let mut s = Store::open(dir.path(), cfg()).unwrap();
        (s.put_bytes(&a).unwrap().id, s.put_bytes(&b).unwrap().id)
    };
    fs::remove_file(dir.path().join("index.bin")).unwrap();

    let mut s = Store::open(dir.path(), cfg()).unwrap();
    assert_eq!(s.read_to_vec(&ia).unwrap(), a);
    assert_eq!(s.read_to_vec(&ib).unwrap(), b);
    assert_eq!(s.stats().unwrap().dead_chunks, 0);

    // refcounts came back right, so gc after removing one must not hurt the other
    s.remove(&ia).unwrap();
    s.gc().unwrap();
    assert_eq!(s.read_to_vec(&ib).unwrap(), b);
}

#[test]
fn torn_tail_is_truncated_on_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let data = noise(120_000, 4);
    let id = {
        let mut s = Store::open(dir.path(), cfg()).unwrap();
        s.put_bytes(&data).unwrap().id
    };

    // half a record at the end of the newest segment, then lose the index
    let seg = fs::read_dir(dir.path().join("segments")).unwrap().map(|e| e.unwrap().path()).max().unwrap();
    OpenOptions::new().append(true).open(&seg).unwrap().write_all(&[7u8; 20]).unwrap();
    fs::remove_file(dir.path().join("index.bin")).unwrap();

    let s = Store::open(dir.path(), cfg()).unwrap();
    assert_eq!(s.read_to_vec(&id).unwrap(), data);
}

#[test]
fn bit_rot_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let data = noise(100_000, 6);
    let id = {
        let mut s = Store::open(dir.path(), cfg()).unwrap();
        s.put_bytes(&data).unwrap().id
    };

    let seg = fs::read_dir(dir.path().join("segments")).unwrap().next().unwrap().unwrap().path();
    let mut f = OpenOptions::new().read(true).write(true).open(&seg).unwrap();
    f.seek(SeekFrom::Start(500)).unwrap();
    f.write_all(&[0xAA, 0xBB, 0xCC]).unwrap();
    drop(f);

    let s = Store::open(dir.path(), cfg()).unwrap();
    assert!(matches!(s.verify(&id), Err(Error::Corrupt(_))));
    assert!(matches!(s.read_to_vec(&id), Err(Error::Corrupt(_))));
    assert!(!s.scrub().unwrap().corrupt.is_empty());
}

#[test]
fn tampered_manifest_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let id = {
        let mut s = Store::open(dir.path(), cfg()).unwrap();
        s.put_bytes(&noise(50_000, 9)).unwrap().id
    };
    let p = dir.path().join("manifests").join(format!("{id}.mf"));
    let mut raw = fs::read(&p).unwrap();
    raw[20] ^= 1;
    fs::write(&p, raw).unwrap();

    let s = Store::open(dir.path(), cfg()).unwrap();
    assert!(matches!(s.manifest(&id), Err(Error::CorruptManifest(_))));
}

#[test]
fn second_open_is_refused_while_first_is_alive() {
    let dir = tempfile::tempdir().unwrap();
    let _first = Store::open(dir.path(), cfg()).unwrap();
    assert!(matches!(Store::open(dir.path(), cfg()), Err(Error::Locked)));
}

#[test]
fn merkle_proof_for_a_stored_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), cfg()).unwrap();
    let id = s.put_bytes(&noise(300_000, 13)).unwrap().id;
    let m = s.manifest(&id).unwrap();

    for i in 0..m.chunks.len() {
        let (c, p) = s.prove(&id, i).unwrap();
        assert!(p.verify(c.leaf(), &id));
    }
    let (c, p) = s.prove(&id, 0).unwrap();
    assert!(!p.verify(c.leaf(), &Hash::of(b"some other root")));
    assert!(matches!(s.prove(&id, m.chunks.len()), Err(Error::OutOfRange)));
}

#[test]
fn many_small_objects_and_interleaved_gc() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), cfg()).unwrap();
    let objs: Vec<(Hash, Vec<u8>)> = (0..40u64)
        .map(|i| {
            let d = noise(5_000 + i as usize * 900, 100 + i);
            (s.put_bytes(&d).unwrap().id, d)
        })
        .collect();

    for (id, _) in objs.iter().step_by(2) {
        s.remove(id).unwrap();
    }
    s.gc().unwrap();
    for (id, d) in objs.iter().skip(1).step_by(2) {
        assert_eq!(&s.read_to_vec(id).unwrap(), d);
    }
    drop(s);

    // and it still opens clean afterwards
    let s = Store::open(dir.path(), cfg()).unwrap();
    assert_eq!(s.list().unwrap().len(), 20);
    assert!(s.scrub().unwrap().corrupt.is_empty());
}

#[test]
fn reader_streams_and_seeks() {
    use std::io::{Read, Seek, SeekFrom};

    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), cfg()).unwrap();
    let data = noise(200_000, 31);
    let id = s.put_bytes(&data).unwrap().id;

    let mut r = s.open_reader(&id).unwrap();
    assert_eq!(r.size(), data.len() as u64);
    let mut all = Vec::new();
    r.read_to_end(&mut all).unwrap();
    assert_eq!(all, data);

    for (off, len) in [(0usize, 10usize), (4_000, 9_000), (199_990, 50), (123_456, 1)] {
        assert_eq!(s.read_range(&id, off as u64, len).unwrap(), &data[off..(off + len).min(data.len())]);
    }
    assert!(s.read_range(&id, 500_000, 10).unwrap().is_empty());

    r.seek(SeekFrom::End(-5)).unwrap();
    let mut tail = Vec::new();
    r.read_to_end(&mut tail).unwrap();
    assert_eq!(tail, &data[data.len() - 5..]);
    assert!(r.seek(SeekFrom::Current(-1_000_000)).is_err());
}

#[test]
fn reader_reports_corruption_as_io_error() {
    use std::io::Read;

    let dir = tempfile::tempdir().unwrap();
    let id = {
        let mut s = Store::open(dir.path(), cfg()).unwrap();
        s.put_bytes(&noise(60_000, 32)).unwrap().id
    };
    let seg = fs::read_dir(dir.path().join("segments")).unwrap().next().unwrap().unwrap().path();
    let mut raw = fs::read(&seg).unwrap();
    raw[100] ^= 0xFF;
    fs::write(&seg, raw).unwrap();

    let s = Store::open(dir.path(), cfg()).unwrap();
    let mut sink = Vec::new();
    assert!(s.open_reader(&id).unwrap().read_to_end(&mut sink).is_err());
}

#[test]
fn concurrent_readers_share_one_store() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), cfg()).unwrap();
    let objs: Vec<(Hash, Vec<u8>)> = (0..8u64)
        .map(|i| {
            let d = noise(80_000 + i as usize * 1000, 200 + i);
            (s.put_bytes(&d).unwrap().id, d)
        })
        .collect();

    let s = &s;
    std::thread::scope(|scope| {
        for t in 0..8 {
            let objs = &objs;
            scope.spawn(move || {
                for round in 0..20 {
                    let (id, d) = &objs[(t + round) % objs.len()];
                    assert_eq!(&s.read_to_vec(id).unwrap(), d);
                }
            });
        }
    });
}

#[test]
fn data_written_with_one_chunker_reads_back_with_another() {
    use cas::Algorithm;

    let dir = tempfile::tempdir().unwrap();
    let data = noise(300_000, 41);
    let gear = {
        let mut c = cfg();
        c.chunker.algorithm = Algorithm::Gear;
        c
    };

    let id = Store::open(dir.path(), gear).unwrap().put_bytes(&data).unwrap().id;
    let mut s = Store::open(dir.path(), cfg()).unwrap();
    assert_eq!(s.read_to_vec(&id).unwrap(), data);
    s.verify(&id).unwrap();

    // same bytes under the other algorithm are a different object, both coexist
    let id2 = s.put_bytes(&data).unwrap().id;
    assert_ne!(id, id2);
    assert_eq!(s.read_to_vec(&id2).unwrap(), data);
    assert!(s.remove(&id).unwrap());
    s.gc().unwrap();
    assert_eq!(s.read_to_vec(&id2).unwrap(), data);
}
