use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use cas::segment;
use cas::{ChunkerConfig, Error, Kdf, Password, Store, StoreConfig};

fn cfg() -> StoreConfig {
    StoreConfig {
        chunker: ChunkerConfig { min_size: 1 << 10, avg_size: 4 << 10, max_size: 16 << 10, ..ChunkerConfig::default() },
        segment_size: 32 << 10,
        gc_threshold: 0.3,
        kdf: Kdf { memory_kib: 8, passes: 1, lanes: 1 },
        ..StoreConfig::default()
    }
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

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dst = to.join(e.file_name());
        if e.path().is_dir() {
            copy_dir(&e.path(), &dst);
        } else if e.file_name() != "LOCK" {
            fs::copy(e.path(), dst).unwrap();
        }
    }
}

fn flip(p: &Path, at: u64) {
    let mut f = OpenOptions::new().write(true).open(p).unwrap();
    f.seek(SeekFrom::Start(at)).unwrap();
    f.write_all(&[0xA5]).unwrap();
}

// a store with a few objects, plus a byte-for-byte replica of it
fn pair(c: StoreConfig) -> (tempfile::TempDir, tempfile::TempDir, Vec<(cas::Hash, Vec<u8>)>) {
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let mut objs = Vec::new();
    {
        let mut s = Store::open(a.path(), c).unwrap();
        for i in 0..4 {
            let d = noise(60_000, 10 + i * 2);
            objs.push((s.put_bytes(&d).unwrap().id, d));
        }
    }
    copy_dir(a.path(), b.path());
    (a, b, objs)
}

#[test]
fn healthy_store_needs_nothing() {
    let (a, b, _) = pair(cfg());
    let mut s = Store::open(a.path(), cfg()).unwrap();
    let copy = Store::open(b.path(), cfg()).unwrap();
    assert!(s.check().unwrap().is_empty());
    let r = s.repair_from(&copy).unwrap();
    assert_eq!((r.chunks_fixed, r.manifests_fixed), (0, 0));
}

#[test]
fn bit_rot_is_healed_and_the_bad_bytes_leave_the_disk() {
    let (a, b, objs) = pair(cfg());
    let seg = segment::path(&a.path().join("segments"), 1);
    flip(&seg, 100);

    let copy = Store::open(b.path(), cfg()).unwrap();
    {
        let mut s = Store::open(a.path(), cfg()).unwrap();
        let d = s.check().unwrap();
        assert_eq!(d.corrupt_chunks.len(), 1);
        assert!(objs.iter().any(|(id, _)| s.verify(id).is_err()));

        let r = s.repair_from(&copy).unwrap();
        assert_eq!(r.chunks_fixed, 1);
        assert!(r.unrecoverable.is_empty());
        assert!(s.check().unwrap().is_empty());
        for (id, data) in &objs {
            assert_eq!(&s.read_to_vec(id).unwrap(), data);
        }
    }

    // a rebuild scans every segment from scratch and refuses a damaged one, so this only
    // passes if the bad record is really gone
    fs::remove_file(a.path().join("index.bin")).unwrap();
    let s = Store::open(a.path(), cfg()).unwrap();
    assert!(s.check().unwrap().is_empty());
    for (id, data) in &objs {
        assert_eq!(&s.read_to_vec(id).unwrap(), data);
    }
}

#[test]
fn a_lost_segment_file_is_restored_chunk_by_chunk() {
    let (a, b, objs) = pair(cfg());
    fs::remove_file(segment::path(&a.path().join("segments"), 2)).unwrap();
    fs::remove_file(a.path().join("index.bin")).unwrap();

    let copy = Store::open(b.path(), cfg()).unwrap();
    let mut s = Store::open(a.path(), cfg()).unwrap();
    let d = s.check().unwrap();
    assert!(!d.missing_chunks.is_empty());

    let r = s.repair_from(&copy).unwrap();
    assert_eq!(r.chunks_fixed as usize, d.missing_chunks.len());
    assert!(s.check().unwrap().is_empty());
    for (id, data) in &objs {
        assert_eq!(&s.read_to_vec(id).unwrap(), data);
    }

    // restored chunks have to be counted as referenced or gc would delete them again
    s.gc().unwrap();
    for (id, data) in &objs {
        assert_eq!(&s.read_to_vec(id).unwrap(), data);
    }
}

#[test]
fn a_corrupt_manifest_is_replaced() {
    let (a, b, objs) = pair(cfg());
    let victim = objs[1].0;
    let mf = a.path().join("manifests").join(format!("{victim}.mf"));
    flip(&mf, 20);

    let copy = Store::open(b.path(), cfg()).unwrap();
    let mut s = Store::open(a.path(), cfg()).unwrap();
    assert_eq!(s.check().unwrap().bad_manifests, vec![victim]);
    assert!(s.gc().is_err(), "gc must refuse while a manifest is unreadable");

    let r = s.repair_from(&copy).unwrap();
    assert_eq!(r.manifests_fixed, 1);
    assert!(s.check().unwrap().is_empty());
    assert_eq!(s.read_to_vec(&victim).unwrap(), objs[1].1);
    s.gc().unwrap();
    assert_eq!(s.read_to_vec(&victim).unwrap(), objs[1].1);
}

#[test]
fn what_the_copy_lacks_is_reported_not_invented() {
    let (a, b, objs) = pair(cfg());
    flip(&segment::path(&a.path().join("segments"), 1), 100);
    // the replica is damaged in the same place, so it cannot help
    flip(&segment::path(&b.path().join("segments"), 1), 100);

    let copy = Store::open(b.path(), cfg()).unwrap();
    let mut s = Store::open(a.path(), cfg()).unwrap();
    let r = s.repair_from(&copy).unwrap();
    assert_eq!(r.chunks_fixed, 0);
    assert_eq!(r.unrecoverable.len(), 1);
    assert!(!s.check().unwrap().is_empty());
    // untouched objects still read
    assert!(objs.iter().filter(|(id, _)| s.verify(id).is_ok()).count() >= 3);
}

#[test]
fn a_chunk_from_a_different_store_is_refused() {
    let (a, _b, _) = pair(cfg());
    flip(&segment::path(&a.path().join("segments"), 1), 100);

    // same data written independently with another key: ids differ, nothing matches
    let other = tempfile::tempdir().unwrap();
    let pw = StoreConfig { password: Some(Password::from("pw")), ..cfg() };
    {
        let mut o = Store::open(other.path(), pw.clone()).unwrap();
        for i in 0..4 {
            o.put_bytes(&noise(60_000, 10 + i * 2)).unwrap();
        }
    }
    let copy = Store::open(other.path(), pw).unwrap();
    let mut s = Store::open(a.path(), cfg()).unwrap();
    let r = s.repair_from(&copy).unwrap();
    assert_eq!(r.chunks_fixed, 0);
    assert_eq!(r.unrecoverable.len(), 1);
}

#[test]
fn encrypted_replica_repairs_an_encrypted_store() {
    let pw = StoreConfig { password: Some(Password::from("pw")), ..cfg() };
    let (a, b, objs) = pair(pw.clone());
    flip(&segment::path(&a.path().join("segments"), 1), 150);

    let copy = Store::open(b.path(), pw.clone()).unwrap();
    let mut s = Store::open(a.path(), pw).unwrap();
    let r = s.repair_from(&copy).unwrap();
    assert_eq!(r.chunks_fixed, 1);
    for (id, data) in &objs {
        assert_eq!(&s.read_to_vec(id).unwrap(), data);
    }
}

#[test]
fn raw_chunk_transfer_checks_what_it_receives() {
    let (_a, b, objs) = pair(cfg());
    let src = Store::open(b.path(), cfg()).unwrap();
    let out = tempfile::tempdir().unwrap();
    let mut dst = Store::open(out.path(), cfg()).unwrap();

    let h = src.manifest(&objs[0].0).unwrap().chunks[0].hash;
    let (codec, mut payload) = src.read_chunk_raw(&h).unwrap();
    payload[0] ^= 1;
    assert!(matches!(dst.write_chunk_raw(&h, codec, payload.clone(), false), Err(Error::Corrupt(_))));
    assert!(!dst.has_chunk(&h));

    payload[0] ^= 1;
    assert!(dst.write_chunk_raw(&h, codec, payload.clone(), false).unwrap());
    assert!(!dst.write_chunk_raw(&h, codec, payload, false).unwrap());
}

#[test]
fn manifest_transfer_needs_its_chunks_first() {
    let (_a, b, objs) = pair(cfg());
    let src = Store::open(b.path(), cfg()).unwrap();
    let out = tempfile::tempdir().unwrap();
    let mut dst = Store::open(out.path(), cfg()).unwrap();

    let id = objs[0].0;
    let raw = src.manifest_bytes(&id).unwrap();
    assert!(matches!(dst.put_manifest_bytes(&id, raw.clone()), Err(Error::MissingChunk(_))));

    for c in src.manifest(&id).unwrap().chunks {
        let (codec, p) = src.read_chunk_raw(&c.hash).unwrap();
        dst.write_chunk_raw(&c.hash, codec, p, false).unwrap();
    }
    assert!(dst.put_manifest_bytes(&id, raw.clone()).unwrap());
    assert!(!dst.put_manifest_bytes(&id, raw).unwrap());
    assert_eq!(dst.read_to_vec(&id).unwrap(), objs[0].1);

    // refcounts came out right: removing the object lets gc reclaim everything
    dst.remove(&id).unwrap();
    dst.gc().unwrap();
    assert_eq!(dst.stats().unwrap().live_chunks, 0);

    // wrong id for the bytes
    let other = objs[1].0;
    assert!(dst.put_manifest_bytes(&other, src.manifest_bytes(&id).unwrap()).is_err());
}
