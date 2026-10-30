use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use cas::segment;
use cas::{ChunkRef, ChunkerConfig, Compression, Error, Hash, Kdf, Manifest, Password, Store, StoreConfig};

fn cfg() -> StoreConfig {
    StoreConfig {
        chunker: ChunkerConfig { min_size: 1 << 10, avg_size: 4 << 10, max_size: 16 << 10, ..ChunkerConfig::default() },
        segment_size: 64 << 10,
        gc_threshold: 0.3,
        kdf: Kdf { memory_kib: 8, passes: 1, lanes: 1 },
        ..StoreConfig::default()
    }
}

fn enc(pw: &str) -> StoreConfig {
    StoreConfig { password: Some(Password::from(pw)), ..cfg() }
}

fn lz4(c: StoreConfig) -> StoreConfig {
    StoreConfig { compression: Compression::Lz4, ..c }
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

fn text(len: usize) -> Vec<u8> {
    b"all work and no play makes jack a dull boy. ".iter().cycle().take(len).copied().collect()
}

fn files_under(dir: &Path) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(files_under(&p));
        } else {
            out.push(fs::read(&p).unwrap());
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn compression_shrinks_text_and_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), lz4(cfg())).unwrap();
    let data = text(200_000);
    let r = s.put_bytes(&data).unwrap();
    assert!(r.stored_bytes < r.new_bytes / 10, "{} vs {}", r.stored_bytes, r.new_bytes);
    assert_eq!(s.read_to_vec(&r.id).unwrap(), data);
    s.verify(&r.id).unwrap();

    let st = s.stats().unwrap();
    assert!(st.dedup_ratio() > 10.0);
}

#[test]
fn incompressible_data_costs_no_extra_payload() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), lz4(cfg())).unwrap();
    let r = s.put_bytes(&noise(100_000, 3)).unwrap();
    assert_eq!(r.stored_bytes, r.new_bytes);
}

#[test]
fn compression_can_change_between_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (text(50_000), noise(30_000, 4));
    let (ida, idb);
    {
        let mut s = Store::open(dir.path(), cfg()).unwrap();
        ida = s.put_bytes(&a).unwrap().id;
    }
    {
        let mut s = Store::open(dir.path(), lz4(cfg())).unwrap();
        idb = s.put_bytes(&b).unwrap().id;
        s.remove(&idb).unwrap();
        idb_gc(&mut s);
        assert_eq!(s.read_to_vec(&ida).unwrap(), a);
    }
    let s = Store::open(dir.path(), cfg()).unwrap();
    assert_eq!(s.read_to_vec(&ida).unwrap(), a);
    assert!(!s.contains(&idb));
}

fn idb_gc(s: &mut Store) {
    s.gc().unwrap();
}

#[test]
fn encrypted_roundtrip_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let data = noise(120_000, 5);
    let id;
    {
        let mut s = Store::open(dir.path(), enc("correct horse")).unwrap();
        assert!(s.is_encrypted());
        id = s.put_bytes(&data).unwrap().id;
        s.verify(&id).unwrap();
    }
    let s = Store::open(dir.path(), enc("correct horse")).unwrap();
    assert_eq!(s.read_to_vec(&id).unwrap(), data);
    assert_eq!(s.read_range(&id, 5_000, 100).unwrap(), data[5_000..5_100]);
}

#[test]
fn wrong_missing_and_unneeded_passwords() {
    let dir = tempfile::tempdir().unwrap();
    Store::open(dir.path(), enc("right")).unwrap();
    assert!(matches!(Store::open(dir.path(), enc("wrong")), Err(Error::WrongPassword)));
    assert!(matches!(Store::open(dir.path(), cfg()), Err(Error::PasswordRequired)));

    let plain = tempfile::tempdir().unwrap();
    Store::open(plain.path(), cfg()).unwrap();
    assert!(matches!(Store::open(plain.path(), enc("x")), Err(Error::NotEncrypted)));
}

#[test]
fn nothing_readable_ends_up_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let marker = b"TOP-SECRET-MARKER-0123456789";
    let mut data = Vec::new();
    for _ in 0..2_000 {
        data.extend_from_slice(marker);
        data.push(b' ');
    }
    {
        let mut s = Store::open(dir.path(), enc("pw")).unwrap();
        s.put_bytes(&data).unwrap();
    }
    for f in files_under(dir.path()) {
        assert!(!contains(&f, marker));
    }

    // control: the same thing in a plain store is visible, so the check can fail
    let plain = tempfile::tempdir().unwrap();
    Store::open(plain.path(), cfg()).unwrap().put_bytes(&data).unwrap();
    assert!(files_under(plain.path()).iter().any(|f| contains(f, marker)));
}

#[test]
fn ids_are_keyed_per_store() {
    let data = noise(40_000, 6);
    let ids: Vec<Hash> = ["a", "b"]
        .iter()
        .map(|pw| {
            let d = tempfile::tempdir().unwrap();
            let mut s = Store::open(d.path(), enc(pw)).unwrap();
            s.put_bytes(&data).unwrap().id
        })
        .collect();
    let d = tempfile::tempdir().unwrap();
    let plain = Store::open(d.path(), cfg()).unwrap().put_bytes(&data).unwrap().id;
    assert_ne!(ids[0], ids[1]);
    assert_ne!(ids[0], plain);
}

#[test]
fn dedup_still_works_when_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), lz4(enc("pw"))).unwrap();
    let data = noise(80_000, 7);
    let a = s.put_bytes(&data).unwrap();
    let b = s.put_bytes(&data).unwrap();
    assert_eq!(a.id, b.id);
    assert!(b.existed);
    assert_eq!(b.new_chunks, 0);
}

#[test]
fn change_password_keeps_the_data() {
    let dir = tempfile::tempdir().unwrap();
    let data = text(60_000);
    let id;
    {
        let mut s = Store::open(dir.path(), enc("old")).unwrap();
        id = s.put_bytes(&data).unwrap().id;
        s.change_password(&Password::from("new")).unwrap();
    }
    assert!(matches!(Store::open(dir.path(), enc("old")), Err(Error::WrongPassword)));
    let s = Store::open(dir.path(), enc("new")).unwrap();
    assert_eq!(s.read_to_vec(&id).unwrap(), data);

    let plain = tempfile::tempdir().unwrap();
    let mut p = Store::open(plain.path(), cfg()).unwrap();
    assert!(matches!(p.change_password(&Password::from("x")), Err(Error::NotEncrypted)));
}

#[test]
fn bit_rot_in_an_encrypted_segment_is_caught() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), enc("pw")).unwrap();
    let id = s.put_bytes(&noise(50_000, 8)).unwrap().id;
    s.sync().unwrap();

    let seg = segment::path(&dir.path().join("segments"), 1);
    let mut f = OpenOptions::new().write(true).open(seg).unwrap();
    f.seek(SeekFrom::Start(200)).unwrap();
    f.write_all(&[0xAA]).unwrap();
    drop(f);

    assert!(matches!(s.verify(&id), Err(Error::Corrupt(_))));
    assert!(!s.scrub().unwrap().corrupt.is_empty());
}

#[test]
fn rebuild_after_losing_the_index_works_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let data = text(90_000);
    let id;
    {
        let mut s = Store::open(dir.path(), lz4(enc("pw"))).unwrap();
        id = s.put_bytes(&data).unwrap().id;
    }
    fs::remove_file(dir.path().join("index.bin")).unwrap();
    let mut s = Store::open(dir.path(), lz4(enc("pw"))).unwrap();
    assert_eq!(s.read_to_vec(&id).unwrap(), data);
    s.remove(&id).unwrap();
    assert!(s.gc().unwrap().segments_removed > 0);
}

#[test]
fn gc_moves_compressed_encrypted_chunks_intact() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), lz4(enc("pw"))).unwrap();
    let keep = noise(60_000, 9);
    let kid = s.put_bytes(&keep).unwrap().id;
    let junk: Vec<_> = (0..6).map(|i| s.put_bytes(&noise(40_000, 100 + i)).unwrap().id).collect();
    for j in &junk {
        s.remove(j).unwrap();
    }
    let rep = s.gc().unwrap();
    assert!(rep.chunks_removed > 0);
    assert_eq!(s.read_to_vec(&kid).unwrap(), keep);
    s.verify(&kid).unwrap();
    assert!(s.scrub().unwrap().corrupt.is_empty());
}

#[test]
fn tampered_format_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    Store::open(dir.path(), enc("pw")).unwrap();
    let p = dir.path().join("FORMAT");
    let mut b = fs::read(&p).unwrap();
    b[30] ^= 1;
    fs::write(&p, b).unwrap();
    assert!(matches!(Store::open(dir.path(), enc("pw")), Err(Error::BadFormat(_))));
}

#[test]
fn manifests_are_not_readable_plaintext_when_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), enc("pw")).unwrap();
    let id = s.put_bytes(&noise(30_000, 10)).unwrap().id;
    let raw = fs::read(dir.path().join("manifests").join(format!("{id}.mf"))).unwrap();
    assert!(Manifest::decode(&raw).is_err());
    assert_eq!(s.manifest(&id).unwrap().size, 30_000);

    // swapping one manifest file for another must not pass
    let id2 = s.put_bytes(&noise(30_000, 20)).unwrap().id;
    let other = fs::read(dir.path().join("manifests").join(format!("{id2}.mf"))).unwrap();
    fs::write(dir.path().join("manifests").join(format!("{id}.mf")), other).unwrap();
    let r = s.manifest(&id);
    assert!(matches!(r, Err(Error::CorruptManifest(_))), "{r:?}");
}

#[test]
fn snapshots_work_encrypted_and_hide_names() {
    let src = tempfile::tempdir().unwrap();
    fs::create_dir_all(src.path().join("private-folder-name")).unwrap();
    fs::write(src.path().join("private-folder-name/secret-file-name.txt"), text(20_000)).unwrap();

    let st = tempfile::tempdir().unwrap();
    {
        let mut s = Store::open(st.path(), lz4(enc("pw"))).unwrap();
        s.snapshot_dir(src.path(), Some("nightly")).unwrap();
        s.snapshot_verify("nightly").unwrap();
    }
    for f in files_under(st.path()) {
        assert!(!contains(&f, b"secret-file-name"));
        assert!(!contains(&f, b"private-folder-name"));
    }

    let s = Store::open(st.path(), enc("pw")).unwrap();
    let out = tempfile::tempdir().unwrap();
    s.snapshot_restore("nightly", out.path().join("r")).unwrap();
    assert_eq!(fs::read(out.path().join("r/private-folder-name/secret-file-name.txt")).unwrap(), text(20_000));
}

// a store written before FORMAT existed: bare v1 records, no FORMAT file
fn make_legacy_store(root: &Path, data: &[u8]) -> Hash {
    fs::create_dir_all(root.join("segments")).unwrap();
    fs::create_dir_all(root.join("manifests")).unwrap();
    let h = Hash::of(data);
    fs::write(segment::path(&root.join("segments"), 1), segment::encode_record(&h, data)).unwrap();
    let m = Manifest::new(vec![ChunkRef { hash: h, len: data.len() as u32 }]);
    fs::write(root.join("manifests").join(format!("{}.mf", m.id())), m.encode()).unwrap();
    m.id()
}

#[test]
fn legacy_v1_store_still_opens_reads_and_writes() {
    let dir = tempfile::tempdir().unwrap();
    let old = noise(3_000, 12);
    let id = make_legacy_store(dir.path(), &old);

    {
        let mut s = Store::open(dir.path(), cfg()).unwrap();
        assert_eq!(s.read_to_vec(&id).unwrap(), old);
        s.verify(&id).unwrap();

        // new data goes in with the old layout, and compression is simply not applied
        let fresh = text(30_000);
        let r = s.put_bytes(&fresh).unwrap();
        assert_eq!(s.read_to_vec(&r.id).unwrap(), fresh);
    }
    assert!(!dir.path().join("FORMAT").exists());

    // and it survives a rebuild, which re-scans v1 records
    fs::remove_file(dir.path().join("index.bin")).unwrap();
    let mut s = Store::open(dir.path(), cfg()).unwrap();
    assert_eq!(s.read_to_vec(&id).unwrap(), old);
    s.remove(&id).unwrap();
    s.gc().unwrap();
}

#[test]
fn password_on_a_legacy_store_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    make_legacy_store(dir.path(), b"old data");
    assert!(matches!(Store::open(dir.path(), enc("pw")), Err(Error::NotEncrypted)));
}
