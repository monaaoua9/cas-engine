use cas::metrics::prometheus;
use cas::{ChunkerConfig, Error, Store, StoreConfig};

fn cfg(max: Option<u64>) -> StoreConfig {
    StoreConfig {
        chunker: ChunkerConfig { min_size: 1 << 10, avg_size: 4 << 10, max_size: 16 << 10, ..ChunkerConfig::default() },
        segment_size: 32 << 10,
        gc_threshold: 0.3,
        max_bytes: max,
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

#[test]
fn quota_stops_writes_and_keeps_what_was_stored() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), cfg(Some(150_000))).unwrap();

    let keep = noise(60_000, 1);
    let id = s.put_bytes(&keep).unwrap().id;
    let before = s.disk_bytes();
    assert!(before > 60_000 && before < 150_000);

    // 200 KB of fresh data cannot fit
    let err = s.put_bytes(&noise(200_000, 2)).unwrap_err();
    assert!(matches!(err, Error::QuotaExceeded(150_000)));
    assert!(s.disk_bytes() <= 150_000);
    assert_eq!(s.counters().quota_rejections, 1);

    // the failed put left no object behind and the earlier one is fine
    assert_eq!(s.list().unwrap(), vec![id]);
    assert_eq!(s.read_to_vec(&id).unwrap(), keep);
    s.verify(&id).unwrap();
}

#[test]
fn quota_does_not_block_dedup() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), cfg(Some(100_000))).unwrap();
    let d = noise(60_000, 3);
    s.put_bytes(&d).unwrap();
    // writes nothing new, so it needs no room
    assert!(s.put_bytes(&d).unwrap().existed);
}

#[test]
fn gc_frees_room_even_when_the_store_is_full() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), cfg(Some(130_000))).unwrap();

    let a = s.put_bytes(&noise(50_000, 21)).unwrap().id;
    let b = s.put_bytes(&noise(50_000, 23)).unwrap().id;
    assert!(s.put_bytes(&noise(50_000, 25)).is_err());

    s.remove(&a).unwrap();
    // deleting does not free disk until gc runs
    assert!(s.put_bytes(&noise(50_000, 27)).is_err());

    s.gc().unwrap();
    assert!(s.disk_bytes() < 70_000);
    let c = s.put_bytes(&noise(50_000, 29)).unwrap().id;
    assert!(s.verify(&b).is_ok() && s.verify(&c).is_ok());
}

#[test]
fn quota_counts_what_is_already_on_disk_at_open() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut s = Store::open(dir.path(), cfg(None)).unwrap();
        s.put_bytes(&noise(80_000, 9)).unwrap();
    }
    let mut s = Store::open(dir.path(), cfg(Some(90_000))).unwrap();
    assert!(s.disk_bytes() > 80_000);
    assert!(matches!(s.put_bytes(&noise(40_000, 10)), Err(Error::QuotaExceeded(_))));
}

#[test]
fn counters_follow_activity() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), cfg(None)).unwrap();
    assert_eq!(s.counters().puts, 0);

    let d = noise(40_000, 11);
    let r = s.put_bytes(&d).unwrap();
    s.put_bytes(&d).unwrap();
    s.read_to_vec(&r.id).unwrap();

    let c = s.counters();
    assert_eq!(c.puts, 1, "the second put found the manifest and stopped early");
    assert_eq!(c.put_bytes, 40_000);
    assert_eq!(c.chunks_written, r.new_chunks);
    assert_eq!(c.chunk_reads, r.chunks);
    assert_eq!(c.bytes_read, 40_000);
    assert_eq!(c.corrupt_seen, 0);

    s.remove(&r.id).unwrap();
    s.gc().unwrap();
    assert_eq!(s.counters().gc_runs, 1);
}

#[test]
fn prometheus_output_reflects_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), cfg(Some(1 << 20))).unwrap();
    s.put_bytes(&noise(30_000, 12)).unwrap();

    let t = prometheus(&s.stats().unwrap(), &s.counters(), s.disk_bytes(), s.max_bytes(), &[]);
    assert!(t.contains("cas_objects 1\n"));
    assert!(t.contains("cas_logical_bytes 30000\n"));
    assert!(t.contains(&format!("cas_disk_bytes {}\n", s.disk_bytes())));
    assert!(t.contains("cas_quota_bytes 1048576\n"));
    assert!(t.contains("cas_puts_total 1\n"));
}
