use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use cas::client::Client;
use cas::server::{ServeOptions, Server, Shared};
use cas::sync::{Peer, SyncReport, copy_all, copy_object, copy_snapshot};
use cas::{ChunkerConfig, Error, Hash, Kdf, Password, Store, StoreConfig};

fn cfg() -> StoreConfig {
    StoreConfig {
        chunker: ChunkerConfig { min_size: 1 << 10, avg_size: 4 << 10, max_size: 16 << 10, ..ChunkerConfig::default() },
        segment_size: 64 << 10,
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

struct Srv {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    shared: Option<Arc<Shared>>,
    handle: Option<JoinHandle<cas::Result<()>>>,
}

impl Srv {
    fn start(store: Store, mut opts: ServeOptions) -> Srv {
        opts.idle = Duration::from_secs(5);
        let server = Server::bind(store, "127.0.0.1:0", opts).unwrap();
        let addr = server.local_addr().unwrap();
        let stop = server.stop_flag();
        let shared = Some(server.shared());
        let handle = Some(std::thread::spawn(move || server.run()));
        Srv { addr, stop, shared, handle }
    }

    fn connect(&self, token: Option<&[u8]>) -> cas::Result<Client> {
        Client::connect(self.addr, token)
    }

    // clients must be dropped first; the store's lock goes away with the last Arc
    fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.take().unwrap().join().unwrap().unwrap();
        self.shared.take();
    }
}

fn tmp_store() -> (tempfile::TempDir, Store) {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path(), cfg()).unwrap();
    (d, s)
}

fn token(t: &str) -> ServeOptions {
    ServeOptions { token: Some(t.as_bytes().to_vec()), ..ServeOptions::default() }
}

#[test]
fn store_to_store_copy_moves_only_what_is_missing() {
    let (_a, mut a) = tmp_store();
    let (_b, mut b) = tmp_store();

    let base = noise(120_000, 1);
    let mut changed = base.clone();
    changed.extend(noise(10_000, 3));
    let id1 = a.put_bytes(&base).unwrap().id;
    let id2 = a.put_bytes(&changed).unwrap().id;

    let mut rep = SyncReport::default();
    copy_object(&mut a, &mut b, &id1, &mut rep).unwrap();
    let first = rep.chunks_sent;
    assert_eq!(rep.objects_sent, 1);
    assert_eq!(b.read_to_vec(&id1).unwrap(), base);

    // the second object shares almost every chunk with the first
    copy_object(&mut a, &mut b, &id2, &mut rep).unwrap();
    assert!(rep.chunks_sent - first <= 4, "sent {} extra chunks", rep.chunks_sent - first);
    assert_eq!(b.read_to_vec(&id2).unwrap(), changed);

    // nothing left to do
    let again = copy_all(&mut a, &mut b).unwrap();
    assert_eq!((again.objects_sent, again.chunks_sent), (0, 0));
    assert_eq!(again.objects_skipped, 2);

    // refcounts on the receiving side are right: remove both, gc, nothing live
    b.remove(&id1).unwrap();
    b.remove(&id2).unwrap();
    b.gc().unwrap();
    assert_eq!(b.stats().unwrap().live_chunks, 0);
}

#[test]
fn snapshots_copy_with_their_objects_and_conflicts_are_reported() {
    let src = tempfile::tempdir().unwrap();
    fs::create_dir_all(src.path().join("d")).unwrap();
    fs::write(src.path().join("a"), noise(30_000, 5)).unwrap();
    fs::write(src.path().join("d/b"), noise(20_000, 7)).unwrap();

    let (_a, mut a) = tmp_store();
    let (_b, mut b) = tmp_store();
    a.snapshot_dir(src.path(), Some("one")).unwrap();

    let mut rep = SyncReport::default();
    copy_snapshot(&mut a, &mut b, "one", &mut rep).unwrap();
    assert_eq!(rep.snapshots_sent, 1);
    b.snapshot_verify("one").unwrap();
    let out = tempfile::tempdir().unwrap();
    b.snapshot_restore("one", out.path().join("r")).unwrap();
    assert_eq!(fs::read(out.path().join("r/d/b")).unwrap(), noise(20_000, 7));

    // again: identical, skipped
    let mut rep = SyncReport::default();
    copy_snapshot(&mut a, &mut b, "one", &mut rep).unwrap();
    assert_eq!((rep.snapshots_sent, rep.snapshots_skipped), (0, 1));

    // same name, different tree on the other side: reported, not overwritten
    fs::write(src.path().join("a"), b"changed").unwrap();
    let (_c, mut c) = tmp_store();
    c.snapshot_dir(src.path(), Some("one")).unwrap();
    let rep = copy_all(&mut c, &mut b).unwrap();
    assert_eq!(rep.conflicts, vec!["one".to_string()]);
    assert_eq!(rep.snapshots_sent, 0);
    assert_eq!(b.snapshot_get("one").unwrap().root, a.snapshot_get("one").unwrap().root);
}

#[test]
fn push_and_pull_over_a_real_socket() {
    let (_remote_dir, remote) = tmp_store();
    let srv = Srv::start(remote, token("s3cret"));

    let (_a, mut a) = tmp_store();
    let data = noise(200_000, 11);
    let id = a.put_bytes(&data).unwrap().id;
    let src = tempfile::tempdir().unwrap();
    fs::write(src.path().join("f"), noise(40_000, 13)).unwrap();
    a.snapshot_dir(src.path(), Some("nightly")).unwrap();

    {
        let mut c = srv.connect(Some(b"s3cret")).unwrap();
        c.ping().unwrap();
        let rep = copy_all(&mut a, &mut c).unwrap();
        assert!(rep.objects_sent >= 2 && rep.snapshots_sent == 1);
        assert_eq!(c.list_snapshots().unwrap(), vec!["nightly".to_string()]);
        assert!(c.has_object(&id).unwrap());

        // a second push is a no-op
        let rep = copy_all(&mut a, &mut c).unwrap();
        assert_eq!(rep.chunks_sent, 0);
    }

    // pull into a third store
    let (_b, mut b) = tmp_store();
    {
        let mut c = srv.connect(Some(b"s3cret")).unwrap();
        let rep = copy_all(&mut c, &mut b).unwrap();
        assert_eq!(rep.snapshots_sent, 1);
        let m = c.metrics().unwrap();
        assert!(m.contains("cas_net_requests_total"), "{m}");
        assert!(m.contains("cas_objects 3\n") || m.contains("cas_objects 2\n"));
    }
    assert_eq!(b.read_to_vec(&id).unwrap(), data);
    b.snapshot_verify("nightly").unwrap();
    srv.stop();
}

#[test]
fn authentication() {
    let (_d, s) = tmp_store();
    let srv = Srv::start(s, token("right"));

    assert!(matches!(srv.connect(Some(b"wrong")), Err(Error::AuthFailed)));
    assert!(matches!(srv.connect(None), Err(Error::AuthFailed)));
    assert!(srv.connect(Some(b"right")).is_ok());

    let m = srv.shared.as_ref().unwrap().metrics_text().unwrap();
    assert!(m.contains("cas_net_auth_failures_total 1\n"), "{m}");
    srv.stop();
}

#[test]
fn client_refuses_a_server_that_does_not_know_the_token() {
    // an impostor accepts any proof and answers "ok" with a made-up proof of its own
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let h = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut hello = Vec::new();
        hello.extend_from_slice(b"CASN");
        hello.push(1);
        hello.push(1);
        hello.extend_from_slice(&[7u8; 32]);
        s.write_all(&hello).unwrap();
        let mut got = [0u8; 32];
        s.read_exact(&mut got).unwrap();
        let mut body = vec![0u8];
        body.extend_from_slice(&[9u8; 32]);
        cas::wire::write_frame(&mut s, 0, &body).unwrap();
    });
    assert!(matches!(Client::connect(addr, Some(b"token")), Err(Error::AuthFailed)));
    h.join().unwrap();
}

#[test]
fn a_server_without_a_token_lets_tokenless_clients_in() {
    let (_d, s) = tmp_store();
    let srv = Srv::start(s, ServeOptions::default());
    assert!(srv.connect(None).is_ok());
    srv.stop();
}

#[test]
fn read_only_server_serves_reads_and_refuses_writes() {
    let (_d, mut s) = tmp_store();
    let data = noise(50_000, 17);
    let id = s.put_bytes(&data).unwrap().id;
    let srv = Srv::start(s, ServeOptions { read_only: true, ..token("t") });

    let (_a, mut a) = tmp_store();
    {
        let mut c = srv.connect(Some(b"t")).unwrap();
        assert!(c.read_only());
        copy_object(&mut c, &mut a, &id, &mut SyncReport::default()).unwrap();
        assert_eq!(a.read_to_vec(&id).unwrap(), data);

        let h = Hash::of(b"x");
        assert!(matches!(c.put_chunk(&h, 0, b"x".to_vec()), Err(Error::ReadOnly)));
        let sample = a.manifest_bytes(&id).unwrap();
        assert!(matches!(c.put_manifest(&id, sample), Err(Error::ReadOnly)));
    }
    srv.stop();
}

#[test]
fn server_rejects_a_corrupted_chunk_and_stays_healthy() {
    let (_d, s) = tmp_store();
    let srv = Srv::start(s, ServeOptions::default());

    let (_a, mut a) = tmp_store();
    let id = a.put_bytes(&noise(20_000, 19)).unwrap().id;
    let h = a.manifest(&id).unwrap().chunks[0].hash;
    let (codec, mut payload) = a.get_chunk_raw_for_test(&h);
    payload[3] ^= 0x40;

    {
        let mut c = srv.connect(None).unwrap();
        let err = c.put_chunk(&h, codec, payload).unwrap_err();
        assert!(matches!(err, Error::Remote(_)), "{err:?}");
        assert_eq!(c.missing_chunks(&[h]).unwrap(), vec![h], "bad chunk must not have been stored");
        // the same connection keeps working
        c.ping().unwrap();
    }
    srv.stop();
}

trait RawForTest {
    fn get_chunk_raw_for_test(&mut self, h: &Hash) -> (u8, Vec<u8>);
}

impl RawForTest for Store {
    fn get_chunk_raw_for_test(&mut self, h: &Hash) -> (u8, Vec<u8>) {
        self.read_chunk_raw(h).unwrap()
    }
}

#[test]
fn a_manifest_before_its_chunks_is_refused_over_the_wire() {
    let (_d, s) = tmp_store();
    let srv = Srv::start(s, ServeOptions::default());
    let (_a, mut a) = tmp_store();
    let id = a.put_bytes(&noise(30_000, 21)).unwrap().id;
    {
        let mut c = srv.connect(None).unwrap();
        let raw = a.manifest_bytes(&id).unwrap();
        assert!(matches!(c.put_manifest(&id, raw), Err(Error::Remote(_))));
        assert!(!c.has_object(&id).unwrap());
    }
    srv.stop();
}

#[test]
fn garbage_on_the_socket_does_not_hurt_the_server() {
    let (_d, mut s) = tmp_store();
    let id = s.put_bytes(&noise(10_000, 23)).unwrap().id;
    let srv = Srv::start(s, ServeOptions::default());

    // wrong magic handshake reply, a frame announcing 4 GiB, a half frame, an unknown op
    for junk in [&b"GET / HTTP/1.1\r\n\r\n"[..], &[0xFF; 64][..]] {
        let mut t = TcpStream::connect(srv.addr).unwrap();
        t.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut hello = [0u8; 38];
        t.read_exact(&mut hello).unwrap();
        let _ = t.write_all(junk);
    }
    {
        let mut c = srv.connect(None).unwrap();
        // unknown op code
        let mut t = TcpStream::connect(srv.addr).unwrap();
        let mut hello = [0u8; 38];
        t.read_exact(&mut hello).unwrap();
        t.write_all(&[0u8; 32]).unwrap();
        let (st, _) = cas::wire::read_frame(&mut t).unwrap().unwrap();
        assert_eq!(st, 0);
        cas::wire::write_frame(&mut t, 200, b"").unwrap();
        let (st, msg) = cas::wire::read_frame(&mut t).unwrap().unwrap();
        assert_eq!(st, cas::wire::ST_ERROR, "{}", String::from_utf8_lossy(&msg));
        drop(t);

        assert!(c.has_object(&id).unwrap());
    }
    srv.stop();
}

#[test]
fn encrypted_replica_over_the_wire() {
    let pw = StoreConfig { password: Some(Password::from("pw")), ..cfg() };

    // two encrypted stores with the same key: the second starts as a copy of the first one's FORMAT
    let a_dir = tempfile::tempdir().unwrap();
    let mut a = Store::open(a_dir.path(), pw.clone()).unwrap();
    let r_dir = tempfile::tempdir().unwrap();
    fs::copy(a_dir.path().join("FORMAT"), {
        fs::create_dir_all(r_dir.path()).unwrap();
        r_dir.path().join("FORMAT")
    })
    .unwrap();
    let remote = Store::open(r_dir.path(), pw.clone()).unwrap();
    let srv = Srv::start(remote, token("t"));

    let data = noise(80_000, 25);
    let id = a.put_bytes(&data).unwrap().id;
    {
        let mut c = srv.connect(Some(b"t")).unwrap();
        copy_all(&mut a, &mut c).unwrap();
    }
    srv.stop();

    let r = Store::open(r_dir.path(), pw).unwrap();
    assert_eq!(r.read_to_vec(&id).unwrap(), data);
    assert!(r.check().unwrap().is_empty());
    assert_files_hide(&r_dir, &noise(80_000, 25)[100..140]);
}

fn assert_files_hide(dir: &tempfile::TempDir, needle: &[u8]) {
    fn walk(p: &Path, needle: &[u8]) {
        for e in fs::read_dir(p).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, needle);
            } else if p.file_name().is_some_and(|n| n != "LOCK") {
                let b = fs::read(&p).unwrap();
                assert!(!b.windows(needle.len()).any(|w| w == needle), "{p:?}");
            }
        }
    }
    walk(dir.path(), needle);
}

#[test]
fn stores_with_different_keys_cannot_exchange_chunks() {
    let pw1 = StoreConfig { password: Some(Password::from("one")), ..cfg() };
    let pw2 = StoreConfig { password: Some(Password::from("two")), ..cfg() };
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let mut a = Store::open(d1.path(), pw1).unwrap();
    let mut b = Store::open(d2.path(), pw2).unwrap();
    let id = a.put_bytes(&noise(30_000, 27)).unwrap().id;

    let err = copy_object(&mut a, &mut b, &id, &mut SyncReport::default()).unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
    assert!(b.list().unwrap().is_empty());
}

#[test]
fn many_clients_at_once() {
    let (_d, mut s) = tmp_store();
    let datas: Vec<Vec<u8>> = (0..6).map(|i| noise(40_000, 100 + i * 2)).collect();
    let ids: Vec<Hash> = datas.iter().map(|d| s.put_bytes(d).unwrap().id).collect();
    let srv = Srv::start(s, ServeOptions::default());

    let addr = srv.addr;
    let handles: Vec<_> = (0..6)
        .map(|i| {
            let (id, data) = (ids[i], datas[i].clone());
            std::thread::spawn(move || {
                let mut c = Client::connect(addr, None).unwrap();
                let (_d, mut local) = tmp_store();
                copy_object(&mut c, &mut local, &id, &mut SyncReport::default()).unwrap();
                assert_eq!(local.read_to_vec(&id).unwrap(), data);
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    srv.stop();
}
