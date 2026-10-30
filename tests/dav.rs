use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use cas::dav::Dav;
use cas::http::HttpServer;
use cas::server::{ServeOptions, Server, Shared};
use cas::{ChunkerConfig, Store, StoreConfig};

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

struct Resp {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }
}

fn request(addr: SocketAddr, method: &str, path: &str, extra: &[&str]) -> Resp {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
    for h in extra {
        req.push_str(h);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).unwrap();

    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let cut = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("no header end") + 4;
    let head = String::from_utf8_lossy(&raw[..cut]).into_owned();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    Resp { status, head, body: raw[cut..].to_vec() }
}

struct Rig {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<std::io::Result<()>>>,
    _dir: tempfile::TempDir,
    _srv: Arc<Shared>,
}

impl Rig {
    fn start(token: Option<&[u8]>) -> Rig {
        let src = tempfile::tempdir().unwrap();
        fs::create_dir_all(src.path().join("docs/deep")).unwrap();
        fs::write(src.path().join("big.bin"), noise(50_000, 3)).unwrap();
        fs::write(src.path().join("docs/hello world.txt"), b"hello dav").unwrap();
        fs::write(src.path().join("docs/deep/x.json"), b"{}").unwrap();
        fs::write(src.path().join("empty"), b"").unwrap();

        let dir = tempfile::tempdir().unwrap();
        let cfg = StoreConfig {
            chunker: ChunkerConfig {
                min_size: 1 << 10,
                avg_size: 4 << 10,
                max_size: 16 << 10,
                ..ChunkerConfig::default()
            },
            ..StoreConfig::default()
        };
        let mut st = Store::open(dir.path(), cfg).unwrap();
        st.snapshot_dir(src.path(), Some("one")).unwrap();

        let server = Server::bind(st, "127.0.0.1:0", ServeOptions::default()).unwrap();
        let shared = server.shared();
        let dav = Dav::new(shared.clone(), token.map(|t| t.to_vec()));
        let h = HttpServer::bind("127.0.0.1:0", Arc::new(dav)).unwrap().with_idle(Duration::from_secs(2));
        let addr = h.local_addr().unwrap();
        let stop = h.stop_flag();
        let handle = Some(std::thread::spawn(move || h.run()));
        Rig { addr, stop, handle, _dir: dir, _srv: shared }
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[test]
fn options_advertises_dav_and_read_only_methods() {
    let r = Rig::start(None);
    let o = request(r.addr, "OPTIONS", "/", &[]);
    assert_eq!(o.status, 200);
    assert_eq!(o.header("dav"), Some("1"));
    assert!(!o.header("allow").unwrap().contains("PUT"));
}

#[test]
fn propfind_lists_snapshots_and_directories() {
    let r = Rig::start(None);
    let root = request(r.addr, "PROPFIND", "/", &["Depth: 1"]);
    assert_eq!(root.status, 207);
    let xml = String::from_utf8(root.body).unwrap();
    assert!(xml.contains("<D:href>/one/</D:href>"), "{xml}");

    let d = request(r.addr, "PROPFIND", "/one/docs/", &["Depth: 1"]);
    let xml = String::from_utf8(d.body).unwrap();
    assert!(xml.contains("<D:href>/one/docs/hello%20world.txt</D:href>"), "{xml}");
    assert!(xml.contains("<D:getcontentlength>9</D:getcontentlength>"));
    assert!(xml.contains("<D:collection/>"));

    // depth 0 is only the resource itself
    let f = request(r.addr, "PROPFIND", "/one/docs/", &["Depth: 0"]);
    let xml = String::from_utf8(f.body).unwrap();
    assert!(!xml.contains("hello"), "{xml}");

    assert_eq!(request(r.addr, "PROPFIND", "/nope/", &["Depth: 1"]).status, 404);
    assert_eq!(request(r.addr, "PROPFIND", "/one/missing", &["Depth: 0"]).status, 404);
}

#[test]
fn get_returns_file_bytes_with_etag_and_304() {
    let r = Rig::start(None);
    let g = request(r.addr, "GET", "/one/big.bin", &[]);
    assert_eq!(g.status, 200);
    assert_eq!(g.body, noise(50_000, 3));
    let etag = g.header("etag").unwrap().to_string();

    let again = request(r.addr, "GET", "/one/big.bin", &[&format!("If-None-Match: {etag}")]);
    assert_eq!(again.status, 304);
    assert!(again.body.is_empty());

    let h = request(r.addr, "HEAD", "/one/big.bin", &[]);
    assert_eq!(h.status, 200);
    assert_eq!(h.header("content-length"), Some("50000"));
    assert!(h.body.is_empty());

    let e = request(r.addr, "GET", "/one/empty", &[]);
    assert_eq!((e.status, e.body.len()), (200, 0));

    let t = request(r.addr, "GET", "/one/docs/hello%20world.txt", &[]);
    assert_eq!(t.body, b"hello dav");
    assert!(t.header("content-type").unwrap().starts_with("text/plain"));
}

#[test]
fn ranges_are_honoured() {
    let r = Rig::start(None);
    let data = noise(50_000, 3);

    let a = request(r.addr, "GET", "/one/big.bin", &["Range: bytes=100-199"]);
    assert_eq!(a.status, 206);
    assert_eq!(a.body, &data[100..200]);
    assert_eq!(a.header("content-range"), Some("bytes 100-199/50000"));

    let tail = request(r.addr, "GET", "/one/big.bin", &["Range: bytes=-10"]);
    assert_eq!(tail.body, &data[49_990..]);

    let open = request(r.addr, "GET", "/one/big.bin", &["Range: bytes=49990-"]);
    assert_eq!(open.body, &data[49_990..]);

    // end past the file is clamped
    let clamp = request(r.addr, "GET", "/one/big.bin", &["Range: bytes=49990-999999"]);
    assert_eq!(clamp.body, &data[49_990..]);

    let bad = request(r.addr, "GET", "/one/big.bin", &["Range: bytes=60000-"]);
    assert_eq!(bad.status, 416);
    assert_eq!(bad.header("content-range"), Some("bytes */50000"));

    // garbage ranges fall back to the whole file
    let junk = request(r.addr, "GET", "/one/big.bin", &["Range: bytes=abc"]);
    assert_eq!((junk.status, junk.body.len()), (200, 50_000));
}

#[test]
fn directories_get_an_index_page() {
    let r = Rig::start(None);
    let g = request(r.addr, "GET", "/one/docs/", &[]);
    assert_eq!(g.status, 200);
    let html = String::from_utf8(g.body).unwrap();
    assert!(html.contains("hello%20world.txt"), "{html}");
    assert!(html.contains("deep/"));
}

#[test]
fn writes_are_refused() {
    let r = Rig::start(None);
    for m in ["PUT", "DELETE", "MKCOL", "MOVE", "COPY", "PROPPATCH", "LOCK"] {
        assert_eq!(request(r.addr, m, "/one/new", &["Content-Length: 0"]).status, 405, "{m}");
    }
    assert_eq!(request(r.addr, "BREW", "/", &[]).status, 501);
}

#[test]
fn dot_segments_do_not_escape_the_tree() {
    let r = Rig::start(None);
    assert_eq!(request(r.addr, "GET", "/one/../../etc/passwd", &[]).status, 404);
    assert_eq!(request(r.addr, "GET", "/one/docs/%2e%2e/big.bin", &[]).status, 404);
}

#[test]
fn basic_auth_uses_the_token_as_password() {
    let r = Rig::start(Some(b"s3cret"));
    let no = request(r.addr, "GET", "/", &[]);
    assert_eq!(no.status, 401);
    assert!(no.header("www-authenticate").unwrap().starts_with("Basic"));

    // base64("me:wrong") and base64("me:s3cret")
    assert_eq!(request(r.addr, "GET", "/", &["Authorization: Basic bWU6d3Jvbmc="]).status, 401);
    assert_eq!(request(r.addr, "GET", "/", &["Authorization: Basic bWU6czNjcmV0"]).status, 200);
    assert_eq!(request(r.addr, "GET", "/", &["Authorization: Basic !!!"]).status, 401);
}
