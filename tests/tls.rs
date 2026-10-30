use std::sync::atomic::Ordering;
use std::time::Duration;

use cas::client::Client;
use cas::server::{ServeOptions, Server};
use cas::sync::{SyncReport, copy_snapshot};
use cas::tls::{TlsClient, TlsServer, generate_self_signed};
use cas::{ChunkerConfig, Error, Store, StoreConfig};

fn cfg() -> StoreConfig {
    StoreConfig {
        chunker: ChunkerConfig { min_size: 1 << 10, avg_size: 4 << 10, max_size: 16 << 10, ..ChunkerConfig::default() },
        ..StoreConfig::default()
    }
}

struct Pki {
    dir: tempfile::TempDir,
}

impl Pki {
    fn new(names: &[&str]) -> Pki {
        let dir = tempfile::tempdir().unwrap();
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        generate_self_signed(&names, &dir.path().join("c.pem"), &dir.path().join("k.pem")).unwrap();
        Pki { dir }
    }

    fn server(&self) -> TlsServer {
        TlsServer::load(&self.dir.path().join("c.pem"), &self.dir.path().join("k.pem")).unwrap()
    }

    fn client(&self) -> TlsClient {
        TlsClient::load(&self.dir.path().join("c.pem")).unwrap()
    }
}

struct Running {
    port: u16,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    h: Option<std::thread::JoinHandle<cas::Result<()>>>,
    _d: tempfile::TempDir,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.h.take().unwrap().join();
    }
}

fn start(tls: Option<TlsServer>, token: Option<&[u8]>) -> Running {
    let d = tempfile::tempdir().unwrap();
    let st = Store::open(d.path(), cfg()).unwrap();
    let opts =
        ServeOptions { tls, token: token.map(|t| t.to_vec()), idle: Duration::from_secs(2), ..ServeOptions::default() };
    let srv = Server::bind(st, "127.0.0.1:0", opts).unwrap();
    let port = srv.local_addr().unwrap().port();
    let stop = srv.stop_flag();
    Running { port, stop, h: Some(std::thread::spawn(move || srv.run())), _d: d }
}

#[test]
fn sync_over_tls_with_token() {
    let pki = Pki::new(&["127.0.0.1", "localhost"]);
    let r = start(Some(pki.server()), Some(b"tok"));

    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("f"), vec![5u8; 50_000]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut local = Store::open(dir.path(), cfg()).unwrap();
    local.snapshot_dir(src.path(), Some("one")).unwrap();

    let mut c = Client::connect_tls("127.0.0.1", r.port, Some(b"tok"), &pki.client()).unwrap();
    let mut rep = SyncReport::default();
    copy_snapshot(&mut local, &mut c, "one", &mut rep).unwrap();
    assert_eq!(rep.snapshots_sent, 1);

    // a second connection by name works too, the certificate lists it
    let mut c2 = Client::connect_tls("localhost", r.port, Some(b"tok"), &pki.client()).unwrap();
    c2.ping().unwrap();

    // the token is still checked inside the tunnel
    let bad = Client::connect_tls("127.0.0.1", r.port, Some(b"nope"), &pki.client());
    assert!(matches!(bad, Err(Error::AuthFailed)));
}

#[test]
fn client_refuses_a_certificate_it_was_not_given() {
    let good = Pki::new(&["127.0.0.1"]);
    let other = Pki::new(&["127.0.0.1"]);
    let r = start(Some(good.server()), None);
    assert!(Client::connect_tls("127.0.0.1", r.port, None, &other.client()).is_err());
}

#[test]
fn certificate_for_another_name_is_refused() {
    let pki = Pki::new(&["example.test"]);
    let r = start(Some(pki.server()), None);
    assert!(Client::connect_tls("127.0.0.1", r.port, None, &pki.client()).is_err());
}

#[test]
fn plain_and_tls_do_not_mix() {
    let pki = Pki::new(&["127.0.0.1"]);

    let tls_srv = start(Some(pki.server()), None);
    assert!(Client::connect(("127.0.0.1", tls_srv.port), None).is_err());

    let plain_srv = start(None, None);
    assert!(Client::connect_tls("127.0.0.1", plain_srv.port, None, &pki.client()).is_err());
}

#[test]
fn bad_pem_files_are_errors() {
    let d = tempfile::tempdir().unwrap();
    let junk = d.path().join("junk");
    std::fs::write(&junk, "not a pem").unwrap();
    assert!(TlsServer::load(&junk, &junk).is_err());
    assert!(TlsClient::load(&junk).is_err());
    assert!(TlsClient::load(&d.path().join("missing")).is_err());
}

fn https_get(port: u16, host: &str, path: &str, ca: &std::path::Path) -> std::io::Result<String> {
    use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
    use std::io::{Read, Write};

    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(ca).unwrap() {
        roots.add(c.unwrap()).unwrap();
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let conn = rustls::ClientConnection::new(cfg.into(), ServerName::try_from(host.to_owned()).unwrap()).unwrap();
    let sock = std::net::TcpStream::connect(("127.0.0.1", port))?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut tls = rustls::StreamOwned::new(conn, sock);
    write!(tls, "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")?;
    let mut body = Vec::new();
    // the server closes without close_notify when it drops the socket; what was read is still valid
    let _ = tls.read_to_end(&mut body);
    if body.is_empty() {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

#[test]
fn webdav_over_https() {
    use cas::dav::Dav;
    use cas::http::HttpServer;

    let pki = Pki::new(&["127.0.0.1"]);
    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("a.txt"), b"hello tls").unwrap();
    let d = tempfile::tempdir().unwrap();
    let mut st = Store::open(d.path(), cfg()).unwrap();
    st.snapshot_dir(src.path(), Some("one")).unwrap();

    let server = Server::bind(st, "127.0.0.1:0", ServeOptions::default()).unwrap();
    let h = HttpServer::bind("127.0.0.1:0", std::sync::Arc::new(Dav::new(server.shared(), None)))
        .unwrap()
        .with_tls(pki.server())
        .with_idle(Duration::from_secs(2));
    let port = h.local_addr().unwrap().port();
    let stop = h.stop_flag();
    let t = std::thread::spawn(move || h.run());

    let ca = pki.dir.path().join("c.pem");
    let page = https_get(port, "127.0.0.1", "/one/a.txt", &ca).unwrap();
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    assert!(page.ends_with("hello tls"));

    // a keep-alive-less request for a directory listing works the same way
    let idx = https_get(port, "127.0.0.1", "/one/", &ca).unwrap();
    assert!(idx.contains("a.txt"));

    // the wrong CA is refused during the handshake
    let other = Pki::new(&["127.0.0.1"]);
    assert!(https_get(port, "127.0.0.1", "/", &other.dir.path().join("c.pem")).is_err());

    // plain HTTP to the HTTPS port gets no usable answer
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    std::io::Write::write_all(&mut s, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut buf = Vec::new();
    let _ = std::io::Read::read_to_end(&mut s, &mut buf);
    assert!(!String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 200"));

    stop.store(true, Ordering::Relaxed);
    t.join().unwrap().unwrap();
}
