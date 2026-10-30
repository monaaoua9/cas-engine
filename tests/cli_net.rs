use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};

fn cas(store: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cas")).arg("-s").arg(store).args(args).output().unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

struct Served {
    child: Child,
    cas: String,
    dav: String,
    metrics: String,
}

impl Drop for Served {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn field(line: &str, key: &str) -> String {
    let k = format!("\"{key}\":\"");
    let i = line.find(&k).unwrap_or_else(|| panic!("no {key} in {line}")) + k.len();
    line[i..i + line[i..].find('"').unwrap()].to_string()
}

fn serve(store: &Path, extra: &[&str]) -> Served {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cas"))
        .arg("-s")
        .arg(store)
        .args([
            "--json",
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--dav-listen",
            "127.0.0.1:0",
            "--metrics-listen",
            "127.0.0.1:0",
        ])
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    Served { cas: field(&line, "cas"), dav: field(&line, "dav"), metrics: field(&line, "metrics"), child }
}

fn http_get(addr: &str, path: &str, extra: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{extra}\r\n").unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    text(&buf)
}

fn tree() -> tempfile::TempDir {
    let src = tempfile::tempdir().unwrap();
    fs::create_dir_all(src.path().join("sub")).unwrap();
    fs::write(src.path().join("a.txt"), b"alpha").unwrap();
    fs::write(src.path().join("sub/b.bin"), vec![7u8; 100_000]).unwrap();
    src
}

#[test]
fn push_and_pull_through_a_served_store() {
    let d = tempfile::tempdir().unwrap();
    let (a, b, c) = (d.path().join("a"), d.path().join("b"), d.path().join("c"));
    let src = tree();
    assert!(cas(&a, &["snapshot", "create", src.path().to_str().unwrap(), "-n", "one"]).status.success());

    let tok = d.path().join("token");
    fs::write(&tok, "hunter2\n").unwrap();
    let tok = tok.to_str().unwrap();

    let srv = serve(&b, &["--token-file", tok]);

    // wrong / missing token is refused
    let o = cas(&a, &["push", &srv.cas]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stderr));

    let o = cas(&a, &["--json", "push", &srv.cas, "--token-file", tok]);
    assert!(o.status.success(), "{}", text(&o.stderr));
    assert!(text(&o.stdout).contains("\"snapshots_sent\":1"), "{}", text(&o.stdout));

    // second push has nothing to do
    let o = cas(&a, &["--json", "push", &srv.cas, "--token-file", tok]);
    assert!(text(&o.stdout).contains("\"chunks_sent\":0"), "{}", text(&o.stdout));

    let o = cas(&c, &["pull", &srv.cas, "--snapshot", "one", "--token-file", tok]);
    assert!(o.status.success(), "{}", text(&o.stderr));
    let dest = d.path().join("restored");
    assert!(cas(&c, &["snapshot", "restore", "one", dest.to_str().unwrap()]).status.success());
    assert_eq!(fs::read(dest.join("sub/b.bin")).unwrap(), vec![7u8; 100_000]);

    // a pull for a name the server does not have is an error
    assert_eq!(cas(&c, &["pull", &srv.cas, "--snapshot", "nope", "--token-file", tok]).status.code(), Some(2));
}

#[test]
fn read_only_server_refuses_push() {
    let d = tempfile::tempdir().unwrap();
    let (a, b) = (d.path().join("a"), d.path().join("b"));
    let src = tree();
    assert!(cas(&a, &["snapshot", "create", src.path().to_str().unwrap(), "-n", "one"]).status.success());

    let srv = serve(&b, &["--read-only"]);
    let o = cas(&a, &["push", &srv.cas]);
    assert_eq!(o.status.code(), Some(2));
    assert!(text(&o.stderr).contains("read-only"), "{}", text(&o.stderr));
}

#[test]
fn webdav_and_metrics_listeners_answer() {
    let d = tempfile::tempdir().unwrap();
    let (a, b) = (d.path().join("a"), d.path().join("b"));
    let src = tree();
    assert!(cas(&a, &["snapshot", "create", src.path().to_str().unwrap(), "-n", "one"]).status.success());

    let srv = serve(&b, &[]);
    assert!(cas(&a, &["push", &srv.cas]).status.success());

    let page = http_get(&srv.dav, "/one/a.txt", "");
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    assert!(page.ends_with("alpha"));

    let m = http_get(&srv.metrics, "/metrics", "");
    assert!(m.starts_with("HTTP/1.1 200") && m.contains("cas_"), "{m}");
    assert!(http_get(&srv.metrics, "/other", "").starts_with("HTTP/1.1 404"));
}

#[test]
fn export_and_import_round_trip_through_files_and_pipes() {
    let d = tempfile::tempdir().unwrap();
    let (a, b) = (d.path().join("a"), d.path().join("b"));
    let src = tree();
    assert!(cas(&a, &["snapshot", "create", src.path().to_str().unwrap(), "-n", "one"]).status.success());

    let tarfile = d.path().join("one.tar");
    let o = cas(&a, &["export", "one", "-o", tarfile.to_str().unwrap()]);
    assert!(o.status.success(), "{}", text(&o.stderr));

    let o = cas(&b, &["--json", "import", tarfile.to_str().unwrap(), "-n", "copy"]);
    assert!(o.status.success(), "{}", text(&o.stderr));
    assert!(text(&o.stdout).contains("\"files\":2"), "{}", text(&o.stdout));

    // stdout carries only the archive
    let piped = cas(&a, &["export", "one"]);
    assert!(piped.status.success());
    assert_eq!(piped.stdout, fs::read(&tarfile).unwrap());

    let mut imp = Command::new(env!("CARGO_BIN_EXE_cas"))
        .arg("-s")
        .arg(&b)
        .args(["import", "-n", "viapipe"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    imp.stdin.take().unwrap().write_all(&piped.stdout).unwrap();
    let o = imp.wait_with_output().unwrap();
    assert!(o.status.success(), "{}", text(&o.stderr));
    assert_eq!(text(&o.stdout).trim(), "viapipe");

    // not a tar at all
    let junk = d.path().join("junk");
    fs::write(&junk, vec![0x41u8; 2000]).unwrap();
    assert_eq!(cas(&b, &["import", junk.to_str().unwrap(), "-n", "bad"]).status.code(), Some(2));
    assert!(!text(&cas(&b, &["snapshot", "ls"]).stdout).contains("bad"));
}

// SIGINT can't be sent to a child portably, so this only runs where `kill` exists
#[cfg(unix)]
#[test]
fn ctrl_c_stops_serve_cleanly_and_the_store_reopens() {
    let d = tempfile::tempdir().unwrap();
    let (a, b) = (d.path().join("a"), d.path().join("b"));
    let src = tree();
    assert!(cas(&a, &["snapshot", "create", src.path().to_str().unwrap(), "-n", "one"]).status.success());

    let mut srv = serve(&b, &[]);
    assert!(cas(&a, &["push", &srv.cas]).status.success());

    let pid = srv.child.id().to_string();
    assert!(Command::new("kill").args(["-INT", &pid]).status().unwrap().success());

    let t = std::time::Instant::now();
    let status = loop {
        if let Some(s) = srv.child.try_wait().unwrap() {
            break s;
        }
        assert!(t.elapsed().as_secs() < 10, "serve ignored SIGINT");
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    assert!(status.success(), "{status:?}");

    // lock released, data intact
    assert!(cas(&b, &["snapshot", "verify", "one"]).status.success());
}
