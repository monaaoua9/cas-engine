use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Command, Output};

fn cas(store: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cas")).arg("-s").arg(store).args(args).output().unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn sample(dir: &Path, len: usize, seed: u64) -> std::path::PathBuf {
    let mut x = seed | 1;
    let data: Vec<u8> = (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect();
    let p = dir.join(format!("f{seed}"));
    fs::write(&p, data).unwrap();
    p
}

#[test]
fn json_output_for_put_ls_stats_check() {
    let d = tempfile::tempdir().unwrap();
    let st = d.path().join("st");
    let f = sample(d.path(), 200_000, 3);

    let o = cas(&st, &["--json", "put", f.to_str().unwrap()]);
    assert!(o.status.success());
    let j = out(&o);
    assert!(j.starts_with("{\"id\":\"") && j.contains("\"size\":200000") && j.contains("\"existed\":false"), "{j}");
    assert_eq!(j.trim().lines().count(), 1);

    let ls = out(&cas(&st, &["--json", "ls"]));
    assert!(ls.starts_with("[{\"id\":\"") && ls.contains("\"size\":200000"));

    let stats = out(&cas(&st, &["--json", "stats"]));
    assert!(
        stats.contains("\"objects\":1")
            && stats.contains("\"encrypted\":false")
            && stats.contains("\"max_bytes\":null")
    );

    let chk = cas(&st, &["--json", "check"]);
    assert!(chk.status.success());
    assert_eq!(out(&chk).trim(), r#"{"ok":true,"bad_manifests":[],"corrupt_chunks":[],"missing_chunks":[]}"#);
}

#[test]
fn text_output_is_unchanged() {
    let d = tempfile::tempdir().unwrap();
    let st = d.path().join("st");
    let f = sample(d.path(), 50_000, 5);

    let o = cas(&st, &["put", f.to_str().unwrap()]);
    let id = out(&o).trim().to_string();
    assert_eq!(id.len(), 64);
    assert!(err(&o).contains("in 1 chunks") || err(&o).contains("chunks"));
    assert!(out(&cas(&st, &["ls"])).starts_with(&id));
    assert_eq!(out(&cas(&st, &["verify", &id])).trim(), "ok");
}

#[test]
fn size_limit_refuses_writes_with_a_clear_error() {
    let d = tempfile::tempdir().unwrap();
    let st = d.path().join("st");
    let f = sample(d.path(), 300_000, 7);

    let o = cas(&st, &["--max-size", "100K", "put", f.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("store is full"), "{}", err(&o));

    let o = cas(&st, &["--max-size", "banana", "ls"]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn check_and_repair_through_the_cli() {
    let d = tempfile::tempdir().unwrap();
    let (a, b) = (d.path().join("a"), d.path().join("b"));
    let f = sample(d.path(), 400_000, 9);
    let id = out(&cas(&a, &["put", f.to_str().unwrap()])).trim().to_string();

    // replica = copy of the directory
    fs::create_dir_all(b.join("segments")).unwrap();
    fs::create_dir_all(b.join("manifests")).unwrap();
    for sub in ["segments", "manifests"] {
        for e in fs::read_dir(a.join(sub)).unwrap() {
            let e = e.unwrap();
            fs::copy(e.path(), b.join(sub).join(e.file_name())).unwrap();
        }
    }
    for name in ["FORMAT", "index.bin"] {
        fs::copy(a.join(name), b.join(name)).unwrap();
    }

    let seg = fs::read_dir(a.join("segments")).unwrap().next().unwrap().unwrap().path();
    let mut h = OpenOptions::new().write(true).open(seg).unwrap();
    h.seek(SeekFrom::Start(500)).unwrap();
    h.write_all(&[0xEE]).unwrap();
    drop(h);

    let o = cas(&a, &["check"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(out(&o).contains("corrupt"));
    assert_eq!(cas(&a, &["verify", &id]).status.code(), Some(2));

    let o = cas(&a, &["repair", "--from", b.to_str().unwrap()]);
    assert!(o.status.success(), "{} {}", out(&o), err(&o));
    assert!(out(&o).contains("fixed 1 chunks"));
    assert!(cas(&a, &["check"]).status.success());

    let back = d.path().join("back");
    assert!(cas(&a, &["get", &id, back.to_str().unwrap()]).status.success());
    assert_eq!(fs::read(back).unwrap(), fs::read(f).unwrap());
}

#[test]
fn metrics_output() {
    let d = tempfile::tempdir().unwrap();
    let st = d.path().join("st");
    cas(&st, &["put", sample(d.path(), 60_000, 11).to_str().unwrap()]);
    let m = out(&cas(&st, &["--max-size", "1M", "metrics"]));
    assert!(m.contains("cas_objects 1\n"));
    assert!(m.contains("cas_quota_bytes 1048576\n"));
    assert!(m.contains("# TYPE cas_dedup_ratio gauge"));
}

#[test]
fn bench_runs_and_cleans_up() {
    let d = tempfile::tempdir().unwrap();
    let o = cas(&d.path().join("unused"), &["--json", "bench", "--size", "2M"]);
    assert!(o.status.success(), "{}", err(&o));
    let j = out(&o);
    assert!(j.contains("\"bytes\":2097152") && j.contains("\"put_mib_s\":"), "{j}");
    // bench works in a scratch directory and never creates the store it was pointed at
    assert!(!d.path().join("unused").exists());
}

#[test]
fn snapshot_json() {
    let d = tempfile::tempdir().unwrap();
    let st = d.path().join("st");
    let src = d.path().join("src");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("a"), b"hello").unwrap();
    fs::write(src.join("sub/b"), b"world").unwrap();

    let j = out(&cas(&st, &["--json", "snapshot", "create", src.to_str().unwrap(), "-n", "one"]));
    assert!(j.contains("\"name\":\"one\"") && j.contains("\"files\":2") && j.contains("\"dirs\":1"), "{j}");

    fs::write(src.join("a"), b"hello again").unwrap();
    cas(&st, &["snapshot", "create", src.to_str().unwrap(), "-n", "two"]);
    let o = cas(&st, &["--json", "snapshot", "diff", "one", "two"]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(out(&o).trim(), r#"[{"change":"~","path":"a"}]"#);

    let show = out(&cas(&st, &["--json", "snapshot", "show", "one"]));
    assert!(show.contains("\"path\":\"sub/b\"") && show.contains("\"kind\":\"dir\""));
}
