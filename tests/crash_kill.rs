//! Hard-kill tests: no cooperation from the process, the child is just
//! terminated at an arbitrary moment. Timing based, so it explores different
//! crash points on every run instead of the fixed ones in crash_failpoints.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

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

fn cas(store: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_cas"));
    c.arg("-s").arg(store).stdout(Stdio::piped()).stderr(Stdio::piped());
    c
}

fn ok(store: &Path, args: &[&str]) -> String {
    let o = cas(store).args(args).output().unwrap();
    assert!(o.status.success(), "{args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap().trim().to_string()
}

fn kill_after(store: &Path, args: &[&str], ms: u64) {
    let mut child = cas(store).args(args).spawn().unwrap();
    sleep(Duration::from_millis(ms));
    let _ = child.kill();
    let _ = child.wait();
}

fn assert_readable(store: &Path, id: &str, want: &[u8]) {
    let out = store.with_extension("out");
    ok(store, &["get", id, out.to_str().unwrap()]);
    assert_eq!(fs::read(&out).unwrap(), want);
}

#[test]
fn killed_during_put_never_corrupts_committed_data() {
    let work = tempfile::tempdir().unwrap();
    let store = work.path().join("s");
    let small = noise(2 << 20, 1);
    let big = noise(24 << 20, 2);
    let small_path = work.path().join("small");
    let big_path = work.path().join("big");
    fs::write(&small_path, &small).unwrap();
    fs::write(&big_path, &big).unwrap();

    let id_small = ok(&store, &["put", small_path.to_str().unwrap()]);
    let id_big = ok(&work.path().join("ref"), &["put", big_path.to_str().unwrap()]);

    for ms in [5, 30, 90, 200, 400, 800, 1500] {
        kill_after(&store, &["put", big_path.to_str().unwrap()], ms);

        ok(&store, &["verify"]);
        assert_readable(&store, &id_small, &small);
        if ok(&store, &["ls"]).contains(&id_big) {
            assert_readable(&store, &id_big, &big);
        }
    }

    // finish the job for real and make sure the leftovers dedup away
    assert_eq!(ok(&store, &["put", big_path.to_str().unwrap()]), id_big);
    ok(&store, &["gc"]);
    assert_readable(&store, &id_big, &big);
    assert_readable(&store, &id_small, &small);
    ok(&store, &["verify"]);
}

#[test]
fn killed_during_gc_keeps_survivors() {
    for ms in [0, 2, 5, 10, 20, 40, 80] {
        let work = tempfile::tempdir().unwrap();
        let store = work.path().join("s");
        let (a, b) = (noise(5 << 20, 10), noise(5 << 20, 12));
        let (pa, pb) = (work.path().join("a"), work.path().join("b"));
        fs::write(&pa, &a).unwrap();
        fs::write(&pb, &b).unwrap();

        let id_a = ok(&store, &["put", pa.to_str().unwrap()]);
        let id_b = ok(&store, &["put", pb.to_str().unwrap()]);
        ok(&store, &["rm", &id_a]);

        kill_after(&store, &["gc"], ms);

        ok(&store, &["verify"]);
        assert_readable(&store, &id_b, &b);
        ok(&store, &["gc"]);
        assert_readable(&store, &id_b, &b);
        ok(&store, &["verify"]);
    }
}
