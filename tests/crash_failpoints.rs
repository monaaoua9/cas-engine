//! Deterministic crash tests. The `cas` binary is built with the `failpoints`
//! feature and exits without cleanup at a named point, then we reopen the
//! store and check what survived.
//!
//!     cargo test --features failpoints --test crash_failpoints

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CRASHED: i32 = 86;

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

fn cas(store: &Path, args: &[&str], failpoint: Option<&str>) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_cas"));
    c.arg("-s").arg(store).args(args);
    if let Some(p) = failpoint {
        c.env("CAS_FAILPOINT", p);
    }
    c.output().unwrap()
}

fn ok(store: &Path, args: &[&str]) -> String {
    let o = cas(store, args, None);
    assert!(o.status.success(), "{args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap().trim().to_string()
}

fn file(dir: &Path, name: &str, len: usize, seed: u64) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, noise(len, seed)).unwrap();
    p
}

fn get(store: &Path, id: &str, out: &Path) -> bool {
    cas(store, &["get", id, out.to_str().unwrap()], None).status.success()
}

fn dead_chunks(store: &Path) -> u64 {
    let s = ok(store, &["stats"]);
    let line = s.lines().find(|l| l.starts_with("dead chunks")).unwrap();
    line.split_whitespace().nth(2).unwrap().parse().unwrap()
}

/// Reopen after a crash and check everything that should hold regardless of
/// where the crash landed.
fn assert_healthy(store: &Path, committed: &[(&str, &Path)]) {
    ok(store, &["verify"]);
    let scratch = tempfile::tempdir().unwrap();
    for (id, src) in committed {
        let out = scratch.path().join("out");
        assert!(get(store, id, &out), "{id} unreadable");
        assert_eq!(fs::read(&out).unwrap(), fs::read(src).unwrap());
    }
    // gc must neither lose committed data nor choke on leftovers
    ok(store, &["gc"]);
    for (id, src) in committed {
        let out = scratch.path().join("out2");
        assert!(get(store, id, &out));
        assert_eq!(fs::read(&out).unwrap(), fs::read(src).unwrap());
    }
    ok(store, &["verify"]);
}

fn put_crash(point: &str, survives: bool) {
    let work = tempfile::tempdir().unwrap();
    let store = work.path().join("s");
    let a = file(work.path(), "a", 3 << 20, 1);
    let b = file(work.path(), "b", 3 << 20, 2);

    let id_a = ok(&store, &["put", a.to_str().unwrap()]);
    let id_b = ok(&work.path().join("ref"), &["put", b.to_str().unwrap()]);

    let o = cas(&store, &["put", b.to_str().unwrap()], Some(point));
    assert_eq!(o.status.code(), Some(CRASHED), "failpoint {point} never fired");

    // is B visible?
    let listing = ok(&store, &["ls"]);
    assert_eq!(listing.contains(&id_b), survives, "{point}: ls = {listing}");

    if survives {
        assert_healthy(&store, &[(&id_a, &a), (&id_b, &b)]);
    } else {
        assert_healthy(&store, &[(&id_a, &a)]);
        assert_eq!(dead_chunks(&store), 0, "orphan chunks should be collectable");
    }

    // retrying the put after a crash must converge on the same object
    assert_eq!(ok(&store, &["put", b.to_str().unwrap()]), id_b);
    assert_healthy(&store, &[(&id_a, &a), (&id_b, &b)]);
}

#[test]
fn crash_after_chunks_before_manifest() {
    put_crash("put:chunks_written", false);
}

#[test]
fn crash_after_manifest_rename_before_refcounts() {
    // the dangerous one: object is visible but refcounts were never bumped
    put_crash("put:manifest_renamed", true);
}

#[test]
fn crash_after_refcounts() {
    put_crash("put:refs_bumped", true);
}

#[test]
fn crash_during_remove() {
    let work = tempfile::tempdir().unwrap();
    let store = work.path().join("s");
    let a = file(work.path(), "a", 3 << 20, 3);
    let b = file(work.path(), "b", 3 << 20, 4);
    let id_a = ok(&store, &["put", a.to_str().unwrap()]);
    let id_b = ok(&store, &["put", b.to_str().unwrap()]);

    let o = cas(&store, &["rm", &id_a], Some("rm:manifest_deleted"));
    assert_eq!(o.status.code(), Some(CRASHED));

    assert!(!ok(&store, &["ls"]).contains(&id_a));
    assert_healthy(&store, &[(&id_b, &b)]);
    assert_eq!(dead_chunks(&store), 0);
}

fn gc_crash(point: &str) {
    let work = tempfile::tempdir().unwrap();
    let store = work.path().join("s");
    let a = file(work.path(), "a", 3 << 20, 5);
    let b = file(work.path(), "b", 3 << 20, 6);
    let id_a = ok(&store, &["put", a.to_str().unwrap()]);
    let id_b = ok(&store, &["put", b.to_str().unwrap()]);
    ok(&store, &["rm", &id_a]);

    let o = cas(&store, &["gc"], Some(point));
    assert_eq!(o.status.code(), Some(CRASHED), "failpoint {point} never fired");

    assert_healthy(&store, &[(&id_b, &b)]);
    assert_eq!(dead_chunks(&store), 0);
}

#[test]
fn crash_in_gc_after_copy_before_unlink() {
    gc_crash("gc:copied");
}

#[test]
fn crash_in_gc_after_unlink() {
    gc_crash("gc:unlinked_one");
}

// every chunk already on disk (unreferenced), so the crashed put touches no
// index slot except the refcounts it never got to bump
#[test]
fn crash_on_dedup_only_put_does_not_lose_data() {
    let work = tempfile::tempdir().unwrap();
    let store = work.path().join("s");
    let a = file(work.path(), "a", 3 << 20, 7);

    let id = ok(&store, &["put", a.to_str().unwrap()]);
    ok(&store, &["rm", &id]);

    let o = cas(&store, &["put", a.to_str().unwrap()], Some("put:manifest_renamed"));
    assert_eq!(o.status.code(), Some(CRASHED));

    assert_healthy(&store, &[(&id, &a)]);
}
