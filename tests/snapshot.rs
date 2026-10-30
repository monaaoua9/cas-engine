use std::fs;
use std::path::Path;

use cas::backup::ChangeKind;
use cas::{ChunkerConfig, Error, Retention, Store, StoreConfig};

fn cfg() -> StoreConfig {
    StoreConfig {
        chunker: ChunkerConfig { min_size: 1 << 10, avg_size: 4 << 10, max_size: 16 << 10, ..ChunkerConfig::default() },
        segment_size: 64 << 10,
        gc_threshold: 0.3,
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

fn sample_tree(root: &Path) {
    fs::create_dir_all(root.join("docs/deep/er")).unwrap();
    fs::create_dir_all(root.join("empty")).unwrap();
    fs::write(root.join("a.bin"), noise(50_000, 1)).unwrap();
    fs::write(root.join("zero"), b"").unwrap();
    fs::write(root.join("docs/b.txt"), b"hello").unwrap();
    fs::write(root.join("docs/deep/c.bin"), noise(9_000, 2)).unwrap();
    fs::write(root.join("docs/deep/er/d.bin"), noise(30_000, 3)).unwrap();
}

// every regular file under a, byte for byte, exists under b and the other way round
fn same_tree(a: &Path, b: &Path) {
    fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, Option<Vec<u8>>)>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            if p.is_dir() {
                out.push((rel, None));
                collect(root, &p, out);
            } else {
                out.push((rel, Some(fs::read(&p).unwrap())));
            }
        }
    }
    let (mut x, mut y) = (Vec::new(), Vec::new());
    collect(a, a, &mut x);
    collect(b, b, &mut y);
    x.sort();
    y.sort();
    assert_eq!(x, y);
}

#[test]
fn snapshot_then_restore_is_identical() {
    let src = tempfile::tempdir().unwrap();
    sample_tree(src.path());
    let st = tempfile::tempdir().unwrap();
    let mut s = Store::open(st.path(), cfg()).unwrap();

    let rep = s.snapshot_dir(src.path(), Some("first")).unwrap();
    assert_eq!(rep.files, 5);
    assert_eq!(rep.dirs, 4);
    assert_eq!(rep.bytes, 50_000 + 9_000 + 30_000 + 5);

    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("restored");
    let r = s.snapshot_restore("first", &dest).unwrap();
    assert_eq!((r.files, r.dirs), (5, 4));
    same_tree(src.path(), &dest);
    s.snapshot_verify("first").unwrap();
}

#[test]
fn second_snapshot_of_unchanged_dir_stores_nothing_new() {
    let src = tempfile::tempdir().unwrap();
    sample_tree(src.path());
    let st = tempfile::tempdir().unwrap();
    let mut s = Store::open(st.path(), cfg()).unwrap();

    let a = s.snapshot_dir(src.path(), Some("a")).unwrap();
    let b = s.snapshot_dir(src.path(), Some("b")).unwrap();
    assert_eq!(a.root, b.root);
    assert_eq!(b.new_bytes, 0);
    assert!(s.snapshot_diff("a", "b").unwrap().is_empty());
}

#[test]
fn diff_reports_each_kind_of_change() {
    let src = tempfile::tempdir().unwrap();
    sample_tree(src.path());
    let st = tempfile::tempdir().unwrap();
    let mut s = Store::open(st.path(), cfg()).unwrap();
    s.snapshot_dir(src.path(), Some("before")).unwrap();

    fs::write(src.path().join("docs/b.txt"), b"hello world").unwrap();
    fs::remove_file(src.path().join("a.bin")).unwrap();
    fs::create_dir(src.path().join("fresh")).unwrap();
    fs::write(src.path().join("fresh/x"), b"x").unwrap();
    fs::remove_dir_all(src.path().join("empty")).unwrap();
    s.snapshot_dir(src.path(), Some("after")).unwrap();

    let mut got: Vec<(String, ChangeKind)> =
        s.snapshot_diff("before", "after").unwrap().into_iter().map(|c| (c.path, c.kind)).collect();
    got.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        got,
        vec![
            ("a.bin".to_string(), ChangeKind::Removed),
            ("docs/b.txt".to_string(), ChangeKind::Modified),
            ("empty".to_string(), ChangeKind::Removed),
            ("fresh".to_string(), ChangeKind::Added),
        ]
    );
}

#[test]
fn restore_refuses_a_non_empty_destination() {
    let src = tempfile::tempdir().unwrap();
    sample_tree(src.path());
    let st = tempfile::tempdir().unwrap();
    let mut s = Store::open(st.path(), cfg()).unwrap();
    s.snapshot_dir(src.path(), Some("s")).unwrap();

    let out = tempfile::tempdir().unwrap();
    fs::write(out.path().join("keep"), b"mine").unwrap();
    assert!(matches!(s.snapshot_restore("s", out.path()), Err(Error::DestNotEmpty(_))));
    assert_eq!(fs::read(out.path().join("keep")).unwrap(), b"mine");
}

#[test]
fn duplicate_and_bad_names() {
    let src = tempfile::tempdir().unwrap();
    sample_tree(src.path());
    let st = tempfile::tempdir().unwrap();
    let mut s = Store::open(st.path(), cfg()).unwrap();
    s.snapshot_dir(src.path(), Some("one")).unwrap();
    assert!(matches!(s.snapshot_dir(src.path(), Some("one")), Err(Error::SnapshotExists(_))));
    assert!(matches!(s.snapshot_dir(src.path(), Some("../evil")), Err(Error::InvalidName(_))));
    assert!(matches!(s.snapshot_get("nope"), Err(Error::SnapshotNotFound(_))));
    assert_eq!(s.snapshot_list().unwrap().len(), 1);
}

#[test]
fn forget_releases_only_what_nobody_else_needs() {
    let src = tempfile::tempdir().unwrap();
    sample_tree(src.path());
    let st = tempfile::tempdir().unwrap();
    let mut s = Store::open(st.path(), cfg()).unwrap();

    s.snapshot_dir(src.path(), Some("a")).unwrap();
    fs::write(src.path().join("new.bin"), noise(20_000, 9)).unwrap();
    s.snapshot_dir(src.path(), Some("b")).unwrap();
    let with_both = s.list().unwrap().len();

    // a's objects are all shared with b, except a's root tree
    let f = s.snapshot_forget("a").unwrap();
    assert_eq!(f.objects_removed, 1);
    s.snapshot_verify("b").unwrap();
    assert_eq!(s.list().unwrap().len(), with_both - 1);

    let out = tempfile::tempdir().unwrap();
    s.snapshot_restore("b", out.path().join("r")).unwrap();
    same_tree(src.path(), &out.path().join("r"));

    s.snapshot_forget("b").unwrap();
    assert!(s.list().unwrap().is_empty());
    assert!(s.snapshot_list().unwrap().is_empty());
}

#[test]
fn forget_leaves_objects_that_were_stored_by_hand() {
    let src = tempfile::tempdir().unwrap();
    sample_tree(src.path());
    let st = tempfile::tempdir().unwrap();
    let mut s = Store::open(st.path(), cfg()).unwrap();

    let mine = s.put_bytes(&noise(50_000, 1)).unwrap().id; // same bytes as a.bin
    s.snapshot_dir(src.path(), Some("s")).unwrap();
    s.snapshot_forget("s").unwrap();

    assert!(s.contains(&mine));
    assert_eq!(s.list().unwrap(), vec![mine]);
}

#[test]
fn snapshots_survive_reopen_and_gc() {
    let src = tempfile::tempdir().unwrap();
    sample_tree(src.path());
    let st = tempfile::tempdir().unwrap();
    {
        let mut s = Store::open(st.path(), cfg()).unwrap();
        s.snapshot_dir(src.path(), Some("keep")).unwrap();
        fs::write(src.path().join("tmp.bin"), noise(100_000, 7)).unwrap();
        s.snapshot_dir(src.path(), Some("drop")).unwrap();
        s.snapshot_forget("drop").unwrap();
        s.gc().unwrap();
    }
    let s = Store::open(st.path(), cfg()).unwrap();
    s.snapshot_verify("keep").unwrap();
    assert_eq!(s.snapshot_list().unwrap().len(), 1);
}

#[test]
fn prune_applies_policy_and_dry_run_changes_nothing() {
    let src = tempfile::tempdir().unwrap();
    sample_tree(src.path());
    let st = tempfile::tempdir().unwrap();
    let mut s = Store::open(st.path(), cfg()).unwrap();
    for n in ["s1", "s2", "s3", "s4"] {
        fs::write(src.path().join("marker"), n).unwrap();
        s.snapshot_dir(src.path(), Some(n)).unwrap();
    }
    let p = Retention { last: 2, ..Default::default() };

    // all four were taken within the same second; ties break on name
    let dry = s.snapshot_prune(&p, true).unwrap();
    assert_eq!(dry, ["s1", "s2"]);
    assert_eq!(s.snapshot_list().unwrap().len(), 4);

    let gone = s.snapshot_prune(&p, false).unwrap();
    assert_eq!(gone, ["s1", "s2"]);
    let left: Vec<String> = s.snapshot_list().unwrap().into_iter().map(|x| x.name).collect();
    assert_eq!(left, ["s3", "s4"]);
    s.snapshot_verify("s3").unwrap();
    s.snapshot_verify("s4").unwrap();

    assert!(s.snapshot_prune(&Retention::default(), false).is_err());
}

#[test]
fn corrupt_record_is_detected() {
    let src = tempfile::tempdir().unwrap();
    sample_tree(src.path());
    let st = tempfile::tempdir().unwrap();
    let mut s = Store::open(st.path(), cfg()).unwrap();
    s.snapshot_dir(src.path(), Some("x")).unwrap();

    let p = st.path().join("snapshots/x.snap");
    let mut b = fs::read(&p).unwrap();
    b[20] ^= 1;
    fs::write(&p, b).unwrap();
    assert!(matches!(s.snapshot_get("x"), Err(Error::CorruptSnapshot(_))));
}

#[test]
fn verify_catches_a_missing_object() {
    let src = tempfile::tempdir().unwrap();
    sample_tree(src.path());
    let st = tempfile::tempdir().unwrap();
    let mut s = Store::open(st.path(), cfg()).unwrap();
    s.snapshot_dir(src.path(), Some("x")).unwrap();

    let snap = s.snapshot_get("x").unwrap();
    let victim = s.flatten(&snap.root).unwrap().into_iter().find(|(p, _)| p == "a.bin").unwrap().1.id;
    s.remove(&victim).unwrap();
    assert!(s.snapshot_verify("x").is_err());
}

#[cfg(unix)]
#[test]
fn symlinks_and_modes_roundtrip() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let src = tempfile::tempdir().unwrap();
    sample_tree(src.path());
    symlink("docs/b.txt", src.path().join("link")).unwrap();
    fs::set_permissions(src.path().join("a.bin"), fs::Permissions::from_mode(0o600)).unwrap();

    let st = tempfile::tempdir().unwrap();
    let mut s = Store::open(st.path(), cfg()).unwrap();
    let rep = s.snapshot_dir(src.path(), Some("x")).unwrap();
    assert_eq!(rep.symlinks, 1);

    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("r");
    s.snapshot_restore("x", &dest).unwrap();
    assert_eq!(fs::read_link(dest.join("link")).unwrap().to_str().unwrap(), "docs/b.txt");
    assert_eq!(fs::metadata(dest.join("a.bin")).unwrap().permissions().mode() & 0o777, 0o600);
}
