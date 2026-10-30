use std::fs;
use std::process::Command;

use cas::{ChunkerConfig, Error, Kind, Store, StoreConfig};

fn cfg() -> StoreConfig {
    StoreConfig {
        chunker: ChunkerConfig { min_size: 1 << 10, avg_size: 4 << 10, max_size: 16 << 10, ..ChunkerConfig::default() },
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

fn store() -> (tempfile::TempDir, Store) {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path(), cfg()).unwrap();
    (d, s)
}

// hand-made header; `size` is the raw 12 byte field so tests can use odd encodings
fn raw(name: &str, kind: u8, size: &[u8; 12], link: &str) -> Vec<u8> {
    let mut h = vec![0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(b"0000644\0");
    h[124..136].copy_from_slice(size);
    h[136..148].copy_from_slice(b"00000000000\0");
    h[156] = kind;
    h[157..157 + link.len()].copy_from_slice(link.as_bytes());
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

fn octal(n: usize) -> [u8; 12] {
    let mut f = [0u8; 12];
    f[..11].copy_from_slice(format!("{n:011o}").as_bytes());
    f
}

fn push_file(tar: &mut Vec<u8>, name: &str, data: &[u8]) {
    tar.extend(raw(name, b'0', &octal(data.len()), ""));
    tar.extend_from_slice(data);
    tar.resize(tar.len().div_ceil(512) * 512, 0);
}

fn finish(mut tar: Vec<u8>) -> Vec<u8> {
    tar.extend([0u8; 1024]);
    tar
}

fn paths(st: &Store, snap: &str) -> Vec<(String, Kind, u64)> {
    let s = st.snapshot_get(snap).unwrap();
    st.flatten(&s.root).unwrap().into_iter().map(|(p, e)| (p, e.kind, e.size)).collect()
}

#[test]
fn export_then_import_gives_the_same_tree() {
    let src = tempfile::tempdir().unwrap();
    let long: String = (0..5).map(|i| format!("{}{i}", "d".repeat(60))).collect::<Vec<_>>().join("/");
    fs::create_dir_all(src.path().join(&long)).unwrap();
    fs::create_dir_all(src.path().join("sub/empty-dir")).unwrap();
    fs::write(src.path().join(&long).join("deep.bin"), noise(30_000, 2)).unwrap();
    fs::write(src.path().join("top.txt"), b"top").unwrap();
    fs::write(src.path().join("sub/نص.txt"), "مرحبا").unwrap();
    fs::write(src.path().join("zero"), b"").unwrap();
    fs::write(src.path().join("big"), noise(200_000, 9)).unwrap();

    let (_a, mut a) = store();
    a.snapshot_dir(src.path(), Some("one")).unwrap();
    let mut buf = Vec::new();
    let rep = a.export_tar("one", &mut buf).unwrap();
    assert_eq!(rep.files, 5);
    assert_eq!(buf.len() % 512, 0);

    let (_b, mut b) = store();
    let r = b.import_tar(&buf[..], Some("two")).unwrap();
    assert_eq!(r.files, 5);
    assert!(r.skipped.is_empty());
    assert_eq!(paths(&a, "one"), paths(&b, "two"));

    // file contents dedupe to the same objects even though tar drops nanosecond mtimes
    let ids = |st: &Store, n: &str| {
        let s = st.snapshot_get(n).unwrap();
        st.flatten(&s.root)
            .unwrap()
            .into_iter()
            .filter(|(_, e)| e.kind == Kind::File)
            .map(|(p, e)| (p, e.id))
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&a, "one"), ids(&b, "two"));
    b.snapshot_verify("two").unwrap();

    let out = tempfile::tempdir().unwrap();
    b.snapshot_restore("two", out.path().join("r")).unwrap();
    assert_eq!(fs::read(out.path().join("r").join(&long).join("deep.bin")).unwrap(), noise(30_000, 2));
    assert_eq!(fs::read_to_string(out.path().join("r/sub/نص.txt")).unwrap(), "مرحبا");
    assert!(out.path().join("r/sub/empty-dir").is_dir());
}

#[test]
fn importing_twice_stores_nothing_new() {
    let mut tar = Vec::new();
    push_file(&mut tar, "a", &noise(40_000, 1));
    let tar = finish(tar);

    let (_d, mut st) = store();
    st.import_tar(&tar[..], Some("x")).unwrap();
    let r = st.import_tar(&tar[..], Some("y")).unwrap();
    assert_eq!(r.new_bytes, 0);
}

#[test]
fn base256_sizes_and_missing_parents_are_accepted() {
    let mut size = [0u8; 12];
    size[0] = 0x80;
    size[11] = 5;
    let mut tar = raw("a/b/c.txt", b'0', &size, "");
    tar.extend_from_slice(b"hello");
    tar.resize(1024, 0);

    let (_d, mut st) = store();
    st.import_tar(&finish(tar)[..], Some("s")).unwrap();
    let p = paths(&st, "s");
    assert_eq!(p.iter().map(|x| x.0.as_str()).collect::<Vec<_>>(), ["a", "a/b", "a/b/c.txt"]);
    assert_eq!(p[2].2, 5);
}

#[test]
fn gnu_long_names_and_links_and_pax_paths() {
    let long = format!("{}/{}", "p".repeat(120), "q".repeat(120));
    let mut tar = Vec::new();

    // GNU 'L' record
    let mut data = long.clone().into_bytes();
    data.push(0);
    tar.extend(raw("././@LongLink", b'L', &octal(data.len()), ""));
    tar.extend_from_slice(&data);
    tar.resize(tar.len().div_ceil(512) * 512, 0);
    push_file(&mut tar, "truncated-name", b"gnu");

    // pax path
    let rec = "26 path=from-pax/file.txt
";
    tar.extend(raw("PaxHeader", b'x', &octal(rec.len()), ""));
    tar.extend_from_slice(rec.as_bytes());
    tar.resize(tar.len().div_ceil(512) * 512, 0);
    push_file(&mut tar, "ignored", b"pax");

    // symlink with a long target via 'K'
    let target = "t".repeat(150);
    let mut kd = target.clone().into_bytes();
    kd.push(0);
    tar.extend(raw("././@LongLink", b'K', &octal(kd.len()), ""));
    tar.extend_from_slice(&kd);
    tar.resize(tar.len().div_ceil(512) * 512, 0);
    tar.extend(raw("link", b'2', &octal(0), ""));

    let (_d, mut st) = store();
    let r = st.import_tar(&finish(tar)[..], Some("s")).unwrap();
    assert_eq!((r.files, r.symlinks), (2, 1));
    let s = st.snapshot_get("s").unwrap();
    let flat = st.flatten(&s.root).unwrap();
    let find = |p: &str| flat.iter().find(|(n, _)| n == p).map(|(_, e)| e.clone());
    assert_eq!(st.read_to_vec(&find(&long).unwrap().id).unwrap(), b"gnu");
    assert_eq!(st.read_to_vec(&find("from-pax/file.txt").unwrap().id).unwrap(), b"pax");
    assert_eq!(find("link").unwrap().target, target);
}

#[test]
fn hostile_paths_are_skipped_not_followed() {
    let mut tar = Vec::new();
    push_file(&mut tar, "../escape", b"x");
    push_file(&mut tar, "a/../../escape2", b"x");
    push_file(&mut tar, "back\\slash", b"x");
    push_file(&mut tar, "/abs/ok", b"fine");
    tar.extend(raw("dev", b'3', &octal(0), ""));

    let (_d, mut st) = store();
    let r = st.import_tar(&finish(tar)[..], Some("s")).unwrap();
    assert_eq!(r.skipped.len(), 4);
    let names: Vec<_> = paths(&st, "s").into_iter().map(|x| x.0).collect();
    assert_eq!(names, ["abs", "abs/ok"]);
}

#[test]
fn malformed_archives_are_errors_and_leave_no_snapshot() {
    let mut good = Vec::new();
    push_file(&mut good, "f", &noise(5_000, 4));
    let good = finish(good);

    let (_d, mut st) = store();

    // flipped checksum
    let mut bad = good.clone();
    bad[148] = b'9';
    assert!(matches!(st.import_tar(&bad[..], Some("a")), Err(Error::BadTar(_))));

    // cut in the middle of the data
    assert!(matches!(st.import_tar(&good[..512 + 1000], Some("b")), Err(Error::BadTar(_))));

    // cut in the middle of a header
    assert!(matches!(st.import_tar(&good[..100], Some("c")), Err(Error::BadTar(_))));

    // size field claims far more than is there
    let mut huge = raw("f", b'0', &octal(1 << 30), "");
    huge.extend_from_slice(&[7u8; 600]);
    assert!(st.import_tar(&huge[..], Some("d")).is_err());

    // garbage in the size field
    let mut junk = raw("f", b'0', b"zzzzzzzzzzz\0", "");
    junk.extend([0u8; 1024]);
    assert!(st.import_tar(&junk[..], Some("e")).is_err());

    // oversized long-name record is refused before it is read
    let mut big = raw("././@LongLink", b'L', &octal(50 << 20), "");
    big.extend([0u8; 1024]);
    assert!(st.import_tar(&big[..], Some("g")).is_err());

    assert!(st.snapshot_list().unwrap().is_empty());
}

#[test]
fn empty_input_is_an_empty_snapshot() {
    let (_d, mut st) = store();
    let r = st.import_tar(&[][..], Some("e")).unwrap();
    assert_eq!((r.files, r.dirs), (0, 0));
    assert!(paths(&st, "e").is_empty());
}

#[test]
fn existing_name_is_refused_before_reading() {
    let (_d, mut st) = store();
    st.import_tar(&[][..], Some("e")).unwrap();
    assert!(matches!(st.import_tar(&[][..], Some("e")), Err(Error::SnapshotExists(_))));
}

fn have_tar() -> bool {
    Command::new("tar").arg("--version").output().is_ok_and(|o| o.status.success())
}

#[test]
fn system_tar_reads_our_archives_and_we_read_theirs() {
    if !have_tar() {
        return;
    }
    let src = tempfile::tempdir().unwrap();
    let long = format!("{}/{}", "x".repeat(90), "y".repeat(90));
    fs::create_dir_all(src.path().join(&long)).unwrap();
    fs::write(src.path().join(&long).join("f.bin"), noise(70_000, 6)).unwrap();
    fs::write(src.path().join("small"), b"s").unwrap();

    let work = tempfile::tempdir().unwrap();
    let (_a, mut a) = store();
    a.snapshot_dir(src.path(), Some("one")).unwrap();
    let ours = work.path().join("ours.tar");
    a.export_tar("one", fs::File::create(&ours).unwrap()).unwrap();

    let ex = work.path().join("ex");
    fs::create_dir(&ex).unwrap();
    let st = Command::new("tar").arg("-xf").arg(&ours).arg("-C").arg(&ex).status().unwrap();
    assert!(st.success());
    assert_eq!(fs::read(ex.join(&long).join("f.bin")).unwrap(), noise(70_000, 6));

    let theirs = work.path().join("theirs.tar");
    let st = Command::new("tar").arg("-cf").arg(&theirs).arg("-C").arg(src.path()).arg(".").status().unwrap();
    assert!(st.success());
    let (_b, mut b) = store();
    b.import_tar(fs::File::open(&theirs).unwrap(), Some("t")).unwrap();
    assert_eq!(paths(&a, "one"), paths(&b, "t"));
}
