use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::hash::Hash;
use crate::snapshot::{Member, Retention, Snapshot, keep_set, valid_snapshot_name};
use crate::store::{Store, write_atomic};
use crate::tree::{Entry, Kind, Tree, valid_name};

const MAX_DEPTH: usize = 512;
// a tree bigger than this is not a tree
const MAX_TREE_BYTES: u64 = 64 << 20;

#[derive(Debug, Clone)]
pub struct SnapshotReport {
    pub name: String,
    pub root: Hash,
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub bytes: u64,
    pub new_bytes: u64,
    /// Things that could not be represented: non-utf8 or odd names, sockets, devices.
    pub skipped: Vec<PathBuf>,
}

#[derive(Debug, Default, Clone)]
pub struct RestoreReport {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub bytes: u64,
    pub skipped: u64,
}

#[derive(Debug, Default, Clone)]
pub struct ForgetReport {
    pub objects_removed: u64,
    pub objects_kept: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
    Mode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub path: String,
    pub kind: ChangeKind,
}

impl Change {
    pub fn sigil(&self) -> char {
        match self.kind {
            ChangeKind::Added => '+',
            ChangeKind::Removed => '-',
            ChangeKind::Modified => '~',
            ChangeKind::Mode => 'm',
        }
    }
}

#[derive(Default)]
pub(crate) struct Acc {
    // id -> created
    members: BTreeMap<Hash, bool>,
    inherited: HashSet<Hash>,
    pub(crate) files: u64,
    pub(crate) dirs: u64,
    pub(crate) links: u64,
    pub(crate) bytes: u64,
    pub(crate) new_bytes: u64,
    pub(crate) skipped: Vec<PathBuf>,
}

impl Acc {
    pub(crate) fn note(&mut self, id: Hash, existed: bool) {
        let created = !existed || self.inherited.contains(&id);
        *self.members.entry(id).or_default() |= created;
    }
}

fn mtime_of(md: &fs::Metadata) -> (i64, u32) {
    match md.modified().map(|t| t.duration_since(UNIX_EPOCH)) {
        Ok(Ok(d)) => (d.as_secs() as i64, d.subsec_nanos()),
        _ => (0, 0),
    }
}

fn systime(secs: i64, ns: u32) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::new(secs as u64, ns)
    } else {
        UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
    }
}

#[cfg(unix)]
fn mode_of(md: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn mode_of(md: &fs::Metadata) -> u32 {
    if md.is_dir() {
        0o755
    } else if md.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

impl Store {
    fn snap_dir(&self) -> PathBuf {
        self.root_dir().join("snapshots")
    }

    fn snap_path(&self, name: &str) -> PathBuf {
        self.snap_dir().join(format!("{name}.snap"))
    }

    pub fn snapshot_get(&self, name: &str) -> Result<Snapshot> {
        if !valid_snapshot_name(name) {
            return Err(Error::SnapshotNotFound(name.to_string()));
        }
        let buf = match fs::read(self.snap_path(name)) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::SnapshotNotFound(name.to_string()));
            }
            Err(e) => return Err(e.into()),
        };
        let bad = || Error::CorruptSnapshot(name.to_string());
        let buf = self.open_meta(b"snapshot", name.as_bytes(), buf).ok_or_else(bad)?;
        let s = Snapshot::decode(&buf).map_err(|_| bad())?;
        if s.name != name {
            return Err(Error::CorruptSnapshot(name.to_string()));
        }
        Ok(s)
    }

    /// The snapshot record file exactly as stored.
    pub fn snapshot_bytes(&self, name: &str) -> Result<Vec<u8>> {
        self.snapshot_get(name)?;
        Ok(fs::read(self.snap_path(name))?)
    }

    pub fn snapshot_members(&self, name: &str) -> Result<Vec<Hash>> {
        Ok(self.snapshot_get(name)?.members.iter().map(|m| m.id).collect())
    }

    /// Installs a record received from elsewhere. Every object it lists has to be here already.
    /// False if an identical snapshot is already present; a different one under the same name is an error.
    pub fn put_snapshot_bytes(&mut self, name: &str, raw: Vec<u8>) -> Result<bool> {
        if !valid_snapshot_name(name) {
            return Err(Error::InvalidName(name.to_string()));
        }
        let bad = || Error::CorruptSnapshot(name.to_string());
        let plain = self.open_meta(b"snapshot", name.as_bytes(), raw.clone()).ok_or_else(bad)?;
        let snap = Snapshot::decode(&plain).map_err(|_| bad())?;
        if snap.name != name {
            return Err(bad());
        }
        if self.snap_path(name).exists() {
            return if self.snapshot_get(name)? == snap {
                Ok(false)
            } else {
                Err(Error::SnapshotExists(name.to_string()))
            };
        }
        if let Some(m) =
            std::iter::once(&snap.root).chain(snap.members.iter().map(|m| &m.id)).find(|id| !self.contains(id))
        {
            return Err(Error::NotFound(*m));
        }
        fs::create_dir_all(self.snap_dir())?;
        write_atomic(&self.snap_path(name), &raw)?;
        Ok(true)
    }

    /// All snapshots, oldest first.
    pub fn snapshot_list(&self) -> Result<Vec<Snapshot>> {
        let mut out = Vec::new();
        let rd = match fs::read_dir(self.snap_dir()) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for e in rd {
            let name = e?.file_name();
            if let Some(n) = name.to_str().and_then(|n| n.strip_suffix(".snap")) {
                out.push(self.snapshot_get(n)?);
            }
        }
        out.sort_by(|a, b| a.time.cmp(&b.time).then_with(|| a.name.cmp(&b.name)));
        Ok(out)
    }

    /// Stores a directory tree and records it under `name` (default `snap-<unix time>`).
    pub fn snapshot_dir(&mut self, dir: impl AsRef<Path>, name: Option<&str>) -> Result<SnapshotReport> {
        let dir = dir.as_ref();
        let (name, time, mut acc) = self.begin_snapshot(name)?;
        let root = self.snap_walk(dir, 0, &mut acc)?;
        let source = fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf()).display().to_string();
        self.finish_snapshot(name, time, root, source, acc)
    }

    // picks the name and seeds the accumulator with what earlier snapshots created
    pub(crate) fn begin_snapshot(&self, name: Option<&str>) -> Result<(String, i64, Acc)> {
        let time = now();
        let name = name.map_or_else(|| format!("snap-{time}"), str::to_owned);
        if !valid_snapshot_name(&name) {
            return Err(Error::InvalidName(name));
        }
        if self.snap_path(&name).exists() {
            return Err(Error::SnapshotExists(name));
        }
        let mut acc = Acc::default();
        for s in self.snapshot_list()? {
            acc.inherited.extend(s.members.iter().filter(|m| m.created).map(|m| m.id));
        }
        Ok((name, time, acc))
    }

    pub(crate) fn finish_snapshot(&self, name: String, time: i64, root: Hash, source: String, acc: Acc) -> Result<SnapshotReport> {
        let snap = Snapshot {
            name: name.clone(),
            time,
            root,
            source,
            members: acc.members.iter().map(|(&id, &created)| Member { id, created }).collect(),
        };
        // objects are all durable by now; the record is what makes them a snapshot
        fs::create_dir_all(self.snap_dir())?;
        let sealed = self.seal_meta(b"snapshot", name.as_bytes(), snap.encode());
        write_atomic(&self.snap_path(&name), &sealed)?;

        Ok(SnapshotReport {
            name,
            root,
            files: acc.files,
            dirs: acc.dirs,
            symlinks: acc.links,
            bytes: acc.bytes,
            new_bytes: acc.new_bytes,
            skipped: acc.skipped,
        })
    }

    pub(crate) fn put_tree(&mut self, entries: Vec<Entry>, acc: &mut Acc) -> Result<Hash> {
        let t = Tree::new(entries)?;
        let r = self.put_bytes(&t.encode())?;
        acc.note(r.id, r.existed);
        acc.new_bytes += r.new_bytes;
        Ok(r.id)
    }

    fn snap_walk(&mut self, dir: &Path, depth: usize, acc: &mut Acc) -> Result<Hash> {
        if depth > MAX_DEPTH {
            return Err(Error::BadTree("directory nesting too deep"));
        }
        let mut entries = Vec::new();
        for de in fs::read_dir(dir)? {
            let de = de?;
            let path = de.path();
            let Some(name) = de.file_name().to_str().filter(|n| valid_name(n)).map(str::to_owned) else {
                acc.skipped.push(path);
                continue;
            };
            let md = fs::symlink_metadata(&path)?;
            let (mtime, mtime_ns) = mtime_of(&md);
            let mut e = Entry {
                name,
                kind: Kind::File,
                mode: mode_of(&md),
                mtime,
                mtime_ns,
                size: 0,
                id: Entry::zero_id(),
                target: String::new(),
            };

            let ft = md.file_type();
            if ft.is_symlink() {
                let t = fs::read_link(&path)?;
                let ok = t.to_str().filter(|t| !t.is_empty() && !t.contains('\0') && t.len() <= u16::MAX as usize);
                let Some(t) = ok else {
                    acc.skipped.push(path);
                    continue;
                };
                e.kind = Kind::Symlink;
                e.target = t.to_owned();
                acc.links += 1;
            } else if ft.is_dir() {
                e.kind = Kind::Dir;
                e.id = self.snap_walk(&path, depth + 1, acc)?;
                acc.dirs += 1;
            } else if ft.is_file() {
                let r = self.put_file(&path)?;
                e.id = r.id;
                e.size = r.size;
                acc.note(r.id, r.existed);
                acc.files += 1;
                acc.bytes += r.size;
                acc.new_bytes += r.new_bytes;
            } else {
                acc.skipped.push(path);
                continue;
            }
            entries.push(e);
        }

        self.put_tree(entries, acc)
    }

    pub fn load_tree(&self, id: &Hash) -> Result<Tree> {
        if self.manifest(id)?.size > MAX_TREE_BYTES {
            return Err(Error::BadTree("too large"));
        }
        Tree::decode(&self.read_to_vec(id)?)
    }

    /// Every path under a tree, depth first, directories before their contents.
    pub fn flatten(&self, root: &Hash) -> Result<Vec<(String, Entry)>> {
        let mut out = Vec::new();
        self.flatten_into(root, "", 0, &mut out)?;
        Ok(out)
    }

    fn flatten_into(&self, id: &Hash, prefix: &str, depth: usize, out: &mut Vec<(String, Entry)>) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(Error::BadTree("directory nesting too deep"));
        }
        for e in self.load_tree(id)?.entries {
            let p = if prefix.is_empty() { e.name.clone() } else { format!("{prefix}/{}", e.name) };
            let sub = (e.kind == Kind::Dir).then_some(e.id);
            out.push((p.clone(), e));
            if let Some(sub) = sub {
                self.flatten_into(&sub, &p, depth + 1, out)?;
            }
        }
        Ok(())
    }

    /// Re-hashes every object a snapshot reaches. Shared subtrees are checked once.
    pub fn snapshot_verify(&self, name: &str) -> Result<()> {
        let s = self.snapshot_get(name)?;
        let mut seen = HashSet::new();
        self.verify_tree(&s.root, 0, &mut seen)
    }

    fn verify_tree(&self, id: &Hash, depth: usize, seen: &mut HashSet<Hash>) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(Error::BadTree("directory nesting too deep"));
        }
        if !seen.insert(*id) {
            return Ok(());
        }
        self.verify(id)?;
        for e in self.load_tree(id)?.entries {
            match e.kind {
                Kind::Dir => self.verify_tree(&e.id, depth + 1, seen)?,
                Kind::File => {
                    if seen.insert(e.id) {
                        self.verify(&e.id)?;
                    }
                }
                Kind::Symlink => {}
            }
        }
        Ok(())
    }

    pub fn snapshot_restore(&self, name: &str, dest: impl AsRef<Path>) -> Result<RestoreReport> {
        let s = self.snapshot_get(name)?;
        self.restore_tree(&s.root, dest.as_ref())
    }

    /// Rebuilds a tree under `dest`, which must not exist or be an empty directory.
    pub fn restore_tree(&self, id: &Hash, dest: &Path) -> Result<RestoreReport> {
        match fs::read_dir(dest) {
            Ok(mut it) => {
                if it.next().is_some() {
                    return Err(Error::DestNotEmpty(dest.display().to_string()));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs::create_dir_all(dest)?,
            Err(e) => return Err(e.into()),
        }
        let mut rep = RestoreReport::default();
        self.restore_into(id, dest, 0, &mut rep)?;
        Ok(rep)
    }

    fn restore_into(&self, id: &Hash, dir: &Path, depth: usize, rep: &mut RestoreReport) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(Error::BadTree("directory nesting too deep"));
        }
        for e in self.load_tree(id)?.entries {
            // ':' is an alternate data stream separator on NTFS
            if cfg!(windows) && e.name.contains(':') {
                return Err(Error::InvalidName(e.name));
            }
            let path = dir.join(&e.name);
            match e.kind {
                Kind::Dir => {
                    fs::create_dir(&path)?;
                    self.restore_into(&e.id, &path, depth + 1, rep)?;
                    set_dir_meta(&path, &e);
                    rep.dirs += 1;
                }
                Kind::File => {
                    let f = OpenOptions::new().write(true).create_new(true).open(&path)?;
                    let mut w = BufWriter::new(&f);
                    let n = self.read_into(&e.id, &mut w)?;
                    w.flush()?;
                    drop(w);
                    if n != e.size {
                        return Err(Error::BadTree("file size differs from its tree entry"));
                    }
                    f.set_modified(systime(e.mtime, e.mtime_ns))?;
                    drop(f);
                    set_file_mode(&path, e.mode)?;
                    rep.files += 1;
                    rep.bytes += n;
                }
                Kind::Symlink => {
                    if make_symlink(&e.target, &path)? {
                        rep.symlinks += 1;
                    } else {
                        rep.skipped += 1;
                    }
                }
            }
        }
        Ok(())
    }

    /// Differences between two trees. Identical subtrees are skipped by id, and
    /// an added or removed directory is reported once, not file by file.
    /// Timestamp-only changes are not differences.
    pub fn diff_trees(&self, a: &Hash, b: &Hash) -> Result<Vec<Change>> {
        let mut out = Vec::new();
        self.diff_into(a, b, "", 0, &mut out)?;
        Ok(out)
    }

    pub fn snapshot_diff(&self, a: &str, b: &str) -> Result<Vec<Change>> {
        let (a, b) = (self.snapshot_get(a)?, self.snapshot_get(b)?);
        self.diff_trees(&a.root, &b.root)
    }

    fn diff_into(&self, a: &Hash, b: &Hash, prefix: &str, depth: usize, out: &mut Vec<Change>) -> Result<()> {
        use std::cmp::Ordering::*;
        if a == b {
            return Ok(());
        }
        if depth > MAX_DEPTH {
            return Err(Error::BadTree("directory nesting too deep"));
        }
        let (ta, tb) = (self.load_tree(a)?, self.load_tree(b)?);
        let path = |n: &str| if prefix.is_empty() { n.to_string() } else { format!("{prefix}/{n}") };
        let (mut i, mut j) = (0, 0);

        while i < ta.entries.len() || j < tb.entries.len() {
            let ord = match (ta.entries.get(i), tb.entries.get(j)) {
                (Some(x), Some(y)) => x.name.cmp(&y.name),
                (Some(_), None) => Less,
                (None, _) => Greater,
            };
            match ord {
                Less => {
                    out.push(Change { path: path(&ta.entries[i].name), kind: ChangeKind::Removed });
                    i += 1;
                }
                Greater => {
                    out.push(Change { path: path(&tb.entries[j].name), kind: ChangeKind::Added });
                    j += 1;
                }
                Equal => {
                    let (x, y) = (&ta.entries[i], &tb.entries[j]);
                    i += 1;
                    j += 1;
                    let p = path(&x.name);
                    if x.kind != y.kind {
                        out.push(Change { path: p, kind: ChangeKind::Modified });
                        continue;
                    }
                    match x.kind {
                        Kind::Dir => {
                            if x.mode != y.mode {
                                out.push(Change { path: p.clone(), kind: ChangeKind::Mode });
                            }
                            self.diff_into(&x.id, &y.id, &p, depth + 1, out)?;
                        }
                        Kind::File => {
                            if x.id != y.id {
                                out.push(Change { path: p, kind: ChangeKind::Modified });
                            } else if x.mode != y.mode {
                                out.push(Change { path: p, kind: ChangeKind::Mode });
                            }
                        }
                        Kind::Symlink => {
                            if x.target != y.target {
                                out.push(Change { path: p, kind: ChangeKind::Modified });
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Deletes the record, then releases the objects only this snapshot kept
    /// alive. Objects somebody stored by hand before the snapshot saw them are
    /// never touched. Space comes back on the next `gc`.
    pub fn snapshot_forget(&mut self, name: &str) -> Result<ForgetReport> {
        let target = self.snapshot_get(name)?;
        let others: HashSet<Hash> = self
            .snapshot_list()?
            .iter()
            .filter(|s| s.name != target.name)
            .flat_map(|s| s.members.iter().map(|m| m.id))
            .collect();

        fs::remove_file(self.snap_path(name))?;
        crate::store::sync_dir(&self.snap_dir())?;

        let mut rep = ForgetReport::default();
        for m in target.members {
            if m.created && !others.contains(&m.id) {
                if self.remove(&m.id)? {
                    rep.objects_removed += 1;
                }
            } else {
                rep.objects_kept += 1;
            }
        }
        Ok(rep)
    }

    /// Applies a retention policy; returns the names that were (or with
    /// `dry_run`, would be) forgotten, oldest first.
    pub fn snapshot_prune(&mut self, policy: &Retention, dry_run: bool) -> Result<Vec<String>> {
        if policy.is_empty() {
            return Err(Error::InvalidConfig("retention policy is empty"));
        }
        let snaps = self.snapshot_list()?;
        let times: Vec<(String, i64)> = snaps.iter().map(|s| (s.name.clone(), s.time)).collect();
        let keep = keep_set(&times, policy);

        let gone: Vec<String> = snaps.into_iter().map(|s| s.name).filter(|n| !keep.contains(n)).collect();
        if !dry_run {
            for n in &gone {
                self.snapshot_forget(n)?;
            }
        }
        Ok(gone)
    }
}

#[cfg(unix)]
fn set_file_mode(p: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if mode != 0 {
        fs::set_permissions(p, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode(p: &Path, mode: u32) -> Result<()> {
    if mode & 0o200 == 0 {
        let mut perm = fs::metadata(p)?.permissions();
        perm.set_readonly(true);
        fs::set_permissions(p, perm)?;
    }
    Ok(())
}

// best effort; a directory we just made not taking its mode is not worth failing a restore
#[cfg(unix)]
fn set_dir_meta(p: &Path, e: &Entry) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(f) = fs::File::open(p) {
        let _ = f.set_modified(systime(e.mtime, e.mtime_ns));
    }
    if e.mode != 0 {
        let _ = fs::set_permissions(p, fs::Permissions::from_mode(e.mode));
    }
}

#[cfg(not(unix))]
fn set_dir_meta(_: &Path, _: &Entry) {}

#[cfg(unix)]
fn make_symlink(target: &str, at: &Path) -> Result<bool> {
    std::os::unix::fs::symlink(target, at)?;
    Ok(true)
}

// symlinks need a privilege on Windows, so they are left out there
#[cfg(not(unix))]
fn make_symlink(_: &str, _: &Path) -> Result<bool> {
    Ok(false)
}
