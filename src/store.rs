use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};

use crate::chunker::{Chunker, ChunkerConfig};
use crate::error::{Error, Result};
use crate::hash::Hash;
use crate::index::{Entry, Index};
use crate::manifest::{ChunkRef, Manifest};
use crate::merkle::Proof;
use crate::segment;

// Test hook: with the `failpoints` feature, the process dies without running
// destructors when CAS_FAILPOINT names the point, like a kill -9 would.
#[cfg(feature = "failpoints")]
fn fail(point: &str) {
    if std::env::var("CAS_FAILPOINT").is_ok_and(|v| v == point) {
        std::process::exit(86);
    }
}

#[cfg(not(feature = "failpoints"))]
#[inline(always)]
fn fail(_: &str) {}

// A rename or unlink is only durable once the directory entry is flushed.
// Windows has no equivalent of fsync on a directory handle; NTFS journals
// metadata itself.
#[cfg(unix)]
pub(crate) fn sync_dir(p: &Path) -> io::Result<()> {
    File::open(p)?.sync_all()
}

#[cfg(not(unix))]
pub(crate) fn sync_dir(_: &Path) -> io::Result<()> {
    Ok(())
}

// tmp + fsync + rename, same dance the manifests use
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    sync_dir(path.parent().unwrap_or(Path::new(".")))
}

#[derive(Clone, Debug)]
pub struct StoreConfig {
    pub chunker: ChunkerConfig,
    /// Active segment is sealed and a new one started past this size.
    pub segment_size: u64,
    /// A sealed segment is rewritten by gc once this fraction of its bytes is dead.
    pub gc_threshold: f64,
}

impl Default for StoreConfig {
    fn default() -> Self {
        StoreConfig { chunker: ChunkerConfig::default(), segment_size: 64 << 20, gc_threshold: 0.3 }
    }
}

#[derive(Debug, Clone)]
pub struct PutReport {
    pub id: Hash,
    pub size: u64,
    pub chunks: u64,
    pub new_chunks: u64,
    pub new_bytes: u64,
    /// The whole object was already stored; nothing was written.
    pub existed: bool,
}

#[derive(Debug, Default, Clone)]
pub struct GcReport {
    pub chunks_removed: u64,
    pub chunks_moved: u64,
    pub segments_removed: u64,
    pub bytes_reclaimed: u64,
}

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub objects: u64,
    pub logical_bytes: u64,
    pub live_chunks: u64,
    pub dead_chunks: u64,
    pub live_bytes: u64,
    pub dead_bytes: u64,
    pub segments: u64,
}

impl Stats {
    pub fn dedup_ratio(&self) -> f64 {
        if self.live_bytes == 0 { 1.0 } else { self.logical_bytes as f64 / self.live_bytes as f64 }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ScrubReport {
    pub checked: u64,
    pub corrupt: Vec<Hash>,
}

struct Active {
    id: u32,
    file: File,
    len: u64,
}

/// Single-writer handle to an on-disk store. Reads take `&self` and are safe to share across threads.
pub struct Store {
    root: PathBuf,
    cfg: StoreConfig,
    _lock: File,
    index: Index,
    active: Option<Active>,
    next_segment: u32,
    readers: Mutex<HashMap<u32, Arc<File>>>,
}

impl Store {
    /// Opens or creates a store, taking an exclusive lock. Rebuilds the index first if the last session did not shut down cleanly.
    pub fn open(root: impl AsRef<Path>, cfg: StoreConfig) -> Result<Store> {
        cfg.chunker.validate()?;
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("segments"))?;
        fs::create_dir_all(root.join("manifests"))?;

        let lock = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(root.join("LOCK"))?;
        lock.try_lock().map_err(|e| match e {
            TryLockError::WouldBlock => Error::Locked,
            TryLockError::Error(e) => Error::Io(e),
        })?;

        // half-written manifests from a crashed put; the rename never happened
        for e in fs::read_dir(root.join("manifests"))? {
            let p = e?.path();
            if p.extension().is_some_and(|x| x == "tmp") {
                fs::remove_file(p)?;
            }
        }

        // same for snapshot records
        if let Ok(rd) = fs::read_dir(root.join("snapshots")) {
            for e in rd {
                let p = e?.path();
                if p.extension().is_some_and(|x| x == "tmp") {
                    fs::remove_file(p)?;
                }
            }
        }

        let (index, clean) = Index::open(&root.join("index.bin"))?;
        let ids = segment::list_ids(&root.join("segments"))?;
        let mut s = Store {
            root,
            cfg,
            _lock: lock,
            index,
            active: None,
            next_segment: ids.last().map_or(1, |i| i + 1),
            readers: Mutex::new(HashMap::new()),
        };
        if !clean {
            s.rebuild()?;
        }
        Ok(s)
    }

    pub(crate) fn root_dir(&self) -> &Path {
        &self.root
    }

    fn seg_dir(&self) -> PathBuf {
        self.root.join("segments")
    }

    fn manifest_path(&self, id: &Hash) -> PathBuf {
        self.root.join("manifests").join(format!("{id}.mf"))
    }

    // Segments are the only thing that can't be recomputed, so rebuilding
    // trusts them and re-derives everything else: offsets by scanning,
    // refcounts by walking manifests.
    fn rebuild(&mut self) -> Result<()> {
        self.index.clear()?;
        let dir = self.seg_dir();
        let ids = segment::list_ids(&dir)?;

        for (n, &id) in ids.iter().enumerate() {
            let p = segment::path(&dir, id);
            let scan = segment::scan(&p)?;
            if scan.valid_end < scan.file_len {
                if n + 1 != ids.len() {
                    return Err(Error::CorruptSegment(id));
                }
                // torn tail of the newest segment, safe to cut
                OpenOptions::new().write(true).open(&p)?.set_len(scan.valid_end)?;
            }
            for r in scan.records {
                if self.index.get(&r.hash).is_none() {
                    self.index.insert(&r.hash, Entry { segment: id, offset: r.offset, len: r.len, refs: 0 })?;
                }
            }
        }

        for id in self.list()? {
            let m = self.manifest(&id)?;
            self.adjust_refs(&m, true)?;
        }
        self.index.mark_clean()?;
        Ok(())
    }

    fn adjust_refs(&mut self, m: &Manifest, up: bool) -> Result<()> {
        // one reference per manifest, no matter how often a chunk repeats in it
        let uniq: HashSet<Hash> = m.chunks.iter().map(|c| c.hash).collect();
        for h in uniq {
            match self.index.get(&h) {
                Some(mut e) => {
                    e.refs = if up { e.refs.saturating_add(1) } else { e.refs.saturating_sub(1) };
                    self.index.insert(&h, e)?;
                }
                None if up => return Err(Error::MissingChunk(h)),
                None => {}
            }
        }
        Ok(())
    }

    fn open_active(&mut self, reuse_last: bool) -> Result<()> {
        if let Some(a) = self.active.take() {
            a.file.sync_data()?;
        }
        let dir = self.seg_dir();

        let last = if reuse_last { segment::list_ids(&dir)?.last().copied() } else { None };
        let room = |id: u32| fs::metadata(segment::path(&dir, id)).map(|m| m.len() < self.cfg.segment_size);
        let id = match last {
            Some(l) if room(l)? => Some(l),
            _ => None,
        };
        let id = id.unwrap_or_else(|| {
            self.next_segment += 1;
            self.next_segment - 1
        });

        let file = OpenOptions::new().append(true).create(true).open(segment::path(&dir, id))?;
        let len = file.metadata()?.len();
        if len == 0 {
            sync_dir(&dir)?;
        }
        self.active = Some(Active { id, file, len });
        Ok(())
    }

    fn append(&mut self, hash: &Hash, data: &[u8]) -> Result<Entry> {
        let rec = segment::record_len(data.len() as u32);
        let full = self.active.as_ref().is_some_and(|a| a.len > 0 && a.len + rec > self.cfg.segment_size);
        if self.active.is_none() {
            self.open_active(true)?;
        } else if full {
            self.open_active(false)?;
        }

        let a = self.active.as_mut().unwrap();
        a.file.write_all(&segment::encode_record(hash, data))?;
        let e = Entry { segment: a.id, offset: a.len, len: data.len() as u32, refs: 0 };
        a.len += rec;
        Ok(e)
    }

    /// Chunks, dedups and stores a stream. Returns the object id (Merkle root). Storing the same bytes twice is a no-op.
    pub fn put_reader<R: Read + Send>(&mut self, src: R) -> Result<PutReport> {
        // refcounts only become correct again after add_refs below, so a
        // crash in between must force a rebuild
        self.index.mark_dirty();

        let chunker = Chunker::new(src, self.cfg.chunker)?;
        let mut refs = Vec::new();
        let (mut new_chunks, mut new_bytes) = (0u64, 0u64);

        // The rolling hash is the slowest stage and is strictly serial, so it
        // gets its own thread; hashing and disk writes overlap with it.
        let (tx, rx) = mpsc::sync_channel(16);
        std::thread::scope(|scope| -> Result<()> {
            scope.spawn(move || {
                for c in chunker {
                    let failed = c.is_err();
                    // receiver gone means the consumer bailed out
                    if tx.send(c).is_err() || failed {
                        break;
                    }
                }
            });

            for c in rx {
                let c = c?;
                let hash = Hash::of(&c.data);
                if self.index.get(&hash).is_none() {
                    let e = self.append(&hash, &c.data)?;
                    self.index.insert(&hash, e)?;
                    new_chunks += 1;
                    new_bytes += c.data.len() as u64;
                }
                refs.push(ChunkRef { hash, len: c.data.len() as u32 });
            }
            Ok(())
        })?;

        let m = Manifest::new(refs);
        let id = m.id();
        let mut report =
            PutReport { id, size: m.size, chunks: m.chunks.len() as u64, new_chunks, new_bytes, existed: false };

        let path = self.manifest_path(&id);
        if path.exists() {
            report.existed = true;
            return Ok(report);
        }

        // chunk bytes must be durable before a manifest can point at them
        if let Some(a) = &self.active {
            a.file.sync_data()?;
        }
        fail("put:chunks_written");
        let tmp = path.with_extension("tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&m.encode())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        sync_dir(&self.root.join("manifests"))?;
        fail("put:manifest_renamed");

        self.adjust_refs(&m, true)?;
        fail("put:refs_bumped");
        Ok(report)
    }

    pub fn put_bytes(&mut self, data: &[u8]) -> Result<PutReport> {
        self.put_reader(data)
    }

    pub fn put_file(&mut self, p: impl AsRef<Path>) -> Result<PutReport> {
        self.put_reader(File::open(p)?)
    }

    pub fn contains(&self, id: &Hash) -> bool {
        self.manifest_path(id).exists()
    }

    pub fn list(&self) -> Result<Vec<Hash>> {
        let mut ids = Vec::new();
        for e in fs::read_dir(self.root.join("manifests"))? {
            let name = e?.file_name();
            if let Some(h) = name.to_str().and_then(|n| n.strip_suffix(".mf")).and_then(|n| n.parse().ok()) {
                ids.push(h);
            }
        }
        ids.sort();
        Ok(ids)
    }

    pub fn manifest(&self, id: &Hash) -> Result<Manifest> {
        let buf = match fs::read(self.manifest_path(id)) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Error::NotFound(*id)),
            Err(e) => return Err(e.into()),
        };
        let m = Manifest::decode(&buf).map_err(|_| Error::CorruptManifest(*id))?;
        if m.id() != *id {
            return Err(Error::CorruptManifest(*id));
        }
        Ok(m)
    }

    fn reader(&self, seg: u32) -> Result<Arc<File>> {
        let mut map = self.readers.lock().unwrap();
        if let Some(f) = map.get(&seg) {
            return Ok(f.clone());
        }
        let f = Arc::new(File::open(segment::path(&self.seg_dir(), seg))?);
        map.insert(seg, f.clone());
        Ok(f)
    }

    /// Reads one chunk and re-hashes it; a mismatch is `Error::Corrupt`.
    pub fn get_chunk(&self, h: &Hash) -> Result<Vec<u8>> {
        let e = self.index.get(h).ok_or(Error::MissingChunk(*h))?;
        let f = self.reader(e.segment)?;

        let mut buf = vec![0u8; segment::record_len(e.len) as usize];
        segment::read_exact_at(&f, &mut buf, e.offset).map_err(|err| match err.kind() {
            io::ErrorKind::UnexpectedEof => Error::Corrupt(*h),
            _ => Error::Io(err),
        })?;

        let payload = buf.split_off(segment::REC_HEADER as usize);
        if buf[..32] != h.as_bytes()[..] || Hash::of(&payload) != *h {
            return Err(Error::Corrupt(*h));
        }
        Ok(payload)
    }

    /// Writes the whole object to `out`, verifying every chunk on the way.
    pub fn read_into<W: Write>(&self, id: &Hash, mut out: W) -> Result<u64> {
        let m = self.manifest(id)?;
        for c in &m.chunks {
            let data = self.get_chunk(&c.hash)?;
            if data.len() != c.len as usize {
                return Err(Error::Corrupt(c.hash));
            }
            out.write_all(&data)?;
        }
        Ok(m.size)
    }

    pub fn read_to_vec(&self, id: &Hash) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        self.read_into(id, &mut v)?;
        Ok(v)
    }

    /// Streaming, seekable view of an object. Holds one decoded chunk at a
    /// time, so memory stays at one chunk no matter how big the object is.
    pub fn open_reader(&self, id: &Hash) -> Result<ObjectReader<'_>> {
        let m = self.manifest(id)?;
        let mut end = 0u64;
        let ends = m
            .chunks
            .iter()
            .map(|c| {
                end += c.len as u64;
                end
            })
            .collect();
        Ok(ObjectReader { store: self, chunks: m.chunks, ends, size: m.size, pos: 0, cur: None })
    }

    pub fn read_range(&self, id: &Hash, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut r = self.open_reader(id)?;
        r.seek(SeekFrom::Start(offset))?;
        let mut out = Vec::new();
        r.take(len as u64).read_to_end(&mut out)?;
        Ok(out)
    }

    /// Drops the manifest and releases its references. Chunk bytes stay on
    /// disk until `gc` rewrites the segment holding them.
    pub fn remove(&mut self, id: &Hash) -> Result<bool> {
        let m = match self.manifest(id) {
            Ok(m) => m,
            Err(Error::NotFound(_)) => return Ok(false),
            Err(e) => return Err(e),
        };
        self.index.mark_dirty();
        fs::remove_file(self.manifest_path(id))?;
        sync_dir(&self.root.join("manifests"))?;
        fail("rm:manifest_deleted");
        self.adjust_refs(&m, false)?;
        Ok(true)
    }

    /// Merkle inclusion proof for chunk number `chunk` of the object.
    pub fn prove(&self, id: &Hash, chunk: usize) -> Result<(ChunkRef, Proof)> {
        let m = self.manifest(id)?;
        let p = m.tree().proof(chunk).ok_or(Error::OutOfRange)?;
        Ok((m.chunks[chunk], p))
    }

    /// Re-reads and re-hashes every chunk of one object.
    pub fn verify(&self, id: &Hash) -> Result<()> {
        let m = self.manifest(id)?;
        for c in &m.chunks {
            if self.get_chunk(&c.hash)?.len() != c.len as usize {
                return Err(Error::Corrupt(c.hash));
            }
        }
        Ok(())
    }

    /// Checks every chunk in the index, including unreferenced ones.
    pub fn scrub(&self) -> Result<ScrubReport> {
        let mut rep = ScrubReport::default();
        for (h, _) in self.index.entries() {
            rep.checked += 1;
            match self.get_chunk(&h) {
                Ok(_) => {}
                Err(Error::Corrupt(_)) => rep.corrupt.push(h),
                Err(e) => return Err(e),
            }
        }
        Ok(rep)
    }

    pub fn stats(&self) -> Result<Stats> {
        let mut st = Stats::default();
        for id in self.list()? {
            st.objects += 1;
            st.logical_bytes += self.manifest(&id)?.size;
        }
        for (_, e) in self.index.entries() {
            if e.refs == 0 {
                st.dead_chunks += 1;
                st.dead_bytes += e.len as u64;
            } else {
                st.live_chunks += 1;
                st.live_bytes += e.len as u64;
            }
        }
        st.segments = segment::list_ids(&self.seg_dir())?.len() as u64;
        Ok(st)
    }

    /// Compaction. Segments are immutable, so space comes back by copying the
    /// live chunks of mostly-dead segments into a fresh one and deleting the
    /// old files. Segments under the threshold are left alone.
    pub fn gc(&mut self) -> Result<GcReport> {
        #[derive(Default)]
        struct Tally {
            live: u64,
            dead: u64,
        }

        self.index.mark_dirty();
        let entries = self.index.entries();

        let mut tally: BTreeMap<u32, Tally> = BTreeMap::new();
        for (_, e) in &entries {
            let t = tally.entry(e.segment).or_default();
            let n = segment::record_len(e.len);
            if e.refs == 0 { t.dead += n } else { t.live += n }
        }

        if let Some(a) = self.active.take() {
            a.file.sync_data()?;
        }

        let victims: Vec<u32> = tally
            .iter()
            .filter(|(_, t)| {
                t.dead > 0 && (t.live == 0 || t.dead as f64 / (t.live + t.dead) as f64 >= self.cfg.gc_threshold)
            })
            .map(|(&id, _)| id)
            .collect();

        let mut rep = GcReport::default();
        if victims.is_empty() {
            return Ok(rep);
        }
        let dir = self.seg_dir();
        let mut before = 0u64;
        for &id in &victims {
            before += fs::metadata(segment::path(&dir, id))?.len();
        }

        let mut live = Vec::new();
        for (h, e) in entries {
            if !victims.contains(&e.segment) {
                continue;
            }
            if e.refs == 0 {
                self.index.remove(&h);
                rep.chunks_removed += 1;
            } else {
                live.push((h, e));
            }
        }
        // sequential reads from each victim
        live.sort_by_key(|(_, e)| (e.segment, e.offset));

        // never append into a segment we are about to delete
        self.open_active(false)?;
        let mut moved = 0u64;
        for (h, old) in live {
            let data = self.get_chunk(&h)?;
            let ne = self.append(&h, &data)?;
            self.index.insert(&h, Entry { refs: old.refs, ..ne })?;
            moved += segment::record_len(old.len);
            rep.chunks_moved += 1;
        }
        if let Some(a) = &self.active {
            a.file.sync_data()?;
        }

        fail("gc:copied");

        // new copies are durable; only now is it safe to unlink the originals
        for &id in &victims {
            self.readers.lock().unwrap().remove(&id);
            fs::remove_file(segment::path(&dir, id))?;
            fail("gc:unlinked_one");
        }
        sync_dir(&dir)?;
        rep.segments_removed = victims.len() as u64;
        rep.bytes_reclaimed = before.saturating_sub(moved);

        self.sync()?;
        Ok(rep)
    }

    /// Flushes the active segment and marks the index clean. Also runs on drop.
    pub fn sync(&mut self) -> Result<()> {
        if let Some(a) = &self.active {
            a.file.sync_data()?;
        }
        self.index.mark_clean()?;
        Ok(())
    }
}

pub struct ObjectReader<'a> {
    store: &'a Store,
    chunks: Vec<ChunkRef>,
    // cumulative end offset of each chunk
    ends: Vec<u64>,
    size: u64,
    pos: u64,
    cur: Option<(usize, Vec<u8>)>,
}

impl ObjectReader<'_> {
    pub fn size(&self) -> u64 {
        self.size
    }
}

impl Read for ObjectReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let i = self.ends.partition_point(|&e| e <= self.pos);
        if self.cur.as_ref().is_none_or(|(n, _)| *n != i) {
            let c = &self.chunks[i];
            let data = self.store.get_chunk(&c.hash).map_err(io::Error::other)?;
            if data.len() != c.len as usize {
                return Err(io::Error::other(Error::Corrupt(c.hash)));
            }
            self.cur = Some((i, data));
        }

        let data = &self.cur.as_ref().unwrap().1;
        let start = if i == 0 { 0 } else { self.ends[i - 1] };
        let from = (self.pos - start) as usize;
        let n = buf.len().min(data.len() - from);
        buf[..n].copy_from_slice(&data[from..from + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for ObjectReader<'_> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => self.size.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = target.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before start"))?;
        Ok(self.pos)
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = self.sync();
    }
}
