use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex, mpsc};

use crate::chunker::{Chunker, ChunkerConfig};
use crate::crypto::{Kdf, Keys, Password};
use crate::error::{Error, Result};
use crate::format::Format;
use crate::hash::Hash;
use crate::index::{Entry, Index};
use crate::manifest::{ChunkRef, Manifest};
use crate::merkle::Proof;
use crate::metrics::{CounterSnapshot, Counters};
use crate::segment::{self, Layout};
use crate::transform::{self, Compression};

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
    /// Applied to chunks written from now on; each record says how it was stored, so this can change between runs.
    pub compression: Compression,
    /// Required to open an encrypted store. Given when creating a new store, it makes the store encrypted.
    pub password: Option<Password>,
    /// Key stretching cost, used when a password is set on a new store or changed.
    pub kdf: Kdf,
    /// Writes that would take the segment files past this many bytes fail with `Error::QuotaExceeded`. gc is exempt.
    pub max_bytes: Option<u64>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        StoreConfig {
            chunker: ChunkerConfig::default(),
            segment_size: 64 << 20,
            gc_threshold: 0.3,
            compression: Compression::None,
            password: None,
            kdf: Kdf::default(),
            max_bytes: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PutReport {
    pub id: Hash,
    pub size: u64,
    pub chunks: u64,
    pub new_chunks: u64,
    pub new_bytes: u64,
    /// What the new chunks took in the segment payloads, after compression and encryption.
    pub stored_bytes: u64,
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

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Damage {
    pub bad_manifests: Vec<Hash>,
    pub corrupt_chunks: Vec<Hash>,
    pub missing_chunks: Vec<Hash>,
}

impl Damage {
    pub fn is_empty(&self) -> bool {
        self.bad_manifests.is_empty() && self.corrupt_chunks.is_empty() && self.missing_chunks.is_empty()
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
    layout: Layout,
    format: Format,
    keys: Option<Keys>,
    index: Index,
    active: Option<Active>,
    next_segment: u32,
    readers: Mutex<HashMap<u32, Arc<File>>>,
    disk_bytes: u64,
    // gc has to copy before it can delete, so it may overshoot the quota briefly
    in_gc: bool,
    counters: Counters,
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

        let ids = segment::list_ids(&root.join("segments"))?;
        let (format, layout, mut keys) = match fs::read(root.join("FORMAT")) {
            Ok(b) => (Format::decode(&b)?, Layout::V2, None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // no FORMAT but data present: written before v2 existed
                let used = !ids.is_empty() || fs::read_dir(root.join("manifests"))?.next().is_some();
                if used {
                    (Format::plain(), Layout::V1, None)
                } else {
                    let (f, k) = match &cfg.password {
                        Some(pw) => Format::encrypted(pw.as_bytes(), cfg.kdf).map(|(f, k)| (f, Some(k)))?,
                        None => (Format::plain(), None),
                    };
                    write_atomic(&root.join("FORMAT"), &f.encode())?;
                    (f, Layout::V2, k)
                }
            }
            Err(e) => return Err(e.into()),
        };
        if keys.is_none() {
            keys = match (&format.keys, &cfg.password) {
                (Some(_), Some(pw)) => Some(format.unlock(pw.as_bytes())?),
                (Some(_), None) => return Err(Error::PasswordRequired),
                (None, Some(_)) => return Err(Error::NotEncrypted),
                (None, None) => None,
            };
        }

        let (index, clean) = Index::open(&root.join("index.bin"))?;
        let mut s = Store {
            root,
            cfg,
            _lock: lock,
            layout,
            format,
            keys,
            index,
            active: None,
            next_segment: ids.last().map_or(1, |i| i + 1),
            readers: Mutex::new(HashMap::new()),
            disk_bytes: 0,
            in_gc: false,
            counters: Counters::default(),
        };
        if !clean {
            s.rebuild()?;
        }
        s.disk_bytes = s.measure_disk()?;
        Ok(s)
    }

    pub(crate) fn root_dir(&self) -> &Path {
        &self.root
    }

    fn measure_disk(&self) -> Result<u64> {
        let dir = self.seg_dir();
        let mut n = 0;
        for id in segment::list_ids(&dir)? {
            n += fs::metadata(segment::path(&dir, id))?.len();
        }
        Ok(n)
    }

    /// Bytes currently in segment files, dead chunks included.
    pub fn disk_bytes(&self) -> u64 {
        self.disk_bytes
    }

    pub fn max_bytes(&self) -> Option<u64> {
        self.cfg.max_bytes
    }

    pub fn counters(&self) -> CounterSnapshot {
        self.counters.snapshot()
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
            let scan = segment::scan_layout(&p, self.layout)?;
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

        self.recount_refs()?;
        self.index.mark_clean()?;
        Ok(())
    }

    // refcounts are derived: one per manifest that lists the chunk
    pub(crate) fn recount_refs(&mut self) -> Result<()> {
        for (h, mut e) in self.index.entries() {
            if e.refs != 0 {
                e.refs = 0;
                self.index.insert(&h, e)?;
            }
        }
        // A manifest that fails its check, or lists a chunk that is gone, must not stop the
        // store from opening: that is exactly when repair is needed. check() reports both.
        for id in self.list()? {
            match self.manifest(&id) {
                Ok(m) => self.bump_present(&m)?,
                Err(Error::CorruptManifest(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn bump_present(&mut self, m: &Manifest) -> Result<()> {
        let uniq: HashSet<Hash> = m.chunks.iter().map(|c| c.hash).collect();
        for h in uniq {
            if let Some(mut e) = self.index.get(&h) {
                e.refs = e.refs.saturating_add(1);
                self.index.insert(&h, e)?;
            }
        }
        Ok(())
    }

    // Used by repair when refcounts can't be recomputed: a restored chunk with no reference would be
    // collected by the next gc.
    pub(crate) fn pin_chunk(&mut self, h: &Hash) -> Result<()> {
        if let Some(mut e) = self.index.get(h) {
            e.refs = e.refs.max(1);
            self.index.insert(h, e)?;
        }
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

    // hash is the chunk id; for v2 the payload is what pack() makes of the chunk
    fn append(&mut self, hash: &Hash, data: &[u8]) -> Result<Entry> {
        match self.layout {
            Layout::V1 => self.append_raw(hash, 0, data),
            Layout::V2 => {
                let (codec, payload) = transform::pack(data, hash, self.cfg.compression, self.keys.as_ref());
                self.append_raw(hash, codec, &payload)
            }
        }
    }

    fn append_raw(&mut self, hash: &Hash, codec: u8, payload: &[u8]) -> Result<Entry> {
        let rec = self.layout.record_len(payload.len() as u32);
        if let Some(max) = self.cfg.max_bytes
            && !self.in_gc
            && self.disk_bytes + rec > max
        {
            self.counters.quota_rejections.fetch_add(1, Relaxed);
            return Err(Error::QuotaExceeded(max));
        }
        let full = self.active.as_ref().is_some_and(|a| a.len > 0 && a.len + rec > self.cfg.segment_size);
        if self.active.is_none() {
            self.open_active(true)?;
        } else if full {
            self.open_active(false)?;
        }

        let a = self.active.as_mut().unwrap();
        let bytes = match self.layout {
            Layout::V1 => segment::encode_record(hash, payload),
            Layout::V2 => segment::encode_record_v2(hash, codec, payload),
        };
        a.file.write_all(&bytes)?;
        let e = Entry { segment: a.id, offset: a.len, len: payload.len() as u32, refs: 0 };
        a.len += rec;
        self.disk_bytes += rec;
        Ok(e)
    }

    /// Chunks, dedups and stores a stream. Returns the object id (Merkle root). Storing the same bytes twice is a no-op.
    pub fn put_reader<R: Read + Send>(&mut self, src: R) -> Result<PutReport> {
        // refcounts only become correct again after add_refs below, so a
        // crash in between must force a rebuild
        self.index.mark_dirty();

        let chunker = Chunker::new(src, self.cfg.chunker)?;
        let mut refs = Vec::new();
        let (mut new_chunks, mut new_bytes, mut stored_bytes) = (0u64, 0u64, 0u64);

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
                let hash = self.chunk_id(&c.data);
                if self.index.get(&hash).is_none() {
                    let e = self.append(&hash, &c.data)?;
                    self.index.insert(&hash, e)?;
                    new_chunks += 1;
                    new_bytes += c.data.len() as u64;
                    stored_bytes += e.len as u64;
                }
                refs.push(ChunkRef { hash, len: c.data.len() as u32 });
            }
            Ok(())
        })?;

        let m = Manifest::new(refs);
        let id = m.id();
        let mut report = PutReport {
            id,
            size: m.size,
            chunks: m.chunks.len() as u64,
            new_chunks,
            new_bytes,
            stored_bytes,
            existed: false,
        };

        let path = self.manifest_path(&id);
        if path.exists() {
            report.existed = true;
            return Ok(report);
        }

        let file = self.seal_meta(b"manifest", id.as_bytes(), m.encode());
        self.install_manifest(&id, &m, &file)?;

        let c = &self.counters;
        c.puts.fetch_add(1, Relaxed);
        c.put_bytes.fetch_add(m.size, Relaxed);
        c.chunks_written.fetch_add(new_chunks, Relaxed);
        c.chunks_deduped.fetch_add(report.chunks - new_chunks, Relaxed);
        Ok(report)
    }

    // `file` is exactly what goes on disk (already sealed for encrypted stores)
    fn install_manifest(&mut self, id: &Hash, m: &Manifest, file: &[u8]) -> Result<()> {
        let path = self.manifest_path(id);
        // chunk bytes must be durable before a manifest can point at them
        if let Some(a) = &self.active {
            a.file.sync_data()?;
        }
        fail("put:chunks_written");
        let tmp = path.with_extension("tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(file)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        sync_dir(&self.root.join("manifests"))?;
        fail("put:manifest_renamed");

        self.adjust_refs(m, true)?;
        fail("put:refs_bumped");
        Ok(())
    }

    pub fn has_chunk(&self, h: &Hash) -> bool {
        self.index.get(h).is_some()
    }

    /// A chunk as stored (codec byte and payload), checked against its record header but not decoded.
    /// Together with `write_chunk_raw` this moves chunks between stores without recompressing or re-encrypting.
    pub fn read_chunk_raw(&self, h: &Hash) -> Result<(u8, Vec<u8>)> {
        self.load(h)
    }

    /// Adds a chunk received from elsewhere. It is decoded and re-hashed first, so a store that
    /// doesn't share this store's keys rejects it. Returns false when the chunk was already
    /// here and `replace` is not set. A replaced chunk keeps its reference count.
    pub fn write_chunk_raw(&mut self, h: &Hash, codec: u8, payload: Vec<u8>, replace: bool) -> Result<bool> {
        if !replace && self.index.get(h).is_some() {
            return Ok(false);
        }
        let plain = self.decode(h, codec, payload.clone())?;
        self.index.mark_dirty();
        let e = match self.layout {
            Layout::V2 => self.append_raw(h, codec, &payload)?,
            Layout::V1 => self.append(h, &plain)?,
        };
        let refs = self.index.get(h).map_or(0, |o| o.refs);
        self.index.insert(h, Entry { refs, ..e })?;
        Ok(true)
    }

    /// The manifest file exactly as stored.
    pub fn manifest_bytes(&self, id: &Hash) -> Result<Vec<u8>> {
        match fs::read(self.manifest_path(id)) {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(Error::NotFound(*id)),
            Err(e) => Err(e.into()),
        }
    }

    /// Installs a manifest file received from elsewhere, after checking it decodes, hashes to `id`
    /// and that every chunk it lists is here. False if the object already existed.
    pub fn put_manifest_bytes(&mut self, id: &Hash, raw: Vec<u8>) -> Result<bool> {
        if self.manifest_path(id).exists() {
            return Ok(false);
        }
        let plain = self.open_meta(b"manifest", id.as_bytes(), raw.clone()).ok_or(Error::CorruptManifest(*id))?;
        let m = Manifest::decode(&plain).map_err(|_| Error::CorruptManifest(*id))?;
        if m.id() != *id {
            return Err(Error::CorruptManifest(*id));
        }
        if let Some(c) = m.chunks.iter().find(|c| self.index.get(&c.hash).is_none()) {
            return Err(Error::MissingChunk(c.hash));
        }
        self.index.mark_dirty();
        self.install_manifest(id, &m, &raw)?;
        Ok(true)
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
        let buf = self.open_meta(b"manifest", id.as_bytes(), buf).ok_or(Error::CorruptManifest(*id))?;
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

    // The record as stored: codec byte and payload, header and checksum verified but not decoded.
    fn load(&self, h: &Hash) -> Result<(u8, Vec<u8>)> {
        let e = self.index.get(h).ok_or(Error::MissingChunk(*h))?;
        let f = self.reader(e.segment)?;

        let mut buf = vec![0u8; self.layout.record_len(e.len) as usize];
        segment::read_exact_at(&f, &mut buf, e.offset).map_err(|err| match err.kind() {
            io::ErrorKind::UnexpectedEof => Error::Corrupt(*h),
            _ => Error::Io(err),
        })?;

        let (codec, _) = segment::open_record(self.layout, &buf, h).ok_or(Error::Corrupt(*h))?;
        let start = self.layout.header() as usize;
        buf.truncate(start + e.len as usize);
        buf.drain(..start);
        Ok((codec, buf))
    }

    fn decode(&self, h: &Hash, codec: u8, payload: Vec<u8>) -> Result<Vec<u8>> {
        let data = if codec == 0 && self.keys.is_none() {
            payload
        } else {
            transform::unpack(codec, &payload, h, self.keys.as_ref()).ok_or(Error::Corrupt(*h))?
        };
        if self.chunk_id(&data) != *h {
            return Err(Error::Corrupt(*h));
        }
        Ok(data)
    }

    /// Reads one chunk, undoes compression and encryption, and re-hashes it; a mismatch is `Error::Corrupt`.
    pub fn get_chunk(&self, h: &Hash) -> Result<Vec<u8>> {
        let r = self.load(h).and_then(|(codec, payload)| self.decode(h, codec, payload));
        match &r {
            Ok(d) => {
                self.counters.chunk_reads.fetch_add(1, Relaxed);
                self.counters.bytes_read.fetch_add(d.len() as u64, Relaxed);
            }
            Err(Error::Corrupt(_)) => {
                self.counters.corrupt_seen.fetch_add(1, Relaxed);
            }
            Err(_) => {}
        }
        r
    }

    // ids are keyed hashes in an encrypted store, so nobody without the key can confirm a file is in it
    fn chunk_id(&self, data: &[u8]) -> Hash {
        match &self.keys {
            Some(k) => k.chunk_id(data),
            None => Hash::of(data),
        }
    }

    pub(crate) fn seal_meta(&self, ctx: &[u8], name: &[u8], data: Vec<u8>) -> Vec<u8> {
        match &self.keys {
            Some(k) => k.seal(&[ctx, name].concat(), &data),
            None => data,
        }
    }

    pub(crate) fn open_meta(&self, ctx: &[u8], name: &[u8], data: Vec<u8>) -> Option<Vec<u8>> {
        match &self.keys {
            Some(k) => k.open(&[ctx, name].concat(), &data),
            None => Some(data),
        }
    }

    pub fn is_encrypted(&self) -> bool {
        self.keys.is_some()
    }

    /// Rewraps the master key under a new password; no chunk is rewritten.
    pub fn change_password(&mut self, new: &Password) -> Result<()> {
        let keys = self.keys.as_ref().ok_or(Error::NotEncrypted)?;
        self.format.rewrap(keys, new.as_bytes(), self.cfg.kdf)?;
        write_atomic(&self.root.join("FORMAT"), &self.format.encode())?;
        Ok(())
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

    /// Everything wrong that can be found without changing anything: manifests that fail their
    /// check, chunks that fail theirs (referenced or not), and chunks a good manifest lists
    /// that the index doesn't have.
    pub fn check(&self) -> Result<Damage> {
        let mut d = Damage::default();
        let mut wanted = HashSet::new();
        for id in self.list()? {
            match self.manifest(&id) {
                Ok(m) => wanted.extend(m.chunks.iter().map(|c| c.hash)),
                Err(Error::CorruptManifest(_)) => d.bad_manifests.push(id),
                Err(e) => return Err(e),
            }
        }
        d.missing_chunks = wanted.into_iter().filter(|h| self.index.get(h).is_none()).collect();
        d.missing_chunks.sort();
        d.corrupt_chunks = self.scrub()?.corrupt;
        d.corrupt_chunks.sort();
        Ok(d)
    }

    pub(crate) fn chunk_segment(&self, h: &Hash) -> Option<u32> {
        self.index.get(h).map(|e| e.segment)
    }

    pub(crate) fn drop_manifest_file(&self, id: &Hash) -> Result<()> {
        fs::remove_file(self.manifest_path(id))?;
        sync_dir(&self.root.join("manifests"))?;
        Ok(())
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
        self.gc_segments(&HashSet::new())
    }

    // `force` segments are rewritten whatever their dead fraction is
    pub(crate) fn gc_segments(&mut self, force: &HashSet<u32>) -> Result<GcReport> {
        // chunks only an unreadable manifest refers to look unreferenced; deleting them would make the damage permanent
        for id in self.list()? {
            self.manifest(&id)?;
        }
        self.counters.gc_runs.fetch_add(1, Relaxed);
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
            let n = self.layout.record_len(e.len);
            if e.refs == 0 { t.dead += n } else { t.live += n }
        }

        if let Some(a) = self.active.take() {
            a.file.sync_data()?;
        }

        let dir = self.seg_dir();
        let mut victims: Vec<u32> = tally
            .iter()
            .filter(|(_, t)| {
                t.dead > 0 && (t.live == 0 || t.dead as f64 / (t.live + t.dead) as f64 >= self.cfg.gc_threshold)
            })
            .map(|(&id, _)| id)
            .collect();
        for id in force {
            if !victims.contains(id) && segment::path(&dir, *id).exists() {
                victims.push(*id);
            }
        }
        victims.sort_unstable();

        let mut rep = GcReport::default();
        if victims.is_empty() {
            return Ok(rep);
        }
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
        self.in_gc = true;
        let mut moved = 0u64;
        let copied = (|| -> Result<()> {
            for (h, old) in live {
                // decode first so a rotten chunk stops the gc before its only copy is deleted
                let (codec, payload) = self.load(&h)?;
                self.decode(&h, codec, payload.clone())?;
                let ne = self.append_raw(&h, codec, &payload)?;
                self.index.insert(&h, Entry { refs: old.refs, ..ne })?;
                moved += self.layout.record_len(old.len);
                rep.chunks_moved += 1;
            }
            Ok(())
        })();
        self.in_gc = false;
        copied?;
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
        self.disk_bytes = self.measure_disk()?;

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
