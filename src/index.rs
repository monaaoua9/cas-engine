//! Memory-mapped hash table: chunk hash -> (segment, offset, len, refcount).
//!
//! Open addressing with linear probing and backward-shift deletion (no
//! tombstones, so probe chains stay short after heavy GC). Slots are fixed
//! 64-byte records, which keeps one lookup to one cache line.
//!
//! The file is a cache, not the source of truth: segments hold the bytes and
//! manifests hold the references. A header flag tracks whether the last
//! session shut down cleanly; if not, the store rebuilds this file.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

use memmap2::MmapMut;

use crate::hash::{HASH_LEN, Hash};

const MAGIC: &[u8; 8] = b"CASIDX01";
const HEADER: usize = 64;
const SLOT: usize = 64;
const MIN_CAP: usize = 1024;

// header: magic(8) | capacity u64 | len u64 | clean flag u8
const H_CAP: usize = 8;
const H_LEN: usize = 16;
const H_CLEAN: usize = 24;

// slot: hash(32) | segment u32 | len u32 | offset u64 | refs u32 | used u8
const S_SEG: usize = HASH_LEN;
const S_LEN: usize = S_SEG + 4;
const S_OFF: usize = S_LEN + 4;
const S_REFS: usize = S_OFF + 8;
const S_USED: usize = S_REFS + 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub segment: u32,
    pub offset: u64,
    pub len: u32,
    pub refs: u32,
}

pub struct Index {
    file: File,
    map: MmapMut,
    cap: usize,
    len: usize,
    dirty: bool,
}

fn file_size(cap: usize) -> u64 {
    (HEADER + cap * SLOT) as u64
}

fn map_file(file: &File) -> io::Result<MmapMut> {
    // SAFETY: the store holds an exclusive lock for its whole lifetime and
    // only this module touches the file, so nobody truncates it under us.
    unsafe { MmapMut::map_mut(file) }
}

impl Index {
    /// Returns the index and whether it was shut down cleanly last time.
    /// A missing or unreadable file is reinitialised and reported as unclean.
    pub fn open(path: &Path) -> io::Result<(Index, bool)> {
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        let flen = file.metadata()?.len();

        if flen >= HEADER as u64 {
            let map = map_file(&file)?;
            let cap = u64::from_le_bytes(map[H_CAP..H_CAP + 8].try_into().unwrap()) as usize;
            let ok = &map[..8] == MAGIC && cap.is_power_of_two() && file_size(cap) == flen;
            if ok {
                let len = u64::from_le_bytes(map[H_LEN..H_LEN + 8].try_into().unwrap()) as usize;
                let clean = map[H_CLEAN] == 1;
                let idx = Index { file, map, cap, len, dirty: !clean };
                return Ok((idx, clean));
            }
        }

        let mut idx = Index { file, map: MmapMut::map_anon(1)?, cap: 0, len: 0, dirty: true };
        idx.reinit(MIN_CAP, &[])?;
        Ok((idx, false))
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear(&mut self) -> io::Result<()> {
        self.mark_dirty();
        self.reinit(MIN_CAP, &[])
    }

    fn reinit(&mut self, cap: usize, entries: &[(Hash, Entry)]) -> io::Result<()> {
        // windows refuses to resize a file that still has a live mapping
        self.map = MmapMut::map_anon(1)?;
        self.file.set_len(0)?;
        self.file.set_len(file_size(cap))?;
        self.map = map_file(&self.file)?;
        self.cap = cap;
        self.len = 0;

        self.map[..8].copy_from_slice(MAGIC);
        self.map[H_CAP..H_CAP + 8].copy_from_slice(&(cap as u64).to_le_bytes());
        for (h, e) in entries {
            self.place(h, *e);
        }
        Ok(())
    }

    fn slot(&self, i: usize) -> &[u8] {
        let o = HEADER + i * SLOT;
        &self.map[o..o + SLOT]
    }

    fn slot_mut(&mut self, i: usize) -> &mut [u8] {
        let o = HEADER + i * SLOT;
        &mut self.map[o..o + SLOT]
    }

    fn used(&self, i: usize) -> bool {
        self.slot(i)[S_USED] != 0
    }

    fn key(&self, i: usize) -> Hash {
        Hash::from_bytes(self.slot(i)[..HASH_LEN].try_into().unwrap())
    }

    fn entry(&self, i: usize) -> Entry {
        let s = self.slot(i);
        Entry {
            segment: u32::from_le_bytes(s[S_SEG..S_SEG + 4].try_into().unwrap()),
            len: u32::from_le_bytes(s[S_LEN..S_LEN + 4].try_into().unwrap()),
            offset: u64::from_le_bytes(s[S_OFF..S_OFF + 8].try_into().unwrap()),
            refs: u32::from_le_bytes(s[S_REFS..S_REFS + 4].try_into().unwrap()),
        }
    }

    fn write(&mut self, i: usize, h: &Hash, e: Entry) {
        let s = self.slot_mut(i);
        s[..HASH_LEN].copy_from_slice(h.as_bytes());
        s[S_SEG..S_SEG + 4].copy_from_slice(&e.segment.to_le_bytes());
        s[S_LEN..S_LEN + 4].copy_from_slice(&e.len.to_le_bytes());
        s[S_OFF..S_OFF + 8].copy_from_slice(&e.offset.to_le_bytes());
        s[S_REFS..S_REFS + 4].copy_from_slice(&e.refs.to_le_bytes());
        s[S_USED] = 1;
    }

    fn home(&self, h: &Hash) -> usize {
        // blake3 output is uniform already, no need to mix again
        let x = u64::from_le_bytes(h.as_bytes()[..8].try_into().unwrap());
        x as usize & (self.cap - 1)
    }

    fn find(&self, h: &Hash) -> Option<usize> {
        let mut i = self.home(h);
        while self.used(i) {
            if self.key(i) == *h {
                return Some(i);
            }
            i = (i + 1) & (self.cap - 1);
        }
        None
    }

    fn set_len(&mut self, n: usize) {
        self.len = n;
        self.map[H_LEN..H_LEN + 8].copy_from_slice(&(n as u64).to_le_bytes());
    }

    // caller guarantees the key is absent and there is room
    fn place(&mut self, h: &Hash, e: Entry) {
        let mut i = self.home(h);
        while self.used(i) {
            i = (i + 1) & (self.cap - 1);
        }
        self.write(i, h, e);
        self.set_len(self.len + 1);
    }

    pub fn get(&self, h: &Hash) -> Option<Entry> {
        self.find(h).map(|i| self.entry(i))
    }

    pub fn insert(&mut self, h: &Hash, e: Entry) -> io::Result<()> {
        self.mark_dirty();
        if let Some(i) = self.find(h) {
            self.write(i, h, e);
            return Ok(());
        }
        if (self.len + 1) * 10 > self.cap * 7 {
            let all = self.entries();
            self.reinit(self.cap * 2, &all)?;
        }
        self.place(h, e);
        Ok(())
    }

    pub fn remove(&mut self, h: &Hash) -> bool {
        let Some(mut hole) = self.find(h) else { return false };
        self.mark_dirty();

        let mask = self.cap - 1;
        self.slot_mut(hole)[S_USED] = 0;
        self.set_len(self.len - 1);

        // pull later entries of the probe run back over the hole whenever
        // their home slot doesn't lie between the hole and their position
        let mut j = hole;
        loop {
            j = (j + 1) & mask;
            if !self.used(j) {
                break;
            }
            let home = self.home(&self.key(j));
            let from_home = j.wrapping_sub(home) & mask;
            let from_hole = j.wrapping_sub(hole) & mask;
            if from_home >= from_hole {
                let src = HEADER + j * SLOT;
                self.map.copy_within(src..src + SLOT, HEADER + hole * SLOT);
                self.slot_mut(j)[S_USED] = 0;
                hole = j;
            }
        }
        true
    }

    pub fn entries(&self) -> Vec<(Hash, Entry)> {
        (0..self.cap).filter(|&i| self.used(i)).map(|i| (self.key(i), self.entry(i))).collect()
    }

    pub fn mark_dirty(&mut self) {
        if self.dirty {
            return;
        }
        self.dirty = true;
        self.map[H_CLEAN] = 0;
        // best effort: the flag only matters after a crash, and a failed
        // flush here will surface on the next real write anyway
        let _ = self.map.flush_range(0, HEADER);
    }

    pub fn mark_clean(&mut self) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        self.map.flush()?;
        self.map[H_CLEAN] = 1;
        self.map.flush_range(0, HEADER)?;
        self.dirty = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn e(n: u32) -> Entry {
        Entry { segment: n, offset: n as u64 * 7, len: n + 1, refs: 1 }
    }

    #[test]
    fn insert_get_remove_against_model() {
        let dir = tempfile::tempdir().unwrap();
        let (mut idx, clean) = Index::open(&dir.path().join("i.bin")).unwrap();
        assert!(!clean);

        let mut model = HashMap::new();
        for n in 0..5000u32 {
            let h = Hash::of(&n.to_le_bytes());
            idx.insert(&h, e(n)).unwrap();
            model.insert(h, e(n));
        }
        // drop every third, which exercises backward shifting inside long runs
        for n in (0..5000u32).step_by(3) {
            let h = Hash::of(&n.to_le_bytes());
            assert!(idx.remove(&h));
            model.remove(&h);
        }
        assert!(!idx.remove(&Hash::of(b"never inserted")));

        assert_eq!(idx.len(), model.len());
        for n in 0..5000u32 {
            let h = Hash::of(&n.to_le_bytes());
            assert_eq!(idx.get(&h), model.get(&h).copied(), "n={n}");
        }
    }

    #[test]
    fn overwrite_keeps_one_slot() {
        let dir = tempfile::tempdir().unwrap();
        let (mut idx, _) = Index::open(&dir.path().join("i.bin")).unwrap();
        let h = Hash::of(b"k");
        idx.insert(&h, e(1)).unwrap();
        idx.insert(&h, e(2)).unwrap();
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.get(&h), Some(e(2)));
    }

    #[test]
    fn persists_and_reports_clean_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("i.bin");
        let h = Hash::of(b"persist");
        {
            let (mut idx, _) = Index::open(&p).unwrap();
            idx.insert(&h, e(9)).unwrap();
            idx.mark_clean().unwrap();
        }
        let (idx, clean) = Index::open(&p).unwrap();
        assert!(clean);
        assert_eq!(idx.get(&h), Some(e(9)));
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn unflushed_session_is_reported_dirty() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("i.bin");
        {
            let (mut idx, _) = Index::open(&p).unwrap();
            idx.mark_clean().unwrap();
            idx.insert(&Hash::of(b"a"), e(1)).unwrap();
            // no mark_clean: simulates a crash
        }
        let (_, clean) = Index::open(&p).unwrap();
        assert!(!clean);
    }
}
