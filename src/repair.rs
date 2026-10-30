use std::collections::HashSet;

use crate::error::{Error, Result};
use crate::hash::Hash;
use crate::store::Store;

#[derive(Debug, Default, Clone)]
pub struct RepairReport {
    pub chunks_fixed: u64,
    pub manifests_fixed: u64,
    /// Chunk and manifest ids the other copy couldn't supply either.
    pub unrecoverable: Vec<Hash>,
}

impl Store {
    /// Heals this store from a second copy that shares its chunk ids (a replica made by
    /// copying the directory, or by push/pull). Anything `check` finds wrong is fetched
    /// from `copy`, verified again here, and written in place of the damaged version.
    /// Segments that held a bad chunk are rewritten afterwards so the damage is gone
    /// from disk, not just from the index.
    pub fn repair_from(&mut self, copy: &Store) -> Result<RepairReport> {
        let dmg = self.check()?;
        let mut rep = RepairReport::default();
        if dmg.is_empty() {
            return Ok(rep);
        }

        let mut fixed_in: HashSet<u32> = HashSet::new();
        let mut stuck_in: HashSet<u32> = HashSet::new();
        let mut restored = Vec::new();

        for h in dmg.corrupt_chunks.iter().chain(&dmg.missing_chunks) {
            let seg = self.chunk_segment(h);
            let was_missing = seg.is_none();
            match copy.read_chunk_raw(h).and_then(|(c, p)| self.write_chunk_raw(h, c, p, true)) {
                Ok(_) => {
                    rep.chunks_fixed += 1;
                    fixed_in.extend(seg);
                    if was_missing {
                        restored.push(*h);
                    }
                }
                Err(Error::Io(e)) => return Err(Error::Io(e)),
                Err(_) => {
                    rep.unrecoverable.push(*h);
                    stuck_in.extend(seg);
                }
            }
        }

        for id in &dmg.bad_manifests {
            let fetched = copy.manifest_bytes(id).and_then(|raw| {
                self.drop_manifest_file(id)?;
                self.put_manifest_bytes(id, raw)
            });
            match fetched {
                Ok(_) => rep.manifests_fixed += 1,
                Err(Error::Io(e)) => return Err(Error::Io(e)),
                Err(_) => rep.unrecoverable.push(*id),
            }
        }

        let force: HashSet<u32> = fixed_in.difference(&stuck_in).copied().collect();
        let manifests_ok = !rep.unrecoverable.iter().any(|h| dmg.bad_manifests.contains(h));
        if manifests_ok {
            self.recount_refs()?;
        } else {
            for h in &restored {
                self.pin_chunk(h)?;
            }
        }
        // gc refuses to run while a manifest is unreadable
        if manifests_ok && !force.is_empty() {
            self.gc_segments(&force)?;
        }
        self.sync()?;
        Ok(rep)
    }
}
