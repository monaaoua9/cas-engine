use crate::cursor::Cursor;
use crate::error::{Error, Result};
use crate::hash::{HASH_LEN, Hash};

const MAGIC: &[u8; 4] = b"CAST";
const VERSION: u8 = 1;

// tag + mode + mtime + mtime_ns + size + id + name len + target len
const MIN_ENTRY: usize = 1 + 4 + 8 + 4 + 8 + HASH_LEN + 2 + 2;

pub const MAX_NAME: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
}

impl Kind {
    fn tag(self) -> u8 {
        match self {
            Kind::File => 0,
            Kind::Dir => 1,
            Kind::Symlink => 2,
        }
    }

    fn from_tag(t: u8) -> Option<Kind> {
        match t {
            0 => Some(Kind::File),
            1 => Some(Kind::Dir),
            2 => Some(Kind::Symlink),
            _ => None,
        }
    }
}

/// One directory entry. `id` is the file object or the subtree; symlinks
/// carry their target inline and a zero id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub mode: u32,
    pub mtime: i64,
    pub mtime_ns: u32,
    pub size: u64,
    pub id: Hash,
    pub target: String,
}

impl Entry {
    pub fn zero_id() -> Hash {
        Hash::from_bytes([0; HASH_LEN])
    }
}

/// Names end up as path components on restore, so anything that could climb
/// out of the destination is refused here and again on decode.
pub fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= MAX_NAME && n != "." && n != ".." && !n.contains(['/', '\\', '\0'])
}

fn check(e: &Entry) -> Result<()> {
    if !valid_name(&e.name) {
        return Err(Error::InvalidName(e.name.clone()));
    }
    match e.kind {
        Kind::Symlink => {
            if e.target.is_empty() || e.target.len() > u16::MAX as usize || e.target.contains('\0') {
                return Err(Error::BadTree("bad symlink target"));
            }
            if e.id != Entry::zero_id() {
                return Err(Error::BadTree("symlink with an object id"));
            }
        }
        _ => {
            if !e.target.is_empty() {
                return Err(Error::BadTree("target on a non-symlink"));
            }
        }
    }
    Ok(())
}

/// A directory listing, sorted by name. Stored as an ordinary object, so
/// identical directories share an id and unchanged subtrees dedupe for free.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Tree {
    pub entries: Vec<Entry>,
}

impl Tree {
    pub fn new(mut entries: Vec<Entry>) -> Result<Tree> {
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        for e in &entries {
            check(e)?;
        }
        if let Some(w) = entries.windows(2).find(|w| w[0].name == w[1].name) {
            return Err(Error::InvalidName(w[0].name.clone()));
        }
        Ok(Tree { entries })
    }

    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.entries.binary_search_by(|e| e.name.as_str().cmp(name)).ok().map(|i| &self.entries[i])
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.entries.len() * (MIN_ENTRY + 24));
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for e in &self.entries {
            out.push(e.kind.tag());
            out.extend_from_slice(&e.mode.to_le_bytes());
            out.extend_from_slice(&e.mtime.to_le_bytes());
            out.extend_from_slice(&e.mtime_ns.to_le_bytes());
            out.extend_from_slice(&e.size.to_le_bytes());
            out.extend_from_slice(e.id.as_bytes());
            out.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            out.extend_from_slice(e.name.as_bytes());
            out.extend_from_slice(&(e.target.len() as u16).to_le_bytes());
            out.extend_from_slice(e.target.as_bytes());
        }
        let sum = Hash::of(&out);
        out.extend_from_slice(sum.as_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Tree> {
        if buf.len() < 4 + 1 + 4 + HASH_LEN {
            return Err(Error::BadTree("too short"));
        }
        let (body, sum) = buf.split_at(buf.len() - HASH_LEN);
        if Hash::of(body).as_bytes() != sum {
            return Err(Error::BadTree("checksum mismatch"));
        }

        let mut c = Cursor::new(body, Error::BadTree);
        if c.take(4)? != MAGIC {
            return Err(Error::BadTree("bad magic"));
        }
        if c.u8()? != VERSION {
            return Err(Error::BadTree("unsupported version"));
        }
        let count = c.u32()? as usize;
        if count > c.left() / MIN_ENTRY {
            return Err(Error::BadTree("entry count does not fit"));
        }

        let mut entries: Vec<Entry> = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = Kind::from_tag(c.u8()?).ok_or(Error::BadTree("unknown entry kind"))?;
            let mode = c.u32()?;
            let mtime = c.i64()?;
            let mtime_ns = c.u32()?;
            let size = c.u64()?;
            let id = c.hash()?;
            let n = c.u16()? as usize;
            let name = c.string(n)?;
            let n = c.u16()? as usize;
            let target = c.string(n)?;

            let e = Entry { name, kind, mode, mtime, mtime_ns, size, id, target };
            check(&e)?;
            if entries.last().is_some_and(|p| p.name >= e.name) {
                return Err(Error::BadTree("entries not strictly sorted"));
            }
            entries.push(e);
        }
        if c.left() != 0 {
            return Err(Error::BadTree("trailing bytes"));
        }
        Ok(Tree { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, n: u8) -> Entry {
        Entry {
            name: name.into(),
            kind: Kind::File,
            mode: 0o644,
            mtime: 1_700_000_000 + n as i64,
            mtime_ns: 5,
            size: 10 * n as u64,
            id: Hash::of(&[n]),
            target: String::new(),
        }
    }

    fn link(name: &str, to: &str) -> Entry {
        Entry { kind: Kind::Symlink, id: Entry::zero_id(), target: to.into(), size: 0, ..file(name, 0) }
    }

    #[test]
    fn roundtrip_and_sorting() {
        let t = Tree::new(vec![file("zeta", 1), link("alpha", "../x"), file("mid", 2)]).unwrap();
        let names: Vec<_> = t.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["alpha", "mid", "zeta"]);
        assert_eq!(Tree::decode(&t.encode()).unwrap(), t);
    }

    #[test]
    fn same_entries_same_bytes_regardless_of_input_order() {
        let a = Tree::new(vec![file("a", 1), file("b", 2)]).unwrap();
        let b = Tree::new(vec![file("b", 2), file("a", 1)]).unwrap();
        assert_eq!(a.encode(), b.encode());
    }

    #[test]
    fn any_flipped_byte_is_rejected() {
        let enc = Tree::new(vec![file("a", 1), link("l", "t")]).unwrap().encode();
        for i in 0..enc.len() {
            let mut bad = enc.clone();
            bad[i] ^= 0x10;
            assert!(Tree::decode(&bad).is_err(), "byte {i}");
        }
    }

    #[test]
    fn hostile_names_are_refused() {
        for n in ["", ".", "..", "a/b", "a\\b", "x\0y", "../etc"] {
            assert!(Tree::new(vec![file(n, 1)]).is_err(), "{n:?}");
        }
        assert!(Tree::new(vec![file(&"n".repeat(MAX_NAME + 1), 1)]).is_err());
    }

    #[test]
    fn duplicates_are_refused() {
        assert!(Tree::new(vec![file("a", 1), file("a", 2)]).is_err());
    }

    #[test]
    fn decode_rejects_unsorted_even_with_a_valid_checksum() {
        // bypass Tree::new so the entries stay out of order
        let t = Tree { entries: vec![file("b", 1), file("a", 2)] };
        assert!(matches!(Tree::decode(&t.encode()), Err(Error::BadTree(_))));
    }

    #[test]
    fn decode_rejects_traversal_names_even_with_a_valid_checksum() {
        let t = Tree { entries: vec![file("..", 1)] };
        assert!(matches!(Tree::decode(&t.encode()), Err(Error::InvalidName(_))));
    }

    #[test]
    fn huge_count_does_not_allocate() {
        let mut b = Vec::new();
        b.extend_from_slice(MAGIC);
        b.push(VERSION);
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        let sum = Hash::of(&b);
        b.extend_from_slice(sum.as_bytes());
        assert!(Tree::decode(&b).is_err());
    }

    #[test]
    fn get_by_name() {
        let t = Tree::new(vec![file("a", 1), file("c", 3), file("b", 2)]).unwrap();
        assert_eq!(t.get("b").unwrap().size, 20);
        assert!(t.get("d").is_none());
    }
}
