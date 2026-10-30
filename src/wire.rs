//! Framing and message encoding for the store protocol. A frame is
//! `len u32 | tag u8 | body`, where `len` counts the tag and the body.

use std::io::{self, Read, Write};

use crate::cursor::Cursor;
use crate::error::{Error, Result};
use crate::hash::{HASH_LEN, Hash};

pub const MAGIC: &[u8; 4] = b"CASN";
pub const VERSION: u8 = 1;

// a chunk is at most a few MiB; this only stops a bogus length from sizing an allocation
pub const MAX_FRAME: usize = 32 << 20;

pub const OP_PING: u8 = 0;
pub const OP_MISSING: u8 = 1;
pub const OP_HAS_OBJECT: u8 = 2;
pub const OP_GET_CHUNK: u8 = 3;
pub const OP_PUT_CHUNK: u8 = 4;
pub const OP_GET_MANIFEST: u8 = 5;
pub const OP_PUT_MANIFEST: u8 = 6;
pub const OP_MANIFEST_CHUNKS: u8 = 7;
pub const OP_LIST_OBJECTS: u8 = 8;
pub const OP_LIST_SNAPSHOTS: u8 = 9;
pub const OP_GET_SNAPSHOT: u8 = 10;
pub const OP_PUT_SNAPSHOT: u8 = 11;
pub const OP_SNAPSHOT_MEMBERS: u8 = 12;
pub const OP_METRICS: u8 = 13;

pub const ST_OK: u8 = 0;
pub const ST_NOT_FOUND: u8 = 1;
pub const ST_ERROR: u8 = 2;
pub const ST_DENIED: u8 = 3;
pub const ST_CONFLICT: u8 = 4;

pub fn write_frame(w: &mut impl Write, tag: u8, body: &[u8]) -> io::Result<()> {
    let len = (body.len() + 1) as u32;
    let mut head = [0u8; 5];
    head[..4].copy_from_slice(&len.to_le_bytes());
    head[4] = tag;
    w.write_all(&head)?;
    w.write_all(body)?;
    w.flush()
}

/// None when the peer closed the connection cleanly between frames.
pub fn read_frame(r: &mut impl Read) -> Result<Option<(u8, Vec<u8>)>> {
    let mut len = [0u8; 4];
    match r.read(&mut len[..1])? {
        0 => return Ok(None),
        _ => r.read_exact(&mut len[1..])?,
    }
    let len = u32::from_le_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME + 1 {
        return Err(Error::Protocol("frame length out of range"));
    }
    let mut tag = [0u8; 1];
    r.read_exact(&mut tag)?;
    let mut body = vec![0u8; len - 1];
    r.read_exact(&mut body)?;
    Ok(Some((tag[0], body)))
}

pub fn put_hash(out: &mut Vec<u8>, h: &Hash) {
    out.extend_from_slice(h.as_bytes());
}

pub fn put_hashes(out: &mut Vec<u8>, hs: &[Hash]) {
    out.extend_from_slice(&(hs.len() as u32).to_le_bytes());
    for h in hs {
        put_hash(out, h);
    }
}

pub fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

pub(crate) fn reader(body: &[u8]) -> Cursor<'_> {
    Cursor::new(body, Error::Protocol)
}

pub(crate) fn get_hashes(c: &mut Cursor<'_>) -> Result<Vec<Hash>> {
    let n = c.u32()? as usize;
    // the claimed count has to fit in what was actually sent
    if n > c.left() / HASH_LEN {
        return Err(Error::Protocol("hash count does not fit"));
    }
    (0..n).map(|_| c.hash()).collect()
}

pub(crate) fn get_str(c: &mut Cursor<'_>) -> Result<String> {
    let n = c.u16()? as usize;
    c.string(n)
}

pub(crate) fn done(c: &Cursor<'_>) -> Result<()> {
    if c.left() != 0 { Err(Error::Protocol("trailing bytes")) } else { Ok(()) }
}

/// Both sides prove they know the token without sending it: keyed hash of a
/// fresh server nonce, with a different label for each direction so one
/// side's answer can't be replayed to the other.
pub fn auth_key(token: &[u8]) -> [u8; 32] {
    blake3::derive_key("cas net auth v1", token)
}

pub fn proof(key: &[u8; 32], who: &[u8], nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(who);
    h.update(nonce);
    *h.finalize().as_bytes()
}

pub fn proofs_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    blake3::Hash::from_bytes(*a) == blake3::Hash::from_bytes(*b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, 7, b"hello").unwrap();
        write_frame(&mut buf, 9, b"").unwrap();
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r).unwrap(), Some((7, b"hello".to_vec())));
        assert_eq!(read_frame(&mut r).unwrap(), Some((9, vec![])));
        assert_eq!(read_frame(&mut r).unwrap(), None);
    }

    #[test]
    fn bad_lengths_are_refused() {
        let mut zero = &[0u8, 0, 0, 0, 1][..];
        assert!(read_frame(&mut zero).is_err());
        let mut huge = &[0xFFu8, 0xFF, 0xFF, 0x7F, 1][..];
        assert!(read_frame(&mut huge).is_err());
    }

    #[test]
    fn truncated_frame_is_an_error_not_a_hang() {
        let mut buf = Vec::new();
        write_frame(&mut buf, 1, b"0123456789").unwrap();
        for cut in 1..buf.len() {
            let mut r = &buf[..cut];
            assert!(read_frame(&mut r).is_err(), "cut {cut}");
        }
    }

    #[test]
    fn hash_lists() {
        let hs: Vec<Hash> = (0u8..5).map(|i| Hash::of(&[i])).collect();
        let mut b = Vec::new();
        put_hashes(&mut b, &hs);
        let mut c = reader(&b);
        assert_eq!(get_hashes(&mut c).unwrap(), hs);
        done(&c).unwrap();
    }

    #[test]
    fn lying_hash_count_does_not_allocate() {
        let mut b = u32::MAX.to_le_bytes().to_vec();
        b.extend_from_slice(&[0u8; 64]);
        assert!(get_hashes(&mut reader(&b)).is_err());
    }

    #[test]
    fn proofs_depend_on_key_direction_and_nonce() {
        let k = auth_key(b"secret");
        let n = [3u8; 32];
        let p = proof(&k, b"client", &n);
        assert!(proofs_equal(&p, &proof(&k, b"client", &n)));
        assert!(!proofs_equal(&p, &proof(&k, b"server", &n)));
        assert!(!proofs_equal(&p, &proof(&k, b"client", &[4u8; 32])));
        assert!(!proofs_equal(&p, &proof(&auth_key(b"other"), b"client", &n)));
    }

    #[test]
    fn strings() {
        let mut b = Vec::new();
        put_str(&mut b, "nightly-2024");
        let mut c = reader(&b);
        assert_eq!(get_str(&mut c).unwrap(), "nightly-2024");
        done(&c).unwrap();
        assert!(get_str(&mut reader(&[5, 0, b'a'])).is_err());
    }
}
