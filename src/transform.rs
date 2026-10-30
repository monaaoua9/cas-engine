use crate::crypto::Keys;
use crate::hash::Hash;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Compression {
    #[default]
    None,
    Lz4,
}

// codec byte stored in every v2 record; a reader can always tell what was done to a chunk
const LZ4: u8 = 0x01;
const ENC: u8 = 0x80;

// nothing a chunker produces comes close; stops a bogus length from sizing an allocation
const MAX_PLAIN: usize = 64 << 20;

/// compress (when it helps), then encrypt. Incompressible chunks are kept raw.
pub fn pack(data: &[u8], id: &Hash, comp: Compression, keys: Option<&Keys>) -> (u8, Vec<u8>) {
    let mut codec = 0;
    let mut squeezed = None;
    if comp == Compression::Lz4 {
        let c = lz4_flex::block::compress(data);
        if c.len() + 4 < data.len() {
            let mut v = Vec::with_capacity(4 + c.len());
            v.extend_from_slice(&(data.len() as u32).to_le_bytes());
            v.extend_from_slice(&c);
            squeezed = Some(v);
            codec |= LZ4;
        }
    }
    let body = squeezed.as_deref().unwrap_or(data);
    match keys {
        Some(k) => (codec | ENC, k.seal(id.as_bytes(), body)),
        None => (codec, body.to_vec()),
    }
}

/// Inverse of `pack`. None means the bytes are not what the codec byte claims.
pub fn unpack(codec: u8, payload: &[u8], id: &Hash, keys: Option<&Keys>) -> Option<Vec<u8>> {
    if codec & !(LZ4 | ENC) != 0 {
        return None;
    }
    // a plain record in an encrypted store (or the reverse) is never legitimate
    let plain = match (codec & ENC != 0, keys) {
        (true, Some(k)) => k.open(id.as_bytes(), payload)?,
        (false, None) => payload.to_vec(),
        _ => return None,
    };
    if codec & LZ4 == 0 {
        return Some(plain);
    }

    let n = u32::from_le_bytes(plain.get(..4)?.try_into().ok()?) as usize;
    if n > MAX_PLAIN {
        return None;
    }
    let mut out = vec![0u8; n];
    let got = lz4_flex::block::decompress_into(&plain[4..], &mut out).ok()?;
    (got == n).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text() -> Vec<u8> {
        b"the quick brown fox ".repeat(500)
    }

    fn noise() -> Vec<u8> {
        let mut x = 0x9e3779b97f4a7c15u64;
        (0..5000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn plain_passthrough() {
        let d = text();
        let id = Hash::of(&d);
        let (c, p) = pack(&d, &id, Compression::None, None);
        assert_eq!((c, p.as_slice()), (0, d.as_slice()));
        assert_eq!(unpack(c, &p, &id, None).unwrap(), d);
    }

    #[test]
    fn lz4_shrinks_text_and_roundtrips() {
        let d = text();
        let id = Hash::of(&d);
        let (c, p) = pack(&d, &id, Compression::Lz4, None);
        assert_eq!(c, LZ4);
        assert!(p.len() < d.len() / 5);
        assert_eq!(unpack(c, &p, &id, None).unwrap(), d);
    }

    #[test]
    fn incompressible_data_stays_raw() {
        let d = noise();
        let (c, p) = pack(&d, &Hash::of(&d), Compression::Lz4, None);
        assert_eq!(c, 0);
        assert_eq!(p, d);
    }

    #[test]
    fn encrypted_roundtrip_with_and_without_compression() {
        let k = Keys::generate();
        for comp in [Compression::None, Compression::Lz4] {
            let d = text();
            let id = k.chunk_id(&d);
            let (c, p) = pack(&d, &id, comp, Some(&k));
            assert_ne!(c & ENC, 0);
            assert_eq!(unpack(c, &p, &id, Some(&k)).unwrap(), d);
            // bound to its id: replaying under another id fails
            assert!(unpack(c, &p, &k.chunk_id(b"other"), Some(&k)).is_none());
        }
    }

    #[test]
    fn mismatched_encryption_state_is_rejected() {
        let k = Keys::generate();
        let d = text();
        let id = k.chunk_id(&d);
        let (c, p) = pack(&d, &id, Compression::None, Some(&k));
        assert!(unpack(c, &p, &id, None).is_none());
        let (c, p) = pack(&d, &id, Compression::None, None);
        assert!(unpack(c, &p, &id, Some(&k)).is_none());
    }

    #[test]
    fn garbage_is_rejected_not_trusted() {
        let id = Hash::of(b"x");
        assert!(unpack(0x42, b"abc", &id, None).is_none());
        // lz4 flag with a length prefix that promises far too much
        let mut bad = u32::MAX.to_le_bytes().to_vec();
        bad.extend_from_slice(b"junk");
        assert!(unpack(LZ4, &bad, &id, None).is_none());
        // lz4 flag with a length prefix that lies about the real size
        let d = text();
        let (c, mut p) = pack(&d, &id, Compression::Lz4, None);
        p[..4].copy_from_slice(&(d.len() as u32 + 7).to_le_bytes());
        assert!(unpack(c, &p, &id, None).is_none());
        assert!(unpack(LZ4, b"ab", &id, None).is_none());
    }
}
