use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

use crate::hash::{HASH_LEN, Hash};

// v1 record: hash (32) | payload len (u32 le) | payload
// v2 record: hash (32) | payload len (u32 le) | codec (u8) | payload | sum (8)
//
// v1 is what stores without a FORMAT file use; the hash covers the payload, so
// a scan can check it alone. In v2 the payload may be compressed or encrypted,
// so the hash (a chunk id, possibly keyed) can't be checked without the key and
// a short checksum over the whole record stands in for it during scans.
pub const REC_HEADER: u64 = HASH_LEN as u64 + 4;
const SUM_LEN: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    V1,
    V2,
}

impl Layout {
    pub fn header(self) -> u64 {
        match self {
            Layout::V1 => REC_HEADER,
            Layout::V2 => REC_HEADER + 1,
        }
    }

    pub fn record_len(self, payload: u32) -> u64 {
        let trailer = if self == Layout::V2 { SUM_LEN as u64 } else { 0 };
        self.header() + payload as u64 + trailer
    }
}

// anything bigger than this in a header is garbage from a torn write
const MAX_PAYLOAD: u32 = 1 << 30;

pub fn record_len(payload: u32) -> u64 {
    Layout::V1.record_len(payload)
}

pub fn path(dir: &Path, id: u32) -> PathBuf {
    dir.join(format!("seg-{id:08}.dat"))
}

pub fn list_ids(dir: &Path) -> io::Result<Vec<u32>> {
    let mut ids = Vec::new();
    for e in fs::read_dir(dir)? {
        let name = e?.file_name();
        let id = name
            .to_str()
            .and_then(|n| n.strip_prefix("seg-"))
            .and_then(|n| n.strip_suffix(".dat"))
            .and_then(|n| n.parse::<u32>().ok());
        ids.extend(id);
    }
    ids.sort_unstable();
    Ok(ids)
}

pub fn encode_record(hash: &Hash, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(REC_HEADER as usize + payload.len());
    buf.extend_from_slice(hash.as_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

fn sum(hash: &Hash, len: u32, codec: u8, payload: &[u8]) -> [u8; SUM_LEN] {
    let mut h = blake3::Hasher::new();
    h.update(hash.as_bytes());
    h.update(&len.to_le_bytes());
    h.update(&[codec]);
    h.update(payload);
    h.finalize().as_bytes()[..SUM_LEN].try_into().unwrap()
}

pub fn encode_record_v2(hash: &Hash, codec: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(Layout::V2.record_len(len) as usize);
    buf.extend_from_slice(hash.as_bytes());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.push(codec);
    buf.extend_from_slice(payload);
    buf.extend_from_slice(&sum(hash, len, codec, payload));
    buf
}

/// Splits one whole record, as read from the file, into (codec, payload).
/// None if it is not the record for `want`, or fails its checksum (v2).
pub fn open_record<'a>(layout: Layout, buf: &'a [u8], want: &Hash) -> Option<(u8, &'a [u8])> {
    let h = layout.header() as usize;
    if buf.len() < h || buf[..HASH_LEN] != want.as_bytes()[..] {
        return None;
    }
    match layout {
        Layout::V1 => Some((0, &buf[h..])),
        Layout::V2 => {
            let body = buf.len().checked_sub(h + SUM_LEN)?;
            let len = u32::from_le_bytes(buf[HASH_LEN..HASH_LEN + 4].try_into().unwrap());
            if len as usize != body {
                return None;
            }
            let codec = buf[HASH_LEN + 4];
            let (payload, tail) = buf[h..].split_at(body);
            (sum(want, len, codec, payload) == tail).then_some((codec, payload))
        }
    }
}

#[cfg(unix)]
pub fn read_exact_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(f, buf, off)
}

#[cfg(windows)]
pub fn read_exact_at(f: &File, mut buf: &mut [u8], mut off: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match f.seek_read(buf, off) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                buf = &mut buf[n..];
                off += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub struct ScanRecord {
    pub hash: Hash,
    pub offset: u64,
    pub len: u32,
}

pub struct Scan {
    pub records: Vec<ScanRecord>,
    pub valid_end: u64,
    pub file_len: u64,
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}

/// Walks a segment front to back, checking every record. Stops at the first
/// one that is short or fails its check; `valid_end` says where the good
/// prefix stops.
pub fn scan(p: &Path) -> io::Result<Scan> {
    scan_layout(p, Layout::V1)
}

pub fn scan_layout(p: &Path, layout: Layout) -> io::Result<Scan> {
    let f = File::open(p)?;
    let file_len = f.metadata()?.len();
    let mut r = BufReader::with_capacity(1 << 20, f);

    let mut records = Vec::new();
    let mut off = 0u64;
    let mut payload = Vec::new();
    let mut hdr = [0u8; REC_HEADER as usize + 1];
    let hdr = &mut hdr[..layout.header() as usize];
    loop {
        if read_full(&mut r, hdr)? < hdr.len() {
            break;
        }
        let hash = Hash::from_bytes(hdr[..HASH_LEN].try_into().unwrap());
        let len = u32::from_le_bytes(hdr[HASH_LEN..HASH_LEN + 4].try_into().unwrap());
        if len > MAX_PAYLOAD {
            break;
        }

        payload.resize(len as usize, 0);
        if read_full(&mut r, &mut payload)? < payload.len() {
            break;
        }
        let ok = match layout {
            Layout::V1 => Hash::of(&payload) == hash,
            Layout::V2 => {
                let mut tail = [0u8; SUM_LEN];
                read_full(&mut r, &mut tail)? == SUM_LEN && tail == sum(&hash, len, hdr[hdr.len() - 1], &payload)
            }
        };
        if !ok {
            break;
        }
        records.push(ScanRecord { hash, offset: off, len });
        off += layout.record_len(len);
    }
    Ok(Scan { records, valid_end: off, file_len })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(layout: Layout, recs: &[(Hash, u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (h, c, p) in recs {
            match layout {
                Layout::V1 => out.extend(encode_record(h, p)),
                Layout::V2 => out.extend(encode_record_v2(h, *c, p)),
            }
        }
        out
    }

    fn scan_bytes(layout: Layout, b: &[u8]) -> Scan {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s");
        fs::write(&p, b).unwrap();
        scan_layout(&p, layout).unwrap()
    }

    // v2 payloads are opaque, so the hash is just a label here
    fn recs() -> Vec<(Hash, u8, Vec<u8>)> {
        (0u8..4).map(|i| (Hash::of(&[i]), i & 1, vec![i; 10 + i as usize * 7])).collect()
    }

    #[test]
    fn v2_scan_finds_every_record() {
        let r = recs();
        let view: Vec<_> = r.iter().map(|(h, c, p)| (*h, *c, p.as_slice())).collect();
        let b = seg(Layout::V2, &view);
        let s = scan_bytes(Layout::V2, &b);
        assert_eq!(s.records.len(), 4);
        assert_eq!(s.valid_end, b.len() as u64);
        assert_eq!(s.records[1].offset, Layout::V2.record_len(10));
    }

    #[test]
    fn v2_torn_tail_is_a_clean_prefix() {
        let r = recs();
        let view: Vec<_> = r.iter().map(|(h, c, p)| (*h, *c, p.as_slice())).collect();
        let b = seg(Layout::V2, &view);
        let first_three: u64 = r[..3].iter().map(|(_, _, p)| Layout::V2.record_len(p.len() as u32)).sum();
        for cut in 1..b.len() {
            let s = scan_bytes(Layout::V2, &b[..cut]);
            assert!(s.valid_end <= cut as u64);
            if cut as u64 >= first_three {
                assert_eq!(s.records.len(), 3, "cut {cut}");
            }
        }
    }

    #[test]
    fn v2_flipped_byte_stops_the_scan_at_that_record() {
        let r = recs();
        let view: Vec<_> = r.iter().map(|(h, c, p)| (*h, *c, p.as_slice())).collect();
        let b = seg(Layout::V2, &view);
        let second = Layout::V2.record_len(10) as usize;
        for i in 0..b.len() {
            let mut bad = b.clone();
            bad[i] ^= 0x01;
            let s = scan_bytes(Layout::V2, &bad);
            if i >= second {
                // everything before the damaged record survives
                assert!(s.records.len() >= 1, "byte {i}");
            }
            assert!(s.records.len() < 4, "byte {i} went unnoticed");
        }
    }

    #[test]
    fn open_record_checks_hash_codec_and_sum() {
        let h = Hash::of(b"id");
        let rec = encode_record_v2(&h, 0x81, b"opaque");
        assert_eq!(open_record(Layout::V2, &rec, &h), Some((0x81, &b"opaque"[..])));
        assert!(open_record(Layout::V2, &rec, &Hash::of(b"other")).is_none());
        for i in 0..rec.len() {
            let mut bad = rec.clone();
            bad[i] ^= 4;
            assert!(open_record(Layout::V2, &bad, &h).is_none(), "byte {i}");
        }
        assert!(open_record(Layout::V2, &rec[..rec.len() - 1], &h).is_none());

        let v1 = encode_record(&h, b"raw");
        assert_eq!(open_record(Layout::V1, &v1, &h), Some((0, &b"raw"[..])));
    }
}
