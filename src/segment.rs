use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

use crate::hash::{HASH_LEN, Hash};

// record: hash (32) | payload len (u32 le) | payload
pub const REC_HEADER: u64 = HASH_LEN as u64 + 4;

// anything bigger than this in a header is garbage from a torn write
const MAX_PAYLOAD: u32 = 1 << 30;

pub fn record_len(payload: u32) -> u64 {
    REC_HEADER + payload as u64
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

/// Walks a segment front to back, re-hashing every payload. Stops at the
/// first record that is short or doesn't match its hash; `valid_end` says
/// where the good prefix stops.
pub fn scan(p: &Path) -> io::Result<Scan> {
    let f = File::open(p)?;
    let file_len = f.metadata()?.len();
    let mut r = BufReader::with_capacity(1 << 20, f);

    let mut records = Vec::new();
    let mut off = 0u64;
    let mut payload = Vec::new();
    loop {
        let mut hdr = [0u8; REC_HEADER as usize];
        if read_full(&mut r, &mut hdr)? < hdr.len() {
            break;
        }
        let hash = Hash::from_bytes(hdr[..HASH_LEN].try_into().unwrap());
        let len = u32::from_le_bytes(hdr[HASH_LEN..].try_into().unwrap());
        if len > MAX_PAYLOAD {
            break;
        }

        payload.resize(len as usize, 0);
        if read_full(&mut r, &mut payload)? < payload.len() || Hash::of(&payload) != hash {
            break;
        }
        records.push(ScanRecord { hash, offset: off, len });
        off += record_len(len);
    }
    Ok(Scan { records, valid_end: off, file_len })
}
