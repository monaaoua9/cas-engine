use std::path::Path;
use std::time::Instant;

use crate::chunker::Chunker;
use crate::error::Result;
use crate::hash::Hash;
use crate::store::{Store, StoreConfig};

#[derive(Debug, Clone)]
pub struct BenchReport {
    pub bytes: u64,
    pub chunk_mib_s: f64,
    pub hash_mib_s: f64,
    pub put_mib_s: f64,
    pub get_mib_s: f64,
    pub chunks: u64,
    pub stored_bytes: u64,
}

fn rate(bytes: u64, secs: f64) -> f64 {
    bytes as f64 / (1 << 20) as f64 / secs.max(1e-9)
}

// xorshift: fast and incompressible enough that lz4 won't skew the numbers
fn data(len: usize) -> Vec<u8> {
    let mut x = 0x2545F4914F6CDD1Du64;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// Times each stage on `size` bytes of random data in a scratch store under `dir`
/// (which must not hold a real store). Uses the chunker, compression and
/// password settings in `cfg`.
pub fn run(cfg: StoreConfig, size: u64, dir: &Path) -> Result<BenchReport> {
    let buf = data(size as usize);

    let t = Instant::now();
    let chunks = Chunker::new(&buf[..], cfg.chunker)?.count();
    let chunk_s = t.elapsed().as_secs_f64();

    let t = Instant::now();
    let h = Hash::of(&buf);
    let hash_s = t.elapsed().as_secs_f64();
    std::hint::black_box(h);

    let mut s = Store::open(dir, cfg)?;
    let t = Instant::now();
    let put = s.put_bytes(&buf)?;
    s.sync()?;
    let put_s = t.elapsed().as_secs_f64();

    let t = Instant::now();
    let n = s.read_into(&put.id, std::io::sink())?;
    let get_s = t.elapsed().as_secs_f64();
    debug_assert_eq!(n, size);

    Ok(BenchReport {
        bytes: size,
        chunk_mib_s: rate(size, chunk_s),
        hash_mib_s: rate(size, hash_s),
        put_mib_s: rate(size, put_s),
        get_mib_s: rate(size, get_s),
        chunks: chunks as u64,
        stored_bytes: put.stored_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_end_to_end_on_a_small_input() {
        let d = tempfile::tempdir().unwrap();
        let r = run(StoreConfig::default(), 4 << 20, d.path()).unwrap();
        assert_eq!(r.bytes, 4 << 20);
        assert!(r.chunks >= 8);
        assert!(r.put_mib_s > 0.0 && r.get_mib_s > 0.0 && r.chunk_mib_s > 0.0 && r.hash_mib_s > 0.0);
        // random data does not compress
        assert!(r.stored_bytes >= 4 << 20);
    }
}
