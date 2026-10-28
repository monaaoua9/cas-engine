use std::io::{self, Read};
use std::sync::OnceLock;

use crate::error::{Error, Result};

// Irreducible degree-53 polynomial over GF(2). Same one restic uses, so the
// fingerprints are easy to cross-check against a known implementation.
const POLY: u64 = 0x003D_A335_8B4D_C173;
const POLY_DEG: u32 = 53;

pub const WINDOW: usize = 48;

#[derive(Clone, Copy, Debug)]
pub struct ChunkerConfig {
    pub min_size: usize,
    /// Must be a power of two. Boundaries are declared when the low
    /// log2(avg_size) bits of the fingerprint are zero, so a chunk is
    /// roughly min_size + avg_size long on average.
    pub avg_size: usize,
    pub max_size: usize,
}

impl Default for ChunkerConfig {
    fn default() -> Self {
        ChunkerConfig { min_size: 64 << 10, avg_size: 256 << 10, max_size: 1 << 20 }
    }
}

impl ChunkerConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.avg_size.is_power_of_two() {
            return Err(Error::InvalidConfig("avg_size must be a power of two"));
        }
        if self.min_size < WINDOW {
            return Err(Error::InvalidConfig("min_size is smaller than the rolling window"));
        }
        if self.max_size <= self.min_size {
            return Err(Error::InvalidConfig("max_size must exceed min_size"));
        }
        if self.max_size > 1 << 30 {
            return Err(Error::InvalidConfig("max_size above 1 GiB"));
        }
        Ok(())
    }
}

struct Tables {
    out: [u64; 256],
    modt: [u64; 256],
}

fn deg(x: u64) -> i32 {
    63 - x.leading_zeros() as i32
}

fn poly_mod(mut x: u64, p: u64) -> u64 {
    let dp = deg(p);
    while x != 0 && deg(x) >= dp {
        x ^= p << (deg(x) - dp);
    }
    x
}

fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| {
        let mut t = Tables { out: [0; 256], modt: [0; 256] };
        for b in 0..256u64 {
            // fingerprint contribution of byte b once it has aged through the
            // whole window; xoring it out slides the window forward
            let mut h = poly_mod(b, POLY);
            for _ in 0..WINDOW - 1 {
                h = poly_mod(h << 8, POLY);
            }
            t.out[b as usize] = h;

            let shifted = b << POLY_DEG;
            t.modt[b as usize] = poly_mod(shifted, POLY) | shifted;
        }
        t
    })
}

struct Rolling {
    win: [u8; WINDOW],
    pos: usize,
    digest: u64,
    t: &'static Tables,
}

impl Rolling {
    fn new() -> Rolling {
        let mut r = Rolling { win: [0; WINDOW], pos: 0, digest: 0, t: tables() };
        r.slide(1);
        r
    }

    #[inline(always)]
    fn slide(&mut self, b: u8) {
        let gone = self.win[self.pos];
        self.win[self.pos] = b;
        self.pos += 1;
        if self.pos == WINDOW {
            self.pos = 0;
        }
        self.digest ^= self.t.out[gone as usize];

        let top = (self.digest >> (POLY_DEG - 8)) as usize;
        self.digest = (self.digest << 8) | b as u64;
        self.digest ^= self.t.modt[top];
    }
}

pub struct Chunk {
    pub offset: u64,
    pub data: Vec<u8>,
}

pub struct Chunker<R> {
    src: R,
    cfg: ChunkerConfig,
    mask: u64,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    eof: bool,
    offset: u64,
}

impl<R: Read> Chunker<R> {
    pub fn new(src: R, cfg: ChunkerConfig) -> Result<Self> {
        cfg.validate()?;
        Ok(Chunker {
            src,
            cfg,
            mask: cfg.avg_size as u64 - 1,
            buf: vec![0; cfg.max_size],
            start: 0,
            end: 0,
            eof: false,
            offset: 0,
        })
    }

    fn fill(&mut self) -> io::Result<()> {
        if self.start > 0 {
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        while self.end < self.buf.len() && !self.eof {
            match self.src.read(&mut self.buf[self.end..]) {
                Ok(0) => self.eof = true,
                Ok(n) => self.end += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    // buffer is either full (max_size) or the source is drained, so a cut
    // always exists and we never have to rescan
    fn cut_point(&self) -> usize {
        let data = &self.buf[self.start..self.end];
        let min = self.cfg.min_size;
        if data.len() <= min {
            return data.len();
        }

        // no boundary can land before min, so only the last WINDOW bytes
        // before it are needed to prime the fingerprint
        let mut r = Rolling::new();
        for &b in &data[min - WINDOW..min] {
            r.slide(b);
        }

        let limit = data.len().min(self.cfg.max_size);
        scan_boundary(data, min, limit, self.mask, r.digest)
    }
}

// Hot loop. The window is the input itself: the byte leaving at position i
// is data[i - WINDOW], so no ring buffer and no position bookkeeping.
fn scan_boundary(data: &[u8], min: usize, limit: usize, mask: u64, mut d: u64) -> usize {
    let t = tables();
    let leaving = &data[min - WINDOW..limit - WINDOW];
    let entering = &data[min..limit];
    for (i, (&gone, &b)) in leaving.iter().zip(entering).enumerate() {
        d ^= t.out[gone as usize];
        let top = (d >> (POLY_DEG - 8)) as usize & 0xFF;
        d = ((d << 8) | b as u64) ^ t.modt[top];
        if d & mask == 0 {
            return min + i + 1;
        }
    }
    limit
}

impl<R: Read> Iterator for Chunker<R> {
    type Item = io::Result<Chunk>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Err(e) = self.fill() {
            self.eof = true;
            self.start = self.end;
            return Some(Err(e));
        }
        if self.start == self.end {
            return None;
        }

        let n = self.cut_point();
        let data = self.buf[self.start..self.start + n].to_vec();
        self.start += n;

        let c = Chunk { offset: self.offset, data };
        self.offset += n as u64;
        Some(Ok(c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash;
    use std::collections::HashSet;

    pub(crate) fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    fn small() -> ChunkerConfig {
        ChunkerConfig { min_size: 2 << 10, avg_size: 8 << 10, max_size: 32 << 10 }
    }

    fn split(data: &[u8]) -> Vec<Chunk> {
        Chunker::new(data, small()).unwrap().map(|c| c.unwrap()).collect()
    }

    #[test]
    fn empty_input_yields_nothing() {
        assert!(split(&[]).is_empty());
    }

    #[test]
    fn reassembles_exactly() {
        let data = noise(1 << 20, 7);
        let chunks = split(&data);
        let joined: Vec<u8> = chunks.iter().flat_map(|c| c.data.iter().copied()).collect();
        assert_eq!(joined, data);

        let mut off = 0;
        for c in &chunks {
            assert_eq!(c.offset, off);
            off += c.data.len() as u64;
        }
    }

    #[test]
    fn respects_size_bounds() {
        let data = noise(2 << 20, 99);
        let chunks = split(&data);
        let cfg = small();
        for c in &chunks[..chunks.len() - 1] {
            assert!(c.data.len() > cfg.min_size && c.data.len() <= cfg.max_size);
        }
        assert!(chunks.len() > 20);
    }

    #[test]
    fn deterministic() {
        let data = noise(512 << 10, 3);
        let a: Vec<_> = split(&data).iter().map(|c| Hash::of(&c.data)).collect();
        let b: Vec<_> = split(&data).iter().map(|c| Hash::of(&c.data)).collect();
        assert_eq!(a, b);
    }

    #[test]
    fn boundaries_resync_after_insertion() {
        let base = noise(2 << 20, 42);
        let mut shifted = noise(1234, 5);
        shifted.extend_from_slice(&base);

        let a: HashSet<_> = split(&base).iter().map(|c| Hash::of(&c.data)).collect();
        let b: Vec<_> = split(&shifted).iter().map(|c| Hash::of(&c.data)).collect();
        let shared = b.iter().filter(|h| a.contains(h)).count();
        assert!(shared * 10 >= b.len() * 9, "only {shared}/{} chunks survived", b.len());
    }

    #[test]
    fn fast_scan_matches_ring_buffer_reference() {
        let data = noise(300_000, 77);
        let (min, mask) = (2048usize, 8191u64);
        for start in [0usize, 5000, 123_457] {
            let d = &data[start..start + 40_000];
            let mut r = Rolling::new();
            for &b in &d[min - WINDOW..min] {
                r.slide(b);
            }
            let primed = r.digest;

            let mut want = d.len();
            for (i, &b) in d.iter().enumerate().skip(min) {
                r.slide(b);
                if r.digest & mask == 0 {
                    want = i + 1;
                    break;
                }
            }
            assert_eq!(scan_boundary(d, min, d.len(), mask, primed), want);
        }
    }

    #[test]
    fn rejects_bad_config() {
        let bad = ChunkerConfig { min_size: 100, avg_size: 1000, max_size: 5000 };
        assert!(Chunker::new(&[][..], bad).is_err());
    }

    #[test]
    fn rolling_matches_from_scratch() {
        // the fingerprint of a window must not depend on what came before it
        let data = noise(4096, 11);
        let mut a = Rolling::new();
        for &b in &data {
            a.slide(b);
        }
        let mut b = Rolling::new();
        for &x in &data[data.len() - WINDOW..] {
            b.slide(x);
        }
        // priming byte `1` has aged out of both by now
        assert_eq!(a.digest, b.digest);
    }
}
