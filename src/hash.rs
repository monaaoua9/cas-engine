use std::fmt;
use std::str::FromStr;

use crate::error::Error;

pub const HASH_LEN: usize = 32;

const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash([u8; HASH_LEN]);

impl Hash {
    /// BLAKE3 digest of `data`.
    pub fn of(data: &[u8]) -> Hash {
        Hash(*blake3::hash(data).as_bytes())
    }

    pub const fn from_bytes(b: [u8; HASH_LEN]) -> Hash {
        Hash(b)
    }

    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(HASH_LEN * 2);
        for b in self.0 {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 15) as usize] as char);
        }
        s
    }

    pub fn short(&self) -> String {
        self.to_hex()[..12].to_string()
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.short())
    }
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl FromStr for Hash {
    type Err = Error;

    fn from_str(s: &str) -> Result<Hash, Error> {
        let bad = || Error::InvalidHash(s.to_string());
        if s.len() != HASH_LEN * 2 {
            return Err(bad());
        }
        let mut out = [0u8; HASH_LEN];
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let hi = nibble(pair[0]).ok_or_else(bad)?;
            let lo = nibble(pair[1]).ok_or_else(bad)?;
            out[i] = hi << 4 | lo;
        }
        Ok(Hash(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let h = Hash::of(b"hello");
        assert_eq!(h.to_hex().parse::<Hash>().unwrap(), h);
        assert_eq!(h.to_hex().to_uppercase().parse::<Hash>().unwrap(), h);
    }

    #[test]
    fn rejects_garbage() {
        assert!("abc".parse::<Hash>().is_err());
        assert!("zz".repeat(32).parse::<Hash>().is_err());
    }

    #[test]
    fn matches_blake3_vector() {
        // blake3 of the empty input
        assert_eq!(Hash::of(b"").to_hex(), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    }
}
