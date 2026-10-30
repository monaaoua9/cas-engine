use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::error::{Error, Result};
use crate::hash::Hash;

const NONCE: usize = 24;
const TAG: usize = 16;

/// Argon2id cost. The defaults take a few hundred ms and 64 MiB; tests turn them down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kdf {
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
}

impl Default for Kdf {
    fn default() -> Self {
        Kdf { memory_kib: 64 << 10, passes: 3, lanes: 1 }
    }
}

impl Kdf {
    // the numbers come out of a file on disk, so don't let them pick the allocation size
    pub(crate) fn sane(&self) -> bool {
        (8..=2 << 20).contains(&self.memory_kib) && (1..=64).contains(&self.passes) && (1..=16).contains(&self.lanes)
    }
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("os randomness unavailable");
    b
}

pub fn stretch(password: &[u8], salt: &[u8; 16], kdf: &Kdf) -> Result<[u8; 32]> {
    if !kdf.sane() {
        return Err(Error::InvalidConfig("kdf parameters out of range"));
    }
    let params = argon2::Params::new(kdf.memory_kib, kdf.passes, kdf.lanes, Some(32))
        .map_err(|_| Error::InvalidConfig("kdf parameters rejected"))?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    a.hash_password_into(password, salt, &mut out).map_err(|_| Error::InvalidConfig("kdf failed"))?;
    Ok(out)
}

/// nonce | ciphertext | tag. The nonce is random; 192 bits makes collisions a non-issue.
pub fn seal(key: &[u8; 32], aad: &[u8], data: &[u8]) -> Vec<u8> {
    let nonce: [u8; NONCE] = random();
    let c = XChaCha20Poly1305::new_from_slice(key).expect("32 byte key");
    let n = XNonce::try_from(&nonce[..]).expect("24 byte nonce");
    let ct = c.encrypt(&n, Payload { msg: data, aad }).expect("encrypt");
    let mut out = Vec::with_capacity(NONCE + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < NONCE + TAG {
        return None;
    }
    let (nonce, ct) = sealed.split_at(NONCE);
    let c = XChaCha20Poly1305::new_from_slice(key).ok()?;
    let n = XNonce::try_from(nonce).ok()?;
    c.decrypt(&n, Payload { msg: ct, aad }).ok()
}

/// Everything derived from the store's master key. Chunk ids become keyed
/// hashes, so without the key nobody can test whether a known file is stored.
pub struct Keys {
    master: [u8; 32],
    enc: [u8; 32],
    id: [u8; 32],
}

impl Keys {
    pub fn from_master(master: [u8; 32]) -> Keys {
        Keys {
            master,
            enc: blake3::derive_key("cas chunk encryption v1", &master),
            id: blake3::derive_key("cas chunk id v1", &master),
        }
    }

    pub fn generate() -> Keys {
        Keys::from_master(random())
    }

    pub fn master(&self) -> &[u8; 32] {
        &self.master
    }

    pub fn chunk_id(&self, data: &[u8]) -> Hash {
        Hash::from_bytes(*blake3::keyed_hash(&self.id, data).as_bytes())
    }

    /// `aad` ties the ciphertext to what it is for (a chunk id, a manifest id, a snapshot name).
    pub fn seal(&self, aad: &[u8], data: &[u8]) -> Vec<u8> {
        seal(&self.enc, aad, data)
    }

    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        open(&self.enc, aad, sealed)
    }
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Keys(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cheap() -> Kdf {
        Kdf { memory_kib: 8, passes: 1, lanes: 1 }
    }

    #[test]
    fn seal_open_roundtrip() {
        let k = Keys::generate();
        let s = k.seal(b"ctx", b"hello");
        assert_eq!(k.open(b"ctx", &s).unwrap(), b"hello");
        assert_eq!(s.len(), 24 + 5 + 16);
    }

    #[test]
    fn nonces_differ() {
        let k = Keys::generate();
        assert_ne!(k.seal(b"a", b"same"), k.seal(b"a", b"same"));
    }

    #[test]
    fn wrong_aad_wrong_key_or_flipped_byte_fails() {
        let k = Keys::generate();
        let s = k.seal(b"one", b"payload");
        assert!(k.open(b"two", &s).is_none());
        assert!(Keys::generate().open(b"one", &s).is_none());
        for i in 0..s.len() {
            let mut bad = s.clone();
            bad[i] ^= 1;
            assert!(k.open(b"one", &bad).is_none(), "byte {i}");
        }
        assert!(k.open(b"one", &s[..10]).is_none());
    }

    #[test]
    fn chunk_ids_are_keyed() {
        let (a, b) = (Keys::generate(), Keys::generate());
        assert_ne!(a.chunk_id(b"x"), b.chunk_id(b"x"));
        assert_ne!(a.chunk_id(b"x"), Hash::of(b"x"));
        assert_eq!(a.chunk_id(b"x"), a.chunk_id(b"x"));
    }

    #[test]
    fn stretch_depends_on_password_and_salt() {
        let s1 = [1u8; 16];
        let a = stretch(b"pw", &s1, &cheap()).unwrap();
        assert_eq!(a, stretch(b"pw", &s1, &cheap()).unwrap());
        assert_ne!(a, stretch(b"pW", &s1, &cheap()).unwrap());
        assert_ne!(a, stretch(b"pw", &[2u8; 16], &cheap()).unwrap());
    }

    #[test]
    fn absurd_kdf_params_are_refused() {
        let huge = Kdf { memory_kib: u32::MAX, passes: 1, lanes: 1 };
        assert!(stretch(b"pw", &[0; 16], &huge).is_err());
        assert!(stretch(b"pw", &[0; 16], &Kdf { passes: 0, ..cheap() }).is_err());
    }
}
