use crate::crypto::{self, Kdf, Keys};
use crate::cursor::Cursor;
use crate::error::{Error, Result};
use crate::hash::{HASH_LEN, Hash};

const MAGIC: &[u8; 4] = b"CASF";
const VERSION: u8 = 2;
const WRAP_AAD: &[u8] = b"cas master key";

// nonce + 32 byte key + tag
const WRAPPED_LEN: usize = 24 + 32 + 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBlock {
    pub kdf: Kdf,
    pub salt: [u8; 16],
    pub wrapped: Vec<u8>,
}

/// Contents of the store's FORMAT file. A store without one predates v2 and
/// uses the old record layout with no compression or encryption.
///
/// Encrypted stores keep a random master key, wrapped under a key stretched
/// from the password. Changing the password rewraps 72 bytes; no chunk is touched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Format {
    pub keys: Option<KeyBlock>,
}

impl Format {
    pub fn plain() -> Format {
        Format { keys: None }
    }

    pub fn encrypted(password: &[u8], kdf: Kdf) -> Result<(Format, Keys)> {
        let keys = Keys::generate();
        let mut f = Format { keys: None };
        f.rewrap(&keys, password, kdf)?;
        Ok((f, keys))
    }

    pub fn rewrap(&mut self, keys: &Keys, password: &[u8], kdf: Kdf) -> Result<()> {
        let salt: [u8; 16] = crypto::random();
        let kek = crypto::stretch(password, &salt, &kdf)?;
        let wrapped = crypto::seal(&kek, WRAP_AAD, keys.master());
        debug_assert_eq!(wrapped.len(), WRAPPED_LEN);
        self.keys = Some(KeyBlock { kdf, salt, wrapped });
        Ok(())
    }

    pub fn unlock(&self, password: &[u8]) -> Result<Keys> {
        let kb = self.keys.as_ref().ok_or(Error::NotEncrypted)?;
        let kek = crypto::stretch(password, &kb.salt, &kb.kdf)?;
        let m = crypto::open(&kek, WRAP_AAD, &kb.wrapped).ok_or(Error::WrongPassword)?;
        let master: [u8; 32] = m.try_into().map_err(|_| Error::BadFormat("master key has the wrong length"))?;
        Ok(Keys::from_master(master))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        match &self.keys {
            None => out.push(0),
            Some(kb) => {
                out.push(1);
                out.extend_from_slice(&kb.kdf.memory_kib.to_le_bytes());
                out.extend_from_slice(&kb.kdf.passes.to_le_bytes());
                out.extend_from_slice(&kb.kdf.lanes.to_le_bytes());
                out.extend_from_slice(&kb.salt);
                out.extend_from_slice(&(kb.wrapped.len() as u16).to_le_bytes());
                out.extend_from_slice(&kb.wrapped);
            }
        }
        let sum = Hash::of(&out);
        out.extend_from_slice(sum.as_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Format> {
        if buf.len() < 4 + 1 + 1 + HASH_LEN {
            return Err(Error::BadFormat("too short"));
        }
        let (body, sum) = buf.split_at(buf.len() - HASH_LEN);
        if Hash::of(body).as_bytes() != sum {
            return Err(Error::BadFormat("checksum mismatch"));
        }

        let mut c = Cursor::new(body, Error::BadFormat);
        if c.take(4)? != MAGIC {
            return Err(Error::BadFormat("bad magic"));
        }
        if c.u8()? != VERSION {
            return Err(Error::BadFormat("unsupported version"));
        }
        let keys = match c.u8()? {
            0 => None,
            1 => {
                let kdf = Kdf { memory_kib: c.u32()?, passes: c.u32()?, lanes: c.u32()? };
                if !kdf.sane() {
                    return Err(Error::BadFormat("kdf parameters out of range"));
                }
                let salt: [u8; 16] = c.take(16)?.try_into().unwrap();
                let n = c.u16()? as usize;
                if n != WRAPPED_LEN {
                    return Err(Error::BadFormat("wrapped key has the wrong length"));
                }
                Some(KeyBlock { kdf, salt, wrapped: c.take(n)?.to_vec() })
            }
            _ => return Err(Error::BadFormat("bad flags")),
        };
        if c.left() != 0 {
            return Err(Error::BadFormat("trailing bytes"));
        }
        Ok(Format { keys })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cheap() -> Kdf {
        Kdf { memory_kib: 8, passes: 1, lanes: 1 }
    }

    #[test]
    fn plain_roundtrip() {
        let f = Format::plain();
        assert_eq!(Format::decode(&f.encode()).unwrap(), f);
        assert!(matches!(f.unlock(b"x"), Err(Error::NotEncrypted)));
    }

    #[test]
    fn encrypted_roundtrip_and_unlock() {
        let (f, keys) = Format::encrypted(b"hunter2", cheap()).unwrap();
        let back = Format::decode(&f.encode()).unwrap();
        assert_eq!(back, f);
        let again = back.unlock(b"hunter2").unwrap();
        assert_eq!(again.master(), keys.master());
        assert!(matches!(back.unlock(b"hunter3"), Err(Error::WrongPassword)));
    }

    #[test]
    fn rewrap_keeps_the_master_key() {
        let (mut f, keys) = Format::encrypted(b"old", cheap()).unwrap();
        f.rewrap(&keys, b"new", cheap()).unwrap();
        assert!(matches!(f.unlock(b"old"), Err(Error::WrongPassword)));
        assert_eq!(f.unlock(b"new").unwrap().master(), keys.master());
    }

    #[test]
    fn any_flipped_byte_is_rejected() {
        let (f, _) = Format::encrypted(b"pw", cheap()).unwrap();
        let enc = f.encode();
        for i in 0..enc.len() {
            let mut bad = enc.clone();
            bad[i] ^= 0x20;
            assert!(Format::decode(&bad).is_err(), "byte {i}");
        }
    }

    #[test]
    fn hostile_kdf_cost_is_rejected_before_it_runs() {
        let (mut f, _) = Format::encrypted(b"pw", cheap()).unwrap();
        f.keys.as_mut().unwrap().kdf.memory_kib = u32::MAX;
        assert!(Format::decode(&f.encode()).is_err());
    }
}
