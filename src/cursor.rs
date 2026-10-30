use crate::error::{Error, Result};
use crate::hash::{HASH_LEN, Hash};

// bounds-checked reader for the little binary formats (trees, snapshot records)
pub(crate) struct Cursor<'a> {
    buf: &'a [u8],
    err: fn(&'static str) -> Error,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8], err: fn(&'static str) -> Error) -> Self {
        Cursor { buf, err }
    }

    pub fn left(&self) -> usize {
        self.buf.len()
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err((self.err)("truncated"));
        }
        let (a, b) = self.buf.split_at(n);
        self.buf = b;
        Ok(a)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn hash(&mut self) -> Result<Hash> {
        Ok(Hash::from_bytes(self.take(HASH_LEN)?.try_into().unwrap()))
    }

    pub fn string(&mut self, n: usize) -> Result<String> {
        let b = self.take(n)?;
        std::str::from_utf8(b).map(str::to_owned).map_err(|_| (self.err)("not utf-8"))
    }
}
