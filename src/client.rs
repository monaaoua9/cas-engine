use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::hash::Hash;
use crate::sync::Peer;
use crate::tls::{Conn, TlsClient};
use crate::wire::*;

/// One authenticated connection to a `Server`. Requests are strictly one at a time.
pub struct Client {
    sock: Conn,
    read_only: bool,
}

impl Client {
    /// `token` has to match the server's; with none given, only a server running without a token lets you in.
    pub fn connect(addr: impl ToSocketAddrs, token: Option<&[u8]>) -> Result<Client> {
        let sock = TcpStream::connect(addr)?;
        sock.set_nodelay(true)?;
        Self::open(Conn::Plain(sock), token)
    }

    /// `host` must match a name or address in the server certificate.
    pub fn connect_tls(host: &str, port: u16, token: Option<&[u8]>, tls: &TlsClient) -> Result<Client> {
        let sock = TcpStream::connect((host, port))?;
        sock.set_nodelay(true)?;
        Self::open(tls.connect(host, sock)?, token)
    }

    fn open(mut sock: Conn, token: Option<&[u8]>) -> Result<Client> {
        sock.set_read_timeout(Some(Duration::from_secs(60)))?;
        sock.set_write_timeout(Some(Duration::from_secs(60)))?;

        let mut hello = [0u8; 4 + 1 + 1 + 32];
        sock.read_exact(&mut hello)?;
        if &hello[..4] != MAGIC {
            return Err(Error::Protocol("not a cas server"));
        }
        if hello[4] != VERSION {
            return Err(Error::Protocol("unsupported protocol version"));
        }
        let wants_token = hello[5] != 0;
        let nonce: [u8; 32] = hello[6..].try_into().unwrap();

        let key = token.map(auth_key);
        let reply = match &key {
            Some(k) => proof(k, b"client", &nonce),
            None => [0u8; 32],
        };
        if wants_token && key.is_none() {
            return Err(Error::AuthFailed);
        }
        sock.write_all(&reply)?;

        let (status, body) = read_frame(&mut sock)?.ok_or(Error::Protocol("closed during handshake"))?;
        match status {
            ST_OK => {}
            ST_DENIED => return Err(Error::AuthFailed),
            _ => return Err(Error::Protocol("unexpected handshake reply")),
        }
        let read_only = *body.first().ok_or(Error::Protocol("short handshake reply"))? != 0;
        if wants_token {
            // the server has to know the token too, or we'd be handing data to an impostor
            let theirs: [u8; 32] = body.get(1..33).ok_or(Error::Protocol("short handshake reply"))?.try_into().unwrap();
            let k = key.as_ref().unwrap();
            if !proofs_equal(&theirs, &proof(k, b"server", &nonce)) {
                return Err(Error::AuthFailed);
            }
        }
        Ok(Client { sock, read_only })
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    fn call(&mut self, op: u8, body: &[u8]) -> Result<Vec<u8>> {
        write_frame(&mut self.sock, op, body)?;
        let (status, out) = read_frame(&mut self.sock)?.ok_or(Error::Protocol("server closed the connection"))?;
        let msg = || String::from_utf8_lossy(&out).into_owned();
        match status {
            ST_OK => Ok(out),
            ST_DENIED => Err(Error::ReadOnly),
            ST_CONFLICT => Err(Error::SnapshotExists(msg())),
            ST_NOT_FOUND => Err(Error::Remote(msg())),
            _ => Err(Error::Remote(msg())),
        }
    }

    pub fn ping(&mut self) -> Result<()> {
        self.call(OP_PING, &[]).map(drop)
    }

    pub fn metrics(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.call(OP_METRICS, &[])?).into_owned())
    }

    fn hashes_reply(out: &[u8]) -> Result<Vec<Hash>> {
        let mut c = reader(out);
        let h = get_hashes(&mut c)?;
        done(&c)?;
        Ok(h)
    }
}

fn flag(out: &[u8]) -> Result<bool> {
    match out {
        [b] => Ok(*b != 0),
        _ => Err(Error::Protocol("bad flag reply")),
    }
}

impl Peer for Client {
    fn missing_chunks(&mut self, ids: &[Hash]) -> Result<Vec<Hash>> {
        // keep each request well under the frame limit
        let mut missing = Vec::new();
        for batch in ids.chunks(100_000) {
            let mut b = Vec::new();
            put_hashes(&mut b, batch);
            missing.extend(Self::hashes_reply(&self.call(OP_MISSING, &b)?)?);
        }
        Ok(missing)
    }

    fn has_object(&mut self, id: &Hash) -> Result<bool> {
        flag(&self.call(OP_HAS_OBJECT, id.as_bytes())?)
    }

    fn get_chunk(&mut self, id: &Hash) -> Result<(u8, Vec<u8>)> {
        let out = self.call(OP_GET_CHUNK, id.as_bytes())?;
        let (codec, payload) = out.split_first().ok_or(Error::Protocol("empty chunk reply"))?;
        Ok((*codec, payload.to_vec()))
    }

    fn put_chunk(&mut self, id: &Hash, codec: u8, payload: Vec<u8>) -> Result<()> {
        let mut b = Vec::with_capacity(33 + payload.len());
        put_hash(&mut b, id);
        b.push(codec);
        b.extend_from_slice(&payload);
        self.call(OP_PUT_CHUNK, &b).map(drop)
    }

    fn get_manifest(&mut self, id: &Hash) -> Result<Vec<u8>> {
        self.call(OP_GET_MANIFEST, id.as_bytes())
    }

    fn put_manifest(&mut self, id: &Hash, raw: Vec<u8>) -> Result<()> {
        let mut b = Vec::with_capacity(32 + raw.len());
        put_hash(&mut b, id);
        b.extend_from_slice(&raw);
        self.call(OP_PUT_MANIFEST, &b).map(drop)
    }

    fn manifest_chunks(&mut self, id: &Hash) -> Result<Vec<Hash>> {
        Self::hashes_reply(&self.call(OP_MANIFEST_CHUNKS, id.as_bytes())?)
    }

    fn list_objects(&mut self) -> Result<Vec<Hash>> {
        Self::hashes_reply(&self.call(OP_LIST_OBJECTS, &[])?)
    }

    fn list_snapshots(&mut self) -> Result<Vec<String>> {
        let out = self.call(OP_LIST_SNAPSHOTS, &[])?;
        let mut c = reader(&out);
        let n = c.u32()? as usize;
        if n > c.left() / 2 {
            return Err(Error::Protocol("snapshot count does not fit"));
        }
        let names = (0..n).map(|_| get_str(&mut c)).collect::<Result<Vec<_>>>()?;
        done(&c)?;
        Ok(names)
    }

    fn get_snapshot(&mut self, name: &str) -> Result<Vec<u8>> {
        let mut b = Vec::new();
        put_str(&mut b, name);
        self.call(OP_GET_SNAPSHOT, &b)
    }

    fn put_snapshot(&mut self, name: &str, raw: Vec<u8>) -> Result<bool> {
        let mut b = Vec::new();
        put_str(&mut b, name);
        b.extend_from_slice(&raw);
        flag(&self.call(OP_PUT_SNAPSHOT, &b)?)
    }

    fn snapshot_members(&mut self, name: &str) -> Result<Vec<Hash>> {
        let mut b = Vec::new();
        put_str(&mut b, name);
        Self::hashes_reply(&self.call(OP_SNAPSHOT_MEMBERS, &b)?)
    }
}
