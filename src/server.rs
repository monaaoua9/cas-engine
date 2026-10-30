use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use crate::crypto::random;
use crate::error::{Error, Result};
use crate::hash::Hash;
use crate::metrics;
use crate::store::Store;
use crate::tls::{Conn, TlsServer};
use crate::wire::*;

pub struct ServeOptions {
    /// None means anyone who can reach the port is let in. Only for loopback or a tunnel.
    pub token: Option<Vec<u8>>,
    pub read_only: bool,
    pub max_conns: usize,
    /// A connection that sends nothing for this long is dropped.
    pub idle: Duration,
    /// Wrap every connection in TLS. The token handshake still runs inside it.
    pub tls: Option<TlsServer>,
}

impl Default for ServeOptions {
    fn default() -> Self {
        ServeOptions { token: None, read_only: false, max_conns: 64, idle: Duration::from_secs(60), tls: None }
    }
}

#[derive(Default)]
pub struct NetStats {
    pub connections: AtomicU64,
    pub requests: AtomicU64,
    pub auth_failures: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub errors: AtomicU64,
    active: AtomicUsize,
}

pub struct Shared {
    store: RwLock<Store>,
    opts: ServeOptions,
    pub stats: NetStats,
}

// a handler that panicked must not take the whole server down with a poisoned lock
impl Shared {
    fn read(&self) -> RwLockReadGuard<'_, Store> {
        self.store.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, Store> {
        self.store.write().unwrap_or_else(|e| e.into_inner())
    }

    /// Runs `f` with the store held for reading. Other readers go on in parallel; writers wait.
    pub fn with_store<R>(&self, f: impl FnOnce(&Store) -> R) -> R {
        f(&self.read())
    }

    /// Prometheus text for the store plus this server's own counters.
    pub fn metrics_text(&self) -> Result<String> {
        let st = self.read();
        let n = &self.stats;
        let extra = [
            ("net_connections_total", "connections accepted", n.connections.load(Relaxed)),
            ("net_requests_total", "requests served", n.requests.load(Relaxed)),
            ("net_auth_failures_total", "failed handshakes", n.auth_failures.load(Relaxed)),
            ("net_bytes_in_total", "request bytes received", n.bytes_in.load(Relaxed)),
            ("net_bytes_out_total", "response bytes sent", n.bytes_out.load(Relaxed)),
            ("net_errors_total", "requests that returned an error", n.errors.load(Relaxed)),
        ];
        Ok(metrics::prometheus(&st.stats()?, &st.counters(), st.disk_bytes(), st.max_bytes(), &extra))
    }
}

pub struct Server {
    listener: TcpListener,
    shared: Arc<Shared>,
    stop: Arc<AtomicBool>,
}

impl Server {
    pub fn bind(store: Store, addr: impl ToSocketAddrs, opts: ServeOptions) -> Result<Server> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let shared = Arc::new(Shared { store: RwLock::new(store), opts, stats: NetStats::default() });
        Ok(Server { listener, shared, stop: Arc::new(AtomicBool::new(false)) })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Set to true from another thread to make `run` return.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }

    pub fn shared(&self) -> Arc<Shared> {
        self.shared.clone()
    }

    /// Serves until the stop flag is set, then waits for open connections to finish their current request.
    pub fn run(self) -> Result<()> {
        let mut handlers = Vec::new();
        while !self.stop.load(Relaxed) {
            match self.listener.accept() {
                Ok((sock, _)) => {
                    let sh = self.shared.clone();
                    if sh.stats.active.load(Relaxed) >= sh.opts.max_conns {
                        // turn away rather than queue: a busy server should say so
                        drop(sock);
                        continue;
                    }
                    sh.stats.active.fetch_add(1, Relaxed);
                    sh.stats.connections.fetch_add(1, Relaxed);
                    let stop = self.stop.clone();
                    handlers.push(std::thread::spawn(move || {
                        let _ = serve_conn(sock, &sh, &stop);
                        sh.stats.active.fetch_sub(1, Relaxed);
                    }));
                    handlers.retain(|h| !h.is_finished());
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => return Err(e.into()),
            }
        }
        for h in handlers {
            let _ = h.join();
        }
        // flush the store's index on the way out
        self.shared.write().sync()
    }
}

fn handshake(s: &mut Conn, sh: &Shared) -> Result<()> {
    let nonce: [u8; 32] = random();
    let mut hello = Vec::with_capacity(4 + 1 + 1 + 32);
    hello.extend_from_slice(MAGIC);
    hello.push(VERSION);
    hello.push(sh.opts.token.is_some() as u8);
    hello.extend_from_slice(&nonce);
    s.write_all(&hello)?;

    let mut reply = [0u8; 32];
    s.read_exact(&mut reply)?;

    let Some(token) = &sh.opts.token else {
        write_frame(s, ST_OK, &[sh.opts.read_only as u8])?;
        return Ok(());
    };
    let key = auth_key(token);
    if !proofs_equal(&reply, &proof(&key, b"client", &nonce)) {
        sh.stats.auth_failures.fetch_add(1, Relaxed);
        write_frame(s, ST_DENIED, b"bad token")?;
        return Err(Error::AuthFailed);
    }
    let mut ok = vec![sh.opts.read_only as u8];
    ok.extend_from_slice(&proof(&key, b"server", &nonce));
    write_frame(s, ST_OK, &ok)?;
    Ok(())
}

fn serve_conn(sock: TcpStream, sh: &Shared, stop: &AtomicBool) -> Result<()> {
    sock.set_nonblocking(false)?;
    sock.set_nodelay(true)?;
    let mut s = match &sh.opts.tls {
        Some(t) => t.accept(sock)?,
        None => Conn::Plain(sock),
    };
    s.set_write_timeout(Some(sh.opts.idle))?;
    // the handshake is not allowed to dawdle either
    s.set_read_timeout(Some(sh.opts.idle))?;
    handshake(&mut s, sh)?;

    let mut last = Instant::now();
    while !stop.load(Relaxed) {
        // Wait for the first byte of the next request in short slices so a stop request or an
        // idle deadline is noticed; once a request has started it gets the full idle allowance.
        s.set_read_timeout(Some(Duration::from_millis(250)))?;
        match s.peek(&mut [0u8; 1]) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                if last.elapsed() >= sh.opts.idle {
                    break;
                }
                continue;
            }
            Err(e) => return Err(e.into()),
        }
        s.set_read_timeout(Some(sh.opts.idle))?;

        let Some((op, body)) = read_frame(&mut s)? else { break };
        sh.stats.requests.fetch_add(1, Relaxed);
        sh.stats.bytes_in.fetch_add(body.len() as u64 + 5, Relaxed);

        let (status, out) = match dispatch(sh, op, &body) {
            Ok(out) => (ST_OK, out),
            Err(e) => {
                sh.stats.errors.fetch_add(1, Relaxed);
                match e {
                    Error::ReadOnly => (ST_DENIED, b"server is read-only".to_vec()),
                    Error::SnapshotExists(n) => (ST_CONFLICT, n.into_bytes()),
                    Error::NotFound(_) | Error::SnapshotNotFound(_) | Error::MissingChunk(_) => {
                        (ST_NOT_FOUND, e.to_string().into_bytes())
                    }
                    e => (ST_ERROR, e.to_string().into_bytes()),
                }
            }
        };
        sh.stats.bytes_out.fetch_add(out.len() as u64 + 5, Relaxed);
        write_frame(&mut s, status, &out)?;
        last = Instant::now();
    }
    Ok(())
}

fn dispatch(sh: &Shared, op: u8, body: &[u8]) -> Result<Vec<u8>> {
    let mut c = reader(body);
    let writable = || if sh.opts.read_only { Err(Error::ReadOnly) } else { Ok(()) };
    let mut out = Vec::new();

    match op {
        OP_PING => {}
        OP_MISSING => {
            let ids = get_hashes(&mut c)?;
            done(&c)?;
            let st = sh.read();
            let missing: Vec<Hash> = ids.iter().filter(|h| !st.has_chunk(h)).copied().collect();
            put_hashes(&mut out, &missing);
        }
        OP_HAS_OBJECT => {
            let id = c.hash()?;
            done(&c)?;
            out.push(sh.read().contains(&id) as u8);
        }
        OP_GET_CHUNK => {
            let id = c.hash()?;
            done(&c)?;
            let (codec, payload) = sh.read().read_chunk_raw(&id)?;
            out.push(codec);
            out.extend_from_slice(&payload);
        }
        OP_PUT_CHUNK => {
            writable()?;
            let id = c.hash()?;
            let codec = c.u8()?;
            let payload = c.take(c.left())?.to_vec();
            out.push(sh.write().write_chunk_raw(&id, codec, payload, false)? as u8);
        }
        OP_GET_MANIFEST => {
            let id = c.hash()?;
            done(&c)?;
            out = sh.read().manifest_bytes(&id)?;
        }
        OP_PUT_MANIFEST => {
            writable()?;
            let id = c.hash()?;
            let raw = c.take(c.left())?.to_vec();
            out.push(sh.write().put_manifest_bytes(&id, raw)? as u8);
        }
        OP_MANIFEST_CHUNKS => {
            let id = c.hash()?;
            done(&c)?;
            put_hashes(&mut out, &sh.read().manifest_chunk_ids(&id)?);
        }
        OP_LIST_OBJECTS => {
            done(&c)?;
            put_hashes(&mut out, &sh.read().list()?);
        }
        OP_LIST_SNAPSHOTS => {
            done(&c)?;
            let names: Vec<String> = sh.read().snapshot_list()?.into_iter().map(|s| s.name).collect();
            out.extend_from_slice(&(names.len() as u32).to_le_bytes());
            for n in &names {
                put_str(&mut out, n);
            }
        }
        OP_GET_SNAPSHOT => {
            let name = get_str(&mut c)?;
            done(&c)?;
            out = sh.read().snapshot_bytes(&name)?;
        }
        OP_PUT_SNAPSHOT => {
            writable()?;
            let name = get_str(&mut c)?;
            let raw = c.take(c.left())?.to_vec();
            out.push(sh.write().put_snapshot_bytes(&name, raw)? as u8);
        }
        OP_SNAPSHOT_MEMBERS => {
            let name = get_str(&mut c)?;
            done(&c)?;
            put_hashes(&mut out, &sh.read().snapshot_members(&name)?);
        }
        OP_METRICS => {
            done(&c)?;
            out = sh.metrics_text()?.into_bytes();
        }
        _ => return Err(Error::Protocol("unknown operation")),
    }
    Ok(out)
}
