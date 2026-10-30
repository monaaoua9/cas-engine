use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};

use crate::error::{Error, Result};

fn tls_err(e: impl std::fmt::Display) -> Error {
    Error::Tls(e.to_string())
}

/// What a server needs to speak TLS: a certificate chain and its key, both PEM.
#[derive(Clone)]
pub struct TlsServer(Arc<ServerConfig>);

impl TlsServer {
    pub fn load(cert: &Path, key: &Path) -> Result<TlsServer> {
        let certs = CertificateDer::pem_file_iter(cert)
            .map_err(tls_err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(tls_err)?;
        if certs.is_empty() {
            return Err(Error::Tls("no certificate in the cert file".into()));
        }
        let key = PrivateKeyDer::from_pem_file(key).map_err(tls_err)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(tls_err)?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(tls_err)?;
        Ok(TlsServer(Arc::new(cfg)))
    }

    pub(crate) fn accept(&self, sock: TcpStream) -> Result<Conn> {
        let conn = ServerConnection::new(self.0.clone()).map_err(tls_err)?;
        Ok(Conn::Server(Box::new(StreamOwned::new(conn, sock))))
    }
}

/// Trusts exactly the certificates in the given PEM file, nothing from the system store.
#[derive(Clone)]
pub struct TlsClient(Arc<ClientConfig>);

impl TlsClient {
    pub fn load(ca: &Path) -> Result<TlsClient> {
        let mut roots = RootCertStore::empty();
        for c in CertificateDer::pem_file_iter(ca).map_err(tls_err)? {
            roots.add(c.map_err(tls_err)?).map_err(tls_err)?;
        }
        if roots.is_empty() {
            return Err(Error::Tls("no certificate in the CA file".into()));
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(tls_err)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(TlsClient(Arc::new(cfg)))
    }

    pub(crate) fn connect(&self, host: &str, sock: TcpStream) -> Result<Conn> {
        let name = ServerName::try_from(host.to_owned()).map_err(tls_err)?;
        let conn = ClientConnection::new(self.0.clone(), name).map_err(tls_err)?;
        Ok(Conn::Client(Box::new(StreamOwned::new(conn, sock))))
    }
}

/// A connection that is either plain TCP or TLS over TCP. Timeouts and `peek` act on the socket.
pub(crate) enum Conn {
    Plain(TcpStream),
    Server(Box<StreamOwned<ServerConnection, TcpStream>>),
    Client(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Conn {
    fn sock(&self) -> &TcpStream {
        match self {
            Conn::Plain(s) => s,
            Conn::Server(s) => &s.sock,
            Conn::Client(s) => &s.sock,
        }
    }

    pub fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.sock().set_read_timeout(d)
    }

    pub fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.sock().set_write_timeout(d)
    }

    // On TLS this sees the next record's first byte, not plaintext. That is enough to know a
    // request is starting, because the protocol never has more than one request in flight.
    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.sock().peek(buf)
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Server(s) => s.read(buf),
            Conn::Client(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Server(s) => s.write(buf),
            Conn::Client(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Server(s) => s.flush(),
            Conn::Client(s) => s.flush(),
        }
    }
}

/// Writes a self-signed certificate and key (PEM) valid for the given names or IP addresses.
/// The certificate doubles as the CA file clients pass with `--tls-ca`.
pub fn generate_self_signed(names: &[String], cert_out: &Path, key_out: &Path) -> Result<()> {
    let ck = rcgen::generate_simple_self_signed(names.to_vec()).map_err(tls_err)?;
    std::fs::write(cert_out, ck.cert.pem())?;
    std::fs::write(key_out, ck.signing_key.serialize_pem())?;
    Ok(())
}
