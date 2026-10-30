//! A small HTTP/1.1 server: enough for WebDAV clients and a metrics scrape.
//! Request bodies are read and discarded, responses always carry a
//! Content-Length, and a connection is reused until the client says otherwise.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::time::Duration;

use crate::tls::{Conn, SharedConn, TlsServer};

const MAX_LINE: usize = 8 << 10;
const MAX_HEADERS: usize = 64 << 10;
const MAX_BODY: usize = 1 << 20;

pub struct Request {
    pub method: String,
    /// Percent-decoded path, always starting with `/`.
    pub path: String,
    pub headers: Vec<(String, String)>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

pub trait Handler: Send + Sync {
    /// Write exactly one complete response to `out`.
    fn handle(&self, req: &Request, out: &mut dyn Write) -> io::Result<()>;
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        206 => "Partial Content",
        207 => "Multi-Status",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        416 => "Range Not Satisfiable",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "Error",
    }
}

/// Status line and headers; the caller then writes `Content-Length` bytes of body (none for HEAD).
pub fn write_head(out: &mut dyn Write, status: u16, headers: &[(&str, String)]) -> io::Result<()> {
    write!(out, "HTTP/1.1 {status} {}\r\n", reason(status))?;
    for (k, v) in headers {
        write!(out, "{k}: {v}\r\n")?;
    }
    out.write_all(b"\r\n")
}

pub fn respond(
    out: &mut dyn Write,
    status: u16,
    headers: &[(&str, String)],
    body: &[u8],
    head_only: bool,
) -> io::Result<()> {
    let mut h: Vec<(&str, String)> = headers.to_vec();
    h.push(("Content-Length", body.len().to_string()));
    write_head(out, status, &h)?;
    if !head_only {
        out.write_all(body)?;
    }
    out.flush()
}

pub fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Keeps `/` and the RFC 3986 unreserved characters, escapes the rest.
pub fn percent_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn xml_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            c => o.push(c),
        }
    }
    o
}

pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn read_line(r: &mut impl BufRead, buf: &mut Vec<u8>, limit: usize) -> io::Result<bool> {
    buf.clear();
    loop {
        let chunk = r.fill_buf()?;
        if chunk.is_empty() {
            return if buf.is_empty() { Ok(false) } else { Err(io::ErrorKind::UnexpectedEof.into()) };
        }
        match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => {
                buf.extend_from_slice(&chunk[..i]);
                r.consume(i + 1);
                if buf.len() > limit {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
                }
                if buf.last() == Some(&b'\r') {
                    buf.pop();
                }
                return Ok(true);
            }
            None => {
                let n = chunk.len();
                buf.extend_from_slice(chunk);
                r.consume(n);
            }
        }
        if buf.len() > limit {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
    }
}

enum Parsed {
    Req(Request, bool),
    Closed,
    Bad(u16),
}

fn read_request(r: &mut impl BufRead) -> io::Result<Parsed> {
    let mut line = Vec::new();
    // tolerate stray blank lines between pipelined requests
    loop {
        match read_line(r, &mut line, MAX_LINE) {
            Ok(false) => return Ok(Parsed::Closed),
            Ok(true) if line.is_empty() => continue,
            Ok(true) => break,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => return Ok(Parsed::Bad(431)),
            Err(e) => return Err(e),
        }
    }
    let Ok(text) = String::from_utf8(line.clone()) else { return Ok(Parsed::Bad(400)) };
    let mut parts = text.split(' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Ok(Parsed::Bad(400));
    };
    if !version.starts_with("HTTP/1.") {
        return Ok(Parsed::Bad(400));
    }
    let keep_default = version == "HTTP/1.1";

    let mut headers = Vec::new();
    let mut total = 0;
    loop {
        match read_line(r, &mut line, MAX_LINE) {
            Ok(true) if line.is_empty() => break,
            Ok(true) => {}
            Ok(false) => return Ok(Parsed::Closed),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => return Ok(Parsed::Bad(431)),
            Err(e) => return Err(e),
        }
        total += line.len();
        if total > MAX_HEADERS {
            return Ok(Parsed::Bad(431));
        }
        let Ok(l) = std::str::from_utf8(&line) else { return Ok(Parsed::Bad(400)) };
        let Some((k, v)) = l.split_once(':') else { return Ok(Parsed::Bad(400)) };
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }

    // the path part of the target; absolute-form targets lose their scheme and host
    let target = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .map_or(target, |t| t.find('/').map_or("/", |i| &t[i..]));
    let raw_path = target.split(['?', '#']).next().unwrap_or("/");
    let Some(path) = percent_decode(raw_path) else { return Ok(Parsed::Bad(400)) };
    if !path.starts_with('/') || path.contains('\0') {
        return Ok(Parsed::Bad(400));
    }

    let req = Request { method: method.to_ascii_uppercase(), path, headers };
    if req.header("transfer-encoding").is_some() {
        return Ok(Parsed::Bad(501));
    }
    let len: usize = match req.header("content-length") {
        None => 0,
        Some(v) => match v.parse() {
            Ok(n) => n,
            Err(_) => return Ok(Parsed::Bad(400)),
        },
    };
    if len > MAX_BODY {
        return Ok(Parsed::Bad(413));
    }
    io::copy(&mut r.take(len as u64), &mut io::sink())?;

    let conn = req.header("connection").map(str::to_ascii_lowercase);
    let keep = match conn.as_deref() {
        Some("close") => false,
        Some("keep-alive") => true,
        _ => keep_default,
    };
    Ok(Parsed::Req(req, keep))
}

/// Parses one request the way the server does. `Ok(Err(status))` is a request the server
/// would answer with that error code, `Ok(Ok(None))` is a clean end of input.
pub fn parse_request(r: &mut impl BufRead) -> io::Result<std::result::Result<Option<Request>, u16>> {
    Ok(match read_request(r)? {
        Parsed::Req(req, _) => Ok(Some(req)),
        Parsed::Closed => Ok(None),
        Parsed::Bad(code) => Err(code),
    })
}

fn serve_conn(
    sock: TcpStream,
    tls: Option<&TlsServer>,
    h: &dyn Handler,
    stop: &AtomicBool,
    idle: Duration,
) -> io::Result<()> {
    sock.set_nonblocking(false)?;
    sock.set_read_timeout(Some(idle))?;
    sock.set_write_timeout(Some(idle))?;
    let conn = match tls {
        Some(t) => t.accept(sock).map_err(io::Error::other)?,
        None => Conn::Plain(sock),
    };
    let shared = SharedConn::new(conn);
    let mut out = shared.clone();
    let mut r = BufReader::new(shared);

    while !stop.load(Relaxed) {
        match read_request(&mut r)? {
            Parsed::Closed => break,
            Parsed::Bad(code) => {
                let msg = reason(code);
                respond(
                    &mut out,
                    code,
                    &[("Connection", "close".into()), ("Content-Type", "text/plain".into())],
                    msg.as_bytes(),
                    false,
                )?;
                break;
            }
            Parsed::Req(req, keep) => {
                h.handle(&req, &mut out)?;
                if !keep {
                    break;
                }
            }
        }
    }
    Ok(())
}

pub struct HttpServer {
    listener: TcpListener,
    handler: Arc<dyn Handler>,
    stop: Arc<AtomicBool>,
    idle: Duration,
    tls: Option<TlsServer>,
}

impl HttpServer {
    pub fn bind(addr: impl ToSocketAddrs, handler: Arc<dyn Handler>) -> io::Result<HttpServer> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        Ok(HttpServer {
            listener,
            handler,
            stop: Arc::new(AtomicBool::new(false)),
            idle: Duration::from_secs(30),
            tls: None,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }

    /// Use a flag owned by someone else, so several servers can be stopped together.
    pub fn with_stop_flag(mut self, stop: Arc<AtomicBool>) -> Self {
        self.stop = stop;
        self
    }

    /// Serve HTTPS instead of HTTP.
    pub fn with_tls(mut self, tls: TlsServer) -> Self {
        self.tls = Some(tls);
        self
    }

    pub fn with_idle(mut self, idle: Duration) -> Self {
        self.idle = idle;
        self
    }

    pub fn run(self) -> io::Result<()> {
        let mut conns = Vec::new();
        while !self.stop.load(Relaxed) {
            match self.listener.accept() {
                Ok((sock, _)) => {
                    let (h, stop, idle, tls) = (self.handler.clone(), self.stop.clone(), self.idle, self.tls.clone());
                    conns.push(std::thread::spawn(move || {
                        let _ = serve_conn(sock, tls.as_ref(), &*h, &stop, idle);
                    }));
                    conns.retain(|c| !c.is_finished());
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => return Err(e),
            }
        }
        for c in conns {
            let _ = c.join();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> Parsed {
        read_request(&mut BufReader::new(raw.as_bytes())).unwrap()
    }

    #[test]
    fn plain_request() {
        let Parsed::Req(r, keep) = parse("GET /a%20b/c?x=1 HTTP/1.1\r\nHost: x\r\nDepth: 1\r\n\r\n") else { panic!() };
        assert_eq!((r.method.as_str(), r.path.as_str()), ("GET", "/a b/c"));
        assert_eq!(r.header("depth"), Some("1"));
        assert!(keep);
    }

    #[test]
    fn connection_handling() {
        let Parsed::Req(_, keep) = parse("GET / HTTP/1.1\r\nConnection: close\r\n\r\n") else { panic!() };
        assert!(!keep);
        let Parsed::Req(_, keep) = parse("GET / HTTP/1.0\r\n\r\n") else { panic!() };
        assert!(!keep);
        let Parsed::Req(_, keep) = parse("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n") else { panic!() };
        assert!(keep);
    }

    #[test]
    fn absolute_form_target() {
        let Parsed::Req(r, _) = parse("PROPFIND http://host:8080/snap/dir HTTP/1.1\r\n\r\n") else { panic!() };
        assert_eq!(r.path, "/snap/dir");
    }

    #[test]
    fn body_is_consumed() {
        let raw = "PROPFIND / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloGET /next HTTP/1.1\r\n\r\n";
        let mut r = BufReader::new(raw.as_bytes());
        assert!(matches!(read_request(&mut r).unwrap(), Parsed::Req(..)));
        let Parsed::Req(second, _) = read_request(&mut r).unwrap() else { panic!() };
        assert_eq!(second.path, "/next");
    }

    #[test]
    fn bad_requests() {
        assert!(matches!(parse("GET\r\n\r\n"), Parsed::Bad(400)));
        assert!(matches!(parse("GET / FTP/1.1\r\n\r\n"), Parsed::Bad(400)));
        assert!(matches!(parse("GET /%zz HTTP/1.1\r\n\r\n"), Parsed::Bad(400)));
        assert!(matches!(parse("GET /%00 HTTP/1.1\r\n\r\n"), Parsed::Bad(400)));
        assert!(matches!(parse("GET /%ff HTTP/1.1\r\n\r\n"), Parsed::Bad(400)));
        assert!(matches!(parse("GET x HTTP/1.1\r\n\r\n"), Parsed::Bad(400)));
        assert!(matches!(parse("GET / HTTP/1.1\r\nno colon\r\n\r\n"), Parsed::Bad(400)));
        assert!(matches!(parse("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), Parsed::Bad(501)));
        assert!(matches!(parse("POST / HTTP/1.1\r\nContent-Length: nope\r\n\r\n"), Parsed::Bad(400)));
        assert!(matches!(parse("POST / HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n"), Parsed::Bad(413)));
        let long = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(MAX_LINE + 10));
        assert!(matches!(parse(&long), Parsed::Bad(431)));
        let many =
            format!("GET / HTTP/1.1\r\n{}\r\n", "X-A: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\r\n".repeat(2000));
        assert!(matches!(parse(&many), Parsed::Bad(431)));
        assert!(matches!(parse(""), Parsed::Closed));
    }

    #[test]
    fn percent_roundtrip() {
        let s = "dir with space/файл & more#1.txt";
        let enc = percent_encode_path(s);
        assert!(!enc.contains(' ') && !enc.contains('&') && !enc.contains('#'));
        assert_eq!(percent_decode(&enc).unwrap(), s);
    }

    #[test]
    fn escapes_and_base64() {
        assert_eq!(xml_escape("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&apos;");
        assert_eq!(base64_decode("dXNlcjpwYXNz").unwrap(), b"user:pass");
        assert_eq!(base64_decode("dXNlcjpwYXNzMQ==").unwrap(), b"user:pass1");
        assert!(base64_decode("not base64!").is_none());
    }

    #[test]
    fn response_has_length_and_head_skips_body() {
        let mut v = Vec::new();
        respond(&mut v, 200, &[("X-A", "b".into())], b"hello", false).unwrap();
        let s = String::from_utf8(v).unwrap();
        assert!(
            s.starts_with("HTTP/1.1 200 OK\r\n") && s.contains("Content-Length: 5\r\n") && s.ends_with("\r\n\r\nhello")
        );
        let mut v = Vec::new();
        respond(&mut v, 200, &[], b"hello", true).unwrap();
        assert!(String::from_utf8(v).unwrap().ends_with("Content-Length: 5\r\n\r\n"));
    }
}
