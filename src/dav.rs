//! Read-only WebDAV (class 1) over the snapshots in a store. The root lists
//! snapshots; each snapshot is a directory tree. Windows can map it as a
//! network drive, macOS Finder and `davfs2` mount it, and a browser gets a
//! plain index page.

use std::fmt::Write as _;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::hash::Hash;
use crate::http::{Handler, Request, base64_decode, percent_encode_path, respond, write_head, xml_escape};
use crate::server::Shared;
use crate::store::Store;
use crate::timefmt::{http_date, iso8601};
use crate::tree::{Entry, Kind};

const ALLOW: &str = "OPTIONS, GET, HEAD, PROPFIND";

pub struct Dav {
    shared: Arc<Shared>,
    token: Option<Vec<u8>>,
}

impl Dav {
    /// With a token, clients must send it as the HTTP Basic password (any user name). Basic
    /// auth is cleartext, so use it on loopback or behind a tunnel.
    pub fn new(shared: Arc<Shared>, token: Option<Vec<u8>>) -> Dav {
        Dav { shared, token }
    }

    fn authorized(&self, req: &Request) -> bool {
        let Some(token) = &self.token else { return true };
        let Some(v) = req.header("authorization") else { return false };
        let Some(b64) = v.strip_prefix("Basic ").or_else(|| v.strip_prefix("basic ")) else { return false };
        let Some(raw) = base64_decode(b64.trim()) else { return false };
        let Some(i) = raw.iter().position(|&c| c == b':') else { return false };
        // hashing first makes the comparison constant-time and length-blind
        blake3::hash(&raw[i + 1..]) == blake3::hash(token)
    }
}

enum Node {
    Root,
    Dir { id: Hash, mtime: i64 },
    File(Entry),
}

fn resolve(st: &Store, path: &str) -> Result<Option<Node>> {
    let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    let Some((first, rest)) = comps.split_first() else { return Ok(Some(Node::Root)) };

    let snap = match st.snapshot_get(first) {
        Ok(s) => s,
        Err(Error::SnapshotNotFound(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut node = Node::Dir { id: snap.root, mtime: snap.time };
    for c in rest {
        let Node::Dir { id, .. } = &node else { return Ok(None) };
        // names holding '.', '..' or a separator cannot be in a tree, so they simply do not match
        let tree = st.load_tree(id)?;
        node = match tree.get(c) {
            None => return Ok(None),
            Some(e) => match e.kind {
                Kind::Dir => Node::Dir { id: e.id, mtime: e.mtime },
                Kind::File => Node::File(e.clone()),
                Kind::Symlink => return Ok(None),
            },
        };
    }
    Ok(Some(node))
}

struct Child {
    name: String,
    dir: bool,
    size: u64,
    mtime: i64,
    etag: Option<Hash>,
}

fn children(st: &Store, node: &Node) -> Result<Vec<Child>> {
    Ok(match node {
        Node::Root => st
            .snapshot_list()?
            .into_iter()
            .map(|s| Child { name: s.name, dir: true, size: 0, mtime: s.time, etag: None })
            .collect(),
        Node::Dir { id, .. } => st
            .load_tree(id)?
            .entries
            .into_iter()
            .filter(|e| e.kind != Kind::Symlink)
            .map(|e| Child {
                dir: e.kind == Kind::Dir,
                size: e.size,
                mtime: e.mtime,
                etag: (e.kind == Kind::File).then_some(e.id),
                name: e.name,
            })
            .collect(),
        Node::File(_) => Vec::new(),
    })
}

fn mime(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map_or("", |(_, e)| e).to_ascii_lowercase();
    match ext.as_str() {
        "txt" | "log" | "md" | "csv" | "rs" | "toml" => "text/plain; charset=utf-8",
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css",
        "js" => "text/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        _ => "application/octet-stream",
    }
}

fn href(base: &str, name: Option<&str>, dir: bool) -> String {
    let mut p = base.trim_end_matches('/').to_string();
    if let Some(n) = name {
        p.push('/');
        p.push_str(n);
    }
    if dir || p.is_empty() {
        p.push('/');
    }
    percent_encode_path(&p)
}

fn prop_entry(out: &mut String, href: &str, name: &str, dir: bool, size: u64, mtime: i64, etag: Option<&Hash>) {
    let _ = write!(out, "<D:response><D:href>{}</D:href><D:propstat><D:prop>", xml_escape(href));
    let _ = write!(out, "<D:displayname>{}</D:displayname>", xml_escape(name));
    let _ = write!(out, "<D:creationdate>{}</D:creationdate>", iso8601(mtime));
    let _ = write!(out, "<D:getlastmodified>{}</D:getlastmodified>", http_date(mtime));
    if dir {
        out.push_str("<D:resourcetype><D:collection/></D:resourcetype>");
    } else {
        out.push_str("<D:resourcetype/>");
        let _ = write!(out, "<D:getcontentlength>{size}</D:getcontentlength>");
        let _ = write!(out, "<D:getcontenttype>{}</D:getcontenttype>", mime(name));
        if let Some(e) = etag {
            let _ = write!(out, "<D:getetag>\"{e}\"</D:getetag>");
        }
    }
    out.push_str("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>");
}

enum Range {
    Whole,
    Part(u64, u64),
    Unsatisfiable,
}

// one range only; several are legal to ignore, the client just gets the whole file
fn parse_range(h: Option<&str>, size: u64) -> Range {
    let Some(spec) = h.and_then(|h| h.trim().strip_prefix("bytes=")) else { return Range::Whole };
    if spec.contains(',') {
        return Range::Whole;
    }
    let Some((a, b)) = spec.split_once('-') else { return Range::Whole };
    let (a, b) = (a.trim(), b.trim());
    let r = if a.is_empty() {
        // suffix: the last n bytes
        let Ok(n) = b.parse::<u64>() else { return Range::Whole };
        if n == 0 {
            return Range::Unsatisfiable;
        }
        (size.saturating_sub(n), size.saturating_sub(1))
    } else {
        let Ok(start) = a.parse::<u64>() else { return Range::Whole };
        let end = if b.is_empty() {
            size.saturating_sub(1)
        } else {
            match b.parse::<u64>() {
                Ok(e) => e.min(size.saturating_sub(1)),
                Err(_) => return Range::Whole,
            }
        };
        (start, end)
    };
    if size == 0 || r.0 >= size || r.0 > r.1 { Range::Unsatisfiable } else { Range::Part(r.0, r.1) }
}

fn error_page(out: &mut dyn Write, status: u16, head: bool) -> io::Result<()> {
    let msg = crate::http::reason(status);
    respond(out, status, &[("Content-Type", "text/plain".into())], msg.as_bytes(), head)
}

impl Dav {
    fn propfind(&self, req: &Request, out: &mut dyn Write) -> io::Result<()> {
        // "infinity" is allowed to be refused; one level is what clients actually want
        let depth0 = req.header("depth").is_some_and(|d| d.trim() == "0");
        let built = self.shared.with_store(|st| -> Result<Option<String>> {
            let Some(node) = resolve(st, &req.path)? else { return Ok(None) };
            let mut x = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">");
            let base = req.path.as_str();
            let self_name = base.trim_end_matches('/').rsplit('/').next().unwrap_or("");
            match &node {
                Node::Root => prop_entry(&mut x, &href(base, None, true), "", true, 0, 0, None),
                Node::Dir { mtime, .. } => {
                    prop_entry(&mut x, &href(base, None, true), self_name, true, 0, *mtime, None)
                }
                Node::File(e) => {
                    prop_entry(&mut x, &href(base, None, false), self_name, false, e.size, e.mtime, Some(&e.id))
                }
            }
            if !depth0 {
                for c in children(st, &node)? {
                    let h = href(base, Some(&c.name), c.dir);
                    prop_entry(&mut x, &h, &c.name, c.dir, c.size, c.mtime, c.etag.as_ref());
                }
            }
            x.push_str("</D:multistatus>");
            Ok(Some(x))
        });
        match built {
            Ok(Some(xml)) => {
                respond(out, 207, &[("Content-Type", "application/xml; charset=utf-8".into())], xml.as_bytes(), false)
            }
            Ok(None) => error_page(out, 404, false),
            Err(_) => error_page(out, 500, false),
        }
    }

    fn get(&self, req: &Request, out: &mut dyn Write, head: bool) -> io::Result<()> {
        enum Found {
            Missing,
            Failed,
            Index(String),
            File(Entry),
        }
        let found = self.shared.with_store(|st| -> Found {
            match resolve(st, &req.path) {
                Ok(None) => Found::Missing,
                Err(_) => Found::Failed,
                Ok(Some(Node::File(e))) => Found::File(e),
                Ok(Some(node)) => match children(st, &node) {
                    Ok(cs) => Found::Index(index_page(&req.path, &cs)),
                    Err(_) => Found::Failed,
                },
            }
        });
        match found {
            Found::Missing => error_page(out, 404, head),
            Found::Failed => error_page(out, 500, head),
            Found::Index(html) => {
                respond(out, 200, &[("Content-Type", "text/html; charset=utf-8".into())], html.as_bytes(), head)
            }
            Found::File(e) => self.send_file(req, out, &e, head),
        }
    }

    fn send_file(&self, req: &Request, out: &mut dyn Write, e: &Entry, head: bool) -> io::Result<()> {
        let etag = format!("\"{}\"", e.id);
        let mut h: Vec<(&str, String)> = vec![
            ("Content-Type", mime(&e.name).into()),
            ("ETag", etag.clone()),
            ("Last-Modified", http_date(e.mtime)),
            ("Accept-Ranges", "bytes".into()),
        ];
        if req.header("if-none-match").is_some_and(|v| v.split(',').any(|t| t.trim() == etag || t.trim() == "*")) {
            return respond(out, 304, &h, b"", true);
        }

        let (status, start, len) = match parse_range(req.header("range"), e.size) {
            Range::Whole => (200, 0, e.size),
            Range::Part(a, b) => {
                h.push(("Content-Range", format!("bytes {a}-{b}/{}", e.size)));
                (206, a, b - a + 1)
            }
            Range::Unsatisfiable => {
                h.push(("Content-Range", format!("bytes */{}", e.size)));
                return respond(out, 416, &h, b"", head);
            }
        };
        h.push(("Content-Length", len.to_string()));
        write_head(out, status, &h)?;
        if head {
            return out.flush();
        }

        // the store stays read-locked while the bytes go out, so a writer waits for slow clients
        self.shared.with_store(|st| -> io::Result<()> {
            let mut r = st.open_reader(&e.id).map_err(io::Error::other)?;
            r.seek(SeekFrom::Start(start))?;
            let n = io::copy(&mut r.take(len), out)?;
            if n != len {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            Ok(())
        })?;
        out.flush()
    }
}

fn index_page(path: &str, cs: &[Child]) -> String {
    let title = xml_escape(if path == "/" { "snapshots" } else { path });
    let mut h = format!("<!doctype html><meta charset=\"utf-8\"><title>{title}</title><h1>{title}</h1><ul>");
    if path != "/" {
        h.push_str("<li><a href=\"../\">../</a></li>");
    }
    for c in cs {
        let link = percent_encode_path(&c.name) + if c.dir { "/" } else { "" };
        let _ = write!(h, "<li><a href=\"{link}\">{}{}</a>", xml_escape(&c.name), if c.dir { "/" } else { "" });
        if !c.dir {
            let _ = write!(h, " ({} bytes)", c.size);
        }
        h.push_str("</li>");
    }
    h.push_str("</ul>");
    h
}

impl Handler for Dav {
    fn handle(&self, req: &Request, out: &mut dyn Write) -> io::Result<()> {
        if !self.authorized(req) {
            return respond(
                out,
                401,
                &[("WWW-Authenticate", "Basic realm=\"cas\"".into()), ("Content-Type", "text/plain".into())],
                b"Unauthorized",
                req.method == "HEAD",
            );
        }
        match req.method.as_str() {
            "OPTIONS" => respond(
                out,
                200,
                &[("DAV", "1".into()), ("Allow", ALLOW.into()), ("MS-Author-Via", "DAV".into())],
                b"",
                false,
            ),
            "PROPFIND" => self.propfind(req, out),
            "GET" => self.get(req, out, false),
            "HEAD" => self.get(req, out, true),
            // everything that would change something
            "PUT" | "DELETE" | "MKCOL" | "PROPPATCH" | "LOCK" | "UNLOCK" | "COPY" | "MOVE" | "POST" | "PATCH" => {
                respond(
                    out,
                    405,
                    &[("Allow", ALLOW.into()), ("Content-Type", "text/plain".into())],
                    b"read-only",
                    false,
                )
            }
            _ => error_page(out, 501, false),
        }
    }
}
