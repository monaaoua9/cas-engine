use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use crate::backup::SnapshotReport;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::tree::{Entry, Kind, valid_name};

const BLOCK: usize = 512;
const MAX_DEPTH: usize = 512;
// long names and pax blocks are tiny in practice
const MAX_META: u64 = 1 << 20;

#[derive(Debug, Default, Clone)]
pub struct TarReport {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub bytes: u64,
}

fn put_octal(dst: &mut [u8], v: u64) {
    // width-1 digits and a NUL
    let w = dst.len() - 1;
    let s = format!("{v:0w$o}");
    dst[..w].copy_from_slice(s.as_bytes());
    dst[w] = 0;
}

fn put_num(dst: &mut [u8], v: u64) {
    let max = (1u64 << (3 * (dst.len() - 1))) - 1;
    if v <= max {
        put_octal(dst, v);
        return;
    }
    // GNU base-256: high bit set, big endian
    dst.fill(0);
    dst[0] = 0x80;
    let n = dst.len();
    dst[n - 8..].copy_from_slice(&v.to_be_bytes());
}

fn header(name: &[u8], prefix: &[u8], mode: u32, size: u64, mtime: i64, kind: u8, link: &[u8]) -> [u8; BLOCK] {
    let mut h = [0u8; BLOCK];
    h[..name.len()].copy_from_slice(name);
    put_octal(&mut h[100..108], u64::from(mode & 0o7777));
    put_octal(&mut h[108..116], 0);
    put_octal(&mut h[116..124], 0);
    put_num(&mut h[124..136], size);
    put_num(&mut h[136..148], mtime.max(0) as u64);
    h[156] = kind;
    h[157..157 + link.len()].copy_from_slice(link);
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[345..345 + prefix.len()].copy_from_slice(prefix);

    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    let s = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(s.as_bytes());
    h
}

// ustar can hold a path as prefix/name when it splits at a slash
fn split_path(p: &str) -> Option<(&str, &str)> {
    if p.len() <= 100 {
        return Some(("", p));
    }
    p.char_indices()
        .filter(|&(i, c)| c == '/' && i <= 155 && p.len() - i - 1 <= 100 && i > 0)
        .map(|(i, _)| (&p[..i], &p[i + 1..]))
        .next_back()
}

fn pad(out: &mut impl Write, len: u64) -> io::Result<()> {
    let rem = (len % BLOCK as u64) as usize;
    if rem != 0 {
        out.write_all(&[0u8; BLOCK][..BLOCK - rem])?;
    }
    Ok(())
}

// GNU 'L' / 'K' record: the real text travels as the entry's data
fn gnu_long(out: &mut impl Write, kind: u8, text: &str) -> io::Result<()> {
    let mut data = text.as_bytes().to_vec();
    data.push(0);
    out.write_all(&header(b"././@LongLink", b"", 0, data.len() as u64, 0, kind, b""))?;
    out.write_all(&data)?;
    pad(out, data.len() as u64)
}

impl Store {
    /// Writes a snapshot as a tar stream. Names that don't fit ustar use GNU long-name records.
    pub fn export_tar(&self, snapshot: &str, mut out: impl Write) -> Result<TarReport> {
        let snap = self.snapshot_get(snapshot)?;
        let mut rep = TarReport::default();

        for (path, e) in self.flatten(&snap.root)? {
            let is_dir = e.kind == Kind::Dir;
            let full = if is_dir { format!("{path}/") } else { path.clone() };
            let (prefix, name) = match split_path(&full) {
                Some((p, n)) => (p.as_bytes(), n.as_bytes()),
                None => {
                    gnu_long(&mut out, b'L', &full)?;
                    // readers use the long record; the header copy is just a cut-down hint
                    (&b""[..], &full.as_bytes()[..100])
                }
            };

            match e.kind {
                Kind::Dir => {
                    out.write_all(&header(name, prefix, e.mode, 0, e.mtime, b'5', b""))?;
                    rep.dirs += 1;
                }
                Kind::Symlink => {
                    if e.target.len() > 100 {
                        gnu_long(&mut out, b'K', &e.target)?;
                    }
                    let link = &e.target.as_bytes()[..e.target.len().min(100)];
                    out.write_all(&header(name, prefix, e.mode, 0, e.mtime, b'2', link))?;
                    rep.symlinks += 1;
                }
                Kind::File => {
                    out.write_all(&header(name, prefix, e.mode, e.size, e.mtime, b'0', b""))?;
                    let n = io::copy(&mut self.open_reader(&e.id)?, &mut out)?;
                    if n != e.size {
                        return Err(Error::BadTar("object size differs from its tree entry"));
                    }
                    pad(&mut out, n)?;
                    rep.files += 1;
                    rep.bytes += n;
                }
            }
        }
        out.write_all(&[0u8; BLOCK * 2])?;
        out.flush()?;
        Ok(rep)
    }
}

fn parse_num(f: &[u8]) -> Result<u64> {
    if f.first().is_some_and(|b| b & 0x80 != 0) {
        // base-256; anything beyond u64 is refused
        if f[0] & 0x40 != 0 {
            return Err(Error::BadTar("negative number"));
        }
        let mut v = 0u64;
        for (i, &b) in f.iter().enumerate() {
            let b = if i == 0 { b & 0x3f } else { b };
            v = v
                .checked_mul(256)
                .and_then(|v| v.checked_add(u64::from(b)))
                .ok_or(Error::BadTar("number too large"))?;
        }
        return Ok(v);
    }
    let mut v = 0u64;
    let mut seen = false;
    for &b in f {
        match b {
            b'0'..=b'7' => {
                seen = true;
                v = v
                    .checked_mul(8)
                    .and_then(|v| v.checked_add(u64::from(b - b'0')))
                    .ok_or(Error::BadTar("number too large"))?;
            }
            b' ' if !seen => {}
            b' ' | 0 => break,
            _ => return Err(Error::BadTar("bad number field")),
        }
    }
    Ok(v)
}

fn cstr(f: &[u8]) -> &[u8] {
    &f[..f.iter().position(|&b| b == 0).unwrap_or(f.len())]
}

fn read_block(r: &mut impl Read) -> Result<Option<[u8; BLOCK]>> {
    let mut b = [0u8; BLOCK];
    let mut got = 0;
    while got < BLOCK {
        let n = r.read(&mut b[got..])?;
        if n == 0 {
            return if got == 0 { Ok(None) } else { Err(Error::BadTar("truncated header")) };
        }
        got += n;
    }
    Ok(Some(b))
}

fn skip(r: &mut impl Read, n: u64) -> Result<()> {
    if io::copy(&mut r.take(n), &mut io::sink())? != n {
        return Err(Error::BadTar("truncated data"));
    }
    Ok(())
}

fn padding(size: u64) -> u64 {
    (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64
}

fn read_meta(r: &mut impl Read, size: u64) -> Result<Vec<u8>> {
    if size > MAX_META {
        return Err(Error::BadTar("metadata record too large"));
    }
    let mut buf = vec![0u8; size as usize];
    r.read_exact(&mut buf).map_err(|_| Error::BadTar("truncated data"))?;
    skip(r, padding(size))?;
    Ok(buf)
}

#[derive(Default)]
struct Pax {
    path: Option<String>,
    link: Option<String>,
    size: Option<u64>,
    mtime: Option<i64>,
}

fn parse_pax(buf: &[u8], into: &mut Pax) -> Result<()> {
    let mut rest = buf;
    while !rest.is_empty() {
        let sp = rest.iter().position(|&b| b == b' ').ok_or(Error::BadTar("bad pax record"))?;
        let len: usize = std::str::from_utf8(&rest[..sp])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(Error::BadTar("bad pax length"))?;
        if len <= sp + 1 || len > rest.len() || rest[len - 1] != b'\n' {
            return Err(Error::BadTar("bad pax record"));
        }
        let rec = &rest[sp + 1..len - 1];
        rest = &rest[len..];
        let Some(eq) = rec.iter().position(|&b| b == b'=') else { continue };
        let (k, v) = (&rec[..eq], &rec[eq + 1..]);
        let Ok(v) = std::str::from_utf8(v) else { continue };
        match k {
            b"path" => into.path = Some(v.to_owned()),
            b"linkpath" => into.link = Some(v.to_owned()),
            b"size" => into.size = Some(v.parse().map_err(|_| Error::BadTar("bad pax size"))?),
            // fractions are cut off; the tree keeps whole seconds from tar
            b"mtime" => into.mtime = v.split('.').next().and_then(|s| s.parse().ok()),
            _ => {}
        }
    }
    Ok(())
}

enum Node {
    Dir(Dir),
    File(Entry),
    Link(Entry),
}

#[derive(Default)]
struct Dir {
    kids: BTreeMap<String, Node>,
    mode: u32,
    mtime: i64,
}

impl Dir {
    fn implicit() -> Dir {
        Dir { kids: BTreeMap::new(), mode: 0o755, mtime: 0 }
    }
}

// None when any component can't live in a tree; `..` lands here too
fn components(p: &str) -> Option<Vec<&str>> {
    let v: Vec<&str> = p.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
    (v.len() <= MAX_DEPTH && v.iter().all(|c| valid_name(c))).then_some(v)
}

fn dir_at<'a>(root: &'a mut Dir, path: &[&str]) -> Result<&'a mut Dir> {
    let mut cur = root;
    for c in path {
        let n = cur.kids.entry((*c).to_owned()).or_insert_with(|| Node::Dir(Dir::implicit()));
        cur = match n {
            Node::Dir(d) => d,
            // a file or link where a directory is needed: later entry wins, like extracting would
            other => {
                *other = Node::Dir(Dir::implicit());
                let Node::Dir(d) = other else { unreachable!() };
                d
            }
        };
    }
    Ok(cur)
}

fn place(root: &mut Dir, comps: &[&str], node: Node) -> Result<()> {
    let (last, parents) = comps.split_last().ok_or(Error::BadTar("entry without a name"))?;
    let parent = dir_at(root, parents)?;
    match (parent.kids.get_mut(*last), node) {
        // an explicit directory record only fills in metadata of what is already there
        (Some(Node::Dir(old)), Node::Dir(new)) => {
            old.mode = new.mode;
            old.mtime = new.mtime;
        }
        (_, node) => {
            parent.kids.insert((*last).to_owned(), node);
        }
    }
    Ok(())
}

impl Store {
    /// Reads a tar stream (ustar, GNU long names, pax) into a new snapshot. Entries that cannot
    /// be represented are skipped and listed in the report; a malformed archive is an error and
    /// leaves no snapshot behind.
    pub fn import_tar<R: Read + Send>(&mut self, mut input: R, name: Option<&str>) -> Result<SnapshotReport> {
        let (name, time, mut acc) = self.begin_snapshot(name)?;
        let mut root = Dir::implicit();

        let mut long_name: Option<String> = None;
        let mut long_link: Option<String> = None;
        let mut pax = Pax::default();
        let mut skipped: Vec<std::path::PathBuf> = Vec::new();
        // regular files seen so far, so a hard link can point at one
        let mut seen: std::collections::HashMap<String, (crate::hash::Hash, u64)> = std::collections::HashMap::new();

        while let Some(h) = read_block(&mut input)? {
            if h.iter().all(|&b| b == 0) {
                break;
            }
            let want: u32 = parse_num(&h[148..156])?.try_into().map_err(|_| Error::BadTar("bad checksum"))?;
            let have: u32 =
                h.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { 32 } else { u32::from(b) }).sum();
            if want != have {
                return Err(Error::BadTar("header checksum mismatch"));
            }

            let kind = h[156];
            let mut size = parse_num(&h[124..136])?;
            match kind {
                b'L' | b'K' => {
                    let buf = read_meta(&mut input, size)?;
                    let s = String::from_utf8_lossy(cstr(&buf)).into_owned();
                    if kind == b'L' {
                        long_name = Some(s)
                    } else {
                        long_link = Some(s)
                    }
                    continue;
                }
                b'x' => {
                    let buf = read_meta(&mut input, size)?;
                    parse_pax(&buf, &mut pax)?;
                    continue;
                }
                b'g' => {
                    read_meta(&mut input, size)?;
                    continue;
                }
                _ => {}
            }

            let mut path = match (&long_name.take(), &pax.path.take()) {
                (_, Some(p)) | (Some(p), None) => p.clone(),
                (None, None) => {
                    let name = cstr(&h[..100]);
                    let prefix = if &h[257..262] == b"ustar" { cstr(&h[345..500]) } else { b"" };
                    let mut p = Vec::new();
                    if !prefix.is_empty() {
                        p.extend_from_slice(prefix);
                        p.push(b'/');
                    }
                    p.extend_from_slice(name);
                    String::from_utf8_lossy(&p).into_owned()
                }
            };
            let link = match (long_link.take(), pax.link.take()) {
                (_, Some(l)) | (Some(l), None) => l,
                (None, None) => String::from_utf8_lossy(cstr(&h[157..257])).into_owned(),
            };
            if let Some(s) = pax.size.take() {
                size = s;
            }
            let mtime = match pax.mtime.take() {
                Some(m) => m,
                None => i64::try_from(parse_num(&h[136..148])?).map_err(|_| Error::BadTar("bad mtime"))?,
            };
            let mode = (parse_num(&h[100..108])? & 0o7777) as u32;
            if path.contains('\u{fffd}') {
                // not utf-8; the data still has to be consumed
                skipped.push(path.clone().into());
                skip(&mut input, size + padding(size))?;
                continue;
            }
            let is_dir = kind == b'5' || (kind == b'0' || kind == 0) && path.ends_with('/');
            if is_dir {
                path = path.trim_end_matches('/').to_owned();
            }

            let Some(comps) = components(&path) else {
                skipped.push(path.into());
                skip(&mut input, size + padding(size))?;
                continue;
            };
            let entry = |kind: Kind, size: u64, id, target: String| Entry {
                name: comps.last().map(|c| (*c).to_owned()).unwrap_or_default(),
                kind,
                mode,
                mtime,
                mtime_ns: 0,
                size,
                id,
                target,
            };

            if comps.is_empty() {
                // the archive root itself ("./")
                skip(&mut input, size + padding(size))?;
                continue;
            }

            match kind {
                b'5' | b'0' | 0 | b'7' if is_dir => {
                    skip(&mut input, size + padding(size))?;
                    place(&mut root, &comps, Node::Dir(Dir { kids: BTreeMap::new(), mode, mtime }))?;
                }
                b'0' | 0 | b'7' => {
                    let r = self.put_reader((&mut input).take(size))?;
                    if r.size != size {
                        return Err(Error::BadTar("truncated data"));
                    }
                    skip(&mut input, padding(size))?;
                    acc.note(r.id, r.existed);
                    acc.files += 1;
                    acc.bytes += r.size;
                    acc.new_bytes += r.new_bytes;
                    seen.insert(comps.join("/"), (r.id, r.size));
                    place(&mut root, &comps, Node::File(entry(Kind::File, r.size, r.id, String::new())))?;
                }
                b'1' => {
                    skip(&mut input, size + padding(size))?;
                    // the link target is a path from the archive root, same cleanup as entry names
                    let target = components(link.trim_start_matches("./")).map(|c| c.join("/"));
                    let Some(&(id, fsize)) = target.as_ref().and_then(|t| seen.get(t)) else {
                        skipped.push(path.into());
                        continue;
                    };
                    // a link to something we already stored costs nothing; it becomes a second entry
                    acc.files += 1;
                    acc.bytes += fsize;
                    seen.insert(comps.join("/"), (id, fsize));
                    place(&mut root, &comps, Node::File(entry(Kind::File, fsize, id, String::new())))?;
                }
                b'2' => {
                    skip(&mut input, size + padding(size))?;
                    if link.is_empty() || link.len() > u16::MAX as usize || link.contains('\0') {
                        skipped.push(path.into());
                        continue;
                    }
                    place(&mut root, &comps, Node::Link(entry(Kind::Symlink, 0, Entry::zero_id(), link)))?;
                    acc.links += 1;
                }
                _ => {
                    // devices, fifos, links to things we did not keep
                    skip(&mut input, size + padding(size))?;
                    skipped.push(path.into());
                }
            }
        }

        let tree_root = self.build_dir(root, &mut acc, 0)?;
        acc.skipped = skipped;
        self.finish_snapshot(name, time, tree_root, "tar".to_owned(), acc)
    }

    fn build_dir(&mut self, d: Dir, acc: &mut crate::backup::Acc, depth: usize) -> Result<crate::hash::Hash> {
        if depth > MAX_DEPTH {
            return Err(Error::BadTar("directories nested too deep"));
        }
        let mut entries = Vec::with_capacity(d.kids.len());
        for (name, n) in d.kids {
            entries.push(match n {
                Node::File(e) | Node::Link(e) => e,
                Node::Dir(sub) => {
                    let (mode, mtime) = (sub.mode, sub.mtime);
                    let id = self.build_dir(sub, acc, depth + 1)?;
                    acc.dirs += 1;
                    Entry { name, kind: Kind::Dir, mode, mtime, mtime_ns: 0, size: 0, id, target: String::new() }
                }
            });
        }
        self.put_tree(entries, acc)
    }
}
