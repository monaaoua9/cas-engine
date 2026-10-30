use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use cas::client::Client;
use cas::dav::Dav;
use cas::http::{Handler, HttpServer, Request, respond};
use cas::json::{Json, obj};
use cas::server::{ServeOptions, Server, Shared};
use cas::sync::{SyncReport, copy_all, copy_snapshot};
use cas::tls::{TlsClient, TlsServer, generate_self_signed};
use cas::units::{human, parse_size};
use cas::{Algorithm, Compression, Hash, Password, Result, Retention, Store, StoreConfig};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cas", version, about = "content-addressed immutable object store")]
struct Cli {
    /// store directory, created on first use
    #[arg(short, long, default_value = "./cas-store")]
    store: PathBuf,

    /// boundary algorithm for new data; gear is several times faster, rabin is the default
    #[arg(long, value_parser = ["rabin", "gear"], default_value = "rabin")]
    chunker: String,

    /// compress new chunks; chunks that don't shrink are stored as they are
    #[arg(long, value_parser = ["none", "lz4"], default_value = "none")]
    compress: String,

    /// file holding the store password (first line, or CAS_PASSWORD_FILE). On a new store this turns encryption on.
    #[arg(long)]
    password_file: Option<PathBuf>,

    /// refuse writes that would take the segment files past this size (64M, 10GiB, ...)
    #[arg(long, value_parser = parse_size)]
    max_size: Option<u64>,

    /// machine-readable output on stdout
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// store a file, prints its object id
    Put {
        path: PathBuf,
    },
    /// write an object back out to a file
    Get {
        id: Hash,
        out: PathBuf,
    },
    /// drop an object (space returns on the next gc)
    Rm {
        id: Hash,
    },
    /// list stored objects
    Ls,
    /// re-hash one object, or the whole store when no id is given
    Verify {
        id: Option<Hash>,
    },
    /// print a Merkle inclusion proof for one chunk of an object
    Prove {
        id: Hash,
        chunk: usize,
    },
    /// compact segments and drop unreferenced chunks
    Gc,
    Stats,
    /// list everything wrong without changing anything
    Check,
    /// fix what `check` finds using a second copy of the store (a directory copy or a replica)
    Repair {
        #[arg(long)]
        from: PathBuf,
    },
    /// Prometheus text format (gauges from the store; counters cover this process only)
    Metrics,
    /// time chunking, hashing, put and get on random data in a scratch directory
    Bench {
        #[arg(long, default_value = "64M", value_parser = parse_size)]
        size: u64,
    },
    /// set a new password on an encrypted store; no data is rewritten
    Passwd {
        #[arg(long)]
        new_password_file: PathBuf,
    },
    /// directory snapshots: create, list, show, restore, diff, forget, prune
    #[command(subcommand)]
    Snapshot(Snap),
    /// write a snapshot as a tar archive (stdout unless --out)
    Export {
        name: String,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// read a tar archive (stdin unless a file is given) into a new snapshot
    Import {
        file: Option<PathBuf>,
        #[arg(short, long)]
        name: Option<String>,
    },
    /// serve this store over TCP, and optionally as a WebDAV share and a /metrics page
    Serve {
        #[arg(long, default_value = "127.0.0.1:7878")]
        listen: SocketAddr,
        /// read-only WebDAV view of the snapshots
        #[arg(long)]
        dav_listen: Option<SocketAddr>,
        /// plain HTTP /metrics for Prometheus
        #[arg(long)]
        metrics_listen: Option<SocketAddr>,
        /// file whose first line is the shared secret; without it anyone who can connect gets in
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// refuse every write from clients
        #[arg(long)]
        read_only: bool,
        #[arg(long, default_value_t = 64)]
        max_conns: usize,
        /// PEM certificate and key: the cas listener then speaks TLS (the WebDAV and metrics ports stay plain)
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
        /// serve WebDAV and /metrics over HTTPS with the same certificate
        #[arg(long, requires = "tls_cert")]
        http_tls: bool,
    },
    /// write a self-signed certificate and key for `serve --tls-cert`; the certificate is also the `--tls-ca` file
    TlsCert {
        /// host names or IP addresses clients will connect to
        #[arg(long = "name", required = true)]
        names: Vec<String>,
        #[arg(long, default_value = "cas-cert.pem")]
        cert_out: PathBuf,
        #[arg(long, default_value = "cas-key.pem")]
        key_out: PathBuf,
    },
    /// send snapshots (or everything) to a running `cas serve`
    Push {
        addr: String,
        /// only this snapshot and what it needs
        #[arg(long)]
        snapshot: Option<String>,
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// certificate to trust; turns TLS on for this connection
        #[arg(long)]
        tls_ca: Option<PathBuf>,
    },
    /// fetch snapshots (or everything) from a running `cas serve`
    Pull {
        addr: String,
        #[arg(long)]
        snapshot: Option<String>,
        #[arg(long)]
        token_file: Option<PathBuf>,
        #[arg(long)]
        tls_ca: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum Snap {
    /// store a directory tree
    Create {
        dir: PathBuf,
        /// default is snap-<unix time>
        #[arg(short, long)]
        name: Option<String>,
    },
    Ls,
    /// list the paths inside a snapshot
    Show {
        name: String,
    },
    /// rebuild a snapshot into an empty (or new) directory
    Restore {
        name: String,
        dest: PathBuf,
    },
    /// what changed between two snapshots
    Diff {
        a: String,
        b: String,
    },
    /// re-hash everything a snapshot reaches
    Verify {
        name: String,
    },
    /// drop a snapshot and the objects only it needed (run gc afterwards)
    Forget {
        name: String,
    },
    /// forget snapshots that fall outside the kept ones
    Prune {
        #[arg(long, default_value_t = 0)]
        keep_last: usize,
        #[arg(long, default_value_t = 0)]
        keep_daily: usize,
        #[arg(long, default_value_t = 0)]
        keep_weekly: usize,
        #[arg(long, default_value_t = 0)]
        keep_monthly: usize,
        #[arg(long)]
        dry_run: bool,
    },
}

struct Out {
    json: bool,
}

impl Out {
    // text mode: `text` to stdout, `note` to stderr; json mode: just the object
    fn emit(&self, j: Json, text: &str, note: &str) {
        if self.json {
            println!("{}", j.render());
            return;
        }
        if !text.is_empty() {
            println!("{text}");
        }
        if !note.is_empty() {
            eprintln!("{note}");
        }
    }
}

fn hashes(v: &[Hash]) -> Json {
    Json::Arr(v.iter().map(|h| Json::from(h.to_hex())).collect())
}

fn first_line(p: &Path) -> std::io::Result<Vec<u8>> {
    let mut b = std::fs::read(p)?;
    // editors add a newline; the secret is the first line
    if let Some(i) = b.iter().position(|&c| c == b'\n') {
        b.truncate(i);
    }
    if b.last() == Some(&b'\r') {
        b.pop();
    }
    Ok(b)
}

fn read_password(p: &Path) -> std::io::Result<Password> {
    first_line(p).map(Password::from)
}

fn read_token(p: &Option<PathBuf>) -> std::io::Result<Option<Vec<u8>>> {
    p.as_deref().map(first_line).transpose()
}

fn config(cli: &Cli) -> Result<StoreConfig> {
    let mut cfg = StoreConfig::default();
    if cli.chunker == "gear" {
        cfg.chunker.algorithm = Algorithm::Gear;
    }
    if cli.compress == "lz4" {
        cfg.compression = Compression::Lz4;
    }
    cfg.max_bytes = cli.max_size;
    let pw_file = cli.password_file.clone().or_else(|| std::env::var_os("CAS_PASSWORD_FILE").map(PathBuf::from));
    if let Some(p) = pw_file {
        cfg.password = Some(read_password(&p)?);
    }
    Ok(cfg)
}

fn bench(cfg: StoreConfig, size: u64, out: &Out) -> Result<bool> {
    let dir = std::env::temp_dir().join(format!("cas-bench-{}", std::process::id()));
    let r = cas::bench::run(cfg, size, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    let r = r?;

    let j = obj([
        ("bytes", r.bytes.into()),
        ("chunks", r.chunks.into()),
        ("chunk_mib_s", r.chunk_mib_s.into()),
        ("hash_mib_s", r.hash_mib_s.into()),
        ("put_mib_s", r.put_mib_s.into()),
        ("get_mib_s", r.get_mib_s.into()),
        ("stored_bytes", r.stored_bytes.into()),
    ]);
    let t = format!(
        "{} in {} chunks\nchunk only   {:>8.0} MiB/s\nblake3       {:>8.0} MiB/s\nput          {:>8.0} MiB/s\nget          {:>8.0} MiB/s",
        human(r.bytes),
        r.chunks,
        r.chunk_mib_s,
        r.hash_mib_s,
        r.put_mib_s,
        r.get_mib_s
    );
    out.emit(j, &t, "");
    Ok(true)
}

fn run(cli: Cli) -> Result<bool> {
    let out = Out { json: cli.json };
    let cfg = config(&cli)?;
    if let Cmd::Bench { size } = cli.cmd {
        return bench(cfg, size, &out);
    }
    if let Cmd::TlsCert { names, cert_out, key_out } = &cli.cmd {
        generate_self_signed(names, cert_out, key_out)?;
        out.emit(
            obj([("cert", cert_out.display().to_string().into()), ("key", key_out.display().to_string().into())]),
            "",
            &format!("wrote {} and {}", cert_out.display(), key_out.display()),
        );
        return Ok(true);
    }
    let mut store = Store::open(&cli.store, cfg.clone())?;

    match cli.cmd {
        Cmd::Put { path } => {
            let r = store.put_file(path)?;
            let j = obj([
                ("id", r.id.to_hex().into()),
                ("size", r.size.into()),
                ("chunks", r.chunks.into()),
                ("new_chunks", r.new_chunks.into()),
                ("new_bytes", r.new_bytes.into()),
                ("stored_bytes", r.stored_bytes.into()),
                ("existed", r.existed.into()),
            ]);
            let note = format!(
                "{} in {} chunks, {} new ({}, {} stored){}",
                human(r.size),
                r.chunks,
                r.new_chunks,
                human(r.new_bytes),
                human(r.stored_bytes),
                if r.existed { ", already stored" } else { "" }
            );
            out.emit(j, &r.id.to_string(), &note);
        }
        Cmd::Get { id, out: dest } => {
            let mut w = BufWriter::new(File::create(dest)?);
            store.read_into(&id, &mut w)?;
            w.flush()?;
        }
        Cmd::Rm { id } => {
            if !store.remove(&id)? {
                eprintln!("no such object");
                return Ok(false);
            }
        }
        Cmd::Ls => {
            let mut rows = Vec::new();
            let mut text = Vec::new();
            for id in store.list()? {
                let size = store.manifest(&id)?.size;
                rows.push(obj([("id", id.to_hex().into()), ("size", size.into())]));
                text.push(format!("{id}  {}", human(size)));
            }
            out.emit(Json::Arr(rows), &text.join("\n"), "");
        }
        Cmd::Verify { id: Some(id) } => {
            store.verify(&id)?;
            out.emit(obj([("id", id.to_hex().into()), ("ok", true.into())]), "ok", "");
        }
        Cmd::Verify { id: None } => {
            let mut bad = Vec::new();
            for id in store.list()? {
                if let Err(e) = store.verify(&id) {
                    bad.push((id, e.to_string()));
                }
            }
            let s = store.scrub()?;
            let ok = bad.is_empty() && s.corrupt.is_empty();
            let j = obj([
                ("ok", ok.into()),
                ("chunks_checked", s.checked.into()),
                ("corrupt_chunks", hashes(&s.corrupt)),
                (
                    "bad_objects",
                    Json::Arr(
                        bad.iter()
                            .map(|(i, e)| obj([("id", i.to_hex().into()), ("error", e.as_str().into())]))
                            .collect(),
                    ),
                ),
            ]);
            let mut t = Vec::new();
            t.extend(bad.iter().map(|(i, e)| format!("{i}: {e}")));
            t.extend(s.corrupt.iter().map(|h| format!("chunk {h}: corrupt")));
            t.push(format!("{} chunks checked, {} corrupt, {} bad objects", s.checked, s.corrupt.len(), bad.len()));
            out.emit(j, &t.join("\n"), "");
            return Ok(ok);
        }
        Cmd::Prove { id, chunk } => {
            let (c, p) = store.prove(&id, chunk)?;
            let m = store.manifest(&id)?;
            let ok = p.verify(c.leaf(), &m.id());
            let j = obj([
                ("root", id.to_hex().into()),
                ("chunk", c.hash.to_hex().into()),
                ("len", c.len.into()),
                ("leaf_index", p.index.into()),
                ("leaf_count", p.leaf_count.into()),
                ("siblings", hashes(&p.siblings)),
                ("valid", ok.into()),
            ]);
            let mut t = vec![
                format!("root   {id}"),
                format!("chunk  {} ({} bytes), leaf {} of {}", c.hash, c.len, p.index, p.leaf_count),
            ];
            t.extend(p.siblings.iter().map(|s| format!("  sib  {s}")));
            t.push(format!("proof {}", if ok { "valid" } else { "INVALID" }));
            out.emit(j, &t.join("\n"), "");
            return Ok(ok);
        }
        Cmd::Gc => {
            let r = store.gc()?;
            let j = obj([
                ("chunks_removed", r.chunks_removed.into()),
                ("chunks_moved", r.chunks_moved.into()),
                ("segments_removed", r.segments_removed.into()),
                ("bytes_reclaimed", r.bytes_reclaimed.into()),
            ]);
            let t = format!(
                "removed {} chunks, moved {}, deleted {} segments, reclaimed {}",
                r.chunks_removed,
                r.chunks_moved,
                r.segments_removed,
                human(r.bytes_reclaimed)
            );
            out.emit(j, &t, "");
        }
        Cmd::Stats => {
            let s = store.stats()?;
            let snaps = store.snapshot_list()?.len();
            let j = obj([
                ("objects", s.objects.into()),
                ("logical_bytes", s.logical_bytes.into()),
                ("live_chunks", s.live_chunks.into()),
                ("live_bytes", s.live_bytes.into()),
                ("dead_chunks", s.dead_chunks.into()),
                ("dead_bytes", s.dead_bytes.into()),
                ("segments", s.segments.into()),
                ("disk_bytes", store.disk_bytes().into()),
                ("max_bytes", store.max_bytes().map_or(Json::Null, Json::from)),
                ("dedup_ratio", s.dedup_ratio().into()),
                ("snapshots", snaps.into()),
                ("encrypted", store.is_encrypted().into()),
            ]);
            let mut t = vec![
                format!("objects        {}", s.objects),
                format!("logical size   {}", human(s.logical_bytes)),
                format!("live chunks    {} ({})", s.live_chunks, human(s.live_bytes)),
                format!("dead chunks    {} ({})", s.dead_chunks, human(s.dead_bytes)),
                format!("segments       {} ({} on disk)", s.segments, human(store.disk_bytes())),
            ];
            if let Some(m) = store.max_bytes() {
                t.push(format!("size limit     {}", human(m)));
            }
            t.push(format!("dedup ratio    {:.2}x", s.dedup_ratio()));
            t.push(format!("snapshots      {snaps}"));
            t.push(format!("encrypted      {}", if store.is_encrypted() { "yes" } else { "no" }));
            out.emit(j, &t.join("\n"), "");
        }
        Cmd::Check => {
            let d = store.check()?;
            let ok = d.is_empty();
            let j = obj([
                ("ok", ok.into()),
                ("bad_manifests", hashes(&d.bad_manifests)),
                ("corrupt_chunks", hashes(&d.corrupt_chunks)),
                ("missing_chunks", hashes(&d.missing_chunks)),
            ]);
            let mut t = Vec::new();
            t.extend(d.bad_manifests.iter().map(|h| format!("manifest {h}: unreadable")));
            t.extend(d.corrupt_chunks.iter().map(|h| format!("chunk {h}: corrupt")));
            t.extend(d.missing_chunks.iter().map(|h| format!("chunk {h}: missing")));
            if ok {
                t.push("ok".to_string());
            }
            out.emit(j, &t.join("\n"), "");
            return Ok(ok);
        }
        Cmd::Repair { from } => {
            let copy = Store::open(from, cfg)?;
            let r = store.repair_from(&copy)?;
            let ok = r.unrecoverable.is_empty();
            let j = obj([
                ("ok", ok.into()),
                ("chunks_fixed", r.chunks_fixed.into()),
                ("manifests_fixed", r.manifests_fixed.into()),
                ("unrecoverable", hashes(&r.unrecoverable)),
            ]);
            let mut t = vec![format!("fixed {} chunks, {} manifests", r.chunks_fixed, r.manifests_fixed)];
            t.extend(r.unrecoverable.iter().map(|h| format!("{h}: not in the other copy either")));
            out.emit(j, &t.join("\n"), "");
            return Ok(ok);
        }
        Cmd::Metrics => {
            let text = cas::metrics::prometheus(
                &store.stats()?,
                &store.counters(),
                store.disk_bytes(),
                store.max_bytes(),
                &[],
            );
            print!("{text}");
        }
        Cmd::Passwd { new_password_file } => {
            store.change_password(&read_password(&new_password_file)?)?;
        }
        Cmd::Snapshot(c) => return snapshot(&mut store, c, &out),
        Cmd::Export { name, out: dest } => {
            let r = match dest {
                Some(p) => store.export_tar(&name, BufWriter::new(File::create(p)?))?,
                None => store.export_tar(&name, BufWriter::new(io::stdout().lock()))?,
            };
            let j = obj([
                ("files", r.files.into()),
                ("dirs", r.dirs.into()),
                ("symlinks", r.symlinks.into()),
                ("bytes", r.bytes.into()),
            ]);
            // stdout may be the archive itself, so the summary goes to stderr
            if out.json {
                eprintln!("{}", j.render());
            } else {
                eprintln!("{} files, {} dirs, {} symlinks, {}", r.files, r.dirs, r.symlinks, human(r.bytes));
            }
        }
        Cmd::Import { file, name } => {
            let r = match file {
                Some(p) => store.import_tar(BufReader::new(File::open(p)?), name.as_deref())?,
                None => store.import_tar(BufReader::new(io::stdin()), name.as_deref())?,
            };
            let skipped: Vec<String> = r.skipped.iter().map(|p| p.display().to_string()).collect();
            let j = obj([
                ("name", r.name.as_str().into()),
                ("root", r.root.to_hex().into()),
                ("files", r.files.into()),
                ("dirs", r.dirs.into()),
                ("symlinks", r.symlinks.into()),
                ("bytes", r.bytes.into()),
                ("new_bytes", r.new_bytes.into()),
                ("skipped", skipped.clone().into()),
            ]);
            let mut note = format!(
                "{} files, {} dirs, {} symlinks, {} ({} new)",
                r.files,
                r.dirs,
                r.symlinks,
                human(r.bytes),
                human(r.new_bytes)
            );
            for p in &skipped {
                note.push_str(&format!("\nskipped {p}"));
            }
            out.emit(j, &r.name, &note);
        }
        Cmd::Serve {
            listen,
            dav_listen,
            metrics_listen,
            token_file,
            read_only,
            max_conns,
            tls_cert,
            tls_key,
            http_tls,
        } => {
            let token = read_token(&token_file)?;
            let tls = match (tls_cert, tls_key) {
                (Some(c), Some(k)) => Some(TlsServer::load(&c, &k)?),
                _ => None,
            };
            let http_tls = if http_tls { tls.clone() } else { None };
            let opts = ServeOptions { token: token.clone(), read_only, max_conns, tls, ..ServeOptions::default() };
            return serve(store, listen, dav_listen, metrics_listen, token, opts, http_tls, &out);
        }
        Cmd::Push { addr, snapshot, token_file, tls_ca } => {
            let token = read_token(&token_file)?;
            let mut remote = dial(&addr, token.as_deref(), &tls_ca)?;
            let rep = match snapshot {
                Some(n) => {
                    let mut rep = SyncReport::default();
                    copy_snapshot(&mut store, &mut remote, &n, &mut rep)?;
                    rep
                }
                None => copy_all(&mut store, &mut remote)?,
            };
            return Ok(sync_report(&rep, &out));
        }
        Cmd::Pull { addr, snapshot, token_file, tls_ca } => {
            let token = read_token(&token_file)?;
            let mut remote = dial(&addr, token.as_deref(), &tls_ca)?;
            let rep = match snapshot {
                Some(n) => {
                    let mut rep = SyncReport::default();
                    copy_snapshot(&mut remote, &mut store, &n, &mut rep)?;
                    rep
                }
                None => copy_all(&mut remote, &mut store)?,
            };
            return Ok(sync_report(&rep, &out));
        }
        Cmd::Bench { .. } | Cmd::TlsCert { .. } => unreachable!("handled before the store is opened"),
    }
    Ok(true)
}

fn dial(addr: &str, token: Option<&[u8]>, ca: &Option<PathBuf>) -> Result<Client> {
    let Some(ca) = ca else { return Client::connect(addr, token) };
    let tls = TlsClient::load(ca)?;
    let (host, port) = addr.rsplit_once(':').ok_or(cas::Error::Tls("address must be host:port".into()))?;
    let port = port.parse().map_err(|_| cas::Error::Tls("bad port".into()))?;
    // IPv6 literals come as [::1]:port
    Client::connect_tls(host.trim_matches(['[', ']']), port, token, &tls)
}

fn sync_report(rep: &SyncReport, out: &Out) -> bool {
    let j = obj([
        ("objects_sent", rep.objects_sent.into()),
        ("objects_skipped", rep.objects_skipped.into()),
        ("chunks_sent", rep.chunks_sent.into()),
        ("bytes_sent", rep.bytes_sent.into()),
        ("snapshots_sent", rep.snapshots_sent.into()),
        ("snapshots_skipped", rep.snapshots_skipped.into()),
        ("conflicts", rep.conflicts.clone().into()),
    ]);
    let mut note = format!(
        "{} objects ({} already there), {} chunks, {}; {} snapshots ({} already there)",
        rep.objects_sent,
        rep.objects_skipped,
        rep.chunks_sent,
        human(rep.bytes_sent),
        rep.snapshots_sent,
        rep.snapshots_skipped
    );
    for c in &rep.conflicts {
        note.push_str(&format!("\nsnapshot {c} differs on the other side, left alone"));
    }
    out.emit(j, "", &note);
    rep.conflicts.is_empty()
}

struct MetricsPage(Arc<Shared>);

impl Handler for MetricsPage {
    fn handle(&self, req: &Request, out: &mut dyn Write) -> io::Result<()> {
        let head = req.method == "HEAD";
        if !(head || req.method == "GET") || req.path != "/metrics" {
            return respond(out, 404, &[("Content-Type", "text/plain".into())], b"not found", head);
        }
        match self.0.metrics_text() {
            Ok(t) => respond(out, 200, &[("Content-Type", "text/plain; version=0.0.4".into())], t.as_bytes(), head),
            Err(_) => respond(out, 500, &[("Content-Type", "text/plain".into())], b"error", head),
        }
    }
}

fn serve(
    store: Store,
    listen: SocketAddr,
    dav: Option<SocketAddr>,
    metrics: Option<SocketAddr>,
    token: Option<Vec<u8>>,
    opts: ServeOptions,
    http_tls: Option<TlsServer>,
    out: &Out,
) -> Result<bool> {
    let server = Server::bind(store, listen, opts)?;
    let stop = server.stop_flag();
    let shared = server.shared();
    let mut threads = Vec::new();

    let mut addrs = vec![("cas", "cas protocol", server.local_addr()?)];
    if let Some(a) = dav {
        let mut h = HttpServer::bind(a, Arc::new(Dav::new(shared.clone(), token)))?
            .with_stop_flag(stop.clone())
            .with_idle(Duration::from_secs(60));
        if let Some(t) = &http_tls {
            h = h.with_tls(t.clone());
        }
        addrs.push(("dav", "webdav", h.local_addr()?));
        threads.push(std::thread::spawn(move || h.run()));
    }
    if let Some(a) = metrics {
        let mut h = HttpServer::bind(a, Arc::new(MetricsPage(shared.clone())))?.with_stop_flag(stop.clone());
        if let Some(t) = &http_tls {
            h = h.with_tls(t.clone());
        }
        addrs.push(("metrics", "metrics", h.local_addr()?));
        threads.push(std::thread::spawn(move || h.run()));
    }

    let flag = stop.clone();
    ctrlc::set_handler(move || flag.store(true, Ordering::Relaxed)).map_err(io::Error::other)?;

    if out.json {
        let j = Json::Obj(addrs.iter().map(|(k, _, a)| (k.to_string(), a.to_string().into())).collect());
        println!("{}", j.render());
    } else {
        for (_, label, a) in &addrs {
            println!("{label} on {a}");
        }
    }
    io::stdout().flush()?;

    let res = server.run();
    stop.store(true, Ordering::Relaxed);
    for t in threads {
        let _ = t.join();
    }
    res?;
    Ok(true)
}

fn snapshot(store: &mut Store, cmd: Snap, out: &Out) -> Result<bool> {
    match cmd {
        Snap::Create { dir, name } => {
            let r = store.snapshot_dir(dir, name.as_deref())?;
            let skipped: Vec<String> = r.skipped.iter().map(|p| p.display().to_string()).collect();
            let j = obj([
                ("name", r.name.as_str().into()),
                ("root", r.root.to_hex().into()),
                ("files", r.files.into()),
                ("dirs", r.dirs.into()),
                ("symlinks", r.symlinks.into()),
                ("bytes", r.bytes.into()),
                ("new_bytes", r.new_bytes.into()),
                ("skipped", skipped.clone().into()),
            ]);
            let mut note = format!(
                "{} files, {} dirs, {} symlinks, {} ({} new), tree {}",
                r.files,
                r.dirs,
                r.symlinks,
                human(r.bytes),
                human(r.new_bytes),
                r.root.short()
            );
            for p in &skipped {
                note.push_str(&format!("\nskipped {p}"));
            }
            out.emit(j, &r.name, &note);
        }
        Snap::Ls => {
            let snaps = store.snapshot_list()?;
            let j = Json::Arr(
                snaps
                    .iter()
                    .map(|s| {
                        obj([
                            ("name", s.name.as_str().into()),
                            ("time", s.time.into()),
                            ("root", s.root.to_hex().into()),
                            ("source", s.source.as_str().into()),
                        ])
                    })
                    .collect(),
            );
            let t: Vec<String> =
                snaps.iter().map(|s| format!("{:<24} {}  {}  {}", s.name, s.time, s.root.short(), s.source)).collect();
            out.emit(j, &t.join("\n"), "");
        }
        Snap::Show { name } => {
            let s = store.snapshot_get(&name)?;
            let items = store.flatten(&s.root)?;
            let j = Json::Arr(
                items
                    .iter()
                    .map(|(path, e)| {
                        let kind = match e.kind {
                            cas::Kind::Dir => "dir",
                            cas::Kind::File => "file",
                            cas::Kind::Symlink => "symlink",
                        };
                        obj([
                            ("path", path.as_str().into()),
                            ("kind", kind.into()),
                            ("size", e.size.into()),
                            ("mode", e.mode.into()),
                            ("mtime", e.mtime.into()),
                            ("target", if e.target.is_empty() { Json::Null } else { e.target.as_str().into() }),
                        ])
                    })
                    .collect(),
            );
            let t: Vec<String> = items
                .iter()
                .map(|(path, e)| match e.kind {
                    cas::Kind::Dir => format!("d {:>10}  {path}/", ""),
                    cas::Kind::File => format!("- {:>10}  {path}", human(e.size)),
                    cas::Kind::Symlink => format!("l {:>10}  {path} -> {}", "", e.target),
                })
                .collect();
            out.emit(j, &t.join("\n"), "");
        }
        Snap::Restore { name, dest } => {
            let r = store.snapshot_restore(&name, dest)?;
            let j = obj([
                ("files", r.files.into()),
                ("dirs", r.dirs.into()),
                ("symlinks", r.symlinks.into()),
                ("bytes", r.bytes.into()),
                ("skipped_symlinks", r.skipped.into()),
            ]);
            let mut note = format!("{} files, {} dirs, {} symlinks, {}", r.files, r.dirs, r.symlinks, human(r.bytes));
            if r.skipped > 0 {
                note.push_str(&format!("\n{} symlinks skipped (not supported here)", r.skipped));
            }
            out.emit(j, "", &note);
        }
        Snap::Diff { a, b } => {
            let ch = store.snapshot_diff(&a, &b)?;
            let j = Json::Arr(
                ch.iter()
                    .map(|c| obj([("change", c.sigil().to_string().into()), ("path", c.path.as_str().into())]))
                    .collect(),
            );
            let t: Vec<String> = ch.iter().map(|c| format!("{} {}", c.sigil(), c.path)).collect();
            out.emit(j, &t.join("\n"), "");
            return Ok(ch.is_empty());
        }
        Snap::Verify { name } => {
            store.snapshot_verify(&name)?;
            out.emit(obj([("name", name.as_str().into()), ("ok", true.into())]), "ok", "");
        }
        Snap::Forget { name } => {
            let r = store.snapshot_forget(&name)?;
            let j = obj([("objects_removed", r.objects_removed.into()), ("objects_kept", r.objects_kept.into())]);
            let note = format!("released {} objects, {} still needed", r.objects_removed, r.objects_kept);
            out.emit(j, "", &note);
        }
        Snap::Prune { keep_last, keep_daily, keep_weekly, keep_monthly, dry_run } => {
            let p = Retention { last: keep_last, daily: keep_daily, weekly: keep_weekly, monthly: keep_monthly };
            let gone = store.snapshot_prune(&p, dry_run)?;
            let j = obj([("dry_run", dry_run.into()), ("forgotten", gone.clone().into())]);
            let verb = if dry_run { "would forget" } else { "forgot" };
            let t: Vec<String> = gone.iter().map(|n| format!("{verb} {n}")).collect();
            out.emit(j, &t.join("\n"), "");
        }
    }
    Ok(true)
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
