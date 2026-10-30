use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cas::json::{Json, obj};
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

fn read_password(p: &Path) -> std::io::Result<Password> {
    let mut b = std::fs::read(p)?;
    // editors add a newline; the password is the first line
    if let Some(i) = b.iter().position(|&c| c == b'\n') {
        b.truncate(i);
    }
    if b.last() == Some(&b'\r') {
        b.pop();
    }
    Ok(Password::from(b))
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
        Cmd::Bench { .. } => unreachable!("handled before the store is opened"),
    }
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
