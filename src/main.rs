use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;
use std::process::ExitCode;

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

fn human(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n} B") } else { format!("{v:.1} {}", U[i]) }
}

fn read_password(p: &std::path::Path) -> std::io::Result<Password> {
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

fn run(cli: Cli) -> Result<bool> {
    let mut cfg = StoreConfig::default();
    if cli.chunker == "gear" {
        cfg.chunker.algorithm = Algorithm::Gear;
    }
    if cli.compress == "lz4" {
        cfg.compression = Compression::Lz4;
    }
    let pw_file = cli.password_file.clone().or_else(|| std::env::var_os("CAS_PASSWORD_FILE").map(PathBuf::from));
    if let Some(p) = pw_file {
        cfg.password = Some(read_password(&p)?);
    }
    let mut store = Store::open(&cli.store, cfg)?;

    match cli.cmd {
        Cmd::Put { path } => {
            let r = store.put_file(path)?;
            println!("{}", r.id);
            eprintln!(
                "{} in {} chunks, {} new ({}, {} stored){}",
                human(r.size),
                r.chunks,
                r.new_chunks,
                human(r.new_bytes),
                human(r.stored_bytes),
                if r.existed { ", already stored" } else { "" }
            );
        }
        Cmd::Get { id, out } => {
            let mut w = BufWriter::new(File::create(out)?);
            store.read_into(&id, &mut w)?;
            std::io::Write::flush(&mut w)?;
        }
        Cmd::Rm { id } => {
            if !store.remove(&id)? {
                eprintln!("no such object");
                return Ok(false);
            }
        }
        Cmd::Ls => {
            for id in store.list()? {
                println!("{id}  {}", human(store.manifest(&id)?.size));
            }
        }
        Cmd::Verify { id: Some(id) } => {
            store.verify(&id)?;
            println!("ok");
        }
        Cmd::Verify { id: None } => {
            let mut bad = 0;
            for id in store.list()? {
                if let Err(e) = store.verify(&id) {
                    println!("{id}: {e}");
                    bad += 1;
                }
            }
            let s = store.scrub()?;
            for h in &s.corrupt {
                println!("chunk {h}: corrupt");
            }
            println!("{} chunks checked, {} corrupt, {bad} bad objects", s.checked, s.corrupt.len());
            return Ok(bad == 0 && s.corrupt.is_empty());
        }
        Cmd::Prove { id, chunk } => {
            let (c, p) = store.prove(&id, chunk)?;
            let m = store.manifest(&id)?;
            println!("root   {id}");
            println!("chunk  {} ({} bytes), leaf {} of {}", c.hash, c.len, p.index, p.leaf_count);
            for s in &p.siblings {
                println!("  sib  {s}");
            }
            let ok = p.verify(c.leaf(), &m.id());
            println!("proof {}", if ok { "valid" } else { "INVALID" });
            return Ok(ok);
        }
        Cmd::Gc => {
            let r = store.gc()?;
            println!(
                "removed {} chunks, moved {}, deleted {} segments, reclaimed {}",
                r.chunks_removed,
                r.chunks_moved,
                r.segments_removed,
                human(r.bytes_reclaimed)
            );
        }
        Cmd::Stats => {
            let s = store.stats()?;
            println!("objects        {}", s.objects);
            println!("logical size   {}", human(s.logical_bytes));
            println!("live chunks    {} ({})", s.live_chunks, human(s.live_bytes));
            println!("dead chunks    {} ({})", s.dead_chunks, human(s.dead_bytes));
            println!("segments       {}", s.segments);
            println!("dedup ratio    {:.2}x", s.dedup_ratio());
            println!("snapshots      {}", store.snapshot_list()?.len());
            println!("encrypted      {}", if store.is_encrypted() { "yes" } else { "no" });
        }
        Cmd::Passwd { new_password_file } => {
            store.change_password(&read_password(&new_password_file)?)?;
        }
        Cmd::Snapshot(c) => return snapshot(&mut store, c),
    }
    Ok(true)
}

fn snapshot(store: &mut Store, cmd: Snap) -> Result<bool> {
    match cmd {
        Snap::Create { dir, name } => {
            let r = store.snapshot_dir(dir, name.as_deref())?;
            println!("{}", r.name);
            eprintln!(
                "{} files, {} dirs, {} symlinks, {} ({} new), tree {}",
                r.files,
                r.dirs,
                r.symlinks,
                human(r.bytes),
                human(r.new_bytes),
                r.root.short()
            );
            for p in &r.skipped {
                eprintln!("skipped {}", p.display());
            }
        }
        Snap::Ls => {
            for s in store.snapshot_list()? {
                println!("{:<24} {}  {}  {}", s.name, s.time, s.root.short(), s.source);
            }
        }
        Snap::Show { name } => {
            let s = store.snapshot_get(&name)?;
            for (path, e) in store.flatten(&s.root)? {
                match e.kind {
                    cas::Kind::Dir => println!("d {:>10}  {path}/", ""),
                    cas::Kind::File => println!("- {:>10}  {path}", human(e.size)),
                    cas::Kind::Symlink => println!("l {:>10}  {path} -> {}", "", e.target),
                }
            }
        }
        Snap::Restore { name, dest } => {
            let r = store.snapshot_restore(&name, dest)?;
            eprintln!("{} files, {} dirs, {} symlinks, {}", r.files, r.dirs, r.symlinks, human(r.bytes));
            if r.skipped > 0 {
                eprintln!("{} symlinks skipped (not supported here)", r.skipped);
            }
        }
        Snap::Diff { a, b } => {
            let ch = store.snapshot_diff(&a, &b)?;
            for c in &ch {
                println!("{} {}", c.sigil(), c.path);
            }
            return Ok(ch.is_empty());
        }
        Snap::Verify { name } => {
            store.snapshot_verify(&name)?;
            println!("ok");
        }
        Snap::Forget { name } => {
            let r = store.snapshot_forget(&name)?;
            eprintln!("released {} objects, {} still needed", r.objects_removed, r.objects_kept);
        }
        Snap::Prune { keep_last, keep_daily, keep_weekly, keep_monthly, dry_run } => {
            let p = Retention { last: keep_last, daily: keep_daily, weekly: keep_weekly, monthly: keep_monthly };
            for n in store.snapshot_prune(&p, dry_run)? {
                println!("{}{n}", if dry_run { "would forget " } else { "forgot " });
            }
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
