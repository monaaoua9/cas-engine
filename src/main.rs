use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;
use std::process::ExitCode;

use cas::{Hash, Result, Store, StoreConfig};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cas", version, about = "content-addressed immutable object store")]
struct Cli {
    /// store directory, created on first use
    #[arg(short, long, default_value = "./cas-store")]
    store: PathBuf,

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

fn run(cli: Cli) -> Result<bool> {
    let mut store = Store::open(&cli.store, StoreConfig::default())?;

    match cli.cmd {
        Cmd::Put { path } => {
            let r = store.put_file(path)?;
            println!("{}", r.id);
            eprintln!(
                "{} in {} chunks, {} new ({}){}",
                human(r.size),
                r.chunks,
                r.new_chunks,
                human(r.new_bytes),
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
