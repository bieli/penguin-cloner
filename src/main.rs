//! penguin-cloner — dump a running Linux process binary + memory for recovery.
//!
//! This does **not** create a live-resumable checkpoint (use [CRIU](https://criu.org)
//! for that). It recovers:
//! - the executable image (`/proc/<pid>/exe`)
//! - selected memory regions (heap/stack/anon + optional file-backed)
//! - cmdline, environ, cwd, open fds
//! - printable strings (often holds in-memory config)

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use penguin_cloner::dump::{self, DumpOptions};
use penguin_cloner::maps;
use penguin_cloner::process;
use penguin_cloner::strings::{self, StringOptions};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "penguin-cloner",
    about = "Clone / dump a running Linux process binary and memory for disaster recovery",
    long_about = "Freeze (optional) a live PID, copy its executable and memory maps, and \
extract strings that often contain runtime configuration. Intended for legacy servers \
where a long-running process holds unique in-memory state and nobody wants to restart \
it until a dump exists.\n\nRequires: same UID as the target, or root / CAP_SYS_PTRACE. \
Yama ptrace_scope may still block attach — see README."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Dump binary + memory + metadata for a running PID
    Dump {
        /// Target process id
        #[arg(long, short)]
        pid: i32,

        /// Output directory (created if missing)
        #[arg(long, short, default_value = "./clone-out")]
        out: PathBuf,

        /// Also dump read-only file-backed mappings (libs, binary pages) — much larger
        #[arg(long)]
        include_file_backed: bool,

        /// Only dump [heap] and [stack] regions
        #[arg(long)]
        heap_stack_only: bool,

        /// Skip ptrace attach (faster, but memory may change while dumping)
        #[arg(long)]
        no_freeze: bool,

        /// Skip copying /proc/<pid>/exe
        #[arg(long)]
        no_exe: bool,

        /// Max bytes per region (skip larger); default 512 MiB
        #[arg(long, default_value_t = 512 * 1024 * 1024)]
        max_region_bytes: u64,

        /// Also build memory_combined.bin + index
        #[arg(long)]
        combined: bool,

        /// Extract printable strings after dump
        #[arg(long, default_value_t = true)]
        strings: bool,

        /// Keep only strings that look like paths / config / secrets
        #[arg(long)]
        interesting_strings: bool,

        /// Minimum string length
        #[arg(long, default_value_t = 6)]
        min_string: usize,
    },

    /// List memory maps for a PID (no dump)
    Maps {
        #[arg(long, short)]
        pid: i32,
    },

    /// Extract strings from an existing dump's memory/ directory
    Strings {
        #[arg(long, short)]
        dir: PathBuf,

        #[arg(long, default_value_t = 6)]
        min_string: usize,

        #[arg(long)]
        interesting_only: bool,
    },

    /// Spawn a short-lived child and dump it (verifies permissions / Yama)
    #[command(name = "self-test")]
    Probe {
        #[arg(long, short, default_value = "./clone-selftest")]
        out: PathBuf,
    },
}

#[derive(Serialize)]
struct Manifest {
    tool: &'static str,
    version: &'static str,
    timestamp: String,
    host: HostInfo,
    process: process::ProcessInfo,
    dump: dump::DumpReport,
    notes: Vec<&'static str>,
}

#[derive(Serialize)]
struct HostInfo {
    hostname: String,
    kernel: String,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Dump {
            pid,
            out,
            include_file_backed,
            heap_stack_only,
            no_freeze,
            no_exe,
            max_region_bytes,
            combined,
            strings,
            interesting_strings,
            min_string,
        } => {
            if pid <= 1 {
                bail!("refusing to target pid {pid}");
            }
            cmd_dump(
                pid,
                out,
                DumpOptions {
                    include_file_backed,
                    heap_stack_only,
                    max_region_bytes,
                    freeze: !no_freeze,
                },
                !no_exe,
                combined,
                strings,
                StringOptions {
                    min_len: min_string,
                    interesting_only: interesting_strings,
                },
            )
        }
        Commands::Maps { pid } => cmd_maps(pid),
        Commands::Strings {
            dir,
            min_string,
            interesting_only,
        } => cmd_strings(
            dir,
            StringOptions {
                min_len: min_string,
                interesting_only,
            },
        ),
        Commands::Probe { out } => cmd_selftest(out),
    }
}

fn cmd_dump(
    pid: i32,
    out: PathBuf,
    opts: DumpOptions,
    copy_exe: bool,
    combined: bool,
    do_strings: bool,
    string_opts: StringOptions,
) -> Result<()> {
    fs::create_dir_all(&out).with_context(|| format!("mkdir {}", out.display()))?;

    eprintln!("[*] collecting /proc/{pid} metadata…");
    let info = process::collect(pid)?;
    fs::write(
        out.join("process.json"),
        serde_json::to_string_pretty(&info)?,
    )?;
    fs::write(out.join("cmdline.txt"), info.cmdline.join("\0") + "\0")?;
    fs::write(
        out.join("environ.txt"),
        info.environ.to_vec().join("\n") + "\n",
    )?;

    if copy_exe {
        let exe_dest = out.join("exe.bin");
        eprintln!("[*] copying /proc/{pid}/exe → {}", exe_dest.display());
        match process::copy_exe(pid, &exe_dest) {
            Ok(n) => eprintln!("    ok ({n} bytes)"),
            Err(e) => eprintln!("    warn: could not copy exe: {e:#}"),
        }
        // Best-effort: also try the real path if still on disk
        if let Some(ref path) = info.exe_path {
            if PathBuf::from(path).exists() {
                let _ = fs::copy(path, out.join("exe_ondisk_copy.bin"));
            }
        }
    }

    eprintln!(
        "[*] dumping memory (freeze={}, file_backed={}, heap_stack_only={})…",
        opts.freeze, opts.include_file_backed, opts.heap_stack_only
    );
    let report = dump::dump_process(pid, &out, &opts)?;
    dump::write_index(&out, &report)?;
    eprintln!(
        "    dumped {} / {} regions ({} bytes)",
        report.regions_dumped, report.regions_total, report.bytes_dumped
    );
    if report.regions_dumped == 0 {
        eprintln!(
            "[!] no memory regions dumped. Likely blocked by Yama ptrace_scope or missing \
             CAP_SYS_PTRACE. Try: sudo penguin-cloner dump --pid {pid} … \
             or run `penguin-cloner self-test` to verify this build."
        );
    }

    if combined {
        let p = dump::write_combined_blob(&out, &report)?;
        eprintln!("[*] combined blob → {}", p.display());
    }

    if do_strings {
        let strings_path = out.join("strings.txt");
        eprintln!("[*] extracting strings → {}", strings_path.display());
        let n = strings::extract_from_dir(&out.join("memory"), &strings_path, &string_opts)?;
        eprintln!("    {n} strings");
    }

    let manifest = Manifest {
        tool: "penguin-cloner",
        version: env!("CARGO_PKG_VERSION"),
        timestamp: chrono::Local::now().to_rfc3339(),
        host: HostInfo {
            hostname: fs::read_to_string("/etc/hostname")
                .unwrap_or_else(|_| "unknown".into())
                .trim()
                .to_string(),
            kernel: fs::read_to_string("/proc/version")
                .unwrap_or_else(|_| "unknown".into())
                .trim()
                .to_string(),
        },
        process: info,
        dump: report,
        notes: vec![
            "This is a forensic/recovery dump, NOT a live process checkpoint.",
            "To resume a process across reboot, use CRIU (Checkpoint/Restore In Userspace).",
            "Use strings.txt / environ.txt / open fds to rebuild configuration after restart.",
            "exe.bin is the running image from /proc/<pid>/exe (may differ from disk if replaced).",
        ],
    };
    fs::write(
        out.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;

    eprintln!("[+] done → {}", out.display());
    Ok(())
}

fn cmd_maps(pid: i32) -> Result<()> {
    let regions = maps::parse_maps(pid)?;
    println!(
        "{:<17} {:<17} {:<5} {:>12}  PATH",
        "START", "END", "PERM", "SIZE"
    );
    for r in regions {
        println!(
            "{:016x} {:016x} {:<5} {:>12}  {}",
            r.start,
            r.end,
            r.perms,
            r.size(),
            r.pathname
        );
    }
    Ok(())
}

fn cmd_strings(dir: PathBuf, opts: StringOptions) -> Result<()> {
    let mem = if dir.join("memory").is_dir() {
        dir.join("memory")
    } else {
        dir.clone()
    };
    let out = dir.join("strings.txt");
    let n = strings::extract_from_dir(&mem, &out, &opts)?;
    eprintln!("[+] wrote {n} strings → {}", out.display());
    Ok(())
}

fn cmd_selftest(out: PathBuf) -> Result<()> {
    use std::process::{Command, Stdio};

    let mut child = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn sleep for self-test")?;
    let pid = child.id() as i32;
    eprintln!("[*] self-test child pid={pid}");

    let result = cmd_dump(
        pid,
        out.clone(),
        DumpOptions {
            include_file_backed: false,
            heap_stack_only: false,
            max_region_bytes: 64 * 1024 * 1024,
            freeze: true,
        },
        true,
        false,
        true,
        StringOptions {
            min_len: 4,
            interesting_only: false,
        },
    );

    let _ = child.kill();
    let _ = child.wait();

    let report_path = out.join("memory_index.json");
    if report_path.exists() {
        let v: serde_json::Value = serde_json::from_str(&fs::read_to_string(report_path)?)?;
        let n = v["regions_dumped"].as_u64().unwrap_or(0);
        if n == 0 {
            bail!("self-test failed: 0 regions dumped (check ptrace permissions)");
        }
        eprintln!("[+] self-test ok ({n} regions)");
    }
    result
}
